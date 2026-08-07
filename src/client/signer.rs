//! `client::signer` — the SIGNING interface (SPEC §4, §8). dig-app holds the key HERE.
//!
//! This module and [`super::hd`] are the ONLY places the crate touches secret material
//! (`chia_bls::SecretKey`), compiled ONLY under the `client` feature. dig-app implements
//! [`IdentitySigner`] with a [`LocalSigner`] that holds the master key and, when the engine needs
//! a spend signed, matches each [`crate::types::RequiredSignature`] to a derived key, signs, and aggregates.
//! The key never leaves dig-app — the engine only ever calls OUT to a
//! [`crate::engine::signer::RemoteSigner`], for which [`LocalSigner`] is the concrete impl.
//!
//! # Custody controls (fail-closed)
//! The signer defends against a compromised or buggy engine (it is reachable as a `RemoteSigner`
//! over IPC) handing it dangerous bytes to sign:
//!
//! 1. **Only forced standard-layer `AGG_SIG_ME` requirements are ever signed.** `sign_unsigned`
//!    re-derives the required signatures FROM the verified coin spends and keeps ONLY those whose
//!    SDK-extracted kind is `AGG_SIG_ME` (`domain_string == Some(me())`). Every other agg_sig kind —
//!    `AGG_SIG_UNSAFE` (raw, coin-unbound, attacker-chosen message) and the Parent/Puzzle/Amount/…
//!    families — is refused fail-closed, so the engine cannot launder an arbitrary drain
//!    authorization through a benign carrier spend. The engine-supplied `required_signatures` field
//!    is untrusted (only cross-checked), never the signing source. (`verify::analyze` additionally
//!    rejects any coin spend carrying a non-ME agg_sig condition, defense-in-depth.)
//! 2. **Key-must-match, fail-closed.** A required signature whose public key the signer cannot
//!    reproduce from its own derivation is rejected — the signer never fabricates or skips a
//!    signature.
//! 3. **Verify-before-sign.** No signature is produced until `verify::analyze` has independently
//!    accounted for the coin spends' value flow and the reviewed summary matches (see
//!    [`LocalSigner::sign_unsigned`]).

use async_trait::async_trait;
use chia_bls::{aggregate, sign as bls_sign, PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, SpendBundle};
use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};

use crate::types::{
    IdentityRef, Network, SignedBundle, TransactionSummary, UnsignedSpend, WalletError,
    WalletErrorCode, WalletResult,
};

use super::hd::{MasterKey, DEFAULT_ADDRESS_GAP};
use super::review::{self, HumanReadableSummary};
use super::verify::{self, SpendEffect};

/// The Chia mainnet genesis challenge — the AGG_SIG_ME additional data every mainnet spend
/// signature is bound to. Sourced from `dig-constants` (the ecosystem's single source of truth for
/// the Chia-L1 domain), so the signer binds byte-identically to what [`crate::engine::build`]
/// binds — signer == engine by construction (see the `signer_binds_the_same_agg_sig_me_as_engine`
/// KAT). `CHIA_L1_*` is the Chia L1 genesis, deliberately distinct from the DIG L2 genesis.
const MAINNET_AGG_SIG_ME_EXTRA_DATA: [u8; 32] = dig_constants::CHIA_L1_MAINNET_AGG_SIG_ME;

/// The Chia testnet11 genesis challenge — the AGG_SIG_ME additional data on testnet11, likewise
/// sourced from `dig-constants` so signer and engine cannot drift.
const TESTNET11_AGG_SIG_ME_EXTRA_DATA: [u8; 32] = dig_constants::CHIA_L1_TESTNET11_AGG_SIG_ME;

/// The client-side signing contract: sign an unsigned spend for a specific identity.
///
/// dig-app implements this over the key it holds. It is deliberately separate from the engine's
/// [`crate::engine::signer::RemoteSigner`]: `IdentitySigner` is the local, key-holding view;
/// `RemoteSigner` is the engine's remote-callback view. [`LocalSigner`] bridges the two.
#[async_trait]
pub trait IdentitySigner: Send + Sync {
    /// The public identity this signer signs for.
    fn identity(&self) -> &IdentityRef;

    /// Gather the required signatures for `unsigned`, aggregate, and return a signed bundle.
    async fn sign(&self, unsigned: UnsignedSpend) -> WalletResult<SignedBundle>;
}

/// Which HD derivation the signer's money keys use to match + own coins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalletKeyScheme {
    /// The legacy profile path `m/44'/8444'/{profile_ix}'/{ix}` (#997) — a DISTINCT, never-funded
    /// address set. Retained only for pre-canonical internal callers; NEVER controls real funds.
    LegacyProfile,
    /// The CANONICAL Chia wallet path `master_to_wallet_unhardened(master, ix).derive_synthetic()`
    /// (`m/12381/8444/2/ix`, unhardened + synthetic) — byte-identical to dig-account's `WalletKey`,
    /// the pre-cutover dig-app wallet, and every standard Chia wallet (incl. Sage). This is the set
    /// funds ACTUALLY live at, so a consumer's money spends MUST sign through this scheme.
    CanonicalWallet,
}

/// A signer that holds the master HD key in-process (dig-app side).
///
/// Holds a [`MasterKey`] entirely within the client seam — it never crosses to the engine. On
/// [`sign_unsigned`](LocalSigner::sign_unsigned) it derives the active wallet's address keys (via
/// its [`WalletKeyScheme`]), matches each [`crate::types::RequiredSignature`] to a derived key,
/// signs the (network-bound) message with augmented BLS, and aggregates. Deliberately no
/// `Debug`/`Serialize`/`Clone`: the held key never leaks.
pub struct LocalSigner {
    identity: IdentityRef,
    master: MasterKey,
    agg_sig_me_extra_data: [u8; 32],
    address_gap: u32,
    scheme: WalletKeyScheme,
}

impl LocalSigner {
    /// Create a signer for `identity` holding `master`, bound to `network` (which fixes the
    /// AGG_SIG_ME additional data the signer requires on every message).
    ///
    /// [`Network::Simulator`] has no fixed genesis challenge; use
    /// [`with_agg_sig_me_extra_data`](LocalSigner::with_agg_sig_me_extra_data) to supply the
    /// simulator's constant explicitly.
    pub fn new(identity: IdentityRef, master: MasterKey, network: Network) -> WalletResult<Self> {
        let agg_sig_me_extra_data = match network {
            Network::Mainnet => MAINNET_AGG_SIG_ME_EXTRA_DATA,
            Network::Testnet => TESTNET11_AGG_SIG_ME_EXTRA_DATA,
            Network::Simulator => return Err(WalletError::invalid_input(
                "Network::Simulator has no fixed genesis challenge; use with_agg_sig_me_extra_data",
            )),
        };
        Ok(Self {
            identity,
            master,
            agg_sig_me_extra_data,
            address_gap: DEFAULT_ADDRESS_GAP,
            scheme: WalletKeyScheme::LegacyProfile,
        })
    }

    /// Create a signer over the CANONICAL Chia wallet money keys
    /// (`master_to_wallet_unhardened(master, ix).derive_synthetic()`) — the derivation that controls
    /// the address funds actually live at (byte-identical to dig-account's `WalletKey`, the
    /// pre-cutover dig-app wallet, and Sage). **This is the constructor money-spending consumers
    /// (dig-account, dig-node) MUST use**: it makes [`find_key`](LocalSigner::find_key) search — and
    /// [`owns_puzzle_hash`](LocalSigner::owns_puzzle_hash) recognize — the canonical synthetic
    /// address set across the address gap, so the signer can authorize a spend of the wallet's real
    /// coins (the legacy [`new`](LocalSigner::new) profile path is a distinct, never-funded set).
    pub fn new_canonical(
        identity: IdentityRef,
        master: MasterKey,
        network: Network,
    ) -> WalletResult<Self> {
        Ok(Self::new(identity, master, network)?.with_canonical_wallet_keys())
    }

    /// Create a signer bound to an explicit AGG_SIG_ME additional data (e.g. a simulator or custom
    /// network genesis challenge). Defaults to the legacy profile scheme; chain
    /// [`with_canonical_wallet_keys`](LocalSigner::with_canonical_wallet_keys) for the money path.
    pub fn with_agg_sig_me_extra_data(
        identity: IdentityRef,
        master: MasterKey,
        agg_sig_me_extra_data: [u8; 32],
    ) -> Self {
        Self {
            identity,
            master,
            agg_sig_me_extra_data,
            address_gap: DEFAULT_ADDRESS_GAP,
            scheme: WalletKeyScheme::LegacyProfile,
        }
    }

    /// Switch this signer to the CANONICAL Chia wallet money-key scheme (see
    /// [`new_canonical`](LocalSigner::new_canonical)). The derivation that controls real funds.
    #[must_use]
    pub fn with_canonical_wallet_keys(mut self) -> Self {
        self.scheme = WalletKeyScheme::CanonicalWallet;
        self
    }

    /// Override the address gap limit — how many derived address keys the signer will try to match
    /// a required signature against.
    pub fn with_address_gap(mut self, address_gap: u32) -> Self {
        self.address_gap = address_gap;
        self
    }

    /// The public key of the active profile's account node. Public material — safe to expose.
    pub fn public_key(&self) -> PublicKey {
        self.master.profile_public_key(self.identity.profile_ix)
    }

    /// The AGG_SIG_ME additional data (network genesis challenge) this signer requires every
    /// message to be bound to. Public, non-secret material — exposed so the engine seam can prove,
    /// in a KAT, that it builds messages bound to the exact bytes this signer will accept
    /// (signer == engine). Never secret key material.
    pub fn agg_sig_me_extra_data(&self) -> [u8; 32] {
        self.agg_sig_me_extra_data
    }

    /// Find the secret key matching `target` among the active profile's derived address keys,
    /// searching indices `0..address_gap`. `None` when no derived key matches (fail-closed).
    ///
    /// For each derived address key TWO candidates are tried, in order:
    ///
    /// 1. the RAW derived key — matches an `AGG_SIG_UNSAFE`/non-standard requirement keyed directly
    ///    on the wallet's derivation, and
    /// 2. the standard-layer SYNTHETIC key — `derive_synthetic()` against the canonical
    ///    [`DEFAULT_HIDDEN_PUZZLE_HASH`](chia_puzzle_types::standard::DEFAULT_HIDDEN_PUZZLE_HASH). This is the key
    ///    `p2_delegated_puzzle_or_hidden_puzzle` (`StandardLayer`) curries into a coin's puzzle, so
    ///    the required signature a normal XCH/CAT send extracts names the SYNTHETIC public key, never
    ///    the raw one (#1368). When it matches, the synthetic SECRET key is returned — the one that
    ///    actually authorizes the spend.
    ///
    /// The synthetic derivation comes from chia-puzzle-types' [`DeriveSynthetic`] — the crate's own
    /// vetted BLS offset, never hand-rolled here.
    fn find_key(&self, target: &PublicKey) -> Option<SecretKey> {
        match self.scheme {
            // Canonical: a standard spend is always authorized by the SYNTHETIC money key
            // (`master_to_wallet_unhardened(master, ix).derive_synthetic()`); the raw unhardened key
            // never signs a wallet coin (and `verify` rejects `AGG_SIG_UNSAFE`), so match only the
            // synthetic — the key funds actually live under.
            WalletKeyScheme::CanonicalWallet => (0..self.address_gap).find_map(|ix| {
                let synthetic = self.master.wallet_signing_key(ix);
                (&synthetic.public_key() == target).then_some(synthetic)
            }),
            WalletKeyScheme::LegacyProfile => {
                let profile = self.identity.profile_ix;
                (0..self.address_gap).find_map(|ix| {
                    let raw = self.master.address_key(profile, ix);
                    if &raw.public_key() == target {
                        return Some(raw);
                    }
                    let synthetic = raw.derive_synthetic();
                    (&synthetic.public_key() == target).then_some(synthetic)
                })
            }
        }
    }

    /// True when `puzzle_hash` is a standard-layer puzzle this wallet controls — i.e. the curry of
    /// the standard puzzle over the SYNTHETIC key of some derived address within the gap. Used to
    /// prove every change output of a spend returns to the wallet (never a foreign address).
    fn owns_puzzle_hash(&self, puzzle_hash: Bytes32) -> bool {
        (0..self.address_gap).any(|ix| {
            let synthetic = match self.scheme {
                WalletKeyScheme::CanonicalWallet => self.master.wallet_public_key(ix),
                WalletKeyScheme::LegacyProfile => self
                    .master
                    .address_key(self.identity.profile_ix, ix)
                    .derive_synthetic()
                    .public_key(),
            };
            Bytes32::from(StandardArgs::curry_tree_hash(synthetic).to_bytes()) == puzzle_hash
        })
    }

    /// Independently VERIFY the coin spends before signing (SPEC §4, #1058, #1511): re-derive the
    /// value flow from the coin spends themselves ([`verify::analyze`]), then split the outputs by
    /// KEY OWNERSHIP ([`reclassify_by_ownership`](LocalSigner::reclassify_by_ownership)) — every
    /// output this wallet can derive a key for is change, every other output is a recipient — and
    /// require the engine-supplied summary to equal exactly those recipients + the fee. Fail-closed —
    /// a spend that cannot be fully accounted for, or whose recipients do not match the reviewed
    /// summary byte-for-byte, is refused, so the signer never blindly signs bytes it did not verify
    /// and no non-owned output can leave the wallet unreviewed.
    fn verify_before_signing(&self, unsigned: &UnsignedSpend) -> WalletResult<()> {
        // Re-derive the value flow, then split it by KEY OWNERSHIP: every output this wallet can
        // derive a key for is change (value returning home); everything else is a recipient. This is
        // the authoritative, key-aware split — it supersedes the key-free memo heuristic
        // `verify::analyze` produces, which over-counts recipients for a $DIG tip (dig-cat memo-hints
        // the tip's change coin too). It never lets value leave unnoticed: a non-owned output is
        // always a recipient, and every recipient must appear in the reviewed summary below.
        let effect = self.reclassify_by_ownership(verify::analyze(&unsigned.coin_spends)?);

        // Defense-in-depth (#1511 MR-3): every `protocol_sink` output MUST commit to a recognized
        // canonical structural puzzle (settlement). `analyze` already routes ONLY settlement-destined
        // outputs here, but re-assert it at the signing gate so a future decode change can never let
        // an attacker address be laundered as a "sink" the summary comparison then excludes.
        for output in &effect.protocol_sink {
            if !verify::is_protocol_sink_hash(output.puzzle_hash) {
                return Err(WalletError::new(
                    WalletErrorCode::SpendValidationFailed,
                    "a protocol-sink output does not commit to a recognized canonical structural \
                     puzzle; refusing to sign",
                ));
            }
        }

        // The reviewed summary MUST equal exactly the outputs that leave the wallet — recipients (by
        // address) and settlement sinks (by amount+asset) — otherwise the engine could show a benign
        // summary while the bytes send value elsewhere. With change split off by ownership above, this
        // is the whole no-silent-exfiltration guarantee.
        self.assert_reviewed_summary_matches(&unsigned.summary, &effect)
    }

    /// Split a re-derived [`SpendEffect`] by KEY OWNERSHIP: an output whose puzzle hash this wallet
    /// controls is CHANGE (value returning home); every other output is a RECIPIENT the human must
    /// have reviewed. Unlike the key-free memo split in [`verify::analyze`], this is correct for
    /// spends whose change coin is memo-hinted (every `dig-cat`/$DIG-tip send), and it is strictly
    /// safer — a non-owned output can never be silently reclassified as change and slip past the
    /// summary gate.
    fn reclassify_by_ownership(&self, effect: SpendEffect) -> SpendEffect {
        let mut recipients = Vec::new();
        let mut change = Vec::new();
        for output in effect.recipients.into_iter().chain(effect.change) {
            if self.owns_puzzle_hash(output.puzzle_hash) {
                change.push(output);
            } else {
                recipients.push(output);
            }
        }
        // `protocol_sink` is untouched by ownership: it is value the wallet intentionally commits to a
        // consensus-enforced settlement structure (an offer's offered/paid assets), neither returning
        // home nor going to a chosen recipient. Its canonical-hash invariant is enforced separately in
        // `verify_before_signing` before any signature is produced.
        SpendEffect {
            recipients,
            change,
            protocol_sink: effect.protocol_sink,
            fee: effect.fee,
        }
    }

    /// The KEY-AWARE reviewable summary: the value flow re-derived from `coin_spends`, with every
    /// wallet-owned output treated as change so only the outputs that actually LEAVE the wallet are
    /// listed. This is the summary the signer gates the engine's claim against; unlike the key-free
    /// [`verify::derive_summary`] it is correct for a $DIG tip (whose change coin is memo-hinted).
    pub fn reviewable_summary(
        &self,
        coin_spends: &[chia_protocol::CoinSpend],
    ) -> WalletResult<TransactionSummary> {
        let effect = self.reclassify_by_ownership(verify::analyze(coin_spends)?);
        verify::summarize(&effect)
    }

    /// Decode an unsigned spend for the pre-sign CONSENT prompt — the human-readable screen the user
    /// approves before this signer produces a signature (SPEC §4, #2209). NO fallback, fails closed.
    ///
    /// This is the ONLY safe consent decode, and it lives HERE — on the key-holding signer — for one
    /// reason: the approved screen MUST equal the signed bytes, and that equality holds only if the
    /// screen is rendered from the SAME key-aware view the signer authorizes against. Concretely it:
    ///
    /// 1. re-derives the value flow through the shared interpreter [`verify::analyze`] with NO
    ///    fallback — a spend that cannot be independently accounted for returns
    ///    `Err(SpendValidationFailed)` and NEVER renders the engine's (untrusted) claim; and
    /// 2. applies the SAME key-aware ownership split the signing gate uses
    ///    ([`reviewable_summary`](LocalSigner::reviewable_summary) →
    ///    [`reclassify_by_ownership`](LocalSigner::reclassify_by_ownership)), so every output this
    ///    wallet cannot derive a key for is surfaced as a recipient line — INCLUDING an un-hinted
    ///    non-owned output that the key-free [`review::decode`]/[`verify::derive_summary`] would bucket
    ///    as "change" and silently drop.
    ///
    /// Because it renders exactly [`reviewable_summary`](LocalSigner::reviewable_summary) — the very
    /// summary [`verify_before_signing`](LocalSigner::verify_before_signing) gates the engine claim
    /// against — the consent screen and the signed bytes share BOTH the interpreter AND the ownership
    /// split by construction: there is no view the signer would authorize that this decode does not
    /// show. The returned summary is always [`verified`](HumanReadableSummary::verified). Use the
    /// key-free [`review::decode`] only for a display surface that honours the `verified` flag, never
    /// ahead of signing.
    pub fn decode_verified(&self, unsigned: &UnsignedSpend) -> WalletResult<HumanReadableSummary> {
        let summary = self.reviewable_summary(&unsigned.coin_spends)?;
        Ok(review::render(unsigned, &summary, true))
    }

    /// Require the engine-supplied `claimed` summary to match the independently re-derived `effect` on
    /// the fee, the RECIPIENT set (puzzle hash + amount + asset), and the settlement-SINK set (amount +
    /// asset only). Fail-closed on any discrepancy.
    ///
    /// A summary output is a settlement sink iff its address is EMPTY: settlement egress commits to the
    /// fixed settlement puzzle, so the offer builders leave its address blank and it is compared by
    /// amount+asset (the destination is structurally forced, not human-chosen — #1511 PR-B). Every
    /// other output is a recipient, compared on its decoded puzzle hash + normalized asset id so
    /// display-form differences never mask (or fabricate) a mismatch. Splitting on the empty address is
    /// safe because a sink can NEVER be an ordinary payment: `verify_before_signing` has already proven
    /// every re-derived sink commits to the canonical settlement hash.
    fn assert_reviewed_summary_matches(
        &self,
        claimed: &TransactionSummary,
        effect: &SpendEffect,
    ) -> WalletResult<()> {
        let mismatch = |what: &str| {
            WalletError::new(
                WalletErrorCode::SpendValidationFailed,
                format!("engine summary does not match the coin spends: {what}"),
            )
        };

        if claimed.fee.mojos() != effect.fee {
            return Err(mismatch("fee"));
        }

        // The recipient set: derived recipients (real puzzle hashes) vs the claimed outputs carrying a
        // real address, compared as a sorted multiset of (puzzle hash, amount, asset).
        let mut derived_recipients: Vec<(Vec<u8>, u64, Option<String>)> = effect
            .recipients
            .iter()
            .map(|output| {
                (
                    output.puzzle_hash.to_vec(),
                    output.amount,
                    output.asset_id.map(hex::encode),
                )
            })
            .collect();
        let mut reviewed_recipients: Vec<(Vec<u8>, u64, Option<String>)> = claimed
            .outputs
            .iter()
            .filter(|output| !output.address.0.is_empty())
            .map(|output| {
                let puzzle_hash = decode_puzzle_hash(&output.address)?;
                Ok((
                    puzzle_hash,
                    output.amount.mojos(),
                    output
                        .asset_id
                        .as_ref()
                        .map(|asset| normalize_asset(&asset.0)),
                ))
            })
            .collect::<WalletResult<Vec<_>>>()?;
        derived_recipients.sort();
        reviewed_recipients.sort();
        if derived_recipients != reviewed_recipients {
            return Err(mismatch("recipient outputs"));
        }

        // The settlement-sink set: derived protocol-sink outputs vs the claimed empty-address outputs,
        // compared as a sorted multiset of (amount, asset) — the destination is the fixed settlement
        // puzzle, so it is NOT part of the comparison.
        // Zero-value settlement outputs are announcement carriers, not value leaving the wallet, so
        // they are not part of the reviewed egress (mirrors `verify::summarize`).
        let mut derived_sinks: Vec<(u64, Option<String>)> = effect
            .protocol_sink
            .iter()
            .filter(|output| output.amount > 0)
            .map(|output| (output.amount, output.asset_id.map(hex::encode)))
            .collect();
        let mut reviewed_sinks: Vec<(u64, Option<String>)> = claimed
            .outputs
            .iter()
            .filter(|output| output.address.0.is_empty())
            .map(|output| {
                (
                    output.amount.mojos(),
                    output
                        .asset_id
                        .as_ref()
                        .map(|asset| normalize_asset(&asset.0)),
                )
            })
            .collect();
        derived_sinks.sort();
        reviewed_sinks.sort();
        if derived_sinks != reviewed_sinks {
            return Err(mismatch("settlement-sink outputs"));
        }
        Ok(())
    }

    /// The custody core (SPEC §4). Signs the spend classes the engine builds and
    /// [`verify`](super::verify) can independently decode — a standard-layer XCH send, a CAT send, a
    /// $DIG **tip** (a single-key CAT payment; #1511 PR-A), the three **offer** shapes make / take /
    /// cancel (#1511 PR-B), and the covered-option **transfer** (#1511 PR-C), whose offered/paid assets
    /// are accounted as a settlement `protocol_sink`. Settlement-layer coins the wallet claims carry no
    /// signature and skip the signed-coin guards.
    ///
    /// Two option actions are REFUSED fail-closed and do NOT sign through `LocalSigner`: **mint** (its
    /// cross-seam summary decode is deferred to #2243), and **exercise** — the exercising holder's
    /// underlying-reclaim leg is NOT consensus-forced (`dig_options::exercise` lands the unlocked
    /// underlying on a bare anyone-can-claim settlement coin with no reclaim binding), so a compromised
    /// engine could strip it after the wallet funds the strike and sweep the underlying. Exercise cannot
    /// be safely signable until a dig-options puzzle change binds the reclaim to the holder (deferred to
    /// #2245). [`verify::analyze`] detects an exercise bundle (its locked-underlying leg) and refuses it.
    ///
    /// Fail-closed, in order: (1) independently verify the coin spends' value flow (#1058); (2)
    /// RE-DERIVE the authoritative required signatures FROM the verified coin spends — the
    /// engine-supplied `unsigned.required_signatures` is UNTRUSTED and is only cross-checked, never
    /// the signing source (a malicious engine could otherwise use it as a signing oracle, obtaining
    /// an `AGG_SIG_ME` over an arbitrary delegated puzzle that drains a real coin while the human
    /// reviewed a benign summary); (3) sign ONLY the re-derived set and aggregate.
    pub fn sign_unsigned(&self, unsigned: &UnsignedSpend) -> WalletResult<SignedBundle> {
        // (1) Verify BEFORE anything: no bls_sign may run until the coin spends are independently
        // accounted for and match the reviewed summary.
        self.verify_before_signing(unsigned)?;

        // (2) The AUTHORITATIVE required signatures come from the verified coin spends themselves,
        // never the engine field. Cross-check the engine's claim and fail-closed on any divergence.
        let authoritative = self.required_signatures_from(&unsigned.coin_spends)?;
        assert_required_signatures_match(&unsigned.required_signatures, &authoritative)?;

        // (3) Sign ONLY the re-derived set (bundled with the verified coin spends).
        let verified = UnsignedSpend {
            coin_spends: unsigned.coin_spends.clone(),
            required_signatures: authoritative,
            summary: unsigned.summary.clone(),
        };
        self.produce_signatures(&verified)
    }

    /// Re-derive the required signatures straight from `coin_spends` via chia-wallet-sdk's key-free
    /// [`RequiredSignature`](chia_wallet_sdk::signer::RequiredSignature) extractor, bound to THIS
    /// signer's network genesis challenge (so the messages are exactly what this signer would accept
    /// — signer == engine by construction). A `secp` requirement is not expected in a wallet spend
    /// and is refused. This is the trusted source of truth for what to sign.
    fn required_signatures_from(
        &self,
        coin_spends: &[chia_protocol::CoinSpend],
    ) -> WalletResult<Vec<crate::types::RequiredSignature>> {
        use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature as SdkRequiredSignature};

        let mut allocator = clvmr::Allocator::new();
        let constants = AggSigConstants::new(Bytes32::new(self.agg_sig_me_extra_data));
        let extracted =
            SdkRequiredSignature::from_coin_spends(&mut allocator, coin_spends, &constants)
                .map_err(|e| {
                    WalletError::new(
                        WalletErrorCode::SpendValidationFailed,
                        format!("required-signature extraction failed: {e:?}"),
                    )
                })?;

        let me_domain = constants.me();
        let mut required = Vec::with_capacity(extracted.len());
        for item in extracted {
            match item {
                SdkRequiredSignature::Bls(bls) => {
                    // ONLY force-bound AGG_SIG_ME requirements are ever signed. The SDK sets
                    // `domain_string == Some(me())` exactly for AGG_SIG_ME; it is `None` for
                    // AGG_SIG_UNSAFE (raw, coin-unbound, attacker-chosen message) and a DIFFERENT
                    // domain for the ParentAmount/Puzzle/… kinds. Signing an UNSAFE (or any non-ME)
                    // requirement would let a malicious engine launder an arbitrary AGG_SIG_ME drain
                    // authorization for another coin through a benign-looking carrier spend — so any
                    // non-ME agg_sig requirement is refused fail-closed. A standard-XCH/CAT send only
                    // ever needs the per-coin standard-layer AGG_SIG_ME.
                    if bls.domain_string != Some(me_domain) {
                        return Err(WalletError::new(
                            WalletErrorCode::SpendValidationFailed,
                            "a non-AGG_SIG_ME signature requirement is not signable (possible \
                             AGG_SIG_UNSAFE laundering)",
                        ));
                    }
                    required.push(crate::types::RequiredSignature {
                        public_key: bls.public_key,
                        message: bls.message(),
                    });
                }
                SdkRequiredSignature::Secp(_) => {
                    return Err(WalletError::new(
                        WalletErrorCode::SpendValidationFailed,
                        "unexpected secp signature requirement in a wallet spend",
                    ))
                }
            }
        }
        Ok(required)
    }

    /// Sign each (already-authoritative) required signature — matching its public key to a derived
    /// key and refusing unbound messages — and aggregate into a broadcast-ready bundle. Fail-closed.
    /// This is the signing PRIMITIVE; [`sign_unsigned`](LocalSigner::sign_unsigned) runs the #1058
    /// verification + re-derivation first and only then calls this over the RE-DERIVED set.
    fn produce_signatures(&self, unsigned: &UnsignedSpend) -> WalletResult<SignedBundle> {
        let mut signatures: Vec<Signature> = Vec::with_capacity(unsigned.required_signatures.len());

        for required in &unsigned.required_signatures {
            self.reject_unbound_message(&required.message)?;
            let key = self.find_key(&required.public_key).ok_or_else(|| {
                WalletError::new(
                    WalletErrorCode::SigningFailed,
                    "no derived key matches a required signature's public key",
                )
            })?;
            signatures.push(bls_sign(&key, &required.message));
            // NOTE: `chia_bls::SecretKey` (chia-bls 0.36.1) exposes no `Zeroize`/`Drop` scrub, so the
            // transient derived key cannot be wiped here; it is dropped immediately at end of scope.
            // The master SEED it derives from IS zeroized (see `hd::MasterKey`). Upgrading chia-bls
            // to a zeroizing `SecretKey` is a tracked follow-up.
            drop(key);
        }

        let aggregated = aggregate(&signatures);
        Ok(SignedBundle {
            bundle: SpendBundle::new(unsigned.coin_spends.clone(), aggregated),
        })
    }

    /// The 48-byte compressed G1 identity public key (dig-identity slot `0x0010`) this signer can
    /// DECAP against. Public material — safe to advertise so a sender can seal a dig-message to it.
    pub fn identity_public_key_bytes(&self) -> [u8; 48] {
        self.master.identity_public_key_bytes()
    }

    /// The recipient DECAP: the G1-ECDH `dh(identity_sk, peer_g1)` against the held identity key,
    /// returning the 48-byte compressed shared secret for the dig-message KEM/KDF. `peer_g1` is
    /// subgroup- and non-identity-checked before the scalar multiplication (fail-closed). See
    /// [`MasterKey::identity_dh`](super::hd::MasterKey::identity_dh).
    pub fn decap(&self, peer_g1: &[u8; 48]) -> WalletResult<[u8; 48]> {
        self.master.identity_dh(peer_g1)
    }

    /// Reject any message not bound to this network's AGG_SIG_ME additional data — i.e. refuse to
    /// sign `AGG_SIG_UNSAFE`/unbound bytes that could be replayed against another coin.
    fn reject_unbound_message(&self, message: &[u8]) -> WalletResult<()> {
        if message.ends_with(&self.agg_sig_me_extra_data) {
            Ok(())
        } else {
            Err(WalletError::new(
                WalletErrorCode::SigningFailed,
                "refusing to sign a message not bound to the network (possible AGG_SIG_UNSAFE)",
            ))
        }
    }
}

/// Require the engine-supplied required-signature set to equal the set independently re-derived from
/// the coin spends (compared as multisets of public key + message). This is belt-and-suspenders: the
/// signer already signs ONLY the re-derived set, but any divergence means the engine tried to slip in
/// an extra/altered message (a signing-oracle attempt) and is refused fail-closed.
fn assert_required_signatures_match(
    engine_claimed: &[crate::types::RequiredSignature],
    authoritative: &[crate::types::RequiredSignature],
) -> WalletResult<()> {
    let key = |sig: &crate::types::RequiredSignature| {
        (sig.public_key.to_bytes().to_vec(), sig.message.clone())
    };
    let mut claimed: Vec<_> = engine_claimed.iter().map(key).collect();
    let mut truth: Vec<_> = authoritative.iter().map(key).collect();
    claimed.sort();
    truth.sort();
    if claimed != truth {
        return Err(WalletError::new(
            WalletErrorCode::SpendValidationFailed,
            "engine-supplied required signatures do not match the coin spends (signing-oracle attempt)",
        ));
    }
    Ok(())
}

/// Decode a bech32m recipient address to its 32-byte puzzle hash, fail-closed.
fn decode_puzzle_hash(address: &crate::types::Address) -> WalletResult<Vec<u8>> {
    chia_wallet_sdk::utils::Address::decode(&address.0)
        .map(|decoded| decoded.puzzle_hash.to_vec())
        .map_err(|e| {
            WalletError::new(
                WalletErrorCode::SpendValidationFailed,
                format!(
                    "engine summary carries an undecodable address {}: {e:?}",
                    address.0
                ),
            )
        })
}

/// Normalize an asset id for comparison: lowercase, `0x` prefix stripped. The re-derived asset id
/// is a lowercase hex tail hash; this makes the engine's claimed asset id compare byte-for-byte.
fn normalize_asset(asset_id: &str) -> String {
    asset_id
        .strip_prefix("0x")
        .unwrap_or(asset_id)
        .to_lowercase()
}

#[async_trait]
impl IdentitySigner for LocalSigner {
    fn identity(&self) -> &IdentityRef {
        &self.identity
    }

    async fn sign(&self, unsigned: UnsignedSpend) -> WalletResult<SignedBundle> {
        self.sign_unsigned(&unsigned)
    }
}

/// [`LocalSigner`] is the concrete implementation of the engine's remote-signing callback: the
/// engine holds an `Arc<dyn RemoteSigner>` and calls out to it, never holding the key itself.
/// Available only when the `engine` seam is also compiled (e.g. the in-process DIG-Browser bridge).
#[cfg(feature = "engine")]
#[async_trait]
impl crate::engine::signer::RemoteSigner for LocalSigner {
    async fn sign(&self, unsigned: UnsignedSpend) -> WalletResult<SignedBundle> {
        self.sign_unsigned(&unsigned)
    }

    async fn dh(&self, peer_g1: [u8; 48]) -> WalletResult<[u8; 48]> {
        self.decap(&peer_g1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Amount, RequiredSignature, TransactionSummary, WalletErrorCode, WalletId};
    use chia_bls::{aggregate_verify, verify as bls_verify};
    use sha2::{Digest, Sha256};

    /// A deterministic test seed hashed from a label (not an integer-literal key — dodges the
    /// CodeQL "hard-coded cryptographic value" finding).
    fn seed_from_label(label: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"dig-wallet-backend/client/signer/test/");
        hasher.update(label.as_bytes());
        hasher.finalize().to_vec()
    }

    fn master(label: &str) -> MasterKey {
        MasterKey::from_seed_bytes(seed_from_label(label))
    }

    fn mainnet_signer(label: &str) -> LocalSigner {
        LocalSigner::new(
            IdentityRef::new(WalletId(1)),
            master(label),
            Network::Mainnet,
        )
        .unwrap()
    }

    fn empty_summary() -> TransactionSummary {
        TransactionSummary {
            received: vec![],
            outputs: vec![],
            fee: Amount(0),
        }
    }

    /// An AGG_SIG_ME-style message: an arbitrary body followed by the mainnet genesis-challenge
    /// suffix (what a real network-bound message carries).
    fn bound_message(body: &str) -> Vec<u8> {
        let mut msg = body.as_bytes().to_vec();
        msg.extend_from_slice(&MAINNET_AGG_SIG_ME_EXTRA_DATA);
        msg
    }

    fn spend_needing(sigs: Vec<RequiredSignature>) -> UnsignedSpend {
        UnsignedSpend {
            coin_spends: vec![],
            required_signatures: sigs,
            summary: empty_summary(),
        }
    }

    fn canonical_mainnet_signer(label: &str) -> LocalSigner {
        LocalSigner::new_canonical(
            IdentityRef::new(WalletId(1)),
            master(label),
            Network::Mainnet,
        )
        .unwrap()
    }

    #[test]
    fn public_key_is_the_profile_account_key() {
        let signer = mainnet_signer("pubkey");
        assert_eq!(signer.public_key(), master("pubkey").profile_public_key(0));
    }

    /// A canonical signer signs for the CANONICAL wallet money key — the key funds actually live
    /// under (`master_to_wallet_unhardened(master, ix).derive_synthetic()`). This is the control the
    /// money path depends on: without it a consumer's spend of a real coin cannot be authorized.
    #[test]
    fn canonical_signer_signs_the_canonical_wallet_key() {
        let signer = canonical_mainnet_signer("canon-sign");
        let money_pk = master("canon-sign").wallet_public_key(0);
        let message = bound_message("canonical-spend");

        let signed = signer
            .produce_signatures(&spend_needing(vec![RequiredSignature {
                public_key: money_pk,
                message: message.clone(),
            }]))
            .unwrap();

        assert!(bls_verify(
            &signed.bundle.aggregated_signature,
            &money_pk,
            &message
        ));
    }

    /// FUND-LOCK GUARD: a LEGACY (`m/44'`) signer CANNOT sign for the canonical wallet key — its
    /// derivation set is disjoint from where funds live, so wiring the money path over the legacy
    /// scheme fails closed (`SigningFailed`) rather than silently locking coins. This is exactly the
    /// drift PR1 removes; the canonical constructor above is the fix.
    #[test]
    fn legacy_signer_cannot_sign_the_canonical_wallet_key() {
        let signer = mainnet_signer("canon-sign").with_address_gap(8);
        let money_pk = master("canon-sign").wallet_public_key(0);

        let err = signer
            .produce_signatures(&spend_needing(vec![RequiredSignature {
                public_key: money_pk,
                message: bound_message("canonical-spend"),
            }]))
            .unwrap_err();

        assert_eq!(err.code, WalletErrorCode::SigningFailed);
    }

    /// A canonical signer RECOGNIZES the canonical wallet address as its own (so a self-send's change
    /// passes the no-exfiltration gate); a legacy signer does not.
    #[test]
    fn canonical_signer_owns_the_canonical_puzzle_hash() {
        let canonical = canonical_mainnet_signer("canon-own");
        let legacy = mainnet_signer("canon-own");
        let money_ph = Bytes32::from(
            StandardArgs::curry_tree_hash(master("canon-own").wallet_public_key(0)).to_bytes(),
        );

        assert!(canonical.owns_puzzle_hash(money_ph));
        assert!(!legacy.owns_puzzle_hash(money_ph));
    }

    #[test]
    fn simulator_requires_explicit_extra_data() {
        // `LocalSigner` has no `Debug` (it holds a key), so match rather than `unwrap_err`.
        let result = LocalSigner::new(
            IdentityRef::new(WalletId(1)),
            master("sim"),
            Network::Simulator,
        );
        match result {
            Err(err) => assert_eq!(err.code, WalletErrorCode::InvalidInput),
            Ok(_) => panic!("simulator without explicit extra data must fail"),
        }
    }

    #[test]
    fn signs_a_bound_message_with_a_derived_key() {
        let signer = mainnet_signer("happy");
        let addr_pk = master("happy").address_public_key(0, 0);
        let message = bound_message("spend-me");

        // The signing PRIMITIVE (post-verification): a bound message + a derived key signs.
        let signed = signer
            .produce_signatures(&spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: message.clone(),
            }]))
            .unwrap();

        // The aggregated signature verifies against the derived key + the exact message (AUG).
        assert!(bls_verify(
            &signed.bundle.aggregated_signature,
            &addr_pk,
            &message
        ));
    }

    #[test]
    fn refuses_an_unbound_message_agg_sig_unsafe() {
        let signer = mainnet_signer("unsafe");
        let addr_pk = master("unsafe").address_public_key(0, 0);

        // No genesis-challenge suffix -> looks like AGG_SIG_UNSAFE -> refused.
        let err = signer
            .produce_signatures(&spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: b"unbound-attacker-bytes".to_vec(),
            }]))
            .unwrap_err();

        assert_eq!(err.code, WalletErrorCode::SigningFailed);
    }

    #[test]
    fn refuses_when_no_derived_key_matches() {
        let signer = mainnet_signer("nomatch").with_address_gap(4);
        // A public key from a DIFFERENT seed — the signer cannot reproduce it.
        let foreign = master("foreign").address_public_key(0, 0);

        let err = signer
            .produce_signatures(&spend_needing(vec![RequiredSignature {
                public_key: foreign,
                message: bound_message("x"),
            }]))
            .unwrap_err();

        assert_eq!(err.code, WalletErrorCode::SigningFailed);
    }

    #[test]
    fn signs_key_found_deeper_in_the_gap() {
        let signer = mainnet_signer("deep");
        let addr_pk = master("deep").address_public_key(0, 5);
        let message = bound_message("deep-spend");

        let signed = signer
            .produce_signatures(&spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: message.clone(),
            }]))
            .unwrap();

        assert!(bls_verify(
            &signed.bundle.aggregated_signature,
            &addr_pk,
            &message
        ));
    }

    #[test]
    fn key_beyond_the_gap_is_not_found() {
        let signer = mainnet_signer("gap").with_address_gap(3);
        let out_of_range = master("gap").address_public_key(0, 10);

        let err = signer
            .produce_signatures(&spend_needing(vec![RequiredSignature {
                public_key: out_of_range,
                message: bound_message("y"),
            }]))
            .unwrap_err();

        assert_eq!(err.code, WalletErrorCode::SigningFailed);
    }

    #[test]
    fn aggregates_multiple_required_signatures() {
        let signer = mainnet_signer("multi");
        let pk0 = master("multi").address_public_key(0, 0);
        let pk1 = master("multi").address_public_key(0, 1);
        let m0 = bound_message("first");
        let m1 = bound_message("second");

        let signed = signer
            .produce_signatures(&spend_needing(vec![
                RequiredSignature {
                    public_key: pk0,
                    message: m0.clone(),
                },
                RequiredSignature {
                    public_key: pk1,
                    message: m1.clone(),
                },
            ]))
            .unwrap();

        // The aggregate verifies against both (public_key, message) pairs.
        assert!(aggregate_verify(
            &signed.bundle.aggregated_signature,
            [(&pk0, m0.as_slice()), (&pk1, m1.as_slice())],
        ));
    }

    #[test]
    fn empty_required_signatures_produce_the_infinity_signature() {
        // The signing primitive over an empty required-signature set aggregates to infinity. (The
        // full sign_unsigned path would reject an empty coin-spend set at verification; this asserts
        // the aggregation primitive alone.)
        let signer = mainnet_signer("empty");
        let signed = signer.produce_signatures(&spend_needing(vec![])).unwrap();
        assert_eq!(signed.bundle.aggregated_signature, Signature::default());
    }

    #[tokio::test]
    async fn identity_accessor_returns_the_signing_identity() {
        let signer = mainnet_signer("id");
        assert_eq!(signer.identity().wallet_id, WalletId(1));
    }

    #[test]
    fn explicit_extra_data_binds_a_custom_network() {
        // A bespoke genesis challenge (e.g. a simulator) — messages must end with THESE bytes.
        let extra: [u8; 32] = Sha256::digest(b"custom-genesis").into();
        let signer = LocalSigner::with_agg_sig_me_extra_data(
            IdentityRef::new(WalletId(1)),
            master("custom"),
            extra,
        );
        let addr_pk = master("custom").address_public_key(0, 0);
        let mut message = b"custom-spend".to_vec();
        message.extend_from_slice(&extra);

        let signed = signer
            .produce_signatures(&spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: message.clone(),
            }]))
            .unwrap();
        assert!(bls_verify(
            &signed.bundle.aggregated_signature,
            &addr_pk,
            &message
        ));
    }

    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn local_signer_serves_as_the_engines_remote_signer() {
        use crate::engine::signer::RemoteSigner;

        // The RemoteSigner impl routes through sign_unsigned, so it runs the #1058 coin-spend
        // verification: an unverifiable (coin-spend-less) spend is refused fail-closed — proving the
        // delegation reaches the verifying path, not a bypass.
        let signer = mainnet_signer("remote");
        let addr_pk = master("remote").address_public_key(0, 0);
        let message = bound_message("remote-spend");

        let err = RemoteSigner::sign(
            &signer,
            spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: message.clone(),
            }]),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn remote_signer_dh_decaps_against_the_identity_key() {
        use crate::engine::signer::RemoteSigner;

        let ours = mainnet_signer("dh-ours");
        let peer = mainnet_signer("dh-peer");

        // The engine-facing decap round-trips with the peer's inherent decap (ECDH symmetry).
        let we_open = RemoteSigner::dh(&ours, peer.identity_public_key_bytes())
            .await
            .unwrap();
        let they_open = peer.decap(&ours.identity_public_key_bytes()).unwrap();
        assert_eq!(we_open, they_open);
    }

    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn remote_signer_dh_default_impl_fails_closed() {
        use crate::engine::signer::RemoteSigner;

        // A signer that only signs (no identity key wired) — uses the trait's default `dh`.
        struct SignOnly;
        #[async_trait]
        impl RemoteSigner for SignOnly {
            async fn sign(&self, _u: UnsignedSpend) -> WalletResult<SignedBundle> {
                unreachable!("not exercised")
            }
        }
        let err = SignOnly.dh([0u8; 48]).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[test]
    fn sign_path_is_unchanged_alongside_decap() {
        // The one key does both: signing still works exactly as before after decap is added.
        let signer = mainnet_signer("both");
        let addr_pk = master("both").address_public_key(0, 0);
        let message = bound_message("sign-and-decap");
        let signed = signer
            .produce_signatures(&spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: message.clone(),
            }]))
            .unwrap();
        assert!(bls_verify(
            &signed.bundle.aggregated_signature,
            &addr_pk,
            &message
        ));
        // And decap works with the same holder.
        let peer = mainnet_signer("both-peer");
        assert!(signer.decap(&peer.identity_public_key_bytes()).is_ok());
    }

    /// Regression for #1368: a real standard-layer XCH send requires the BLS SYNTHETIC key (the one
    /// curried into `p2_delegated_puzzle_or_hidden_puzzle`), NOT the raw derived key. The signer MUST
    /// match the synthetic key, sign, and produce an aggregate that verifies against the synthetic
    /// public key. Before the fix `find_key` only compared the raw derived key, so this returned
    /// `SigningFailed` and normal XCH sends could not be signed at all.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn local_signer_signs_standard_layer_synthetic_key() {
        use crate::engine::build::{SdkSpendBuilder, SpendBuilder, SpendInputs};
        use crate::types::{Address, Amount, AssetId, SendXchRequest};
        use chia_protocol::Coin;
        use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};
        use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature as SdkRequiredSignature};
        use chia_wallet_sdk::utils::Address as Bech32Address;
        use clvmr::Allocator;
        use std::sync::Arc;

        const LABEL: &str = "synthetic-standard-layer";

        // The synthetic standard-layer key that actually controls a real wallet coin.
        let synthetic_pk = master(LABEL)
            .address_key(0, 0)
            .derive_synthetic()
            .public_key();
        let puzzle_hash =
            chia_protocol::Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk).to_bytes());
        let coin = Coin::new(chia_protocol::Bytes32::new([3u8; 32]), puzzle_hash, 1_000);

        // A minimal SpendInputs provider exposing that one coin + its synthetic public key.
        struct OneCoin {
            coin: Coin,
            puzzle_hash: chia_protocol::Bytes32,
            synthetic_pk: PublicKey,
        }
        impl SpendInputs for OneCoin {
            fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<Coin>> {
                Ok(vec![self.coin])
            }
            fn spendable_cat(
                &self,
                _: &IdentityRef,
                _: &AssetId,
            ) -> WalletResult<Vec<chia_wallet_sdk::driver::Cat>> {
                Ok(vec![])
            }
            fn synthetic_key(&self, ph: chia_protocol::Bytes32) -> Option<PublicKey> {
                (ph == self.puzzle_hash).then_some(self.synthetic_pk)
            }
            fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<chia_protocol::Bytes32> {
                Ok(self.puzzle_hash)
            }
        }

        let inputs = Arc::new(OneCoin {
            coin,
            puzzle_hash,
            synthetic_pk,
        });
        let builder = SdkSpendBuilder::new(inputs, Network::Mainnet, 500);

        // A real recipient address.
        let recipient = Address(
            Bech32Address::new(chia_protocol::Bytes32::new([7u8; 32]), "xch".into())
                .encode()
                .unwrap(),
        );
        let unsigned = builder
            .build_send_xch(SendXchRequest {
                identity: IdentityRef::new(WalletId(1)),
                to: recipient,
                amount: Amount(600),
                fee: Amount(10),
            })
            .await
            .expect("engine builds a standard-layer XCH send");

        // The extracted required signatures name the SYNTHETIC key (that is the whole point).
        assert!(!unsigned.required_signatures.is_empty());

        // The signer holds the master key and must reproduce the synthetic key to sign.
        let signer = mainnet_signer(LABEL);
        let signed = signer
            .sign(unsigned.clone())
            .await
            .expect("signer must sign a standard-layer synthetic-key spend (#1368)");

        // The aggregate verifies against every (synthetic public key, message) pair — proof the
        // produced signature is the RIGHT one, not merely that no error was returned.
        let mut allocator = Allocator::new();
        let constants = AggSigConstants::new(chia_protocol::Bytes32::new(
            dig_constants::CHIA_L1_MAINNET_AGG_SIG_ME,
        ));
        let extracted = SdkRequiredSignature::from_coin_spends(
            &mut allocator,
            &unsigned.coin_spends,
            &constants,
        )
        .unwrap();
        let pairs: Vec<(PublicKey, Vec<u8>)> = extracted
            .into_iter()
            .map(|item| match item {
                SdkRequiredSignature::Bls(bls) => (bls.public_key, bls.message()),
                SdkRequiredSignature::Secp(_) => panic!("unexpected secp"),
            })
            .collect();
        assert!(aggregate_verify(
            &signed.bundle.aggregated_signature,
            pairs.iter().map(|(pk, m)| (pk, m.as_slice())),
        ));
        // Sanity: at least one required key is the synthetic key, not the raw derived key.
        let raw_pk = master(LABEL).address_public_key(0, 0);
        assert!(
            pairs.iter().any(|(pk, _)| *pk == synthetic_pk),
            "the spend must require the synthetic key"
        );
        assert!(
            pairs.iter().all(|(pk, _)| *pk != raw_pk),
            "a standard-layer spend never requires the raw derived key"
        );
    }

    /// Build a REAL, wallet-owned standard-layer XCH send for `label`, returning the signer that
    /// holds the key and the (valid, summary-matching) unsigned spend. The signer's own synthetic
    /// key controls the input coin and receives the change, so the #1058 verify gate passes — tests
    /// then tamper the spend to prove the gate catches each attack. (#1058 harness.)
    #[cfg(feature = "engine")]
    async fn owned_xch_send(label: &str, amount: u64, fee: u64) -> (LocalSigner, UnsignedSpend) {
        use crate::engine::build::{SdkSpendBuilder, SpendBuilder, SpendInputs};
        use crate::types::{Address, Amount, AssetId, SendXchRequest};
        use chia_protocol::{Bytes32, Coin};
        use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};
        use chia_wallet_sdk::utils::Address as Bech32Address;
        use std::sync::Arc;

        let synthetic_pk = master(label)
            .address_key(0, 0)
            .derive_synthetic()
            .public_key();
        let puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk).to_bytes());
        let coin = Coin::new(Bytes32::new([3u8; 32]), puzzle_hash, 10_000);

        struct OneCoin {
            coin: Coin,
            puzzle_hash: Bytes32,
            synthetic_pk: PublicKey,
        }
        impl SpendInputs for OneCoin {
            fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<Coin>> {
                Ok(vec![self.coin])
            }
            fn spendable_cat(
                &self,
                _: &IdentityRef,
                _: &AssetId,
            ) -> WalletResult<Vec<chia_wallet_sdk::driver::Cat>> {
                Ok(vec![])
            }
            fn synthetic_key(&self, ph: Bytes32) -> Option<PublicKey> {
                (ph == self.puzzle_hash).then_some(self.synthetic_pk)
            }
            fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<Bytes32> {
                Ok(self.puzzle_hash)
            }
        }

        let builder = SdkSpendBuilder::new(
            Arc::new(OneCoin {
                coin,
                puzzle_hash,
                synthetic_pk,
            }),
            Network::Mainnet,
            500,
        );
        let to = Address(
            Bech32Address::new(Bytes32::new([7u8; 32]), "xch".into())
                .encode()
                .unwrap(),
        );
        let unsigned = builder
            .build_send_xch(SendXchRequest {
                identity: IdentityRef::new(WalletId(1)),
                to,
                amount: Amount(amount),
                fee: Amount(fee),
            })
            .await
            .expect("engine builds the send");
        (mainnet_signer(label), unsigned)
    }

    /// #1058 baseline: a genuine, wallet-owned, summary-matching send signs successfully — the
    /// verify gate does not reject legitimate spends.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn verified_send_signs_successfully() {
        let (signer, unsigned) = owned_xch_send("verified-ok", 600, 10).await;
        assert!(signer.sign_unsigned(&unsigned).is_ok());
    }

    /// #1058 ADVERSARIAL: coin spends that actually pay an attacker while the engine summary claims a
    /// benign recipient MUST be refused fail-closed, producing ZERO signatures. This is the
    /// blind-signing gap the verify gate closes.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn refuses_when_summary_hides_the_real_recipient() {
        let (signer, mut unsigned) = owned_xch_send("adversarial", 600, 10).await;
        // The coin spends really pay xch1(7…). Rewrite the summary to CLAIM a benign recipient.
        let benign = crate::types::Address(
            chia_wallet_sdk::utils::Address::new(
                chia_protocol::Bytes32::new([9u8; 32]),
                "xch".into(),
            )
            .encode()
            .unwrap(),
        );
        unsigned.summary.outputs[0].address = benign;

        let err = signer.sign_unsigned(&unsigned).unwrap_err();
        assert_eq!(
            err.code,
            WalletErrorCode::SpendValidationFailed,
            "a spend whose bytes contradict the reviewed summary must be refused"
        );
    }

    /// #1058: an inflated amount in the engine summary (claiming less than the coin spends move) is
    /// refused.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn refuses_when_summary_amount_is_tampered() {
        let (signer, mut unsigned) = owned_xch_send("tamper-amount", 600, 10).await;
        unsigned.summary.outputs[0].amount = crate::types::Amount(1);
        assert_eq!(
            signer.sign_unsigned(&unsigned).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
        );
    }

    /// #1058: a tampered fee in the engine summary is refused.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn refuses_when_summary_fee_is_tampered() {
        let (signer, mut unsigned) = owned_xch_send("tamper-fee", 600, 10).await;
        unsigned.summary.fee = crate::types::Amount(0);
        assert_eq!(
            signer.sign_unsigned(&unsigned).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
        );
    }

    /// #1058: change diverted to a NON-wallet puzzle hash (value exfiltration through an un-hinted
    /// output) is refused, even if the summary looks benign.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn refuses_when_change_leaves_the_wallet() {
        // A signer whose keys do NOT own the builder's change puzzle hash: the change output is not
        // wallet-owned from this signer's perspective → exfiltration guard fires.
        let (_, unsigned) = owned_xch_send("change-leak-build", 600, 10).await;
        let foreign_signer = mainnet_signer("change-leak-different-seed");
        assert_eq!(
            foreign_signer.sign_unsigned(&unsigned).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
        );
    }

    /// #1058 CRITICAL (signing-oracle): a malicious engine sends BENIGN, fully-consistent
    /// coin_spends + summary (they pass verify) but swaps `required_signatures` to an entry NOT
    /// derived from those coin spends — an `AGG_SIG_ME` over an attacker-chosen delegated puzzle that
    /// would drain a real coin. The signer MUST refuse fail-closed and produce ZERO signatures,
    /// because it signs ONLY the set re-derived from the verified coin spends. Before the fix this
    /// returned Ok (the engine field was signed blindly) — that flip is the proof.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn refuses_a_required_signature_not_derived_from_the_coin_spends() {
        use chia_puzzle_types::DeriveSynthetic;

        let (signer, mut unsigned) = owned_xch_send("oracle", 600, 10).await;

        // A forged AGG_SIG_ME message: (attacker delegated-puzzle hash) || (coin id) || genesis
        // challenge — well-formed and network-bound (passes reject_unbound_message), keyed on a REAL
        // wallet key (passes find_key), but NOT among the signatures the coin spends actually
        // require. The verify+re-derive gate must catch it before any signing.
        let wallet_synthetic_pk = master("oracle")
            .address_key(0, 0)
            .derive_synthetic()
            .public_key();
        let mut evil_message = vec![0xAB; 32]; // stand-in delegated-puzzle tree hash
        evil_message.extend_from_slice(&[0xCD; 32]); // stand-in coin id
        evil_message.extend_from_slice(&MAINNET_AGG_SIG_ME_EXTRA_DATA);
        unsigned.required_signatures = vec![RequiredSignature {
            public_key: wallet_synthetic_pk,
            message: evil_message,
        }];

        let err = signer.sign_unsigned(&unsigned).unwrap_err();
        assert_eq!(
            err.code,
            WalletErrorCode::SpendValidationFailed,
            "an engine-supplied required signature not derived from the coin spends must be refused"
        );
    }

    /// #1518 + #1511 PR-B: offers proper now SIGN through `LocalSigner` (see
    /// `golden_offer_make_and_take_sign_and_settle`). What must STILL be refused is a settlement puzzle
    /// reveal paired with a coin that does NOT commit to it — a substituted puzzle the coin never
    /// authorized — so this converted test proves the puzzle-hash binding still gates settlement coins.
    #[cfg(feature = "engine")]
    #[test]
    fn a_settlement_reveal_not_matching_the_coin_is_refused() {
        use crate::types::{Amount, SpendOutput, TransactionSummary};
        use chia_protocol::{Coin, CoinSpend};

        // The canonical, immutable Chia settlement-payments puzzle (chia_puzzles::SETTLEMENT_PAYMENT
        // V1) paired with a coin whose committed puzzle hash is [2u8; 32] — NOT the settlement hash.
        let settlement_puzzle = hex::decode(
            "ff02ffff01ff02ff0affff04ff02ffff04ff03ff80808080ffff04ffff01ffff\
             333effff02ffff03ff05ffff01ff04ffff04ff0cffff04ffff02ff1effff04ff\
             02ffff04ff09ff80808080ff808080ffff02ff16ffff04ff02ffff04ff19ffff\
             04ffff02ff0affff04ff02ffff04ff0dff80808080ff808080808080ff8080ff\
             0180ffff02ffff03ff05ffff01ff04ffff04ff08ff0980ffff02ff16ffff04ff\
             02ffff04ff0dffff04ff0bff808080808080ffff010b80ff0180ff02ffff03ff\
             ff07ff0580ffff01ff0bffff0102ffff02ff1effff04ff02ffff04ff09ff8080\
             8080ffff02ff1effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101\
             ff058080ff0180ff018080",
        )
        .unwrap();
        let coin = Coin::new(
            chia_protocol::Bytes32::new([1u8; 32]),
            chia_protocol::Bytes32::new([2u8; 32]),
            1_000,
        );
        let spend = CoinSpend::new(coin, settlement_puzzle.into(), vec![0x80].into());
        let unsigned = UnsignedSpend {
            coin_spends: vec![spend],
            required_signatures: vec![RequiredSignature {
                public_key: PublicKey::default(),
                message: bound_message("settlement"),
            }],
            summary: TransactionSummary {
                received: vec![],
                outputs: vec![SpendOutput {
                    address: crate::types::Address("xch1whatever".into()),
                    amount: Amount(1_000),
                    asset_id: None,
                }],
                fee: Amount(0),
            },
        };

        let err = mainnet_signer("offer-class")
            .sign_unsigned(&unsigned)
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// Build a standard-layer self-send coin spend for `label` (conserving, wallet-owned change) whose
    /// delegated puzzle ALSO emits `extra` conditions — the carrier a malicious engine would use to
    /// smuggle an agg_sig. Returns the signer + an `UnsignedSpend` with a benign (empty-recipient)
    /// summary. (#1058 laundering harness.)
    #[cfg(feature = "engine")]
    fn carrier_spend_with_conditions(
        label: &str,
        extra: chia_wallet_sdk::types::Conditions,
    ) -> (LocalSigner, UnsignedSpend) {
        use crate::types::{Amount, TransactionSummary};
        use chia_protocol::{Bytes32, Coin};
        use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic, Memos};
        use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;

        let synthetic_pk = master(label)
            .address_key(0, 0)
            .derive_synthetic()
            .public_key();
        let puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk).to_bytes());
        let coin = Coin::new(Bytes32::new([3u8; 32]), puzzle_hash, 1_000);

        let mut ctx = SpendContext::new();
        // A conserving self-send (change back to the wallet, no recipient, no fee) — benign on its
        // own — plus the smuggled `extra` conditions.
        let conditions = Conditions::new()
            .create_coin(puzzle_hash, 1_000, Memos::None)
            .extend(extra);
        StandardLayer::new(synthetic_pk)
            .spend(&mut ctx, coin, conditions)
            .unwrap();
        let coin_spends = ctx.take();

        let unsigned = UnsignedSpend {
            coin_spends,
            required_signatures: vec![],
            summary: TransactionSummary {
                received: vec![],
                outputs: vec![],
                fee: Amount(0),
            },
        };
        (mainnet_signer(label), unsigned)
    }

    /// #1058 CRITICAL (AGG_SIG_UNSAFE laundering): a carrier coin spend that embeds
    /// `AGG_SIG_UNSAFE(wallet_synthetic_key, M)` — where M is attacker-chosen bytes ending in the
    /// genesis challenge (so the old suffix heuristic would pass) — MUST be refused fail-closed with
    /// ZERO signatures. Only forced standard-layer AGG_SIG_ME is ever signed.
    #[cfg(feature = "engine")]
    #[test]
    fn refuses_an_embedded_agg_sig_unsafe() {
        use chia_puzzle_types::DeriveSynthetic;
        use chia_wallet_sdk::types::conditions::AggSigUnsafe;
        use chia_wallet_sdk::types::{Condition, Conditions};

        let synthetic_pk = master("unsafe-launder")
            .address_key(0, 0)
            .derive_synthetic()
            .public_key();
        // M = attacker delegated-puzzle hash || target coin id || genesis (ends in genesis).
        let mut evil = vec![0xABu8; 32];
        evil.extend_from_slice(&[0xCDu8; 32]);
        evil.extend_from_slice(&MAINNET_AGG_SIG_ME_EXTRA_DATA);
        let extra = Conditions::new().with(Condition::AggSigUnsafe(AggSigUnsafe::new(
            synthetic_pk,
            evil.into(),
        )));

        let (signer, unsigned) = carrier_spend_with_conditions("unsafe-launder", extra);
        let err = signer.sign_unsigned(&unsigned).unwrap_err();
        assert_eq!(
            err.code,
            WalletErrorCode::SpendValidationFailed,
            "an embedded AGG_SIG_UNSAFE must be refused, never laundered into the signed set"
        );
    }

    /// #1058: a carrier spend embedding a non-ME domain-separated agg_sig (AGG_SIG_PARENT) is
    /// likewise refused — only AGG_SIG_ME is signable.
    #[cfg(feature = "engine")]
    #[test]
    fn refuses_an_embedded_non_me_agg_sig() {
        use chia_puzzle_types::DeriveSynthetic;
        use chia_wallet_sdk::types::conditions::AggSigParent;
        use chia_wallet_sdk::types::{Condition, Conditions};

        let synthetic_pk = master("parent-launder")
            .address_key(0, 0)
            .derive_synthetic()
            .public_key();
        let extra = Conditions::new().with(Condition::AggSigParent(AggSigParent::new(
            synthetic_pk,
            vec![0x11u8; 8].into(),
        )));

        let (signer, unsigned) = carrier_spend_with_conditions("parent-launder", extra);
        assert_eq!(
            signer.sign_unsigned(&unsigned).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
        );
    }

    /// #1058 CRITICAL#3 (solution-malleable delegated puzzle = reusable blank-check signature): the
    /// standard layer signs `sha256tree(delegated_puzzle) || coin_id || genesis`, which does NOT
    /// commit to the delegated puzzle's SOLUTION. A malicious engine spends coin C with a
    /// SOLUTION-ECHO delegated puzzle (program `1`, which returns its solution as the condition list)
    /// and a BENIGN solution (self-send); `analyze` sees benign outputs and the extracted AGG_SIG_ME
    /// is over the puzzle TREE HASH only. The attacker then re-spends C with the SAME echo puzzle but
    /// an EVIL solution (pay attacker) — the required signature is byte-identical, so the obtained
    /// signature is a blank check that drains C. The signer MUST refuse: a delegated puzzle that is
    /// not the canonical quote form `(1 . conditions)` is rejected fail-closed, ZERO signatures.
    #[cfg(feature = "engine")]
    #[test]
    fn refuses_a_solution_malleable_delegated_puzzle() {
        use crate::types::{Amount, TransactionSummary};
        use chia_protocol::{Bytes32, Coin};
        use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic, Memos};
        use chia_wallet_sdk::driver::{Spend, SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;

        let synthetic_pk = master("malleable")
            .address_key(0, 0)
            .derive_synthetic()
            .public_key();
        let puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk).to_bytes());
        let coin = Coin::new(Bytes32::new([3u8; 32]), puzzle_hash, 1_000);

        let mut ctx = SpendContext::new();
        // D_echo = the CLVM program `1` (returns its solution/environment verbatim as conditions):
        // solution-malleable, NOT quote-form.
        let echo_puzzle = ctx.alloc(&1u8).unwrap();
        // A benign solution: a conserving self-send back to the wallet.
        let benign = Conditions::new().create_coin(puzzle_hash, 1_000, Memos::None);
        let benign_solution = ctx.alloc(&benign).unwrap();
        let spend = StandardLayer::new(synthetic_pk)
            .delegated_inner_spend(&mut ctx, Spend::new(echo_puzzle, benign_solution))
            .unwrap();
        ctx.spend(coin, spend).unwrap();
        let coin_spends = ctx.take();

        let unsigned = UnsignedSpend {
            coin_spends,
            required_signatures: vec![],
            summary: TransactionSummary {
                received: vec![],
                outputs: vec![],
                fee: Amount(0),
            },
        };
        let err = mainnet_signer("malleable")
            .sign_unsigned(&unsigned)
            .unwrap_err();
        assert_eq!(
            err.code,
            WalletErrorCode::SpendValidationFailed,
            "a non-quote (solution-malleable) delegated puzzle must be refused"
        );
    }

    /// Regression for #1368, CAT path: a CAT send spends each CAT coin through its inner
    /// `StandardLayer`, so the extracted required signature likewise names the SYNTHETIC key. The
    /// signer must reproduce it and the aggregate must verify.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn local_signer_signs_cat_send_synthetic_key() {
        use crate::engine::build::{SdkSpendBuilder, SpendBuilder, SpendInputs};
        use crate::types::{Address, Amount, AssetId, SendCatRequest};
        use chia_protocol::{Bytes32, Coin};
        use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};
        use chia_wallet_sdk::driver::{Cat, SpendContext};
        use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature as SdkRequiredSignature};
        use chia_wallet_sdk::types::Conditions;
        use chia_wallet_sdk::utils::Address as Bech32Address;
        use clvmr::Allocator;
        use std::sync::Arc;

        const LABEL: &str = "synthetic-cat-layer";

        let synthetic_pk = master(LABEL)
            .address_key(0, 0)
            .derive_synthetic()
            .public_key();
        let wallet_ph = Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk).to_bytes());

        // Mint a real CAT whose inner p2 puzzle is controlled by the synthetic key.
        let mut mint_ctx = SpendContext::new();
        let genesis = Coin::new(Bytes32::new([5u8; 32]), wallet_ph, 1_000);
        let hint = mint_ctx.hint(wallet_ph).unwrap();
        let create = Conditions::new().create_coin(wallet_ph, 1_000, hint);
        let (_, cats) =
            Cat::single_issuance(&mut mint_ctx, genesis.coin_id(), None, 1_000, create).unwrap();
        let cat = cats[0];

        struct CatInputs {
            cat: Cat,
            wallet_ph: Bytes32,
            synthetic_pk: PublicKey,
        }
        impl SpendInputs for CatInputs {
            fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<Coin>> {
                Ok(vec![])
            }
            fn spendable_cat(&self, _: &IdentityRef, _: &AssetId) -> WalletResult<Vec<Cat>> {
                Ok(vec![self.cat])
            }
            fn synthetic_key(&self, ph: Bytes32) -> Option<PublicKey> {
                (ph == self.wallet_ph).then_some(self.synthetic_pk)
            }
            fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<Bytes32> {
                Ok(self.wallet_ph)
            }
        }

        let builder = SdkSpendBuilder::new(
            Arc::new(CatInputs {
                cat,
                wallet_ph,
                synthetic_pk,
            }),
            Network::Mainnet,
            500,
        );

        let recipient = Address(
            Bech32Address::new(Bytes32::new([7u8; 32]), "xch".into())
                .encode()
                .unwrap(),
        );
        // The summary's asset id must be the real tail hash (hex) so the signer's #1058 verify gate,
        // which re-derives the asset from the CAT coin, matches it.
        let unsigned = builder
            .build_send_cat(SendCatRequest {
                identity: IdentityRef::new(WalletId(1)),
                asset_id: AssetId(hex::encode(cat.info.asset_id)),
                to: recipient,
                amount: Amount(600),
                fee: Amount(0),
            })
            .await
            .expect("engine builds a CAT send");
        assert!(!unsigned.required_signatures.is_empty());

        let signer = mainnet_signer(LABEL);
        let signed = signer
            .sign(unsigned.clone())
            .await
            .expect("signer must sign a CAT synthetic-key spend (#1368)");

        let mut allocator = Allocator::new();
        let constants =
            AggSigConstants::new(Bytes32::new(dig_constants::CHIA_L1_MAINNET_AGG_SIG_ME));
        let pairs: Vec<(PublicKey, Vec<u8>)> = SdkRequiredSignature::from_coin_spends(
            &mut allocator,
            &unsigned.coin_spends,
            &constants,
        )
        .unwrap()
        .into_iter()
        .map(|item| match item {
            SdkRequiredSignature::Bls(bls) => (bls.public_key, bls.message()),
            SdkRequiredSignature::Secp(_) => panic!("unexpected secp"),
        })
        .collect();
        assert!(aggregate_verify(
            &signed.bundle.aggregated_signature,
            pairs.iter().map(|(pk, m)| (pk, m.as_slice())),
        ));
        assert!(pairs.iter().any(|(pk, _)| *pk == synthetic_pk));
    }

    /// signer == engine byte-KAT (signer half). The signer requires every message to be bound to
    /// exactly the `dig-constants` Chia-L1 AGG_SIG_ME value, for mainnet and testnet11. The engine
    /// half (`engine_binds_the_dig_constants_mainnet_agg_sig_me`, src/engine/build.rs) proves the
    /// engine binds that SAME constant into real messages. One SSOT ⇒ signer == engine, no drift.
    #[test]
    fn signer_requires_the_dig_constants_agg_sig_me() {
        let mainnet =
            LocalSigner::new(IdentityRef::new(WalletId(1)), master("m"), Network::Mainnet).unwrap();
        let testnet =
            LocalSigner::new(IdentityRef::new(WalletId(1)), master("t"), Network::Testnet).unwrap();
        assert_eq!(
            mainnet.agg_sig_me_extra_data(),
            dig_constants::CHIA_L1_MAINNET_AGG_SIG_ME,
        );
        assert_eq!(
            testnet.agg_sig_me_extra_data(),
            dig_constants::CHIA_L1_TESTNET11_AGG_SIG_ME,
        );
    }

    /// Genesis-challenge pin: the dig-constants-sourced AGG_SIG_ME values the signer binds to MUST
    /// equal the known Chia L1 genesis challenges. Guards against dig-constants ever drifting these
    /// custody-critical bytes (dig-constants also KATs them against chia-sdk-types independently).
    #[test]
    fn agg_sig_me_extra_data_pins_the_chia_l1_genesis_challenges() {
        assert_eq!(
            hex::encode(MAINNET_AGG_SIG_ME_EXTRA_DATA),
            "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb",
        );
        assert_eq!(
            hex::encode(TESTNET11_AGG_SIG_ME_EXTRA_DATA),
            "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615",
        );
    }

    // ---- PR-A (#1511): $DIG tips are signable through `LocalSigner::sign_unsigned` ----
    //
    // A tip is a pure single-key CAT payment (recipient CREATE_COIN hinted + change CREATE_COIN
    // un-hinted, no separate XCH fee), so it decodes through the SAME `verify::analyze` CAT path a
    // normal CAT send does — no verify change was required, only the removal of the tip refusal
    // wording. The golden harness below is the reusable custody proof for tips (and the base
    // PR-B/PR-C extend): it builds a REAL tip via the engine `build_tips` path, signs it end-to-end,
    // proves the re-derived summary equals the builder's, and that the produced bundle is a VALID
    // on-chain spend on `chia-sdk-test::Simulator`. It never broadcasts to mainnet.

    /// Issue `amount` of a fresh CAT to the standard puzzle of `pk` (`wallet_ph`) on the simulator,
    /// signed with `sk` (the synthetic key controlling the funding coin). Returns the spendable
    /// [`Cat`] (with its lineage proof) and its asset id — so a built tip spends a coin that actually
    /// exists on the simulated chain and its settlement can be validated.
    #[cfg(feature = "engine")]
    fn issue_cat_to_key(
        sim: &mut chia_sdk_test::Simulator,
        sk: &SecretKey,
        pk: PublicKey,
        wallet_ph: Bytes32,
        amount: u64,
    ) -> (chia_wallet_sdk::driver::Cat, Bytes32) {
        use chia_wallet_sdk::driver::{Cat, SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;

        let mut ctx = SpendContext::new();
        let funding = sim.new_coin(wallet_ph, amount);
        let hint = ctx.hint(wallet_ph).unwrap();
        let (issue, cats) = Cat::single_issuance(
            &mut ctx,
            funding.coin_id(),
            None,
            amount,
            Conditions::new().create_coin(wallet_ph, amount, hint),
        )
        .unwrap();
        StandardLayer::new(pk)
            .spend(&mut ctx, funding, issue)
            .unwrap();
        let asset_id = cats[0].info.asset_id;
        sim.spend_coins(ctx.take(), std::slice::from_ref(sk))
            .unwrap();
        (cats[0], asset_id)
    }

    /// A one-CAT-group tip input provider: the wallet holds `cat`, controls it (and returns change)
    /// under `wallet_ph`'s synthetic key `pk`, and — when `change_ph` differs — diverts change to a
    /// foreign puzzle hash (the exfiltration negative below).
    #[cfg(feature = "engine")]
    struct TipInputsProvider {
        cat: chia_wallet_sdk::driver::Cat,
        wallet_ph: Bytes32,
        pk: PublicKey,
        change_ph: Bytes32,
    }

    #[cfg(feature = "engine")]
    impl crate::engine::build::SpendInputs for TipInputsProvider {
        fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<chia_protocol::Coin>> {
            Ok(vec![])
        }
        fn spendable_cat(
            &self,
            _: &IdentityRef,
            _: &crate::types::AssetId,
        ) -> WalletResult<Vec<chia_wallet_sdk::driver::Cat>> {
            Ok(vec![self.cat])
        }
        fn synthetic_key(&self, ph: Bytes32) -> Option<PublicKey> {
            (ph == self.wallet_ph).then_some(self.pk)
        }
        fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<Bytes32> {
            Ok(self.change_ph)
        }
    }

    /// Build a REAL, wallet-owned, simulator-backed unsigned $DIG tip for `label`: a CAT of `total`
    /// base units at the wallet's canonical synthetic key, tipping `tip_amount` to `recipient_ph`,
    /// returning change to `change_ph`. Returns the live simulator, the canonical [`LocalSigner`]
    /// holding the key, and the unsigned tip — bound to testnet11 (the simulator's AGG_SIG_ME
    /// domain), so a signed bundle can be validated with `sim.new_transaction`.
    #[cfg(feature = "engine")]
    async fn owned_tip(
        label: &str,
        total: u64,
        tip_amount: u64,
        recipient_ph: Bytes32,
        change_ph: Bytes32,
    ) -> (chia_sdk_test::Simulator, LocalSigner, UnsignedSpend) {
        use crate::engine::build::SdkSpendBuilder;
        use crate::engine::build_tips::TipBuilder;
        use crate::types::{AssetId, Puzzlehash, TipRequest};
        use chia_puzzle_types::standard::StandardArgs;
        use std::sync::Arc;

        let master = master(label);
        let sk = master.wallet_signing_key(0);
        let pk = master.wallet_public_key(0);
        let wallet_ph = Bytes32::from(StandardArgs::curry_tree_hash(pk).to_bytes());

        let mut sim = chia_sdk_test::Simulator::new();
        let (cat, asset) = issue_cat_to_key(&mut sim, &sk, pk, wallet_ph, total);

        let builder = SdkSpendBuilder::new(
            Arc::new(TipInputsProvider {
                cat,
                wallet_ph,
                pk,
                change_ph,
            }),
            Network::Simulator,
            500,
        );
        let unsigned = builder
            .build_tip(TipRequest {
                identity: IdentityRef::new(WalletId(1)),
                asset_id: AssetId(hex::encode(asset)),
                recipient: Puzzlehash(hex::encode(recipient_ph)),
                amount: crate::types::Amount(tip_amount),
            })
            .await
            .expect("engine builds an unsigned tip");

        let signer = LocalSigner::new_canonical(
            IdentityRef::new(WalletId(1)),
            self::master(label),
            Network::Testnet,
        )
        .unwrap();
        (sim, signer, unsigned)
    }

    /// PR-A GOLDEN (#1511): a genuine $DIG tip built by the engine signs end-to-end through
    /// `LocalSigner::sign_unsigned` (no refusal), the independently re-derived summary byte-equals the
    /// builder's, and the produced bundle is accepted on-chain by the simulator. This is the proof
    /// that a tip is a signable CAT payment through the existing custody model — no verify relaxation.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn golden_tip_signs_and_settles_on_the_simulator() {
        use chia_puzzle_types::standard::StandardArgs;
        let recipient_ph = Bytes32::new([0x77u8; 32]);
        // change returns to the wallet's own canonical puzzle hash.
        let wallet_change = Bytes32::from(
            StandardArgs::curry_tree_hash(master("tips-golden").wallet_public_key(0)).to_bytes(),
        );
        let (mut sim, signer, unsigned) =
            owned_tip("tips-golden", 10_000, 1_000, recipient_ph, wallet_change).await;

        // (a) it SIGNS — a tip is not refused by the custody core.
        let signed = signer
            .sign_unsigned(&unsigned)
            .expect("a genuine $DIG tip must sign through LocalSigner (#1511)");

        // (b) the key-aware re-derived summary byte-equals what the builder claimed (change split off
        // by ownership; the tip's memo-hinted change is NOT mistaken for a second recipient).
        let derived = signer.reviewable_summary(&unsigned.coin_spends).unwrap();
        assert_eq!(
            derived, unsigned.summary,
            "the re-derived tip summary must equal the builder's summary"
        );

        // (c) the signed bundle is a VALID on-chain spend — never auto-broadcast to mainnet.
        sim.new_transaction(signed.bundle)
            .expect("the signed tip must be accepted by the simulator");
    }

    /// Hand-build a CAT spend of `label`'s wallet key that pays `outputs` (each `(ph, amount,
    /// hinted)`), returning change to the wallet. `hinted` outputs are memo-tagged so `analyze`
    /// classifies them as recipients; un-hinted ones are change. The CAT is issued off a fabricated
    /// genesis coin — enough to drive `analyze` + `sign_unsigned`, which act BEFORE any on-chain
    /// check. Returns the canonical signer holding the key + the coin spends.
    #[cfg(feature = "engine")]
    fn wallet_cat_spend(
        label: &str,
        total: u64,
        outputs: &[(Bytes32, u64, bool)],
    ) -> (LocalSigner, Vec<chia_protocol::CoinSpend>) {
        use chia_protocol::Coin;
        use chia_puzzle_types::standard::StandardArgs;
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::SpendWithConditions;
        use chia_wallet_sdk::driver::{Cat, CatSpend, SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;

        let pk = master(label).wallet_public_key(0);
        let wallet_ph = Bytes32::from(StandardArgs::curry_tree_hash(pk).to_bytes());

        // Issue the CAT in ITS OWN context (only `cats[0]` is retained), so the spend context below
        // holds exactly the one CAT spend the negatives exercise — mirroring the verify.rs harness.
        let cat = {
            let mut issue_ctx = SpendContext::new();
            let genesis = Coin::new(Bytes32::new([5u8; 32]), wallet_ph, total);
            let issue_hint = issue_ctx.hint(wallet_ph).unwrap();
            let (_, cats) = Cat::single_issuance(
                &mut issue_ctx,
                genesis.coin_id(),
                None,
                total,
                Conditions::new().create_coin(wallet_ph, total, issue_hint),
            )
            .unwrap();
            cats[0]
        };

        // Build the inner p2 conditions in the spend context's OWN allocator, so each hint NodePtr is
        // valid for the puzzle this allocator serializes.
        let mut ctx = SpendContext::new();
        let mut conditions = Conditions::new();
        for &(ph, amount, hinted) in outputs {
            let memos = if hinted {
                ctx.hint(ph).unwrap()
            } else {
                Memos::None
            };
            conditions = conditions.create_coin(ph, amount, memos);
        }

        let inner = StandardLayer::new(pk)
            .spend_with_conditions(&mut ctx, conditions)
            .unwrap();
        Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner)]).unwrap();
        (
            LocalSigner::new_canonical(
                IdentityRef::new(WalletId(1)),
                master(label),
                Network::Mainnet,
            )
            .unwrap(),
            ctx.take(),
        )
    }

    /// PR-A NEGATIVE (MR-13): a "tip" whose coin spends actually pay TWO recipients while the reviewed
    /// summary claims the single honest tip output MUST be refused fail-closed with ZERO signatures —
    /// the extra recipient is value leaving the wallet the human never approved. Paired with a truthful
    /// control (the same two-recipient shape, summary listing BOTH) that DOES sign, so a
    /// reject-everything guard cannot masquerade as the fix.
    #[cfg(feature = "engine")]
    #[test]
    fn multi_recipient_tip_masquerade_is_refused() {
        use crate::types::{Address, Amount, AssetId, SpendOutput, TransactionSummary};
        use chia_puzzle_types::standard::StandardArgs;
        use chia_wallet_sdk::utils::Address as Bech32Address;

        let honest = Bytes32::new([0x77u8; 32]);
        let sneaky = Bytes32::new([0x66u8; 32]);
        let wallet_ph = Bytes32::from(
            StandardArgs::curry_tree_hash(master("tip-multi").wallet_public_key(0)).to_bytes(),
        );

        // Coin spends that pay 1_000 to `honest` AND 1_000 to `sneaky` (both hinted), 8_000 change —
        // conserving, so `analyze` accepts them; two hinted recipients are derived.
        let (signer, coin_spends) = wallet_cat_spend(
            "tip-multi",
            10_000,
            &[
                (honest, 1_000, true),
                (sneaky, 1_000, true),
                (wallet_ph, 8_000, false),
            ],
        );
        let asset = AssetId(hex::encode(
            // the fabricated CAT's asset id is recovered from the derived effect.
            verify::analyze(&coin_spends).unwrap().recipients[0]
                .asset_id
                .unwrap(),
        ));
        let xch_addr =
            |ph: Bytes32| Address(Bech32Address::new(ph, "xch".into()).encode().unwrap());

        // The DISHONEST summary claims only the single honest tip — a mismatch vs the two real
        // recipients. Must be refused with zero signatures.
        let dishonest = UnsignedSpend {
            coin_spends: coin_spends.clone(),
            required_signatures: signer.required_signatures_from(&coin_spends).unwrap(),
            summary: TransactionSummary {
                received: vec![],
                outputs: vec![SpendOutput {
                    address: xch_addr(honest),
                    amount: Amount(1_000),
                    asset_id: Some(asset.clone()),
                }],
                fee: Amount(0),
            },
        };
        assert_eq!(
            signer.sign_unsigned(&dishonest).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
            "a tip hiding a second recipient must be refused fail-closed",
        );

        // CONTROL: the SAME coin spends with a TRUTHFUL two-recipient summary sign — proving the
        // refusal is the summary mismatch, not a blanket reject of multi-output CAT spends.
        let truthful = UnsignedSpend {
            coin_spends: coin_spends.clone(),
            required_signatures: signer.required_signatures_from(&coin_spends).unwrap(),
            summary: TransactionSummary {
                received: vec![],
                outputs: vec![
                    SpendOutput {
                        address: xch_addr(honest),
                        amount: Amount(1_000),
                        asset_id: Some(asset.clone()),
                    },
                    SpendOutput {
                        address: xch_addr(sneaky),
                        amount: Amount(1_000),
                        asset_id: Some(asset),
                    },
                ],
                fee: Amount(0),
            },
        };
        assert!(
            signer.sign_unsigned(&truthful).is_ok(),
            "the truthful control (summary matches both recipients) must sign",
        );
    }

    /// PR-A NEGATIVE (MR-13): a tip whose CHANGE leg returns to a NON-wallet puzzle hash (value
    /// exfiltration through an un-hinted output) MUST be refused fail-closed with ZERO signatures,
    /// even though the wallet controls the input coin. Paired with the golden tip (change to the
    /// wallet) as the truthful control that signs.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn tip_change_to_a_foreign_puzzle_hash_is_refused() {
        let recipient_ph = Bytes32::new([0x77u8; 32]);
        let foreign_change = Bytes32::new([0x99u8; 32]); // NOT a wallet puzzle hash
        let (_, signer, unsigned) =
            owned_tip("tip-exfil", 10_000, 1_000, recipient_ph, foreign_change).await;

        assert_eq!(
            signer.sign_unsigned(&unsigned).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
            "a tip whose change leaves the wallet must be refused",
        );
        // The truthful control — change back to the wallet — is proven by
        // `golden_tip_signs_and_settles_on_the_simulator`.
    }

    // ---- PR-B (#1511): offers (make / take / cancel) are signable through `LocalSigner` ----
    //
    // A make/take commits the offered/paid assets to the canonical settlement puzzle; `verify::analyze`
    // accounts that egress into the THIRD `protocol_sink` bucket, and the signer's summary gate compares
    // it by amount+asset. Settlement-layer coins the taker CLAIMS carry no signature and skip the
    // signed-coin guards. The golden harness below builds REAL offers via the engine `OfferBuilder`,
    // signs both halves end-to-end through `LocalSigner::sign_unsigned`, proves the re-derived summary
    // equals the builder's, and that the atomic settlement bundle is accepted on the simulator. The
    // MR-3/5/6/7/8 negatives each pair a must-refuse with a truthful signing control.

    /// A simulator-backed input provider serving a wallet's real coins + the synthetic key controlling
    /// them, for driving the engine `OfferBuilder` against coins that exist on the simulated chain.
    #[cfg(feature = "engine")]
    struct OfferInputs {
        xch: Vec<chia_protocol::Coin>,
        cats: Vec<chia_wallet_sdk::driver::Cat>,
        wallet_ph: Bytes32,
        pk: PublicKey,
    }

    #[cfg(feature = "engine")]
    impl crate::engine::build::SpendInputs for OfferInputs {
        fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<chia_protocol::Coin>> {
            Ok(self.xch.clone())
        }
        fn spendable_cat(
            &self,
            _: &IdentityRef,
            asset_id: &crate::types::AssetId,
        ) -> WalletResult<Vec<chia_wallet_sdk::driver::Cat>> {
            let want = hex::decode(&asset_id.0)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .map(Bytes32::new);
            Ok(self
                .cats
                .iter()
                .filter(|cat| want.is_none_or(|a| cat.info.asset_id == a))
                .copied()
                .collect())
        }
        fn synthetic_key(&self, ph: Bytes32) -> Option<PublicKey> {
            (ph == self.wallet_ph).then_some(self.pk)
        }
        fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<Bytes32> {
            Ok(self.wallet_ph)
        }
    }

    /// A wallet party in an offer test: its canonical money key, the standard puzzle hash funds live
    /// at, and a [`LocalSigner`] bound to the simulator's (testnet11) AGG_SIG_ME domain.
    #[cfg(feature = "engine")]
    struct OfferParty {
        sk: SecretKey,
        pk: PublicKey,
        wallet_ph: Bytes32,
        signer: LocalSigner,
    }

    #[cfg(feature = "engine")]
    fn offer_party(label: &str) -> OfferParty {
        use chia_puzzle_types::standard::StandardArgs;
        let master = master(label);
        let pk = master.wallet_public_key(0);
        OfferParty {
            sk: master.wallet_signing_key(0),
            pk,
            wallet_ph: Bytes32::from(StandardArgs::curry_tree_hash(pk).to_bytes()),
            signer: LocalSigner::new_canonical(
                IdentityRef::new(WalletId(1)),
                self::master(label),
                Network::Testnet,
            )
            .unwrap(),
        }
    }

    /// An `OfferBuilder` over `party`'s simulator coins.
    #[cfg(feature = "engine")]
    fn offer_builder(
        party: &OfferParty,
        xch: Vec<chia_protocol::Coin>,
        cats: Vec<chia_wallet_sdk::driver::Cat>,
    ) -> crate::engine::OfferBuilder {
        use std::sync::Arc;
        crate::engine::OfferBuilder::new(
            Arc::new(OfferInputs {
                xch,
                cats,
                wallet_ph: party.wallet_ph,
                pk: party.pk,
            }),
            Network::Simulator,
            500,
        )
    }

    /// Two summaries carry the same outputs (order-independent) and fee — the offer summary comparison
    /// (settlement sinks have empty, structurally-forced addresses, so ordering is not meaningful).
    fn same_summary(a: &TransactionSummary, b: &TransactionSummary) -> bool {
        let key = |s: &TransactionSummary| {
            let mut outs: Vec<_> = s
                .outputs
                .iter()
                .map(|o| {
                    (
                        o.address.0.clone(),
                        o.amount.mojos(),
                        o.asset_id.as_ref().map(|a| a.0.to_lowercase()),
                    )
                })
                .collect();
            outs.sort();
            (outs, s.fee.mojos())
        };
        key(a) == key(b)
    }

    /// PR-B GOLDEN (#1511): a full CAT-for-XCH offer round trip where BOTH halves are signed through
    /// `LocalSigner::sign_unsigned` — the maker's make (offered CAT → settlement `protocol_sink`) and
    /// the taker's take (XCH funding → settlement, maker's settlement CAT coin claimed with no
    /// signature). Proves make + take SIGN, both re-derived summaries equal the builders', and the
    /// atomic settlement bundle is accepted on-chain by the simulator.
    #[cfg(feature = "engine")]
    #[test]
    fn golden_offer_make_and_take_sign_and_settle() {
        use crate::engine::OfferBuilder;
        use crate::types::{
            Amount, AssembleOfferRequest, AssetId, FinalizeTakeRequest, MakeOfferRequest,
            OfferedAssets, RequestedAssets, TakeOfferRequest,
        };
        use chia_wallet_sdk::utils::Address as Bech32Address;

        let mut sim = chia_sdk_test::Simulator::new();
        let maker = offer_party("offer-maker");
        let taker = offer_party("offer-taker");

        // maker holds only a 1_000-unit CAT (no XCH → cannot self-fund); taker holds 60_000 XCH.
        let (maker_cat, asset) =
            issue_cat_to_key(&mut sim, &maker.sk, maker.pk, maker.wallet_ph, 1_000);
        let taker_coin = sim.new_coin(taker.wallet_ph, 60_000);
        let payee = crate::types::Address(
            Bech32Address::new(maker.wallet_ph, "xch".into())
                .encode()
                .unwrap(),
        );

        // --- make: offer 1_000 CAT, request 50_000 XCH; the maker signs its offered-coin spend. ---
        let maker_builder: OfferBuilder = offer_builder(&maker, vec![], vec![maker_cat]);
        let pending = maker_builder
            .build_make(MakeOfferRequest {
                identity: IdentityRef::new(WalletId(1)),
                offered: OfferedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode(asset)), Amount(1_000))],
                },
                requested: RequestedAssets {
                    xch: Amount(50_000),
                    cats: vec![],
                    payee: payee.clone(),
                },
                fee: Amount(0),
            })
            .expect("engine builds the maker's unsigned make");

        let maker_signed = maker
            .signer
            .sign_unsigned(&pending.unsigned)
            .expect("a genuine make must sign through LocalSigner (#1511 PR-B)");
        assert!(
            same_summary(
                &maker
                    .signer
                    .reviewable_summary(&pending.unsigned.coin_spends)
                    .unwrap(),
                &pending.unsigned.summary,
            ),
            "the re-derived make summary must equal the builder's (offered CAT → settlement sink)",
        );

        // #2241: the CONSENT decode surfaces the requested payment as a distinct receive line, so the
        // maker sees what they receive (50_000 XCH) alongside what they give (the offered CAT).
        let consent = maker
            .signer
            .decode_verified(&pending.unsigned)
            .expect("a genuine make decodes for consent");
        assert_eq!(
            consent.receive_lines.len(),
            1,
            "the make's requested payment renders as a distinct receive line",
        );
        // 50_000 mojos renders as 0.00000005 XCH (mojos → decimal XCH, trailing zeros trimmed).
        assert!(consent.receive_lines[0].starts_with("Receive 0.00000005 XCH to xch1"));

        let offer = maker_builder
            .assemble_make(AssembleOfferRequest {
                build_id: pending.build_id,
                signed: maker_signed,
            })
            .unwrap();

        // --- take: fund the 50_000 XCH; the taker signs its funding coins (settlement claim is
        // unsigned). ---
        let taker_builder = offer_builder(&taker, vec![taker_coin], vec![]);
        let take_pending = taker_builder
            .build_take(TakeOfferRequest {
                identity: IdentityRef::new(WalletId(1)),
                offer: offer.offer,
                fee: Amount(0),
            })
            .unwrap();

        let taker_signed = taker
            .signer
            .sign_unsigned(&take_pending.unsigned)
            .expect("a genuine take must sign through LocalSigner (#1511 PR-B)");
        assert!(
            same_summary(
                &taker
                    .signer
                    .reviewable_summary(&take_pending.unsigned.coin_spends)
                    .unwrap(),
                &take_pending.unsigned.summary,
            ),
            "the re-derived take summary must equal the builder's (paid XCH → settlement sink)",
        );

        let settlement = taker_builder
            .finalize_take(FinalizeTakeRequest {
                build_id: take_pending.build_id,
                signed: taker_signed,
            })
            .unwrap();

        sim.new_transaction(settlement.bundle)
            .expect("the atomic offer settlement bundle must be accepted by the simulator");
    }

    /// PR-B GOLDEN (#1511): cancelling an outstanding offer is an ordinary standard-layer reclaim to
    /// the maker — it signs through `LocalSigner::sign_unsigned` and settles on the simulator. (The
    /// maker's original coin is never broadcast when the offer is made, so it is still spendable.)
    #[cfg(feature = "engine")]
    #[test]
    fn golden_offer_cancel_signs_and_settles() {
        use crate::types::{
            Amount, AssembleOfferRequest, AssetId, CancelOfferRequest, MakeOfferRequest,
            OfferedAssets, RequestedAssets,
        };
        use chia_wallet_sdk::utils::Address as Bech32Address;

        let mut sim = chia_sdk_test::Simulator::new();
        let maker = offer_party("cancel-maker");
        let maker_coin = sim.new_coin(maker.wallet_ph, 50_000);
        let payee = crate::types::Address(
            Bech32Address::new(maker.wallet_ph, "xch".into())
                .encode()
                .unwrap(),
        );

        // Make an XCH-for-CAT offer, then cancel it (reclaim the offered XCH to the maker).
        let maker_builder = offer_builder(&maker, vec![maker_coin], vec![]);
        let pending = maker_builder
            .build_make(MakeOfferRequest {
                identity: IdentityRef::new(WalletId(1)),
                offered: OfferedAssets {
                    xch: Amount(50_000),
                    cats: vec![],
                },
                requested: RequestedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode([0xabu8; 32])), Amount(1_000))],
                    payee,
                },
                fee: Amount(0),
            })
            .unwrap();
        let signed = maker.signer.sign_unsigned(&pending.unsigned).unwrap();
        let offer = maker_builder
            .assemble_make(AssembleOfferRequest {
                build_id: pending.build_id,
                signed,
            })
            .unwrap();

        let cancel = maker_builder
            .build_cancel(CancelOfferRequest {
                identity: IdentityRef::new(WalletId(1)),
                offer: offer.offer,
                fee: Amount(0),
            })
            .unwrap();
        let cancel_signed = maker
            .signer
            .sign_unsigned(&cancel)
            .expect("a cancel is an ordinary reclaim and must sign (#1511 PR-B)");
        sim.new_transaction(cancel_signed.bundle)
            .expect("the maker's cancel reclaim must settle on the simulator");
    }

    /// Hand-build a standard-layer XCH spend of `label`'s wallet coin emitting `outputs` (each
    /// `(puzzle_hash, amount, hinted)`), returning the canonical signer + coin spends. When `bind` is
    /// set a benign `ASSERT_CONCURRENT_SPEND` is appended so a settlement egress satisfies the MR-6
    /// binding rule; leave it clear to exercise the give-it-away-for-nothing refusal. Used by the
    /// settlement-sink negatives that need conditions a legitimate builder would never emit.
    #[cfg(feature = "engine")]
    fn wallet_xch_spend(
        label: &str,
        coin_amount: u64,
        outputs: &[(Bytes32, u64, bool)],
        bind: bool,
    ) -> (LocalSigner, Vec<chia_protocol::CoinSpend>) {
        use chia_protocol::Coin;
        use chia_puzzle_types::standard::StandardArgs;
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;

        let pk = master(label).wallet_public_key(0);
        let wallet_ph = Bytes32::from(StandardArgs::curry_tree_hash(pk).to_bytes());
        let coin = Coin::new(Bytes32::new([9u8; 32]), wallet_ph, coin_amount);

        let mut ctx = SpendContext::new();
        let mut conditions = Conditions::new();
        for &(ph, amount, hinted) in outputs {
            let memos = if hinted {
                ctx.hint(ph).unwrap()
            } else {
                Memos::None
            };
            conditions = conditions.create_coin(ph, amount, memos);
        }
        if bind {
            // The offer binding a make/take asserts is an ANNOUNCEMENT assertion (the requested
            // payment's settlement announcement) — the only kind that binds the settlement egress to a
            // value-carrying counter-payment (#2241). A concurrency assertion no longer counts.
            conditions = conditions.assert_puzzle_announcement(Bytes32::new([0x44; 32]));
        }
        StandardLayer::new(pk)
            .spend(&mut ctx, coin, conditions)
            .unwrap();
        (
            LocalSigner::new_canonical(
                IdentityRef::new(WalletId(1)),
                master(label),
                Network::Mainnet,
            )
            .unwrap(),
            ctx.take(),
        )
    }

    /// #2209 FINDING-2 (the headline): the key-FREE consent view fails OPEN on an un-hinted,
    /// NON-owned output — it buckets it as "change" and DROPS it — while the signer's key-AWARE gate
    /// would authorize a spend that pays it. The key-aware [`LocalSigner::decode_verified`] closes the
    /// divergence: it SURFACES that egress as a recipient line, so the approved screen equals the
    /// signed bytes.
    ///
    /// The spend is a REAL, `analyze`-VALID standard-layer spend of a 2-XCH wallet-owned coin (the
    /// signer's own canonical key decides ownership) paying 1 XCH to an attacker address UN-HINTED
    /// (so the memo heuristic mislabels it change) + 1 XCH back home. Anchored to a real spend + real
    /// keys, never a mock.
    #[cfg(feature = "engine")]
    #[test]
    fn consent_decode_surfaces_an_unhinted_non_owned_egress_the_keyfree_view_hides() {
        use chia_puzzle_types::standard::StandardArgs;

        const ONE_XCH: u64 = 1_000_000_000_000;
        // A NON-owned recipient (the attacker) and the wallet's OWN change puzzle hash.
        let attacker = Bytes32::new([0x33u8; 32]);
        let wallet_ph = Bytes32::from(
            StandardArgs::curry_tree_hash(master("blind-egress").wallet_public_key(0)).to_bytes(),
        );

        // Pay 1 XCH to `attacker` UN-HINTED + 1 XCH change home, from a 2-XCH coin (conserving).
        let (signer, coin_spends) = wallet_xch_spend(
            "blind-egress",
            2 * ONE_XCH,
            &[(attacker, ONE_XCH, false), (wallet_ph, ONE_XCH, false)],
            false,
        );
        assert!(
            verify::analyze(&coin_spends).is_ok(),
            "the spend is a valid, conserving standard-layer send"
        );

        // The OLD key-FREE summarizer HIDES the egress: both outputs are un-hinted, so both are
        // bucketed as change and the rendered summary is EMPTY. This is the fail-open gap.
        let key_free = verify::derive_summary(&coin_spends).unwrap();
        assert!(
            key_free.outputs.is_empty(),
            "the key-free view drops the un-hinted non-owned egress (Finding-2 gap)"
        );

        // The KEY-AWARE consent decode SURFACES the 1-XCH → attacker egress as a recipient line.
        let unsigned = UnsignedSpend {
            coin_spends: coin_spends.clone(),
            required_signatures: vec![],
            summary: empty_summary(),
        };
        let consent = signer.decode_verified(&unsigned).unwrap();
        assert!(consent.verified);
        assert_eq!(
            consent.lines,
            vec![format!("Send 1 XCH to {}", xch_addr(attacker).0)],
            "the consent decode must surface the previously-hidden non-owned egress"
        );

        // ... and it equals what the signing gate authorizes for the SAME spend: the key-aware
        // reviewable summary lists exactly that egress (1 XCH to the attacker), so the approved screen
        // and the signed bytes share the ownership split by construction.
        let reviewable = signer.reviewable_summary(&coin_spends).unwrap();
        assert_eq!(reviewable.outputs.len(), 1);
        assert_eq!(reviewable.outputs[0].address, xch_addr(attacker));
        assert_eq!(reviewable.outputs[0].amount, crate::types::Amount(ONE_XCH));
    }

    /// #2209: the key-aware [`LocalSigner::decode_verified`] REFUSES exactly where the lenient
    /// key-free [`review::decode`] silently degrades to the engine's (untrusted) claim
    /// (`verified: false`). Migrated from the removed free-function `review::decode_verified`.
    ///
    /// The bundle is a REAL coin spend whose re-derivation genuinely fails — the identity puzzle `1`
    /// (solution `()`) the chia-wallet-sdk drivers cannot account for — run through the same
    /// [`verify::analyze`] wire the signer gates on. Not a mock: `analyze` runs the actual puzzle and
    /// rejects it fail-closed.
    #[test]
    fn consent_decode_refuses_where_the_lenient_decode_is_unverified() {
        use crate::types::{Address, Amount, SpendOutput, TransactionSummary};
        use chia_protocol::{Coin, CoinSpend};

        let coin = Coin::new(Bytes32::new([1u8; 32]), Bytes32::new([2u8; 32]), 100);
        let bad_spend = CoinSpend::new(coin, vec![0x01].into(), vec![0x80].into());
        let unsigned = UnsignedSpend {
            coin_spends: vec![bad_spend],
            required_signatures: vec![],
            summary: TransactionSummary {
                received: vec![],
                outputs: vec![SpendOutput {
                    address: Address("xch1attacker".into()),
                    amount: Amount(1_000_000_000_000),
                    asset_id: None,
                }],
                fee: Amount(0),
            },
        };

        // The lenient key-free decoder degrades to the engine's untrusted claim, flagged unverified.
        let lenient = review::decode(&unsigned);
        assert!(
            !lenient.verified,
            "the lenient decoder falls back to the engine claim, flagged unverified"
        );

        // The key-aware consent decode REFUSES — it never renders the untrusted engine claim.
        let signer = mainnet_signer("consent-refuse");
        let err = signer
            .decode_verified(&unsigned)
            .expect_err("decode_verified must fail when re-derivation fails, never fall back");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// The canonical settlement-payments puzzle hash — the ONLY destination `analyze` routes to
    /// `protocol_sink`.
    fn settlement_ph() -> Bytes32 {
        Bytes32::new(chia_wallet_sdk::puzzles::SETTLEMENT_PAYMENT_HASH)
    }

    fn xch_addr(ph: Bytes32) -> crate::types::Address {
        crate::types::Address(
            chia_wallet_sdk::utils::Address::new(ph, "xch".into())
                .encode()
                .unwrap(),
        )
    }

    /// PR-B NEGATIVE (MR-3 / MR-5): value routed to a NON-canonical "settlement-looking" hash is NOT a
    /// protocol sink — it is an ordinary payment to that address. Claimed in the summary as a blank
    /// (empty-address) settlement output, it must be refused: the derived recipient (the fake hash) is
    /// unmatched, and the empty-address sink claim has no derived sink to match. The truthful control —
    /// the SAME value routed to the REAL settlement hash, claimed as a sink — signs.
    #[cfg(feature = "engine")]
    #[test]
    fn a_non_canonical_settlement_sink_is_refused() {
        use crate::types::{Amount, AssetId, SpendOutput, TransactionSummary};

        let fake = Bytes32::new([0x5a; 32]); // a settlement look-alike the attacker controls
                                             // Spend 50_000: 50_000 to `fake`, no change (conserving). No sink → MR-6 does not apply.
        let (signer, coin_spends) =
            wallet_xch_spend("mr5", 50_000, &[(fake, 50_000, false)], false);
        let asset: Option<AssetId> = None;
        let _ = &asset;

        // DISHONEST: the summary claims a single empty-address (settlement) output for the 50_000,
        // hiding that the value actually goes to the attacker's `fake` address.
        let dishonest = UnsignedSpend {
            coin_spends: coin_spends.clone(),
            required_signatures: signer.required_signatures_from(&coin_spends).unwrap(),
            summary: TransactionSummary {
                received: vec![],
                outputs: vec![SpendOutput {
                    address: crate::types::Address(String::new()),
                    amount: Amount(50_000),
                    asset_id: None,
                }],
                fee: Amount(0),
            },
        };
        assert_eq!(
            signer.sign_unsigned(&dishonest).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
            "value to a non-canonical settlement look-alike must not pass as a sink",
        );

        // CONTROL: the SAME 50_000 routed to the REAL settlement hash IS a sink; claimed as an
        // empty-address settlement output, it signs — proving the refusal is the non-canonical hash,
        // not a blanket reject.
        let (signer2, real_spends) =
            wallet_xch_spend("mr5", 50_000, &[(settlement_ph(), 50_000, false)], true);
        let honest = UnsignedSpend {
            coin_spends: real_spends.clone(),
            required_signatures: signer2.required_signatures_from(&real_spends).unwrap(),
            summary: TransactionSummary {
                received: vec![],
                outputs: vec![SpendOutput {
                    address: crate::types::Address(String::new()),
                    amount: Amount(50_000),
                    asset_id: None,
                }],
                fee: Amount(0),
            },
        };
        assert!(
            signer2.sign_unsigned(&honest).is_ok(),
            "the truthful control (value to the real settlement hash) must sign",
        );
    }

    /// PR-B NEGATIVE (MR-3, direct): the signing gate's `protocol_sink`-must-be-canonical guard,
    /// exercised on a hand-forged effect — a sink output to a non-settlement hash is refused even
    /// though it sits in the sink bucket. Paired with the canonical control that passes.
    #[test]
    fn protocol_sink_gate_rejects_a_non_canonical_hash() {
        assert!(verify::is_protocol_sink_hash(settlement_ph()));
        assert!(!verify::is_protocol_sink_hash(Bytes32::new([0x11; 32])));
    }

    /// PR-B NEGATIVE (MR-7): a take set that ALSO spends an extra, unrelated wallet coin whose value
    /// leaves to a non-wallet address must be refused — that extra output is an un-summarized recipient
    /// (value the human never approved). Modelled directly: a two-coin spend where the second wallet
    /// coin pays a stranger, with a summary that mentions only the legitimate settlement sink.
    #[cfg(feature = "engine")]
    #[test]
    fn an_extra_wallet_coin_paying_a_stranger_is_refused() {
        use crate::types::{Amount, SpendOutput, TransactionSummary};

        let stranger = Bytes32::new([0x71; 32]);
        // Coin A: 50_000 → settlement sink (a legitimate offered leg, MR-6-bound).
        let (signer, mut coin_spends) =
            wallet_xch_spend("mr7", 50_000, &[(settlement_ph(), 50_000, false)], true);
        // Coin B (same wallet key): a SECOND coin quietly paying 40_000 to a stranger.
        let (_, extra) = wallet_xch_spend("mr7", 40_000, &[(stranger, 40_000, true)], false);
        coin_spends.extend(extra);

        // The summary claims ONLY the settlement sink — the stranger payment is hidden.
        let dishonest = UnsignedSpend {
            coin_spends: coin_spends.clone(),
            required_signatures: signer.required_signatures_from(&coin_spends).unwrap(),
            summary: TransactionSummary {
                received: vec![],
                outputs: vec![SpendOutput {
                    address: crate::types::Address(String::new()),
                    amount: Amount(50_000),
                    asset_id: None,
                }],
                fee: Amount(0),
            },
        };
        assert_eq!(
            signer.sign_unsigned(&dishonest).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
            "a take hiding an extra coin paying a stranger must be refused",
        );

        // CONTROL: declaring the stranger payment truthfully (as a real recipient) signs.
        let truthful = UnsignedSpend {
            coin_spends: coin_spends.clone(),
            required_signatures: signer.required_signatures_from(&coin_spends).unwrap(),
            summary: TransactionSummary {
                received: vec![],
                outputs: vec![
                    SpendOutput {
                        address: crate::types::Address(String::new()),
                        amount: Amount(50_000),
                        asset_id: None,
                    },
                    SpendOutput {
                        address: xch_addr(stranger),
                        amount: Amount(40_000),
                        asset_id: None,
                    },
                ],
                fee: Amount(0),
            },
        };
        assert!(
            signer.sign_unsigned(&truthful).is_ok(),
            "the truthful control (stranger payment declared) must sign",
        );
    }

    /// PR-B NEGATIVE (MR-6): a wallet coin that commits its value to the settlement puzzle with NO
    /// offer-binding assertion (give-it-away-for-nothing) is refused — even with a truthful sink
    /// summary — because nothing forces the offered value to be exchanged for anything. The truthful
    /// control (the SAME sink WITH a binding assertion) signs.
    #[cfg(feature = "engine")]
    #[test]
    fn a_settlement_egress_with_no_binding_assertion_is_refused() {
        use crate::types::{Amount, SpendOutput, TransactionSummary};

        let sink_summary = || TransactionSummary {
            received: vec![],
            outputs: vec![SpendOutput {
                address: crate::types::Address(String::new()),
                amount: Amount(50_000),
                asset_id: None,
            }],
            fee: Amount(0),
        };

        // UNBOUND: 50_000 → settlement, no assertion → refuse.
        let (signer, unbound) =
            wallet_xch_spend("mr6", 50_000, &[(settlement_ph(), 50_000, false)], false);
        let dishonest = UnsignedSpend {
            coin_spends: unbound.clone(),
            required_signatures: signer
                .required_signatures_from(&unbound)
                .unwrap_or_default(),
            summary: sink_summary(),
        };
        assert_eq!(
            signer.sign_unsigned(&dishonest).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
            "an unbound settlement egress (give-it-away-for-nothing) must be refused",
        );

        // BOUND control: the SAME egress WITH an offer-binding assertion signs.
        let (signer2, bound) =
            wallet_xch_spend("mr6", 50_000, &[(settlement_ph(), 50_000, false)], true);
        let honest = UnsignedSpend {
            coin_spends: bound.clone(),
            required_signatures: signer2.required_signatures_from(&bound).unwrap(),
            summary: sink_summary(),
        };
        assert!(
            signer2.sign_unsigned(&honest).is_ok(),
            "the truthful control (settlement egress bound by an assertion) must sign",
        );
    }

    /// Build a CLAIMED settlement (XCH) coin spend paying `payee` `amount` — the shape a taker's set
    /// carries for the maker's offered coins. It carries NO signature (claimed by announcement).
    #[cfg(feature = "engine")]
    fn settlement_coin_spend(payee: Bytes32, amount: u64) -> Vec<chia_protocol::CoinSpend> {
        use chia_protocol::Coin;
        use chia_puzzle_types::offer::{NotarizedPayment, Payment, SettlementPaymentsSolution};
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::{Layer, SettlementLayer, Spend, SpendContext};

        let mut ctx = SpendContext::new();
        let puzzle = SettlementLayer.construct_puzzle(&mut ctx).unwrap();
        let payment = Payment::new(payee, amount, Memos::None);
        let notarized = NotarizedPayment::new(Bytes32::new([0x33; 32]), vec![payment]);
        let solution = SettlementLayer
            .construct_solution(&mut ctx, SettlementPaymentsSolution::new(vec![notarized]))
            .unwrap();
        let coin = Coin::new(Bytes32::new([0x22; 32]), settlement_ph(), amount);
        ctx.spend(coin, Spend::new(puzzle, solution)).unwrap();
        ctx.take()
    }

    /// PR-B NEGATIVE (MR-8): a CLAIMED settlement coin whose notarized payment routes value to an
    /// ATTACKER, while the reviewed summary claims nothing leaves the wallet, is refused — the decoded
    /// settlement payment is reconciled against the summary, and the attacker output is an unmatched
    /// recipient. The truthful control (the SAME settlement payment landing on a WALLET-owned address,
    /// with an empty summary) signs, because a wallet-owned settlement payout is change.
    #[cfg(feature = "engine")]
    #[test]
    fn a_settlement_payment_to_an_attacker_is_refused() {
        use crate::types::{Amount, TransactionSummary};
        use chia_puzzle_types::standard::StandardArgs;

        let attacker = Bytes32::new([0x6e; 32]);
        let signer = canonical_mainnet_signer("mr8");
        let empty = TransactionSummary {
            received: vec![],
            outputs: vec![],
            fee: Amount(0),
        };

        // DISHONEST: the settlement coin pays the attacker; the summary claims nothing leaves.
        let attacker_spends = settlement_coin_spend(attacker, 1_000);
        let dishonest = UnsignedSpend {
            coin_spends: attacker_spends.clone(),
            required_signatures: signer
                .required_signatures_from(&attacker_spends)
                .unwrap_or_default(),
            summary: empty.clone(),
        };
        assert_eq!(
            signer.sign_unsigned(&dishonest).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
            "a settlement payment to an attacker the summary hides must be refused",
        );

        // CONTROL: the SAME payment landing on the WALLET's own address is change — an empty summary
        // matches, and it signs (no signature is required of a claimed settlement coin).
        let wallet_ph = Bytes32::from(
            StandardArgs::curry_tree_hash(master("mr8").wallet_public_key(0)).to_bytes(),
        );
        let owned_spends = settlement_coin_spend(wallet_ph, 1_000);
        let honest = UnsignedSpend {
            coin_spends: owned_spends.clone(),
            required_signatures: signer
                .required_signatures_from(&owned_spends)
                .unwrap_or_default(),
            summary: empty,
        };
        assert!(
            signer.sign_unsigned(&honest).is_ok(),
            "the truthful control (settlement payment to a wallet-owned address) must sign",
        );
    }

    // ---- PR-C (#1511): covered-option TRANSFER signs through `LocalSigner`; EXERCISE + MINT refused ----
    //
    // An option transfer re-homes the singleton through the current owner's inner standard layer (the
    // sole signed `AGG_SIG_ME`); `analyze` decodes it purely through chia-wallet-sdk drivers and the
    // golden below builds a REAL transfer via the engine `OptionBuilder`, signs through
    // `LocalSigner::sign_unsigned`, and settles on the simulator. EXERCISE and MINT are both REFUSED
    // fail-closed: exercise's underlying-reclaim leg is not consensus-forced (deferred #2245), and
    // mint's cross-seam decode is deferred (#2243).

    #[cfg(feature = "engine")]
    use crate::engine::build_options::OptionBuilder;

    /// An `OptionBuilder` (the engine `SdkSpendBuilder`) over `party`'s simulator coins.
    #[cfg(feature = "engine")]
    fn option_builder(
        party: &OfferParty,
        xch: Vec<chia_protocol::Coin>,
    ) -> crate::engine::build::SdkSpendBuilder {
        use std::sync::Arc;
        crate::engine::build::SdkSpendBuilder::new(
            Arc::new(OfferInputs {
                xch,
                cats: vec![],
                wallet_ph: party.wallet_ph,
                pk: party.pk,
            }),
            Network::Simulator,
            500,
        )
    }

    /// Mint a real option (creator `creator_ph`, owner `owner_ph`) funded + signed by `party`, submit it
    /// to `sim`, and return the retained handle + on-chain projection a client would later operate it
    /// with — mirroring how a chain-reading client assembles them (see `tests/options_e2e.rs`).
    #[cfg(feature = "engine")]
    fn mint_option_on_sim(
        sim: &mut chia_sdk_test::Simulator,
        party: &OfferParty,
        creator_ph: Bytes32,
        owner_ph: Bytes32,
        underlying: u64,
        strike: u64,
        expiry: u64,
    ) -> (crate::types::OptionHandle, crate::types::OptionOnChainState) {
        use crate::types::{
            Amount, OptionHandle, OptionOnChainState, OptionStrike, Puzzlehash, WireCoin,
        };
        use chia_sdk_test::sign_transaction;
        use chia_wallet_sdk::driver::SpendContext;
        use dig_options::{create, OptionTerms, OptionType, Owner};

        let funding = sim.new_coin(party.wallet_ph, underlying + 1);
        let mut ctx = SpendContext::new();
        let terms = OptionTerms {
            creator_puzzle_hash: creator_ph,
            owner_puzzle_hash: owner_ph,
            underlying_amount: underlying,
            strike_type: OptionType::Xch { amount: strike },
            expiry_seconds: expiry,
        };
        let mint = create(&mut ctx, &Owner::Standard(party.pk), funding, &terms).unwrap();
        let created = mint.created.clone().unwrap();
        let sig = sign_transaction(&mint.coin_spends, std::slice::from_ref(&party.sk)).unwrap();
        sim.new_transaction(chia_protocol::SpendBundle::new(
            mint.coin_spends.clone(),
            sig,
        ))
        .expect("mint settles on the simulator");

        let wire = |c: &chia_protocol::Coin| WireCoin {
            parent_coin_info: hex::encode(c.parent_coin_info),
            puzzle_hash: hex::encode(c.puzzle_hash),
            amount: c.amount,
        };
        let program_hex = |p: &chia_protocol::Program| hex::encode(Vec::<u8>::from(p.clone()));
        let parent_id = created.option.coin.parent_coin_info;
        let parent = mint
            .coin_spends
            .iter()
            .find(|cs| cs.coin.coin_id() == parent_id)
            .expect("the mint bundle contains the option child's parent spend");

        let handle = OptionHandle {
            launcher_id: hex::encode(created.option.info.launcher_id),
            creator_puzzle_hash: Puzzlehash(hex::encode(creator_ph)),
            owner_puzzle_hash: Puzzlehash(hex::encode(owner_ph)),
            underlying_amount: Amount(underlying),
            strike: OptionStrike::Xch {
                amount: Amount(strike),
            },
            expiry_seconds: expiry,
            underlying_coin_id: hex::encode(created.underlying_coin.coin_id()),
            funding_coin_id: hex::encode(funding.coin_id()),
        };
        let on_chain = OptionOnChainState {
            option_parent_coin: wire(&parent.coin),
            option_parent_puzzle_reveal: program_hex(&parent.puzzle_reveal),
            option_parent_solution: program_hex(&parent.solution),
            underlying_coin: wire(&created.underlying_coin),
        };
        (handle, on_chain)
    }

    /// PR-C: option EXERCISE is REFUSED at the signer, fail-closed, producing ZERO signatures. Exercise
    /// is not safely `LocalSigner`-signable: the exercising holder's underlying-reclaim leg is NOT
    /// consensus-forced — `dig_options::exercise` lands the unlocked underlying on a bare
    /// anyone-can-claim settlement coin with no reclaim binding — so a compromised engine could strip
    /// that leg AFTER the wallet funds the strike-funding coin (the wallet pays the strike while an
    /// attacker sweeps the underlying). It stays refused until a dig-options puzzle change binds the
    /// reclaim to the holder (deferred to #2245). Mirrors `option_mint_is_still_refused`. The engine
    /// still BUILDS a valid exercise (proving the refusal is the signer's deliberate policy, not a build
    /// failure); `sign_unsigned` refuses it.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn option_exercise_is_refused() {
        use crate::types::{Amount, ExerciseOptionRequest};

        let mut sim = chia_sdk_test::Simulator::new();
        let holder = offer_party("opt-exercise-refused");
        let creator_ph = Bytes32::new([0xC1; 32]); // foreign creator (not the wallet)
        let (underlying, strike) = (1_000u64, 250u64);
        let (handle, on_chain) = mint_option_on_sim(
            &mut sim,
            &holder,
            creator_ph,
            holder.wallet_ph,
            underlying,
            strike,
            10_000,
        );

        let strike_coin = sim.new_coin(holder.wallet_ph, strike);
        let unsigned = option_builder(&holder, vec![strike_coin])
            .build_exercise_option(ExerciseOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                fee: Amount(0),
            })
            .await
            .expect("the engine still builds a valid exercise bundle");

        let err = holder.signer.sign_unsigned(&unsigned).unwrap_err();
        assert_eq!(
            err.code,
            WalletErrorCode::SpendValidationFailed,
            "option exercise must be refused fail-closed at the signer (deferred #2245)",
        );
    }

    /// PR-C GOLDEN: a covered-option TRANSFER re-homes the singleton through the owner's inner standard
    /// layer, signs through `LocalSigner::sign_unsigned`, and settles on the simulator.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn golden_option_transfer_signs_and_settles() {
        use crate::types::{Amount, Puzzlehash, TransferOptionRequest};

        let mut sim = chia_sdk_test::Simulator::new();
        let owner = offer_party("opt-transfer-owner");
        let (handle, on_chain) = mint_option_on_sim(
            &mut sim,
            &owner,
            owner.wallet_ph,
            owner.wallet_ph,
            1_000,
            250,
            10_000,
        );
        let destination = Bytes32::new([0x9a; 32]); // a new (foreign) owner

        let unsigned = option_builder(&owner, vec![])
            .build_transfer_option(TransferOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                to_puzzle_hash: Puzzlehash(hex::encode(destination)),
                fee: Amount(0),
            })
            .await
            .unwrap();

        assert!(
            same_summary(
                &owner.signer.reviewable_summary(&unsigned.coin_spends).unwrap(),
                &unsigned.summary,
            ),
            "the re-derived transfer summary must equal the builder's (re-homed singleton → new owner)",
        );
        let signed = owner
            .signer
            .sign_unsigned(&unsigned)
            .expect("a genuine option transfer must sign through LocalSigner (#1511 PR-C)");
        sim.new_transaction(signed.bundle)
            .expect("the option transfer must be accepted by the simulator");
    }

    /// PR-C: option MINT stays REFUSED at the signer (its cross-seam summary decode is deferred to
    /// #2243) — the engine still builds it, but `LocalSigner::sign_unsigned` refuses fail-closed.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn option_mint_is_still_refused() {
        use crate::types::{Amount, MintOptionRequest, OptionStrike};

        let party = offer_party("opt-mint-refused");
        let unsigned = option_builder(&party, vec![sim_free_coin(&party, 1_011)])
            .build_mint_option(MintOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                creator_puzzle_hash: None,
                owner_puzzle_hash: None,
                underlying_amount: Amount(1_000),
                strike: OptionStrike::Xch {
                    amount: Amount(500),
                },
                expiry_seconds: 1_800_000_000,
                fee: Amount(10),
            })
            .await
            .unwrap()
            .unsigned;
        assert_eq!(
            party.signer.sign_unsigned(&unsigned).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
            "option mint must still be refused at the signer (#2243)",
        );
    }

    /// PR-C NEGATIVE — MR-12: a transfer carrying an EXTRA coin riding the (fee) leg — an unauthorized
    /// standard spend siphoning value to an attacker — is REFUSED (the extra egress is an unmatched
    /// recipient). Control: `golden_option_transfer_signs_and_settles`.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn transfer_with_an_extra_riding_coin_is_refused_mr12() {
        use crate::types::{Amount, Puzzlehash, TransferOptionRequest};
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
        use chia_wallet_sdk::types::Conditions;

        let mut sim = chia_sdk_test::Simulator::new();
        let owner = offer_party("opt-mr12");
        let (handle, on_chain) = mint_option_on_sim(
            &mut sim,
            &owner,
            owner.wallet_ph,
            owner.wallet_ph,
            1_000,
            250,
            10_000,
        );
        let mut unsigned = option_builder(&owner, vec![])
            .build_transfer_option(TransferOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                to_puzzle_hash: Puzzlehash(hex::encode([0x9a; 32])),
                fee: Amount(0),
            })
            .await
            .unwrap();

        // Append an unauthorized wallet standard spend paying an attacker — an extra coin the summary
        // never disclosed. `analyze` decodes it as a recipient with no matching summary output → refuse.
        let extra = sim.new_coin(owner.wallet_ph, 5_000);
        let mut ctx = SpendContext::new();
        StandardLayer::new(owner.pk)
            .spend(
                &mut ctx,
                extra,
                Conditions::new().create_coin(Bytes32::new([0x6e; 32]), 5_000, Memos::None),
            )
            .unwrap();
        unsigned.coin_spends.extend(ctx.take());

        assert_eq!(
            owner.signer.sign_unsigned(&unsigned).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
            "a transfer carrying an extra attacker-paying coin must be refused",
        );
    }

    /// A fresh simulator coin at `party`'s wallet puzzle hash, for a builder that needs XCH input.
    #[cfg(feature = "engine")]
    fn sim_free_coin(party: &OfferParty, amount: u64) -> chia_protocol::Coin {
        chia_sdk_test::Simulator::new().new_coin(party.wallet_ph, amount)
    }
}
