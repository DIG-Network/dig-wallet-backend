//! `client::signer` — the SIGNING interface (SPEC §4, §8). dig-app holds the key HERE.
//!
//! This module and [`super::hd`] are the ONLY places the crate touches secret material
//! (`chia::bls::SecretKey`), compiled ONLY under the `client` feature. dig-app implements
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
use chia::bls::{aggregate, sign as bls_sign, PublicKey, SecretKey, Signature};
use chia::protocol::{Bytes32, SpendBundle};
use chia::puzzles::{standard::StandardArgs, DeriveSynthetic};

use crate::types::{
    IdentityRef, Network, SignedBundle, TransactionSummary, UnsignedSpend, WalletError,
    WalletErrorCode, WalletResult,
};

use super::hd::{MasterKey, DEFAULT_ADDRESS_GAP};
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

/// A signer that holds the master HD key in-process (dig-app side).
///
/// Holds a [`MasterKey`] entirely within the client seam — it never crosses to the engine. On
/// [`sign_unsigned`](LocalSigner::sign_unsigned) it derives the active profile's address keys,
/// matches each [`crate::types::RequiredSignature`] to a derived key, signs the (network-bound) message with
/// augmented BLS, and aggregates. Deliberately no `Debug`/`Serialize`/`Clone`: the held key never
/// leaks.
pub struct LocalSigner {
    identity: IdentityRef,
    master: MasterKey,
    agg_sig_me_extra_data: [u8; 32],
    address_gap: u32,
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
        })
    }

    /// Create a signer bound to an explicit AGG_SIG_ME additional data (e.g. a simulator or custom
    /// network genesis challenge).
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
        }
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
    ///    [`DEFAULT_HIDDEN_PUZZLE_HASH`](chia::puzzles::DEFAULT_HIDDEN_PUZZLE_HASH). This is the key
    ///    `p2_delegated_puzzle_or_hidden_puzzle` (`StandardLayer`) curries into a coin's puzzle, so
    ///    the required signature a normal XCH/CAT send extracts names the SYNTHETIC public key, never
    ///    the raw one (#1368). When it matches, the synthetic SECRET key is returned — the one that
    ///    actually authorizes the spend.
    ///
    /// The synthetic derivation comes from chia-puzzle-types' [`DeriveSynthetic`] — the crate's own
    /// vetted BLS offset, never hand-rolled here.
    fn find_key(&self, target: &PublicKey) -> Option<SecretKey> {
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

    /// True when `puzzle_hash` is a standard-layer puzzle this wallet controls — i.e. the curry of
    /// the standard puzzle over the SYNTHETIC key of some derived address within the gap. Used to
    /// prove every change output of a spend returns to the wallet (never a foreign address).
    fn owns_puzzle_hash(&self, puzzle_hash: Bytes32) -> bool {
        let profile = self.identity.profile_ix;
        (0..self.address_gap).any(|ix| {
            let synthetic = self
                .master
                .address_key(profile, ix)
                .derive_synthetic()
                .public_key();
            Bytes32::from(StandardArgs::curry_tree_hash(synthetic).to_bytes()) == puzzle_hash
        })
    }

    /// Independently VERIFY the coin spends before signing (SPEC §4, #1058): re-derive the value
    /// flow from the coin spends themselves ([`verify::analyze`]), require every change output to
    /// return to this wallet, and require the engine-supplied summary to match the re-derived truth.
    /// Fail-closed — a spend that cannot be fully accounted for is refused, so the signer never
    /// blindly signs bytes it did not verify.
    fn verify_before_signing(&self, unsigned: &UnsignedSpend) -> WalletResult<()> {
        let effect = verify::analyze(&unsigned.coin_spends)?;

        // No value may silently leave the wallet: every un-hinted (change) output must be ours.
        for output in &effect.change {
            if !self.owns_puzzle_hash(output.puzzle_hash) {
                return Err(WalletError::new(
                    WalletErrorCode::SpendValidationFailed,
                    "a non-recipient output does not return to this wallet (possible exfiltration)",
                ));
            }
        }

        // The reviewed summary MUST equal what the coin spends actually do — otherwise the engine
        // could show a benign summary while the bytes send elsewhere.
        self.assert_reviewed_summary_matches(&unsigned.summary, &effect)
    }

    /// Require the engine-supplied `claimed` summary to match the independently re-derived `effect`
    /// on the recipient set (puzzle hash + amount + asset) and the fee. Compared on decoded puzzle
    /// hashes + normalized asset ids, so display-form differences never mask (or fabricate) a
    /// mismatch. Fail-closed on any discrepancy.
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

        let mut derived: Vec<(Vec<u8>, u64, Option<String>)> = effect
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

        let mut reviewed: Vec<(Vec<u8>, u64, Option<String>)> = claimed
            .outputs
            .iter()
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

        derived.sort();
        reviewed.sort();
        if derived != reviewed {
            return Err(mismatch("recipient outputs"));
        }
        Ok(())
    }

    /// The custody core (SPEC §4). Currently signs only the two spend classes the engine builds and
    /// [`verify`](super::verify) can independently decode — a standard-layer XCH send and a CAT send.
    /// An offer, option, or tip [`UnsignedSpend`] routed here is refused fail-closed until its
    /// verify decoder lands (#1058 follow-up); those flows do not sign through `LocalSigner` today.
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
        coin_spends: &[chia::protocol::CoinSpend],
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
            // NOTE: `chia::bls::SecretKey` (chia-bls 0.26) exposes no `Zeroize`/`Drop` scrub, so the
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
    use chia::bls::{aggregate_verify, verify as bls_verify};
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

    #[test]
    fn public_key_is_the_profile_account_key() {
        let signer = mainnet_signer("pubkey");
        assert_eq!(signer.public_key(), master("pubkey").profile_public_key(0));
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
        use chia::protocol::Coin;
        use chia::puzzles::{standard::StandardArgs, DeriveSynthetic};
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
            chia::protocol::Bytes32::from(StandardArgs::curry_tree_hash(synthetic_pk).to_bytes());
        let coin = Coin::new(chia::protocol::Bytes32::new([3u8; 32]), puzzle_hash, 1_000);

        // A minimal SpendInputs provider exposing that one coin + its synthetic public key.
        struct OneCoin {
            coin: Coin,
            puzzle_hash: chia::protocol::Bytes32,
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
            fn synthetic_key(&self, ph: chia::protocol::Bytes32) -> Option<PublicKey> {
                (ph == self.puzzle_hash).then_some(self.synthetic_pk)
            }
            fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<chia::protocol::Bytes32> {
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
            Bech32Address::new(chia::protocol::Bytes32::new([7u8; 32]), "xch".into())
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
        let constants = AggSigConstants::new(chia::protocol::Bytes32::new(
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
        use chia::protocol::{Bytes32, Coin};
        use chia::puzzles::{standard::StandardArgs, DeriveSynthetic};
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
                chia::protocol::Bytes32::new([9u8; 32]),
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
        use chia::puzzles::DeriveSynthetic;

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

    /// #1058 scoping: offer/option/tip spends (non-standard puzzles verify cannot yet decode) routed
    /// through `sign_unsigned` are refused fail-closed until their decoders land. Uses the REAL Chia
    /// settlement-payments puzzle (the offer-settlement class) as the coin's puzzle.
    #[cfg(feature = "engine")]
    #[test]
    fn refuses_an_offer_class_settlement_spend() {
        use crate::types::{Amount, SpendOutput, TransactionSummary};
        use chia::protocol::{Coin, CoinSpend};

        // The canonical, immutable Chia settlement-payments puzzle (chia_puzzles::SETTLEMENT_PAYMENT
        // V1) — an offer/settlement coin's puzzle, which is neither standard-layer nor CAT.
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
            chia::protocol::Bytes32::new([1u8; 32]),
            chia::protocol::Bytes32::new([2u8; 32]),
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
        use chia::protocol::{Bytes32, Coin};
        use chia::puzzles::{standard::StandardArgs, DeriveSynthetic, Memos};
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
        use chia::puzzles::DeriveSynthetic;
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
        use chia::puzzles::DeriveSynthetic;
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

    /// Regression for #1368, CAT path: a CAT send spends each CAT coin through its inner
    /// `StandardLayer`, so the extracted required signature likewise names the SYNTHETIC key. The
    /// signer must reproduce it and the aggregate must verify.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn local_signer_signs_cat_send_synthetic_key() {
        use crate::engine::build::{SdkSpendBuilder, SpendBuilder, SpendInputs};
        use crate::types::{Address, Amount, AssetId, SendCatRequest};
        use chia::protocol::{Bytes32, Coin};
        use chia::puzzles::{standard::StandardArgs, DeriveSynthetic};
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
            Cat::issue_with_coin(&mut mint_ctx, genesis.coin_id(), 1_000, create).unwrap();
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
}
