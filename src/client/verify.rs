//! `client::verify` — INDEPENDENT re-derivation of a spend's value flow (SPEC §4, #1058).
//!
//! Before [`LocalSigner`](super::signer::LocalSigner) produces a single signature it must know
//! exactly what the bytes it is about to sign actually DO — never trusting the engine-supplied
//! [`TransactionSummary`](crate::types::TransactionSummary). This module parses the raw
//! [`CoinSpend`]s straight back through the SAME chia-wallet-sdk drivers the engine built them with
//! ([`Cat`], [`StandardLayer`], [`Puzzle`]) and reconstructs the authoritative recipients, change,
//! and fee. The signer then gates on THIS, closing the blind-signing gap.
//!
//! # Fail-closed
//! The decodable spend classes are the standard-layer XCH send, the CAT send, the $DIG **tip**
//! (a single-key CAT payment — recipient + change, no separate XCH fee — that flows through the SAME
//! [`Cat::parse`] path), the three **offer** shapes (make / take / cancel), whose value the wallet
//! commits to the consensus-enforced **settlement-payments** puzzle (#1511 PR-B), and the covered-option
//! **transfer** (#1511 PR-C — see below). A settlement output is accounted into a THIRD
//! bucket, [`SpendEffect::protocol_sink`] — value intentionally handed to a recognized canonical
//! structural puzzle, not to a free address — so an attacker address can never be laundered as a "sink".
//! Settlement-layer coins the wallet CLAIMS (take/cancel) are decoded through [`SettlementLayer`]
//! and carry NO signature (claimed by announcement), so they skip the wallet-signed-coin guards; only the
//! wallet's own standard/CAT coins (and an option singleton's inner standard layer) are signed. Any coin
//! spend the drivers cannot fully parse+account for — a foreign puzzle, a value leak, a minted CAT, a
//! "settlement" output to a non-canonical hash — yields [`WalletErrorCode::SpendValidationFailed`]; the
//! signer refuses to sign it. Covered-option **mint** and **exercise** reaching the signer are refused —
//! that is intended (see below).
//!
//! # Covered options — transfer signs; exercise + mint refused (#1511 PR-C)
//! An option spend is decoded ONLY through chia-wallet-sdk drivers ([`OptionContract`],
//! [`P2OneOfManyLayer`], [`SettlementLayer`]), never bespoke CLVM:
//! - **transfer** (SUPPORTED) re-homes the option singleton: [`OptionContract::parse`] reaches the
//!   current owner's inner standard layer (the sole signed `AGG_SIG_ME`), which emits an odd-amount
//!   `CREATE_COIN` re-homing the singleton to the new owner (a recipient the human reviews). Transfer
//!   touches only the inner standard layer, so it is safely signable. Option bundles use IMPLICIT-fee
//!   conservation (the option builders emit no `RESERVE_FEE`, and the 1-mojo singleton flows through to
//!   the re-homed coin).
//! - **exercise** (REFUSED, deferred #2245) unlocks the locked underlying by melting the option
//!   singleton and emitting the mode-23 (`0x17`) exercise `SEND_MESSAGE`. Consensus couples that message
//!   inseparably to the singleton MELT (SDK `option_contract.rs::test_incomplete_exercise` proves
//!   message-without-melt AND melt-without-message both reject), so "some other spend unlocks the
//!   underlying" is impossible on chain; the ONLY residual risk is the wallet being tricked into SIGNING
//!   the melting/message-bearing leg. [`analyze`] closes that at the signature source: an option-singleton
//!   spend that does NOT re-home (a melt/exercise or clawback) is refused fail-closed REGARDLESS of
//!   whether the [`P2OneOfManyLayer`] underlying leg is present (defeating the strip-the-leg attack), and
//!   a transfer's delegated puzzle is held to a default-deny allowlist that admits no `SEND_MESSAGE`. The
//!   [`P2OneOfManyLayer`] leg is ALSO refused directly (defense in depth). Exercise stays unsignable until
//!   a dig-options puzzle change binds the underlying reclaim to the holder in consensus.
//! - **mint** (REFUSED, deferred #2243) — its cross-seam summary decode is not yet wired.
//!
//! # Recipients vs change is key-relative — so this module does NOT split them
//! Splitting a spend's outputs into recipients (value leaving) and change (value returning home) is
//! inherently a WALLET-RELATIVE judgement: on-chain both are plain `CREATE_COIN`s, indistinguishable
//! without the wallet's keys. A key-free memo heuristic is unreliable — `dig-cat` (and so every $DIG
//! tip) memo-hints its change coin too, and a memo-hinted change coin has already been misclassified
//! in practice (#1511 PR-A). So [`analyze`] returns the created coins UNDIVIDED in
//! [`SpendEffect::outputs`] and performs NO recipient/change split. The one authoritative split lives
//! in [`LocalSigner`](super::signer::LocalSigner), which classifies each output by KEY OWNERSHIP
//! (owned → change, not-owned → recipient); that is what the signer's summary gate compares against.
//! The key-free [`derive_summary`] renders EVERY output as egress (conservative — it never drops a
//! non-owned coin), and is non-authoritative display-only.

use std::collections::{BTreeMap, HashMap, HashSet};

use chia_protocol::{Bytes32, CoinSpend};
use chia_puzzle_types::Proof;
use chia_wallet_sdk::driver::{
    Cat, Layer, Nft, OptionContract, P2OneOfManyLayer, Puzzle, SettlementLayer, StandardLayer,
};
use chia_wallet_sdk::puzzles::{
    SETTLEMENT_PAYMENT_HASH, SINGLETON_LAUNCHER_HASH, SINGLETON_TOP_LAYER_V1_1_HASH,
};
use chia_wallet_sdk::types::{run_puzzle, Condition};
use chia_wallet_sdk::utils::Address as Bech32Address;
use clvm_traits::FromClvm;
use clvm_utils::tree_hash;
use clvmr::serde::node_from_bytes;
use clvmr::Allocator;

use crate::types::{
    Address, Amount, AssetId, SpendOutput, TransactionSummary, WalletError, WalletErrorCode,
    WalletResult,
};

/// One coin the spend creates, re-derived from a coin spend's own puzzle + solution.
///
/// `#[non_exhaustive]` (#2242): a future decode may need to carry more than
/// puzzle-hash/amount/asset-id, so downstream matches/literals must not assume this field set is
/// final.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodedOutput {
    /// The puzzle hash the created coin pays.
    pub puzzle_hash: Bytes32,
    /// The amount created (mojos for XCH, base units for a CAT).
    pub amount: u64,
    /// The CAT asset id (tail hash) the output is denominated in; `None` = native XCH.
    pub asset_id: Option<Bytes32>,
}

/// An NFT lifecycle action a bundle performs, named so a human can review it (#3077).
///
/// An NFT action is worth almost nothing in mojos — a transfer moves the singleton's lone mojo to
/// itself and nets ~0 XCH — so it is INVISIBLE in [`SpendEffect::outputs`] and in the fee. Naming
/// the action, exactly as [`SpendEffect::melted_singletons`] names a destruction, is what lets the
/// confirm screen say "transfer NFT `nft1…`" instead of showing a dust amount, and what lets the
/// signing gate refuse a bundle whose NFT action the reviewed summary never mentioned.
///
/// The NFT is identified by its LAUNCHER ID — the singleton's permanent lineage identifier, stable
/// across every transfer — never by the coin id, which changes on each spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NftOperation {
    /// The bundle re-homes an existing NFT to a new p2 puzzle hash.
    Transfer(Bytes32),
    /// The bundle brings a new NFT into existence (its launcher + eve spends).
    Mint(Bytes32),
}

impl NftOperation {
    /// This NFT's permanent launcher id.
    pub fn launcher_id(self) -> Bytes32 {
        match self {
            Self::Transfer(launcher_id) | Self::Mint(launcher_id) => launcher_id,
        }
    }

    /// The canonical one-line description a human reviews and the signing gate compares —
    /// `"transfer nft1…"` / `"mint nft1…"`.
    ///
    /// Rendering and comparison MUST share this one function: if the confirm screen and the gate
    /// derived the sentence separately they could drift, and a human would then approve a sentence
    /// the gate never checked.
    pub fn describe(self) -> WalletResult<String> {
        let verb = match self {
            Self::Transfer(_) => "transfer",
            Self::Mint(_) => "mint",
        };
        let id = Bech32Address::new(self.launcher_id(), "nft".into())
            .encode()
            .map_err(|e| reject(format!("cannot encode NFT id: {e:?}")))?;
        Ok(format!("{verb} {id}"))
    }
}

/// The authoritative value flow of a spend, reconstructed purely from its coin spends.
///
/// [`outputs`](SpendEffect::outputs) are the created coins UNDIVIDED — every `CREATE_COIN` to a free
/// address, in coin-spend order, with NO recipient-vs-change split. That split is inherently
/// key-relative (both are plain `CREATE_COIN`s on chain), so it is deferred to the key-holding
/// consumer: [`LocalSigner`](super::signer::LocalSigner) classifies each output by KEY OWNERSHIP
/// (owned → change, not-owned → recipient). [`protocol_sink`](SpendEffect::protocol_sink) are outputs
/// the wallet commits to a consensus-enforced canonical structural puzzle (the offer **settlement**
/// puzzle, #1511 PR-B). The signer requires every not-owned output to appear in the reviewed summary
/// and every `protocol_sink` output to be a recognized canonical structural hash, so no value can
/// silently leave the wallet to a free address.
///
/// `#[non_exhaustive]` (ref #2242): the bucket set grows as new spend classes are decoded, so
/// downstream matches must not assume a fixed field set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpendEffect {
    /// The created coins to free addresses, UNDIVIDED (no recipient/change split — that is
    /// key-relative and classified by the key-holding consumer, never here).
    pub outputs: Vec<DecodedOutput>,
    /// Outputs the wallet intentionally commits to a consensus-enforced canonical structural puzzle —
    /// the offer settlement-payments puzzle ([`SETTLEMENT_PAYMENT_HASH`]) or the singleton launcher
    /// ([`SINGLETON_LAUNCHER_HASH`]). This is the sanctioned egress of offered/paid assets:
    /// value leaves the wallet, but to a structure the protocol enforces, never to a chosen address.
    /// Every entry's `puzzle_hash` is a recognized canonical structural hash by construction (see
    /// [`is_protocol_sink_hash`]).
    pub protocol_sink: Vec<DecodedOutput>,
    /// The farmer fee (XCH mojos). For strict (XCH/CAT/offer) spends, summed from `RESERVE_FEE`
    /// conditions; for an OPTION (transfer) bundle, the IMPLICIT fee `inputs − outputs` (the option
    /// builders emit no `RESERVE_FEE`).
    pub fee: u64,
    /// Every NFT lifecycle action this bundle performs (dig_ecosystem#3077).
    ///
    /// An NFT transfer nets ~0 XCH, so it appears in neither [`outputs`](Self::outputs) nor
    /// [`fee`](Self::fee) as anything a person could recognize. It is named here for the same
    /// reason a melt is: an act the summary cannot express is an act the human cannot refuse.
    pub nft_operations: Vec<NftOperation>,
    /// The coin id of every singleton this bundle permanently DESTROYS (dig_ecosystem#3068).
    ///
    /// A melt creates no coin, so it is invisible in [`outputs`](Self::outputs) and shows up in
    /// [`fee`](Self::fee) only as the singleton's lone mojo — which is why it must be named here.
    /// Without it, a melt of the user's DID appended to an ordinary send is reviewable only as a fee
    /// one mojo larger, and the person would confirm a send while destroying an identity.
    pub melted_singletons: Vec<Bytes32>,
}

/// True when `puzzle_hash` is a recognized canonical STRUCTURAL puzzle hash the wallet may commit
/// value to as a [`SpendEffect::protocol_sink`] — the immutable Chia offer settlement-payments puzzle
/// ([`SETTLEMENT_PAYMENT_HASH`]) or the singleton launcher ([`SINGLETON_LAUNCHER_HASH`], the fixed
/// structural puzzle every singleton — incl. an option — is minted through, #1511 PR-C).
///
/// This is the allow-list that stops value exfiltration masquerading as an offer/option: a `CREATE_COIN`
/// routes to `protocol_sink` ONLY when its destination is one of these fixed protocol structures, so a
/// coin created to an attacker's address can never be laundered as a benign "sink" (threat MR-3/MR-5).
/// The per-option locked-underlying puzzle hash is deliberately NOT recognized here — it is not a fixed
/// constant and is not re-derivable from coin spends alone (that is the option-mint decode gap, #2243).
pub fn is_protocol_sink_hash(puzzle_hash: Bytes32) -> bool {
    puzzle_hash == Bytes32::new(SETTLEMENT_PAYMENT_HASH)
        || puzzle_hash == Bytes32::new(SINGLETON_LAUNCHER_HASH)
}

/// The mutable accumulators [`analyze`] threads through every coin spend as it re-derives a
/// bundle's value flow. Grouping them lets each per-spend-class helper take one `&mut SpendLedger`
/// instead of a long list of `&mut` ledgers/buckets — the field set is exactly the locals the
/// single-loop version mutated, and each helper mutates them in the same order it always did.
struct SpendLedger {
    /// The created coins to free addresses, UNDIVIDED (→ [`SpendEffect::outputs`]).
    outputs: Vec<DecodedOutput>,
    /// Outputs committed to a canonical structural puzzle (→ [`SpendEffect::protocol_sink`]).
    protocol_sink: Vec<DecodedOutput>,
    /// The explicit `RESERVE_FEE` total (the strict-path fee).
    fee: u64,
    /// Mojos DESTROYED by a terminal singleton melt (dig_ecosystem#3068).
    ///
    /// A melted singleton's amount enters the spend and leaves it via no `CREATE_COIN` at all — the
    /// `MELT_SINGLETON` magic condition occupies the one odd-amount output slot the puzzle permits,
    /// so the mojo is unrecoverable by construction and consensus absorbs it as an implicit fee.
    /// Tracked separately from [`fee`](Self::fee) so strict conservation still holds over every OTHER
    /// coin in the bundle: the melted total is an explicitly accounted sink, never a relaxation of
    /// the equality.
    melted: u64,
    /// The coin id of every singleton this bundle DESTROYS (→ [`SpendEffect::melted_singletons`]).
    ///
    /// Kept beside [`melted`](Self::melted) rather than folded into it because the mojo total and the
    /// identity destroyed are different facts to a human: one melt of one mojo can end a DID, and the
    /// person confirming needs to see WHICH lineage ends, not a fee a mojo larger.
    melted_singletons: Vec<Bytes32>,
    /// XCH value entering the spend (standard / settlement / option-singleton coin amounts).
    xch_in: u64,
    /// XCH value leaving the spend via `CREATE_COIN`.
    xch_out: u64,
    /// Per-asset CAT value entering, keyed by tail hash.
    cat_in: BTreeMap<Bytes32, u64>,
    /// Per-asset CAT value leaving, keyed by tail hash.
    cat_out: BTreeMap<Bytes32, u64>,
    /// Every NFT lifecycle action accounted so far (→ [`SpendEffect::nft_operations`], #3077).
    nft_operations: Vec<NftOperation>,
    /// The coin id of every coin the bundle spends — filled BEFORE the accounting loop so a mint's
    /// launcher/eve binding can be judged without depending on coin-spend ORDER.
    spent_coin_ids: HashSet<Bytes32>,
    /// The coin id of every singleton LAUNCHER coin this bundle spends and this module accounted.
    launcher_coin_ids: HashSet<Bytes32>,
    /// One entry per launcher spend: the coin that must have CREATED that launcher coin.
    launcher_parents: Vec<Bytes32>,
    /// One entry per eve NFT spend: the launcher coin that must have created that eve coin.
    eve_parents: Vec<Bytes32>,
    /// Offer-binding facts (#2241) gathered from every WALLET-SIGNED coin, checked at the bundle
    /// level AFTER the loop. A make emits the requested-payment announcement on ONE offered coin and
    /// rings the rest with concurrency, so the binding is a property of the whole bundle, never one
    /// coin.
    bindings: Vec<CoinBinding>,
}

impl SpendLedger {
    fn new() -> Self {
        Self {
            outputs: Vec::new(),
            protocol_sink: Vec::new(),
            fee: 0,
            melted: 0,
            melted_singletons: Vec::new(),
            xch_in: 0,
            xch_out: 0,
            cat_in: BTreeMap::new(),
            cat_out: BTreeMap::new(),
            nft_operations: Vec::new(),
            spent_coin_ids: HashSet::new(),
            launcher_coin_ids: HashSet::new(),
            launcher_parents: Vec::new(),
            eve_parents: Vec::new(),
            bindings: Vec::new(),
        }
    }
}

/// Re-derive the value flow of `coin_spends` from the coin spends alone, fail-closed.
///
/// Each coin spend is parsed with the chia-wallet-sdk drivers: a CAT spend via [`Cat::parse`] (its
/// inner p2 conditions carry the CAT outputs), a standard spend via [`StandardLayer`] (its run
/// conditions carry the XCH outputs + fee). Value is checked to conserve per asset. Anything the
/// drivers cannot fully account for is rejected with [`WalletErrorCode::SpendValidationFailed`].
///
/// The shape is: ledger setup → per-coin dispatch ([`account_coin`], which classifies each spend and
/// hands it to the matching `account_*` helper) → the bundle-level offer-binding + conservation
/// epilogue. The per-spend-class accounting lives in the helpers below; this function owns only the
/// cross-coin math.
pub fn analyze(coin_spends: &[CoinSpend]) -> WalletResult<SpendEffect> {
    if coin_spends.is_empty() {
        return Err(reject("no coin spends to verify"));
    }

    let mut allocator = Allocator::new();
    let mut ledger = SpendLedger::new();

    // OPTION MODE is gated on the presence of an option-layer coin. For a signable option action that
    // means a TRANSFER's singleton ([`OptionContract`]); an EXERCISE bundle (its [`P2OneOfManyLayer`]
    // underlying leg) is detected here too but refused fail-closed in the loop below before conservation
    // runs. It selects IMPLICIT-fee conservation: the option builders emit no `RESERVE_FEE` and the
    // 1-mojo singleton flows through to the re-homed coin, so `in − out` IS the fee. The strict
    // XCH/CAT/offer path is byte-unchanged when this is false.
    let option_mode = is_option_bundle(&mut allocator, coin_spends)?;

    // Recorded BEFORE the loop so a mint's launcher/eve binding never depends on the order the
    // coin spends happen to arrive in.
    ledger.spent_coin_ids = coin_spends
        .iter()
        .map(|spend| spend.coin.coin_id())
        .collect();

    for spend in coin_spends {
        account_coin(&mut ledger, &mut allocator, spend)?;
    }

    // Bundle-level NFT-mint binding (#3077): a launcher and an eve spend are UNSIGNED, so the only
    // thing that makes admitting them safe is that they belong to THIS bundle's own mint.
    enforce_bundle_nft_mint_binding(&ledger)?;

    // Bundle-level offer-binding (#2241): every settlement-sink egress must be tied — directly or
    // through the concurrency ring — to an announcement that binds the requested payment.
    //
    // This pass is enforced UNCONDITIONALLY — never gated on `option_mode` (#2249). The MR-6 binding
    // was once disabled for the whole bundle whenever an option-layer coin flipped `option_mode` on,
    // which let an attacker include any option coin to route a standard coin's value into a settlement
    // sink with no binding enforced. The gate is per-EGRESS instead: `bindings` holds only the
    // WALLET-SIGNED coins that can commit value to settlement (standard-XCH + CAT sends) — an option
    // TRANSFER's singleton re-home never targets a structural sink hash (refused in
    // `account_option_transfer`) and is not pushed here, so it is inert in this pass. The one leg that
    // legitimately carries no offer-binding — the consensus-forced option EXERCISE strike — never
    // reaches this pass at all: exercise is refused fail-closed at the signature source (the
    // non-re-home / `P2OneOfManyLayer` refusals in the dispatch), so no strike-leg exemption is needed
    // here and none is granted.
    enforce_bundle_settlement_binding(&ledger.bindings)?;

    // XCH value conservation. Two modes:
    // - STRICT (XCH/CAT/offer, byte-unchanged): `in == out + reserve_fee`, a leak/mint is refused.
    // - OPTION (transfer): the builders emit no `RESERVE_FEE`, so the network-absorbed excess `in − out`
    //   IS the implicit fee. `out > in` (a mint) is still refused (checked_sub). The implicit fee is
    //   compared to the reviewed `summary.fee` by the signer (an MR-11-style implicit-fee guard).
    let effective_fee = if option_mode {
        // A melt is accounted by the STRICT equality below, which names `melted` explicitly; the
        // implicit-fee mode does not reference it at all, so a melt riding an option bundle would
        // get only implicit-fee treatment and its destroyed mojos would never be held to the
        // equality. Rather than widen a second conservation mode, refuse the combination: no DIG
        // flow melts a profile singleton inside an option bundle, and an attacker appending one is
        // exactly what this closes.
        if ledger.melted > 0 {
            return Err(reject(
                "a singleton melt appears in an option bundle, whose implicit-fee conservation \
                 cannot account for destroyed value; refusing to sign",
            ));
        }
        ledger.xch_in.checked_sub(ledger.xch_out).ok_or_else(|| {
            reject(format!(
                "option spend mints value: outputs {} exceed inputs {}",
                ledger.xch_out, ledger.xch_in
            ))
        })?
    } else {
        let xch_out_plus_fee = accumulate(ledger.xch_out, ledger.fee, "XCH output + fee total")?;
        // A melted singleton's mojo is a THIRD accounted destination beside outputs and the explicit
        // fee: it is destroyed rather than paid to a puzzle hash, so the equality must name it or a
        // legitimate melt reads as a value leak. Naming it here — instead of switching the bundle to
        // implicit-fee mode — keeps the strict equality binding on every other coin in the same
        // bundle, so the coin paying a melt's network fee is still held to full conservation.
        let accounted = accumulate(
            xch_out_plus_fee,
            ledger.melted,
            "XCH output + fee + melted total",
        )?;
        if ledger.xch_in != accounted {
            return Err(reject(format!(
                "XCH value not conserved: in {} != out+fee+melted {accounted}",
                ledger.xch_in
            )));
        }
        // The destroyed mojos ARE a fee — consensus hands them to the farmer exactly as a
        // `RESERVE_FEE` does — so the reviewed figure must include them rather than silently
        // omitting value the human is spending.
        accumulate(ledger.fee, ledger.melted, "reported fee")?
    };
    // Conservation is checked in BOTH directions over the union of assets seen as inputs or outputs:
    // an output whose asset was never an input is a mint from thin air; an input asset with no (or a
    // smaller) matching output is a melt/leak. Iterating only one side would miss the other.
    for asset in ledger.cat_in.keys().chain(ledger.cat_out.keys()) {
        let input = ledger.cat_in.get(asset).copied().unwrap_or(0);
        let output = ledger.cat_out.get(asset).copied().unwrap_or(0);
        if input != output {
            return Err(reject(format!(
                "CAT {} value not conserved: in {input} != out {output}",
                hex::encode(asset)
            )));
        }
    }

    Ok(SpendEffect {
        outputs: ledger.outputs,
        protocol_sink: ledger.protocol_sink,
        fee: effective_fee,
        melted_singletons: ledger.melted_singletons,
        nft_operations: ledger.nft_operations,
    })
}

/// Classify ONE coin spend and account it into `ledger`, fail-closed.
///
/// Binds the puzzle reveal to the coin, then dispatches to the matching per-spend-class helper in the
/// SAME order the single-loop version tried them: CAT → option singleton → the `P2OneOfMany` exercise
/// refusal → standard-layer XCH → settlement-layer XCH claim → an unrecognized-puzzle refusal. Every
/// branch either accounts the spend (returning `Ok(())`, so the caller moves to the next coin) or
/// refuses it fail-closed (`Err`), exactly as before.
fn account_coin(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    spend: &CoinSpend,
) -> WalletResult<()> {
    let puzzle_ptr = node_from_bytes(allocator, &spend.puzzle_reveal)
        .map_err(|e| reject(format!("undecodable puzzle reveal: {e:?}")))?;
    let solution_ptr = node_from_bytes(allocator, &spend.solution)
        .map_err(|e| reject(format!("undecodable solution: {e:?}")))?;

    // (#1518) Bind the reveal to the coin BEFORE trusting anything it decodes to. A coin commits
    // on-chain only to its puzzle HASH; the `puzzle_reveal` is caller-supplied bytes. If the
    // reveal does not hash to `coin.puzzle_hash` it is a substituted puzzle the coin never
    // authorized — a malicious engine could pair a benign-looking reveal (that `analyze` accounts
    // for cleanly) with a coin whose real puzzle does something else entirely. Reject fail-closed
    // so every value flow this module derives is the coin's OWN authorized program.
    let revealed_hash = Bytes32::new(tree_hash(allocator, puzzle_ptr).to_bytes());
    if revealed_hash != spend.coin.puzzle_hash {
        return Err(reject(format!(
            "puzzle reveal hashes to {} but the coin commits to {} (substituted puzzle)",
            hex::encode(revealed_hash),
            hex::encode(spend.coin.puzzle_hash)
        )));
    }

    let puzzle = Puzzle::parse(allocator, puzzle_ptr);

    // A CAT coin: the value flows through its INNER p2 conditions, denominated in the asset.
    if let Some(parsed) = Cat::parse(allocator, spend.coin, puzzle, solution_ptr)
        .map_err(|e| reject(format!("malformed CAT spend: {e:?}")))?
    {
        // 0.34's `Cat::parse` returns a `ParsedCat` struct in place of the old
        // `(Cat, inner_puzzle, inner_solution)` tuple; `p2_puzzle`/`p2_solution` are the
        // exact same inner p2 puzzle/solution the tuple carried (non-revocable CAT path).
        return account_cat_spend(
            ledger,
            allocator,
            spend,
            parsed.cat,
            parsed.p2_puzzle,
            parsed.p2_solution,
        );
    }

    // An OPTION SINGLETON spend (#1511 PR-C): the option contract is a singleton wrapping the current
    // owner's inner standard layer (the sole signed coin). Decode via `OptionContract::parse` to reach
    // that inner p2 and enforce the sole-AGG_SIG_ME commitment exactly as a standard/CAT send. ONLY a
    // re-homing TRANSFER (an odd-amount `CREATE_COIN` to the new owner) is signable; a spend that does
    // NOT re-home — a melt/exercise (mode-23 `SEND_MESSAGE` + `MeltSingleton`) or a clawback — is
    // refused fail-closed in the helper, at the signature source, so the wallet never signs the leg
    // that unlocks the option underlying (Case-A guard, #1511 PR-C).
    if let Some((_option, inner_puzzle, inner_solution)) =
        OptionContract::parse(allocator, spend.coin, puzzle, solution_ptr)
            .map_err(|e| reject(format!("malformed option singleton spend: {e:?}")))?
    {
        return account_option_transfer(ledger, allocator, spend, inner_puzzle, inner_solution);
    }

    // An option EXERCISE's locked-underlying coin — a `P2OneOfMany` 1-of-2 (exercise/clawback)
    // puzzle. Its presence UNAMBIGUOUSLY marks the bundle as an exercise (a transfer never spends
    // it), and exercise is REFUSED fail-closed: the exercise path unlocks the underlying onto a bare
    // `SETTLEMENT_PAYMENT_HASH` coin, and consensus forces only the STRIKE payment to the creator —
    // NOT the unlocked underlying back to the holder. That reclaim leg is builder-enforced only, so a
    // compromised engine could strip it AFTER the wallet signs the strike-funding coin: the wallet
    // pays the strike while an attacker sweeps the underlying. Exercise cannot be safely
    // `LocalSigner`-signable until a dig-options puzzle change binds the reclaim to the holder in
    // consensus (deferred to #2245). Transfer, which only touches the inner standard layer, is
    // unaffected and still signs.
    if P2OneOfManyLayer::parse_puzzle(allocator, puzzle)
        .map_err(|e| reject(format!("malformed option underlying spend: {e:?}")))?
        .is_some()
    {
        return Err(reject(
            "option exercise is not signable: the unlocked underlying's reclaim to the holder is \
             not consensus-forced, so a compromised engine could strip it after the wallet funds \
             the strike (deferred to #2245); refusing to sign",
        ));
    }

    // The singleton LAUNCHER coin of an NFT MINT (#3077). Its puzzle hash IS the canonical
    // `SINGLETON_LAUNCHER_HASH`, and the reveal was bound to the coin above, so this is the
    // immutable launcher puzzle itself and nothing else. It carries no signature; what makes it
    // admissible is that the bundle created it (`enforce_bundle_nft_mint_binding`).
    if spend.coin.puzzle_hash == Bytes32::new(SINGLETON_LAUNCHER_HASH) {
        return account_singleton_launch(ledger, allocator, spend, puzzle_ptr, solution_ptr);
    }

    // An NFT singleton spend (#3077) — a TRANSFER or a mint's EVE spend. Placed BEFORE the
    // shallow `is_singleton_puzzle` melt arm, which would otherwise swallow every NFT (an NFT is
    // singleton-wrapped), and AFTER the option arms, so an option singleton keeps its own,
    // stricter rules and this arm can never be used to launder an option exercise.
    if let Some((nft, p2_puzzle, p2_solution)) =
        Nft::parse(allocator, spend.coin, puzzle, solution_ptr)
            .map_err(|e| reject(format!("malformed NFT spend: {e:?}")))?
    {
        return account_nft_spend(
            ledger,
            allocator,
            spend,
            nft,
            p2_puzzle,
            p2_solution,
            puzzle_ptr,
            solution_ptr,
        );
    }

    // A TERMINAL singleton spend — the profile-deletion path (dig_ecosystem#3068). Reached only
    // AFTER the option arms above, so an option singleton is still judged by its own, stricter rules
    // and this arm can never be used to launder an option exercise. Any singleton spend that is not
    // a melt is refused inside the helper.
    if is_singleton_puzzle(puzzle) {
        return account_singleton_melt(ledger, allocator, spend, puzzle_ptr, solution_ptr);
    }

    // A standard-layer XCH coin: its run conditions carry the XCH outputs + the fee.
    if StandardLayer::parse_puzzle(allocator, puzzle)
        .map_err(|e| reject(format!("malformed standard spend: {e:?}")))?
        .is_some()
    {
        return account_standard_send(ledger, allocator, spend, puzzle_ptr, solution_ptr);
    }

    // A settlement-payments (XCH) coin the wallet CLAIMS while taking/cancelling an offer: the
    // canonical, immutable settlement puzzle, spent by announcement with NO signature. Account its
    // notarized-payment outputs into the XCH ledger; there is nothing to sign here.
    if SettlementLayer::parse_puzzle(allocator, puzzle)
        .map_err(|e| reject(format!("malformed settlement spend: {e:?}")))?
        .is_some()
    {
        return account_settlement_claim(ledger, allocator, spend, puzzle_ptr, solution_ptr);
    }

    Err(reject(
        "coin spend is not a standard-layer XCH, a CAT, an option, nor a settlement spend; \
         refusing to sign",
    ))
}

/// Account a CAT coin spend: record its amount as CAT input, then split into the settlement-claim vs
/// wallet-signed-send path exactly as the single loop did.
fn account_cat_spend(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    spend: &CoinSpend,
    cat: Cat,
    inner_puzzle: Puzzle,
    inner_solution: clvmr::NodePtr,
) -> WalletResult<()> {
    let asset = cat.info.asset_id;

    // Every CAT coin's own amount is value entering the spend, whoever authorizes it.
    let cat_in_total = ledger.cat_in.entry(asset).or_default();
    *cat_in_total = accumulate(*cat_in_total, spend.coin.amount, "CAT input total")?;

    // A CAT coin the wallet CLAIMS as part of taking/cancelling an offer wraps the canonical
    // settlement puzzle: it is spent by announcement, carries NO signature, and its notarized
    // payments are the outputs. Account those but skip the wallet-signed-coin guards (there is
    // nothing to sign, and the settlement puzzle is a fixed structure, not a delegated one).
    if SettlementLayer::parse_puzzle(allocator, inner_puzzle)
        .map_err(|e| reject(format!("malformed CAT settlement puzzle: {e:?}")))?
        .is_some()
    {
        return account_cat_settlement_claim(
            ledger,
            allocator,
            asset,
            inner_puzzle,
            inner_solution,
        );
    }

    // Otherwise it is a wallet-signed CAT send: its inner p2 MUST be a standard layer whose
    // delegated puzzle is quote-form — otherwise the signed message (tree-hash-only) would not
    // commit to the actual outputs (see `committed_delegated_puzzle_message`).
    if StandardLayer::parse_puzzle(allocator, inner_puzzle)
        .map_err(|e| reject(format!("malformed CAT inner puzzle: {e:?}")))?
        .is_none()
    {
        return Err(reject(
            "CAT inner puzzle is neither a standard layer nor a settlement layer; refusing \
             to sign",
        ));
    }
    account_cat_send(
        ledger,
        allocator,
        spend,
        asset,
        inner_puzzle,
        inner_solution,
    )
}

/// Account a CAT coin the wallet CLAIMS through the settlement layer (offer take/cancel): its
/// notarized-payment `CREATE_COIN`s become CAT outputs; there is no signature to guard.
fn account_cat_settlement_claim(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    asset: Bytes32,
    inner_puzzle: Puzzle,
    inner_solution: clvmr::NodePtr,
) -> WalletResult<()> {
    let conditions = run_conditions(allocator, inner_puzzle.ptr(), inner_solution)?;
    reject_any_agg_sig(&conditions)?;
    for create in conditions.iter().filter_map(Condition::as_create_coin) {
        let cat_out_total = ledger.cat_out.entry(asset).or_default();
        *cat_out_total = accumulate(*cat_out_total, create.amount, "CAT output total")?;
        route_output(
            &mut ledger.outputs,
            &mut ledger.protocol_sink,
            DecodedOutput {
                puzzle_hash: create.puzzle_hash,
                amount: create.amount,
                asset_id: Some(asset),
            },
        );
    }
    Ok(())
}

/// Account a wallet-signed CAT send: enforce the sole-AGG_SIG_ME commitment over the standard-layer
/// inner puzzle, record its offer binding, and route each `CREATE_COIN` as a CAT output.
fn account_cat_send(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    spend: &CoinSpend,
    asset: Bytes32,
    inner_puzzle: Puzzle,
    inner_solution: clvmr::NodePtr,
) -> WalletResult<()> {
    let committed_message = committed_delegated_puzzle_message(allocator, inner_solution)?;
    let conditions = run_conditions(allocator, inner_puzzle.ptr(), inner_solution)?;
    enforce_sole_agg_sig_me(&conditions, committed_message)?;
    ledger.bindings.push(coin_binding(&spend.coin, &conditions));
    for condition in &conditions {
        reject_unexpected_agg_sig(condition)?;
        if let Some(create) = condition.as_create_coin() {
            let cat_out_total = ledger.cat_out.entry(asset).or_default();
            *cat_out_total = accumulate(*cat_out_total, create.amount, "CAT output total")?;
            route_output(
                &mut ledger.outputs,
                &mut ledger.protocol_sink,
                DecodedOutput {
                    puzzle_hash: create.puzzle_hash,
                    amount: create.amount,
                    asset_id: Some(asset),
                },
            );
        }
    }
    Ok(())
}

/// Account an OPTION SINGLETON spend (#1511 PR-C). Only a re-homing TRANSFER is signable: a spend that
/// does NOT re-home (melt/exercise or clawback) is refused fail-closed at the signature source; a
/// transfer is held to a default-deny condition allowlist and routes its single re-home `CREATE_COIN`.
fn account_option_transfer(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    spend: &CoinSpend,
    inner_puzzle: Puzzle,
    inner_solution: clvmr::NodePtr,
) -> WalletResult<()> {
    if StandardLayer::parse_puzzle(allocator, inner_puzzle)
        .map_err(|e| reject(format!("malformed option inner puzzle: {e:?}")))?
        .is_none()
    {
        return Err(reject(
            "option singleton inner puzzle is not a standard layer; refusing to sign",
        ));
    }
    let committed_message = committed_delegated_puzzle_message(allocator, inner_solution)?;
    let conditions = run_conditions(allocator, inner_puzzle.ptr(), inner_solution)?;
    enforce_sole_agg_sig_me(&conditions, committed_message)?;

    let re_homes = conditions
        .iter()
        .filter_map(Condition::as_create_coin)
        .any(|create| create.amount % 2 == 1);
    if !re_homes {
        // NOT a re-home: this option-singleton spend melts/exercises the singleton (a
        // `melt_singleton` — the magic `CREATE_COIN(_, -113)` decoded as `Condition::MeltSingleton`,
        // never as an odd-amount value `CREATE_COIN`) and/or carries the mode-23 exercise
        // `SEND_MESSAGE`, or is a clawback. NONE of these is a signable action in PR-C: only a
        // re-homing TRANSFER is. Refuse fail-closed HERE, at the signature source, REGARDLESS of
        // whether the P2OneOfMany underlying leg is present in the bundle — so the strip-the-leg
        // attack (omit the underlying leg to dodge the `P2OneOfManyLayer` refusal in the dispatch)
        // cannot obtain the wallet's signature on the melt+message spend that unlocks the underlying.
        // (A plain transfer decodes an odd-amount `CREATE_COIN(amount = 1)` and takes the
        // re-home branch, so it is unaffected.)
        return Err(reject(
            "option singleton spend does not re-home (melt/exercise or clawback); only a \
             re-homing TRANSFER is signable; refusing to sign",
        ));
    }

    // TRANSFER: the singleton's 1 mojo flows through to the re-homed coin — count both.
    ledger.xch_in = accumulate(ledger.xch_in, spend.coin.amount, "XCH input total")?;
    let mut create_coins = 0usize;
    for condition in &conditions {
        reject_unexpected_agg_sig(condition)?;
        // Default-DENY allowlist: a transfer's delegated puzzle may emit ONLY the re-home
        // `CREATE_COIN`, its sole `AGG_SIG_ME`, and benign assertions. Any other condition — a
        // mode-23 exercise `SEND_MESSAGE`/`RECEIVE_MESSAGE`, a `MeltSingleton`, an announcement
        // CREATE, or an unknown opcode — is refused, so a transfer signature can never carry the
        // exercise message even in a mixed spend.
        reject_non_transfer_condition(condition)?;
        if let Some(create) = condition.as_create_coin() {
            // Exactly one value-bearing `CREATE_COIN` (the re-home) is permitted; a second is an
            // undisclosed extra egress riding the transfer.
            create_coins += 1;
            if create_coins > 1 {
                return Err(reject(
                    "option transfer emits more than one CREATE_COIN (undisclosed extra \
                     egress); refusing to sign",
                ));
            }
            // MR-12: the re-homed singleton must go to the new owner's p2 (a chosen address
            // the human reviews via the summary), NEVER to a structural launcher/settlement
            // hash the option layer did not authorize — that would be an unauthorized re-home
            // laundered as a protocol sink. The sole-AGG_SIG_ME commitment already binds the
            // destination to the holder's signature; this refuses the structural-hash case.
            if is_protocol_sink_hash(create.puzzle_hash) {
                return Err(reject(
                    "option transfer re-homes the singleton to a structural puzzle hash \
                     (unauthorized re-home); refusing to sign",
                ));
            }
            ledger.xch_out = accumulate(ledger.xch_out, create.amount, "XCH output total")?;
            route_output(
                &mut ledger.outputs,
                &mut ledger.protocol_sink,
                DecodedOutput {
                    puzzle_hash: create.puzzle_hash,
                    amount: create.amount,
                    asset_id: None,
                },
            );
        }
    }
    Ok(())
}

/// Account an NFT singleton spend (#3077), dispatching on the ONE structural fact that separates the
/// two admissible shapes: whether the singleton has a lineage yet.
///
/// - A mint's **eve** spend carries a [`Proof::Eve`] and is UNSIGNED — the sdk's `mint_nft` gives it
///   a bare quoted condition list with a nil solution, so it emits no `AGG_SIG_ME` at all.
/// - A **transfer** carries a [`Proof::Lineage`] and IS signed, through the owner's inner standard
///   layer, exactly as an option transfer is.
///
/// The proof comes from the caller-supplied SOLUTION, so the dispatch itself is not a guard and is
/// not treated as one. Both destinations fail closed independently: the eve arm admits NO signature
/// condition whatsoever and requires the bundle's own launcher to have created the coin, so a
/// transfer mislabelled as an eve spend obtains nothing; the transfer arm requires a standard-layer
/// inner and exactly one matching `AGG_SIG_ME`, which a quoted eve puzzle cannot present.
///
/// Every OTHER NFT spend stays refused. That is deliberate and is the boundary of this widening: a
/// metadata UPDATE, a DID-link / owner ASSIGNMENT, and an offer settlement lock all re-home or
/// re-parameterize the NFT under conditions the transfer allowlist denies.
#[allow(clippy::too_many_arguments)]
fn account_nft_spend(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    spend: &CoinSpend,
    nft: Nft,
    p2_puzzle: Puzzle,
    p2_solution: clvmr::NodePtr,
    puzzle_ptr: clvmr::NodePtr,
    solution_ptr: clvmr::NodePtr,
) -> WalletResult<()> {
    match nft.proof {
        Proof::Eve(_) => {
            account_nft_eve_mint(ledger, allocator, spend, nft, puzzle_ptr, solution_ptr)
        }
        Proof::Lineage(_) => account_nft_transfer(
            ledger,
            allocator,
            spend,
            nft,
            p2_puzzle,
            p2_solution,
            puzzle_ptr,
            solution_ptr,
        ),
    }
}

/// Account an NFT TRANSFER — the signed leg, modelled on [`account_option_transfer`] because that is
/// the arm in this module that got a singleton re-home right (#3077).
///
/// The discipline is identical and deliberately so, since the hazard is identical: the standard
/// layer signs `sha256tree(delegated_puzzle) || coin_id || genesis`, committing to the delegated
/// puzzle's TREE HASH but never to its SOLUTION. So admission is decided on the artifact the
/// signature actually commits to, never on what the presented solution happens to emit:
///
/// 1. the inner p2 MUST be a standard layer — anything else is refused before its conditions are
///    trusted;
/// 2. [`committed_delegated_puzzle_message`] proves that layer's delegated puzzle is the canonical
///    QUOTE form, which is what makes a solution-malleable delegated puzzle — the #1058 CRITICAL#3
///    blank cheque that re-homed a user's DID — unrepresentable here;
/// 3. [`enforce_sole_agg_sig_me`] proves the coin's ONE `AGG_SIG_ME` commits to exactly that hash,
///    so "the flow this module verified" and "what the signature authorizes" are the same object;
/// 4. a default-DENY condition allowlist ([`reject_non_rehome_condition`]) refuses everything
///    outside a re-home — including the owner-assignment and metadata-update conditions that would
///    otherwise turn a reviewed "transfer" into a different act;
/// 5. exactly ONE odd-amount `CREATE_COIN` re-homes the singleton, and its destination must not be a
///    structural puzzle hash the NFT layer never authorized.
#[allow(clippy::too_many_arguments)]
fn account_nft_transfer(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    spend: &CoinSpend,
    nft: Nft,
    p2_puzzle: Puzzle,
    p2_solution: clvmr::NodePtr,
    puzzle_ptr: clvmr::NodePtr,
    solution_ptr: clvmr::NodePtr,
) -> WalletResult<()> {
    if StandardLayer::parse_puzzle(allocator, p2_puzzle)
        .map_err(|e| reject(format!("malformed NFT inner puzzle: {e:?}")))?
        .is_none()
    {
        return Err(reject(
            "NFT inner puzzle is not a standard layer; refusing to sign",
        ));
    }
    let committed = committed_standard_spend(allocator, p2_solution)?;

    // The SIGNED conditions decide WHICH ACT is admitted, and they must, because the NFT state
    // layer CONSUMES an `UPDATE_NFT_METADATA` and the ownership layer consumes a `TRANSFER_NFT`
    // while re-emitting the rest — so a metadata update and an owner assignment are INVISIBLE in
    // the outer conditions below, where only their re-home survives. Judging the outer list alone
    // would have admitted both as a plain "transfer" and named them as one on the confirm screen.
    // This list is also the artifact the signature commits to, so it is the right one on both
    // counts.
    for condition in &committed.conditions {
        reject_unexpected_agg_sig(condition)?;
        reject_non_rehome_condition(condition, RehomeClass::NftSigned)?;
    }

    // The OUTER conditions are what consensus acts on, so the VALUE FLOW is accounted from them.
    let conditions = run_conditions(allocator, puzzle_ptr, solution_ptr)?;
    enforce_sole_agg_sig_me(&conditions, committed.message)?;

    ledger.xch_in = accumulate(ledger.xch_in, spend.coin.amount, "XCH input total")?;
    let mut re_homes = 0usize;
    for condition in &conditions {
        reject_unexpected_agg_sig(condition)?;
        reject_non_rehome_condition(condition, RehomeClass::Nft)?;
        if let Some(create) = condition.as_create_coin() {
            re_homes += 1;
            if re_homes > 1 {
                return Err(reject(
                    "NFT transfer emits more than one CREATE_COIN (undisclosed extra egress); \
                     refusing to sign",
                ));
            }
            if create.amount % 2 == 0 {
                return Err(reject(
                    "NFT transfer's CREATE_COIN is not the odd-amount singleton re-home; \
                     refusing to sign",
                ));
            }
            // The re-homed NFT must land on a chosen p2 the human reviews, never on a structural
            // hash — a settlement lock or a fresh launcher is a different act than a transfer, and
            // routing it to `protocol_sink` would hide it from the recipient comparison entirely.
            if is_protocol_sink_hash(create.puzzle_hash) {
                return Err(reject(
                    "NFT transfer re-homes the singleton to a structural puzzle hash \
                     (unauthorized re-home); refusing to sign",
                ));
            }
            ledger.xch_out = accumulate(ledger.xch_out, create.amount, "XCH output total")?;
            route_output(
                &mut ledger.outputs,
                &mut ledger.protocol_sink,
                DecodedOutput {
                    puzzle_hash: create.puzzle_hash,
                    amount: create.amount,
                    asset_id: None,
                },
            );
        }
    }
    if re_homes != 1 {
        return Err(reject(
            "NFT transfer does not re-home the singleton (a melt, a settlement lock, or an \
             owner assignment); only a TRANSFER is signable; refusing to sign",
        ));
    }

    ledger
        .nft_operations
        .push(NftOperation::Transfer(nft.info.launcher_id));
    Ok(())
}

/// Account a mint's EVE NFT spend — the UNSIGNED leg (#3077).
///
/// This spend requires no signature from the wallet: the sdk's `mint_nft` gives the eve coin a bare
/// quoted condition list with a nil solution, and consensus authorizes it through the singleton's
/// launcher lineage rather than through a key. Admitting it therefore does not widen what the wallet
/// SIGNS — but only as long as that stays true, so [`reject_any_agg_sig_in`] refuses the arm
/// outright if any signature condition appears. What makes it safe to admit into the bundle at all
/// is the launcher binding checked in [`enforce_bundle_nft_mint_binding`]: without it, an unrelated
/// launcher/eve pair could ride along inside a bundle the human approved for something else.
fn account_nft_eve_mint(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    spend: &CoinSpend,
    nft: Nft,
    puzzle_ptr: clvmr::NodePtr,
    solution_ptr: clvmr::NodePtr,
) -> WalletResult<()> {
    let conditions = run_conditions(allocator, puzzle_ptr, solution_ptr)?;
    reject_any_agg_sig_in(&conditions, "an NFT mint's eve spend")?;

    ledger.xch_in = accumulate(ledger.xch_in, spend.coin.amount, "XCH input total")?;
    let mut settles = 0usize;
    for condition in &conditions {
        reject_non_rehome_condition(condition, RehomeClass::NftEve)?;
        if let Some(create) = condition.as_create_coin() {
            settles += 1;
            if settles > 1 {
                return Err(reject(
                    "an NFT mint's eve spend emits more than one CREATE_COIN (undisclosed extra \
                     egress); refusing to sign",
                ));
            }
            if create.amount % 2 == 0 {
                return Err(reject(
                    "an NFT mint's eve spend does not settle the singleton to an odd amount; \
                     refusing to sign",
                ));
            }
            if is_protocol_sink_hash(create.puzzle_hash) {
                return Err(reject(
                    "an NFT mint settles the new NFT onto a structural puzzle hash; refusing \
                     to sign",
                ));
            }
            ledger.xch_out = accumulate(ledger.xch_out, create.amount, "XCH output total")?;
            route_output(
                &mut ledger.outputs,
                &mut ledger.protocol_sink,
                DecodedOutput {
                    puzzle_hash: create.puzzle_hash,
                    amount: create.amount,
                    asset_id: None,
                },
            );
        }
    }
    if settles != 1 {
        return Err(reject(
            "an NFT mint's eve spend does not settle the new NFT; refusing to sign",
        ));
    }

    ledger.eve_parents.push(spend.coin.parent_coin_info);
    ledger
        .nft_operations
        .push(NftOperation::Mint(nft.info.launcher_id));
    Ok(())
}

/// Account the singleton LAUNCHER spend of an NFT mint — the other UNSIGNED leg (#3077).
///
/// The coin's puzzle hash is the canonical [`SINGLETON_LAUNCHER_HASH`] and its reveal was bound to
/// the coin by [`account_coin`], so this IS the immutable launcher puzzle: it emits one
/// `CREATE_COIN` for the eve singleton plus the announcement that ties the mint together, and it can
/// emit no signature requirement. Both facts are re-asserted here as defence in depth rather than
/// assumed, and the launcher's provenance is checked at the bundle level.
fn account_singleton_launch(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    spend: &CoinSpend,
    puzzle_ptr: clvmr::NodePtr,
    solution_ptr: clvmr::NodePtr,
) -> WalletResult<()> {
    let conditions = run_conditions(allocator, puzzle_ptr, solution_ptr)?;
    reject_any_agg_sig_in(&conditions, "a singleton launcher spend")?;

    ledger.xch_in = accumulate(ledger.xch_in, spend.coin.amount, "XCH input total")?;
    let mut launches = 0usize;
    for condition in &conditions {
        reject_non_rehome_condition(condition, RehomeClass::Launcher)?;
        if let Some(create) = condition.as_create_coin() {
            launches += 1;
            if launches > 1 {
                return Err(reject(
                    "a singleton launcher spend emits more than one CREATE_COIN; refusing to sign",
                ));
            }
            if create.amount % 2 == 0 {
                return Err(reject(
                    "a singleton launcher spend does not launch an odd-amount singleton; \
                     refusing to sign",
                ));
            }
            ledger.xch_out = accumulate(ledger.xch_out, create.amount, "XCH output total")?;
            route_output(
                &mut ledger.outputs,
                &mut ledger.protocol_sink,
                DecodedOutput {
                    puzzle_hash: create.puzzle_hash,
                    amount: create.amount,
                    asset_id: None,
                },
            );
        }
    }
    if launches != 1 {
        return Err(reject(
            "a singleton launcher spend does not launch a singleton; refusing to sign",
        ));
    }

    ledger.launcher_coin_ids.insert(spend.coin.coin_id());
    ledger.launcher_parents.push(spend.coin.parent_coin_info);
    Ok(())
}

/// Require every launcher and eve spend admitted above to belong to a mint THIS bundle performs
/// (#3077).
///
/// Neither leg carries a signature, so neither is bound to the wallet by a key — the binding has to
/// come from the bundle's own shape, and without it an attacker could append an unrelated
/// launcher/eve pair to a bundle the human approved for something else, obtaining a broadcast of a
/// mint (and an NFT summary line) the person never agreed to.
///
/// Two edges close it, and each names the coin that must have CREATED the leg:
///
/// - a launcher coin's parent must be a coin this bundle SPENDS, and the bundle must have accounted
///   a launcher-destined [`SpendEffect::protocol_sink`] output. Because the launcher coin's puzzle
///   hash is the canonical launcher hash, the only way that parent produced it is a
///   `CREATE_COIN(SINGLETON_LAUNCHER_HASH, …)` — which [`route_output`] accounts as exactly that
///   sink. So the launcher output the bundle created and the launcher coin the bundle spends are the
///   same coin.
/// - an eve NFT coin's parent must be one of the LAUNCHER coins accounted above, which is what stops
///   an eve spend claiming descent from a launcher outside this bundle.
fn enforce_bundle_nft_mint_binding(ledger: &SpendLedger) -> WalletResult<()> {
    if ledger.launcher_parents.is_empty() && ledger.eve_parents.is_empty() {
        return Ok(());
    }
    let creates_launcher_output = ledger
        .protocol_sink
        .iter()
        .any(|output| output.puzzle_hash == Bytes32::new(SINGLETON_LAUNCHER_HASH));
    if !ledger.launcher_parents.is_empty() && !creates_launcher_output {
        return Err(reject(
            "a singleton launcher is spent in a bundle that creates no launcher output, so this \
             bundle did not fund the mint it is performing; refusing to sign",
        ));
    }
    for parent in &ledger.launcher_parents {
        if !ledger.spent_coin_ids.contains(parent) {
            return Err(reject(
                "a singleton launcher spend's parent is not spent in this bundle, so this bundle \
                 did not create the launcher it is spending; refusing to sign",
            ));
        }
    }
    for parent in &ledger.eve_parents {
        if !ledger.launcher_coin_ids.contains(parent) {
            return Err(reject(
                "an NFT mint's eve spend does not descend from a launcher spent in this bundle; \
                 refusing to sign",
            ));
        }
    }
    Ok(())
}

/// Which singleton re-home class [`reject_non_rehome_condition`] is judging.
///
/// The three classes share a spine — one `CREATE_COIN` plus benign assertions — and differ only in
/// what else is honest for that leg. Keeping them in ONE allowlist means a condition can never be
/// permitted for one class by an omission in a copy of the list, which is precisely how two
/// allowlists drift apart.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RehomeClass {
    /// A signed NFT transfer's OUTER conditions: the p2 layer emits the coin's own `AGG_SIG_ME`
    /// there, outside the delegated puzzle.
    Nft,
    /// A signed NFT transfer's SIGNED delegated conditions. An `AGG_SIG_ME` inside the quoted list
    /// would authorize a second delegated puzzle on the same coin, which no honest transfer does.
    NftSigned,
    /// A mint's unsigned eve spend: no signature, no announcement.
    NftEve,
    /// The canonical singleton launcher: no signature, and it announces its own coin id.
    Launcher,
}

/// Default-DENY allowlist for a singleton re-home (#3077), fail-CLOSED by construction: an
/// UNRECOGNIZED opcode is REFUSED, never waved through.
///
/// This is what bounds the widening to a transfer and a mint. It denies, in particular, the
/// `TransferNft` owner-assignment (a DID link, or the settlement lock an offer performs) and the
/// `UpdateNftMetadata` metadata update — each of which re-parameterizes the NFT into something the
/// word "transfer" on a confirm screen does not describe — as well as every melt, message, reserved
/// fee, and unknown condition.
fn reject_non_rehome_condition(condition: &Condition, class: RehomeClass) -> WalletResult<()> {
    if matches!(condition, Condition::AggSigMe(_)) {
        // Only the signed transfer legitimately carries one; the unsigned legs are held to zero by
        // `reject_any_agg_sig_in` before this pass, and refusing here too costs an honest mint
        // nothing.
        return match class {
            RehomeClass::Nft => Ok(()),
            RehomeClass::NftSigned => Err(reject(
                "an NFT transfer's SIGNED delegated puzzle carries its own AGG_SIG_ME, which no \
                 honest transfer does (the standard layer emits that condition outside the \
                 delegated puzzle); it would authorize a second delegated puzzle on this coin; \
                 refusing to sign",
            )),
            RehomeClass::NftEve | RehomeClass::Launcher => Err(reject(
                "an unsigned NFT mint leg carries an AGG_SIG_ME; refusing to sign",
            )),
        };
    }
    if matches!(condition, Condition::CreateCoinAnnouncement(_)) {
        // The canonical launcher puzzle announces the coin id that ties the mint's legs together;
        // no other class has an honest reason to CREATE an announcement.
        return match class {
            RehomeClass::Launcher => Ok(()),
            RehomeClass::Nft | RehomeClass::NftSigned | RehomeClass::NftEve => Err(reject(
                "an NFT spend creates a coin announcement, which no transfer or eve settle does; \
                 refusing to sign",
            )),
        };
    }
    let permitted = matches!(
        condition,
        // The re-home / settle / launch output — counted and checked by each caller.
        Condition::CreateCoin(_)
            // Benign timelock assertions.
            | Condition::AssertSecondsAbsolute(_)
            | Condition::AssertSecondsRelative(_)
            | Condition::AssertHeightAbsolute(_)
            | Condition::AssertHeightRelative(_)
            | Condition::AssertBeforeSecondsAbsolute(_)
            | Condition::AssertBeforeSecondsRelative(_)
            | Condition::AssertBeforeHeightAbsolute(_)
            | Condition::AssertBeforeHeightRelative(_)
            // Benign announcement/concurrency ASSERTIONS (never the CREATE side).
            | Condition::AssertCoinAnnouncement(_)
            | Condition::AssertPuzzleAnnouncement(_)
            | Condition::AssertConcurrentSpend(_)
            | Condition::AssertConcurrentPuzzle(_)
            // Benign self-introspection assertions — a real NFT spend emits two of these.
            | Condition::AssertMyCoinId(_)
            | Condition::AssertMyParentId(_)
            | Condition::AssertMyPuzzleHash(_)
            | Condition::AssertMyAmount(_)
            | Condition::AssertMyBirthSeconds(_)
            | Condition::AssertMyBirthHeight(_)
            | Condition::AssertEphemeral(_)
    );
    if !permitted {
        return Err(reject(
            "an NFT spend emits a condition outside the re-home allowlist (an owner assignment, \
             a metadata update, a melt, a message, a reserved fee, or an unknown opcode); only a \
             TRANSFER and a MINT are signable; refusing to sign",
        ));
    }
    Ok(())
}

/// Refuse ANY `AGG_SIG_*` condition on a leg that must carry none, naming the leg in the refusal.
///
/// [`reject_any_agg_sig`] says the same thing for a claimed settlement coin; this variant exists so
/// an NFT mint's refusal names the mint rather than a settlement claim the user never made.
fn reject_any_agg_sig_in(conditions: &[Condition], what: &str) -> WalletResult<()> {
    let has_agg_sig = conditions
        .iter()
        .any(|condition| condition.as_agg_sig_me().is_some() || is_non_me_agg_sig(condition));
    if has_agg_sig {
        return Err(reject(format!(
            "{what} carries an AGG_SIG condition, but consensus authorizes it through the \
             singleton lineage and never through a key; refusing to sign"
        )));
    }
    Ok(())
}

/// True when `puzzle` is the singleton top layer, whatever inner puzzle it wraps.
///
/// Deliberately shallow: the DID layer and the DataLayer metadata layers are DIG types this crate
/// does not and must not know, and a melt's admissibility does not depend on which of them is
/// inside. What is checked instead is the CLVM the coin actually commits to — see
/// [`account_singleton_melt`].
fn is_singleton_puzzle(puzzle: Puzzle) -> bool {
    puzzle
        .as_curried()
        .is_some_and(|curried| curried.mod_hash == SINGLETON_TOP_LAYER_V1_1_HASH.into())
}

/// Account a TERMINAL singleton spend — a melt — and refuse every other singleton spend fail-closed
/// (dig_ecosystem#3068).
///
/// # Why this arm exists
///
/// Deleting a DIG profile ends both of its singletons: the DID and the dig-store. Until this arm,
/// [`analyze`] refused every singleton spend at the dispatch's closing arm, so no melt could ever be
/// authorized and a profile could not be deleted at all.
///
/// # The admission test is the SIGNED melt marker, never the absence of outputs
///
/// Running the coin's own puzzle tells you what consensus does for THE SOLUTION PRESENTED. It does
/// not tell you what the signature authorizes, and those are different questions: the standard layer
/// signs `sha256tree(delegated_puzzle) || coin_id || genesis`, which commits to the delegated
/// puzzle's TREE HASH but NOT to its solution (see [`committed_delegated_puzzle_message`]). A
/// solution-malleable delegated puzzle therefore turns one signature into a reusable blank cheque
/// over the coin: it can emit nothing under the solution presented for review and an odd-amount
/// `CREATE_COIN` re-homing the user's DID or store to an attacker under another (#1058 CRITICAL#3).
/// An outputs-are-absent test cannot see that, because absence is a property of the presented
/// solution alone.
///
/// So the admission test is made POSITIVE and is applied to the artifact the signature actually
/// commits to:
///
/// 1. The outer conditions must carry EXACTLY ONE `AGG_SIG_ME` ([`sole_agg_sig_me_message`]) — zero
///    binds no signature to this coin, more than one launders a blank cheque.
/// 2. That signature's message must be the tree hash of a QUOTED, solution-independent condition
///    list found inside the coin's own solution ([`committed_melt_conditions`]). This is what closes
///    the malleability break: a non-quote delegated puzzle is refused before its conditions are
///    trusted.
/// 3. Those COMMITTED conditions must contain exactly one `MELT_SINGLETON` and nothing outside the
///    melt allowlist ([`reject_non_melt_condition`], which denies every `CREATE_COIN`).
///
/// The melt marker is unobservable in the OUTER conditions — the singleton top layer consumes
/// `(51 () -113)` while morphing its inner puzzle's output — but it is plainly observable one layer
/// down, in the quoted delegated puzzle, which is precisely the artifact the signature commits to.
/// The outer-condition checks are kept as defence in depth, never as the admission test.
///
/// # Failing towards refusal
///
/// [`run_conditions`] decodes through `Vec::<Condition>::from_clvm`, which maps anything the SDK does
/// not model onto a catch-all rather than erroring — so any predicate phrased as "I saw no bad
/// condition" is broken by a lossy parser, and a `CREATE_COIN` encoding the SDK models more narrowly
/// than consensus does would read as a melt. Both condition passes here are default-DENY allowlists
/// and the melt marker must be positively COUNTED, so a condition this crate fails to model causes a
/// refusal, never an admission.
///
/// Every other singleton spend stays refused, and that distinction is the whole guard: an ordinary
/// store UPDATE or a DID TRANSFER recreates the singleton under a new owner puzzle hash, which is a
/// transfer of the profile's identity. Admitting the singleton CLASS would have made those signable
/// as a side effect. `a_singleton_spend_that_recreates_the_singleton_is_still_refused` holds that
/// line.
///
/// # The destroyed mojo is not recoverable, and that is not a defect
///
/// `(51 () -113)` occupies the one odd-amount `CREATE_COIN` a singleton may emit, so a melt that also
/// returned the mojo is unexpressible under the puzzle. It is accounted as an implicit fee, which is
/// what consensus does with it.
fn account_singleton_melt(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    spend: &CoinSpend,
    puzzle_ptr: clvmr::NodePtr,
    solution_ptr: clvmr::NodePtr,
) -> WalletResult<()> {
    // Defence in depth, never the admission test: what consensus does for the solution PRESENTED.
    let conditions = run_conditions(allocator, puzzle_ptr, solution_ptr)?;
    for condition in &conditions {
        reject_unexpected_agg_sig(condition)?;
        reject_non_melt_condition(condition, MeltConditionList::Presented)?;
    }

    // THE admission test, over the artifact the signature commits to rather than the one solution a
    // caller chose to present.
    let committed_message = sole_agg_sig_me_message(&conditions)?;
    let committed = committed_melt_conditions(allocator, solution_ptr, committed_message)?;

    let mut melt_markers = 0usize;
    for condition in &committed {
        reject_unexpected_agg_sig(condition)?;
        reject_non_melt_condition(condition, MeltConditionList::Signed)?;
        if matches!(condition, Condition::MeltSingleton(_)) {
            melt_markers += 1;
        }
    }
    if melt_markers != 1 {
        return Err(reject(format!(
            "the signed delegated puzzle carries {melt_markers} MELT_SINGLETON conditions, not \
             exactly one, so this signature does not authorize a terminal singleton spend; only a \
             melt is signable (an update or transfer re-homes the singleton, which is a change of \
             ownership no melt confirmation covers); refusing to sign"
        )));
    }

    // The melted coin's amount both enters the spend and is destroyed by it. Recording both sides
    // keeps the bundle's conservation equality exact rather than merely tolerant.
    ledger.xch_in = accumulate(ledger.xch_in, spend.coin.amount, "XCH input total")?;
    ledger.melted = accumulate(ledger.melted, spend.coin.amount, "melted total")?;
    // Name the destroyed lineage, not just its mojos: the review surface has no other way to show
    // that this bundle ends a DID or a dig-store (#3068).
    ledger.melted_singletons.push(spend.coin.coin_id());
    Ok(())
}

/// Account a standard-layer XCH send: enforce the sole-AGG_SIG_ME commitment, record its offer
/// binding, sum its `RESERVE_FEE`, and route each `CREATE_COIN` as an XCH output.
fn account_standard_send(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    spend: &CoinSpend,
    puzzle_ptr: clvmr::NodePtr,
    solution_ptr: clvmr::NodePtr,
) -> WalletResult<()> {
    let committed_message = committed_delegated_puzzle_message(allocator, solution_ptr)?;
    ledger.xch_in = accumulate(ledger.xch_in, spend.coin.amount, "XCH input total")?;
    let conditions = run_conditions(allocator, puzzle_ptr, solution_ptr)?;
    enforce_sole_agg_sig_me(&conditions, committed_message)?;
    // In an option TRANSFER a standard-layer XCH coin only ever appears as the OPTIONAL farmer-fee
    // coin the engine links to the singleton via `assert_concurrent_spend` (transfer itself takes
    // no fee). It legitimately commits no value to the settlement puzzle, so MR-6's
    // give-it-away-for-nothing binding does not apply — skip it in option mode. Only the strict
    // offer path requires MR-6. (Exercise never reaches here: its option-singleton melt/message
    // leg is refused fail-closed in the dispatch, at the signature source.) The binding is enforced
    // at the bundle level after the loop; an option-mode farmer-fee coin commits no value to
    // settlement (no sink), so it is inert in that pass.
    ledger.bindings.push(coin_binding(&spend.coin, &conditions));
    for condition in &conditions {
        reject_unexpected_agg_sig(condition)?;
        if let Some(reserve) = condition.as_reserve_fee() {
            ledger.fee = accumulate(ledger.fee, reserve.amount, "reserved fee total")?;
            continue;
        }
        if let Some(create) = condition.as_create_coin() {
            ledger.xch_out = accumulate(ledger.xch_out, create.amount, "XCH output total")?;
            route_output(
                &mut ledger.outputs,
                &mut ledger.protocol_sink,
                DecodedOutput {
                    puzzle_hash: create.puzzle_hash,
                    amount: create.amount,
                    asset_id: None,
                },
            );
        }
    }
    Ok(())
}

/// Account a settlement-payments (XCH) coin the wallet CLAIMS while taking/cancelling an offer: its
/// notarized-payment `CREATE_COIN`s become XCH outputs; spent by announcement, so there is no
/// signature to guard.
fn account_settlement_claim(
    ledger: &mut SpendLedger,
    allocator: &mut Allocator,
    spend: &CoinSpend,
    puzzle_ptr: clvmr::NodePtr,
    solution_ptr: clvmr::NodePtr,
) -> WalletResult<()> {
    ledger.xch_in = accumulate(ledger.xch_in, spend.coin.amount, "XCH input total")?;
    let conditions = run_conditions(allocator, puzzle_ptr, solution_ptr)?;
    reject_any_agg_sig(&conditions)?;
    for condition in &conditions {
        if let Some(create) = condition.as_create_coin() {
            ledger.xch_out = accumulate(ledger.xch_out, create.amount, "XCH output total")?;
            route_output(
                &mut ledger.outputs,
                &mut ledger.protocol_sink,
                DecodedOutput {
                    puzzle_hash: create.puzzle_hash,
                    amount: create.amount,
                    asset_id: None,
                },
            );
        }
    }
    Ok(())
}

/// True when `coin_spends` contain an option-layer coin — an option singleton ([`OptionContract`]) or a
/// locked-underlying 1-of-2 ([`P2OneOfManyLayer`]) — so [`analyze`] should use option-mode conservation.
///
/// This is a read-only pre-scan: a coin whose bytes don't parse (or don't parse as an option layer) is
/// simply not an option coin here; the main [`analyze`] loop re-parses every coin and fails closed on
/// anything it cannot fully account for, so a parse quirk in this scan can never let a spend through.
fn is_option_bundle(allocator: &mut Allocator, coin_spends: &[CoinSpend]) -> WalletResult<bool> {
    for spend in coin_spends {
        let Ok(puzzle_ptr) = node_from_bytes(allocator, &spend.puzzle_reveal) else {
            continue;
        };
        let Ok(solution_ptr) = node_from_bytes(allocator, &spend.solution) else {
            continue;
        };
        let puzzle = Puzzle::parse(allocator, puzzle_ptr);
        if matches!(
            OptionContract::parse(allocator, spend.coin, puzzle, solution_ptr),
            Ok(Some(_))
        ) || matches!(
            P2OneOfManyLayer::parse_puzzle(allocator, puzzle),
            Ok(Some(_))
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Re-derive the human-facing [`TransactionSummary`] from `coin_spends` alone — a KEY-FREE,
/// NON-AUTHORITATIVE display view.
///
/// With no keys it cannot split recipients from change, so it renders EVERY created output as egress
/// (conservative — it NEVER drops a non-owned coin, unlike the old memo heuristic that could hide an
/// un-hinted non-owned egress). It therefore OVER-lists: a spend's own change coins appear as egress
/// too. The AUTHORITATIVE, key-aware view is
/// [`LocalSigner::reviewable_summary`](super::signer::LocalSigner::reviewable_summary), which drops
/// wallet-owned change. Never use `derive_summary` ahead of signing — it is display-only.
pub fn derive_summary(coin_spends: &[CoinSpend]) -> WalletResult<TransactionSummary> {
    let effect = analyze(coin_spends)?;
    summarize_egress(
        &effect.outputs,
        &effect.protocol_sink,
        effect.fee,
        &effect.melted_singletons,
        &effect.nft_operations,
    )
}

/// Render the outputs LEAVING the wallet — `egress` (to real addresses) plus `protocol_sink` (to a
/// consensus-enforced settlement structure) — and the fee, as a [`TransactionSummary`] a human
/// reviews. Shared by the key-free [`derive_summary`] (which passes ALL of `effect.outputs` as egress)
/// and the signer's key-aware summary (which passes only the not-owned outputs), so both encode
/// addresses + asset ids identically.
///
/// A `protocol_sink` output is rendered with an EMPTY address: its destination is the fixed settlement
/// puzzle, not a chosen recipient, so there is no meaningful address to show — the offer builders emit
/// the offered/paid assets the same way, and the signer's summary gate compares these by amount+asset,
/// never by address (#1511 PR-B).
pub fn summarize_egress(
    egress: &[DecodedOutput],
    protocol_sink: &[DecodedOutput],
    fee: u64,
    melted_singletons: &[Bytes32],
    nft_operations: &[NftOperation],
) -> WalletResult<TransactionSummary> {
    let mut outputs = egress
        .iter()
        .map(|output| {
            Ok(SpendOutput {
                address: encode_xch_address(output.puzzle_hash)?,
                amount: Amount(output.amount),
                asset_id: output.asset_id.map(|asset| AssetId(hex::encode(asset))),
            })
        })
        .collect::<WalletResult<Vec<_>>>()?;
    // A zero-value settlement output is an announcement CARRIER (a take creates one to bind the
    // offered coins), not value leaving the wallet — omit it so the reviewed summary lists only real
    // egress.
    outputs.extend(
        protocol_sink
            .iter()
            .filter(|output| output.amount > 0)
            // An EMPTY address marks this as a protocol sink, not a recipient
            // (see `SpendOutput::is_protocol_sink`); the read-back gate matches these by
            // amount + asset only.
            .map(|output| SpendOutput {
                address: Address(String::new()),
                amount: Amount(output.amount),
                asset_id: output.asset_id.map(|asset| AssetId(hex::encode(asset))),
            }),
    );
    Ok(TransactionSummary {
        outputs,
        // The received leg is not re-derivable from coin spends (a make binds the requested payment
        // as a non-invertible settlement-announcement hash, not a readable output), so the key-free /
        // key-aware re-derivation leaves it empty; the engine-declared received leg is surfaced by the
        // review renderer from the reviewed spend's own summary (#2241).
        received: Vec::new(),
        fee: Amount(fee),
        // Destruction is egress of a kind no address can express, so it travels as its own field
        // rather than as an output line the recipient gate would then have to except.
        melted_singletons: melted_singletons.iter().map(hex::encode).collect(),
        // An NFT action is worth ~0 mojos, so like destruction it travels as its own field rather
        // than as an output line the recipient gate would then have to except. Rendered through
        // `NftOperation::describe` — the SAME function the confirm screen uses — so the sentence a
        // human approves and the sentence the gate compares can never drift apart.
        nft_operations: nft_operations
            .iter()
            .map(|operation| operation.describe())
            .collect::<WalletResult<Vec<_>>>()?,
    })
}

/// Run a puzzle against its solution and decode the output condition list, fail-closed.
fn run_conditions(
    allocator: &mut Allocator,
    puzzle: clvmr::NodePtr,
    solution: clvmr::NodePtr,
) -> WalletResult<Vec<Condition>> {
    let output = run_puzzle(allocator, puzzle, solution)
        .map_err(|e| reject(format!("puzzle failed to run: {e:?}")))?;
    Vec::<Condition>::from_clvm(allocator, output)
        .map_err(|e| reject(format!("undecodable conditions: {e:?}")))
}

/// Route a decoded output into one of the two buckets (#1511 PR-B, #2239): a `CREATE_COIN` to a
/// recognized canonical structural puzzle (settlement / launcher) is a [`SpendEffect::protocol_sink`]
/// — the sanctioned egress of an offered/paid asset; everything else is an ordinary output added
/// UNDIVIDED to [`SpendEffect::outputs`] (the recipient-vs-change split is key-relative and deferred
/// to the key-holding consumer). Routing on the DESTINATION HASH (never on a caller-chosen flag or a
/// memo) is what stops a plain payment to an attacker being mislabelled as a benign sink (MR-3/MR-5).
fn route_output(
    outputs: &mut Vec<DecodedOutput>,
    protocol_sink: &mut Vec<DecodedOutput>,
    output: DecodedOutput,
) {
    if is_protocol_sink_hash(output.puzzle_hash) {
        protocol_sink.push(output);
    } else {
        outputs.push(output);
    }
}

/// True when `conditions` carry at least one ANNOUNCEMENT assertion — the binding that ties a coin's
/// settlement egress to a value-carrying counter-payment (#1511 MR-6, #2241).
///
/// Only the announcement-assertion kinds ([`Condition::AssertPuzzleAnnouncement`] /
/// [`Condition::AssertCoinAnnouncement`]) count as an offer binding, because ONLY they can bind the
/// egress to a specific requested payment: a genuine make asserts the requested payment's settlement
/// PUZZLE announcement (its notarized-payment tree hash), and a genuine take asserts the maker offered
/// COINS' announcement. Concurrent-spend / concurrent-puzzle assertions
/// (`AssertConcurrentSpend`/`AssertConcurrentPuzzle`) do NOT count as a binding on their own: they
/// bind spend CONCURRENCY (that some other coin is co-spent) but say nothing about the VALUE received
/// in return. They still MATTER — at the bundle level ([`enforce_bundle_settlement_binding`]) they are
/// the ring that ties a make's non-announcement offered coins to the one coin that DOES carry the
/// announcement — but the tie must always terminate at an announcement.
fn has_offer_binding_assertion(conditions: &[Condition]) -> bool {
    conditions.iter().any(|condition| {
        matches!(
            condition,
            Condition::AssertPuzzleAnnouncement(_) | Condition::AssertCoinAnnouncement(_)
        )
    })
}

/// The offer-binding facts gathered from ONE wallet-signed coin, for the bundle-level MR-6 pass
/// (#2241). A `dig-offers` make binds the requested payment with an announcement on exactly ONE
/// offered coin, then rings ALL offered coins together with concurrency assertions, so the binding
/// can only be judged over the whole bundle — never per coin.
struct CoinBinding {
    /// This coin's id — the target other coins reference in an `AssertConcurrentSpend`.
    coin_id: Bytes32,
    /// This coin's puzzle hash — the target other coins reference in an `AssertConcurrentPuzzle`.
    puzzle_hash: Bytes32,
    /// The coin spends value INTO the settlement puzzle (an offered/paid leg that must be bound).
    creates_sink: bool,
    /// The coin itself carries an announcement assertion (see [`has_offer_binding_assertion`]).
    carries_announcement: bool,
    /// Coin ids this coin asserts are co-spent (`AssertConcurrentSpend`) — edges to follow.
    requires_coin_ids: Vec<Bytes32>,
    /// Puzzle hashes this coin asserts are co-spent (`AssertConcurrentPuzzle`) — edges to follow.
    requires_puzzle_hashes: Vec<Bytes32>,
}

/// Gather the [`CoinBinding`] facts for one wallet-signed coin from its coin + run conditions.
fn coin_binding(coin: &chia_protocol::Coin, conditions: &[Condition]) -> CoinBinding {
    let mut binding = CoinBinding {
        coin_id: coin.coin_id(),
        puzzle_hash: coin.puzzle_hash,
        creates_sink: false,
        carries_announcement: has_offer_binding_assertion(conditions),
        requires_coin_ids: Vec::new(),
        requires_puzzle_hashes: Vec::new(),
    };
    for condition in conditions {
        match condition {
            Condition::AssertConcurrentSpend(assertion) => {
                binding.requires_coin_ids.push(assertion.coin_id);
            }
            Condition::AssertConcurrentPuzzle(assertion) => {
                binding.requires_puzzle_hashes.push(assertion.puzzle_hash);
            }
            _ => {}
        }
        if let Some(create) = condition.as_create_coin() {
            if is_protocol_sink_hash(create.puzzle_hash) {
                binding.creates_sink = true;
            }
        }
    }
    binding
}

/// Enforce MR-6 at the BUNDLE level (#2241, reworked from the per-coin check). The security property
/// is "no settlement-sink egress may occur without the requested-payment binding being enforced
/// ATOMICALLY in the same bundle". A `dig-offers` make binds the requested payment with an
/// announcement on exactly ONE offered coin, then rings ALL offered coins together with
/// `AssertConcurrentSpend`/`AssertConcurrentPuzzle` so no offered coin can reach the chain without the
/// others — the binding coin and every offered sink stand or fall as one.
///
/// A settlement sink is ACCEPTED iff it is tied to a requested-payment binding: it carries an
/// announcement itself, OR it is transitively co-spend-tied (through the concurrency ring) to a coin
/// that does. It is REFUSED iff a sink coin is NEITHER — the real unbound-egress attack: a coin that
/// could be peeled off and given away for nothing. (When the bundle carries no announcement at all,
/// no sink can be tied, so every sink is refused — the give-it-away case the per-coin check caught.)
///
/// The per-coin check this replaces over-refused a legitimate MULTI-offered-coin make (offer XCH + a
/// CAT, or two distinct CATs): only one offered coin carries the announcement, so the others — tied
/// only by concurrency — were wrongly rejected. Judging at the bundle level accepts them while still
/// refusing any sink that is not tied to a binding.
fn enforce_bundle_settlement_binding(bindings: &[CoinBinding]) -> WalletResult<()> {
    // Index the coins so a concurrency assertion (by coin id or puzzle hash) resolves to the coin(s)
    // it requires be co-spent.
    let mut by_coin_id: HashMap<Bytes32, usize> = HashMap::new();
    let mut by_puzzle_hash: HashMap<Bytes32, Vec<usize>> = HashMap::new();
    for (index, binding) in bindings.iter().enumerate() {
        by_coin_id.insert(binding.coin_id, index);
        by_puzzle_hash
            .entry(binding.puzzle_hash)
            .or_default()
            .push(index);
    }

    for (index, binding) in bindings.iter().enumerate() {
        if binding.creates_sink
            && !tied_to_announcement(index, bindings, &by_coin_id, &by_puzzle_hash)
        {
            return Err(reject(
                "a coin commits value to settlement with no offer-binding announcement reachable \
                 through the bundle's concurrency ring (give-it-away-for-nothing); refusing to sign",
            ));
        }
    }
    Ok(())
}

/// True when the coin at `start` is bound to a requested payment: it carries an announcement itself,
/// or it is transitively co-spend-tied to a coin that does. Following the "requires this coin be
/// co-spent" edges (`AssertConcurrentSpend`/`AssertConcurrentPuzzle`) proves the start coin cannot
/// reach the chain unless the announcement-bearing coin is also spent — the atomic binding.
fn tied_to_announcement(
    start: usize,
    bindings: &[CoinBinding],
    by_coin_id: &HashMap<Bytes32, usize>,
    by_puzzle_hash: &HashMap<Bytes32, Vec<usize>>,
) -> bool {
    let mut visited = vec![false; bindings.len()];
    let mut stack = vec![start];
    while let Some(index) = stack.pop() {
        if std::mem::replace(&mut visited[index], true) {
            continue;
        }
        let binding = &bindings[index];
        if binding.carries_announcement {
            return true;
        }
        for coin_id in &binding.requires_coin_ids {
            if let Some(&next) = by_coin_id.get(coin_id) {
                stack.push(next);
            }
        }
        for puzzle_hash in &binding.requires_puzzle_hashes {
            if let Some(indices) = by_puzzle_hash.get(puzzle_hash) {
                stack.extend(indices.iter().copied());
            }
        }
    }
    false
}

/// The seven non-`AGG_SIG_ME` signature-condition variants — `AGG_SIG_UNSAFE` (raw attacker-chosen
/// message) plus the six Parent/Puzzle/Amount-scoped families. This is the single source of truth for
/// "an agg_sig condition that a legitimate standard/CAT/settlement spend never emits"; both
/// fail-closed guards ([`reject_any_agg_sig`] and [`reject_unexpected_agg_sig`]) route through it so
/// the forbidden set can never drift between the two. It deliberately EXCLUDES `AGG_SIG_ME`: whether
/// an `AGG_SIG_ME` is permitted depends on the caller's class (a settlement coin forbids it too; a
/// standard send permits exactly one), so each guard decides that separately.
fn is_non_me_agg_sig(condition: &Condition) -> bool {
    matches!(
        condition,
        Condition::AggSigUnsafe(_)
            | Condition::AggSigParent(_)
            | Condition::AggSigPuzzle(_)
            | Condition::AggSigAmount(_)
            | Condition::AggSigPuzzleAmount(_)
            | Condition::AggSigParentAmount(_)
            | Condition::AggSigParentPuzzle(_)
    )
}

/// A claimed settlement-layer coin is spent by ANNOUNCEMENT and carries no signature; the immutable
/// settlement puzzle emits only `CREATE_COIN` + announcement conditions. Any `AGG_SIG_*` in its run
/// conditions is therefore anomalous — refuse fail-closed rather than account a coin whose spend would
/// silently require a signature the taker never reviewed (defense-in-depth; the canonical puzzle
/// cannot emit one, so this only ever fires on a corrupted decode).
fn reject_any_agg_sig(conditions: &[Condition]) -> WalletResult<()> {
    let has_agg_sig = conditions
        .iter()
        .any(|condition| condition.as_agg_sig_me().is_some() || is_non_me_agg_sig(condition));
    if has_agg_sig {
        return Err(reject(
            "a claimed settlement coin carries an AGG_SIG condition; refusing to sign",
        ));
    }
    Ok(())
}

/// The AGG_SIG_ME message a standard-layer coin's signature MUST commit to — `sha256tree` of its
/// delegated puzzle — returned ONLY after proving that puzzle is the canonical QUOTED,
/// solution-independent form `(q . conditions)` (CLVM quote, opcode `1`, #1058 CRITICAL#3).
///
/// The `p2_delegated_puzzle_or_hidden_puzzle` standard layer signs
/// `sha256tree(delegated_puzzle) || coin_id || genesis` — it commits to the delegated puzzle's TREE
/// HASH and the coin, but NOT to the delegated puzzle's SOLUTION. If the delegated puzzle were
/// solution-malleable (e.g. an echo program that returns its solution as the condition list), the
/// SAME signed message would authorize DIFFERENT outputs for different solutions — a reusable
/// blank-check signature over the coin. Only when the delegated puzzle is a bare quote does
/// `sha256tree(delegated_puzzle)` fully commit to the exact conditions, making "the value flow
/// `analyze` verified" identical to "what the signature authorizes". The SDK's
/// `StandardLayer::spend_with_conditions` always emits `clvm_quote!(conditions)`, so legitimate
/// sends pass; anything else is refused fail-closed BEFORE the conditions are trusted.
///
/// The returned 32-byte tree hash is the exact message the coin's sole AGG_SIG_ME MUST carry (the
/// standard puzzle emits `(AGG_SIG_ME synthetic_key sha256tree(delegated_puzzle))`); the caller
/// enforces that with [`enforce_sole_agg_sig_me`] (#1519).
fn committed_delegated_puzzle_message(
    allocator: &Allocator,
    standard_solution: clvmr::NodePtr,
) -> WalletResult<[u8; 32]> {
    Ok(committed_standard_spend(allocator, standard_solution)?.message)
}

/// The delegated puzzle a standard-layer solution commits to: both its signed tree-hash MESSAGE and
/// the CONDITIONS it quotes.
///
/// [`committed_delegated_puzzle_message`] needs only the message, because for a plain XCH/CAT send
/// the coin's OUTER run conditions ARE the delegated puzzle's conditions. That equivalence does not
/// hold under a layer stack that MORPHS its inner puzzle's output: the NFT state layer CONSUMES an
/// `UPDATE_NFT_METADATA` while re-emitting the rest, so a metadata update is invisible in the outer
/// conditions and a re-home is all that remains to see. An arm that must bound WHICH act it admits
/// therefore has to read the quoted list itself — which is also the list the signature commits to,
/// so nothing is lost by preferring it.
struct CommittedStandardSpend {
    /// `sha256tree(delegated_puzzle)` — the exact message the coin's sole `AGG_SIG_ME` must carry.
    message: [u8; 32],
    /// The conditions the quoted delegated puzzle commits to, for every solution.
    conditions: Vec<Condition>,
}

/// Prove a standard-layer solution's delegated puzzle is the canonical QUOTE form and return what it
/// commits to (#1058 CRITICAL#3).
///
/// The quote check is the whole point and is done BEFORE the conditions are trusted: the standard
/// layer signs `sha256tree(delegated_puzzle) || coin_id || genesis`, which commits to the delegated
/// puzzle's TREE HASH but NOT to its SOLUTION. A solution-malleable delegated puzzle — an echo
/// program that returns its own solution — therefore turns one signature into a reusable blank
/// cheque over the coin, emitting an innocuous re-home under the solution presented for review and
/// an attacker's `CREATE_COIN` under a replay of the same signature. Only a bare quote makes
/// `sha256tree(delegated_puzzle)` pin the conditions, so that "what this spend does" and "what this
/// signature authorizes" are the same object.
fn committed_standard_spend(
    allocator: &Allocator,
    standard_solution: clvmr::NodePtr,
) -> WalletResult<CommittedStandardSpend> {
    let solution = StandardLayer::parse_solution(allocator, standard_solution)
        .map_err(|e| reject(format!("malformed standard-layer solution: {e:?}")))?;
    // A quote is a pair whose first element is the atom `1`.
    let clvmr::SExp::Pair(quote_op, quoted_conditions) = allocator.sexp(solution.delegated_puzzle)
    else {
        return Err(reject(
            "delegated puzzle is not quote-form (not a pair) — signature would not commit to outputs",
        ));
    };
    if allocator.small_number(quote_op) != Some(1) {
        return Err(reject(
            "delegated puzzle is not the canonical quote form — signature would not commit to outputs",
        ));
    }
    Ok(CommittedStandardSpend {
        message: tree_hash(allocator, solution.delegated_puzzle).to_bytes(),
        conditions: Vec::<Condition>::from_clvm(allocator, quoted_conditions)
            .map_err(|e| reject(format!("undecodable signed delegated conditions: {e:?}")))?,
    })
}

/// Enforce that a standard-layer coin's run conditions carry EXACTLY ONE `AGG_SIG_ME` and that it
/// commits to `expected_message` — `sha256tree(delegated_puzzle)`, from
/// [`committed_delegated_puzzle_message`] (#1519).
///
/// A legitimate standard/CAT send is authorized by precisely one signature: the per-coin
/// standard-layer `AGG_SIG_ME` the `p2_delegated_puzzle_or_hidden_puzzle` puzzle emits over the
/// delegated puzzle's tree hash. Three anomalies are refused fail-closed here, because each severs
/// "the value flow `analyze` verified" from "what the signature authorizes":
///
/// - **Zero `AGG_SIG_ME`** — nothing binds a signature to this coin; the spend the human reviewed is
///   not the thing being authorized.
/// - **More than one `AGG_SIG_ME`** — a delegated puzzle may emit an EXTRA `AGG_SIG_ME` over an
///   attacker-chosen message for the SAME wallet key, laundering a blank-check signature for another
///   coin through this benign carrier (the extra ME shares the coin's genesis/coin-id binding, so
///   the signer's per-message suffix check alone would not catch it).
/// - **A wrong-hash `AGG_SIG_ME`** — a single ME whose message is NOT the committed delegated-puzzle
///   hash signs something other than the conditions `analyze` accounted for.
fn enforce_sole_agg_sig_me(
    conditions: &[Condition],
    expected_message: [u8; 32],
) -> WalletResult<()> {
    if sole_agg_sig_me_message(conditions)? != expected_message {
        return Err(reject(
            "AGG_SIG_ME does not commit to the delegated-puzzle hash the outputs derive from \
             (refusing to sign)",
        ));
    }
    Ok(())
}

/// The 32-byte message of a spend's ONE `AGG_SIG_ME`, refusing zero, several, or a malformed one.
///
/// The zero and several cases are the first two anomalies [`enforce_sole_agg_sig_me`] documents,
/// factored out for the arms that must READ the committed message rather than compare it to a
/// message they derived structurally. A melt is such an arm: its delegated puzzle sits under layer
/// stacks (a `DidLayer`, the DataLayer metadata layers) this crate deliberately does not model, so
/// the committed hash is recovered from the signature itself and then proven against the solution
/// (see [`committed_melt_conditions`]).
fn sole_agg_sig_me_message(conditions: &[Condition]) -> WalletResult<[u8; 32]> {
    let mut agg_sig_me = conditions.iter().filter_map(Condition::as_agg_sig_me);
    let Some(sole) = agg_sig_me.next() else {
        return Err(reject(
            "no AGG_SIG_ME condition — nothing binds a signature to this coin (refusing to sign)",
        ));
    };
    if agg_sig_me.next().is_some() {
        return Err(reject(
            "more than one AGG_SIG_ME condition in a send spend (possible blank-check laundering)",
        ));
    }
    sole.message.as_ref().try_into().map_err(|_| {
        reject(
            "AGG_SIG_ME message is not a 32-byte delegated-puzzle hash, so it cannot commit to any \
             condition list (refusing to sign)",
        )
    })
}

/// The conditions a singleton melt's signature ACTUALLY authorizes: the quoted, solution-independent
/// condition list whose tree hash is `committed_message` (dig_ecosystem#3068).
///
/// The melt arm cannot reach its delegated puzzle the way [`account_option_transfer`] does — that
/// walks a known layer stack down to a [`StandardLayer`] solution, and a DIG singleton's inner stack
/// (a `DidLayer`, the DataLayer metadata layers) is deliberately outside this crate's knowledge. So
/// the delegated puzzle is identified by PREIMAGE instead: the sole `AGG_SIG_ME` names the tree hash
/// the signature commits to, and the subtree of the coin's own solution that hashes to it IS that
/// delegated puzzle, by collision resistance — no layer knowledge required, and nothing to keep in
/// sync as new DIG layers appear.
///
/// Finding it is not enough; it must be the canonical QUOTE form `(q . conditions)`, exactly as
/// [`committed_delegated_puzzle_message`] requires of every other signed arm and for the same reason:
/// only then does the signed tree hash pin the conditions, making "what this spend does" identical to
/// "what this signature authorizes" for every solution, not just the one presented.
fn committed_melt_conditions(
    allocator: &Allocator,
    solution: clvmr::NodePtr,
    committed_message: [u8; 32],
) -> WalletResult<Vec<Condition>> {
    let Some(delegated_puzzle) =
        find_subtree_by_tree_hash(allocator, solution, committed_message, 0)
    else {
        return Err(reject(
            "the singleton melt's AGG_SIG_ME commits to a hash that appears nowhere in the coin's \
             solution, so the conditions it authorizes cannot be recovered or checked; refusing \
             to sign",
        ));
    };
    let clvmr::SExp::Pair(quote_op, quoted_conditions) = allocator.sexp(delegated_puzzle) else {
        return Err(reject(
            "the singleton melt's signed delegated puzzle is not quote-form (not a pair), so the \
             signature would authorize different outputs under a different solution; refusing to \
             sign",
        ));
    };
    if allocator.small_number(quote_op) != Some(1) {
        return Err(reject(
            "the singleton melt's signed delegated puzzle is not the canonical quote form, so the \
             signature would authorize different outputs under a different solution; refusing to \
             sign",
        ));
    }
    Vec::<Condition>::from_clvm(allocator, quoted_conditions)
        .map_err(|e| reject(format!("undecodable signed melt conditions: {e:?}")))
}

/// The deepest solution nesting [`find_subtree_by_tree_hash`] will search before refusing.
///
/// The search recurses, so an unbounded depth would let a caller-supplied solution overflow the
/// stack — a caller-triggerable abort in a custody path. Exceeding the bound yields no match and
/// therefore a REFUSAL, and no honest melt comes close: a real DIG store or DID melt solution nests
/// a little over a dozen deep.
const MAX_SOLUTION_SEARCH_DEPTH: usize = 256;

/// The subtree of `node` whose `sha256tree` is `target`, or `None` if there is none within
/// [`MAX_SOLUTION_SEARCH_DEPTH`].
fn find_subtree_by_tree_hash(
    allocator: &Allocator,
    node: clvmr::NodePtr,
    target: [u8; 32],
    depth: usize,
) -> Option<clvmr::NodePtr> {
    if tree_hash(allocator, node).to_bytes() == target {
        return Some(node);
    }
    if depth >= MAX_SOLUTION_SEARCH_DEPTH {
        return None;
    }
    let clvmr::SExp::Pair(first, rest) = allocator.sexp(node) else {
        return None;
    };
    find_subtree_by_tree_hash(allocator, first, target, depth + 1)
        .or_else(|| find_subtree_by_tree_hash(allocator, rest, target, depth + 1))
}

/// Which of a melt's two condition lists is being judged.
///
/// The lists differ in exactly one opcode, and the difference is structural rather than a matter of
/// taste: the `p2_delegated_puzzle_or_hidden_puzzle` layer emits the coin's `AGG_SIG_ME` ITSELF,
/// outside the delegated puzzle. So it is expected in the PRESENTED list and is never honest in the
/// SIGNED one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MeltConditionList {
    /// What the coin emits under the solution the caller presented — defence in depth.
    Presented,
    /// What the quoted delegated puzzle commits to — the admission test.
    Signed,
}

/// Default-DENY allowlist for a TERMINAL singleton melt's conditions (dig_ecosystem#3068), applied
/// both to the outer run conditions (defence in depth) and to the SIGNED quoted ones (the admission
/// test).
///
/// `AGG_SIG_ME` is admitted only in the [`MeltConditionList::Presented`] list, where the p2 layer
/// puts it. Inside the SIGNED quoted list it is a blank cheque for a second delegated puzzle on the
/// same coin — the committed pass counts only `MELT_SINGLETON`, so `[MELT_SINGLETON, AGG_SIG_ME]`
/// would otherwise satisfy the admission test while authorizing arbitrary other conditions one layer
/// in. Today that case happens to make the OUTER `AGG_SIG_ME` count 2 and trip
/// [`sole_agg_sig_me_message`] — but that rests on the exact layer behaviour this arm declares it
/// does not model, which is the dependency the whole fix exists to remove. Refusing it directly
/// costs an honest melt nothing.
///
/// A melt ends a lineage: it destroys the singleton and creates nothing. So EVERY `CREATE_COIN` is
/// refused here — not merely the odd-amount re-home — which makes the guard immune to a
/// `CREATE_COIN` encoding this crate's decoder models more narrowly than consensus does. The melt
/// marker itself is a `MELT_SINGLETON`, positively counted by the caller, never a `CREATE_COIN`.
///
/// Fail-CLOSED by construction: an unrecognized opcode (including anything the SDK maps to its
/// catch-all) is REFUSED, so a condition this crate cannot model can never ride a deletion the human
/// approved.
fn reject_non_melt_condition(condition: &Condition, list: MeltConditionList) -> WalletResult<()> {
    if matches!(condition, Condition::AggSigMe(_)) {
        return match list {
            MeltConditionList::Presented => Ok(()),
            MeltConditionList::Signed => Err(reject(
                "the singleton melt's SIGNED delegated puzzle carries its own AGG_SIG_ME, which no \
                 honest melt does (the standard layer emits that condition outside the delegated \
                 puzzle); it would authorize a second delegated puzzle on this coin; refusing to \
                 sign",
            )),
        };
    }
    let permitted = matches!(
        condition,
        // The melt marker itself.
        Condition::MeltSingleton(_)
            // Benign timelock assertions.
            | Condition::AssertSecondsAbsolute(_)
            | Condition::AssertSecondsRelative(_)
            | Condition::AssertHeightAbsolute(_)
            | Condition::AssertHeightRelative(_)
            | Condition::AssertBeforeSecondsAbsolute(_)
            | Condition::AssertBeforeSecondsRelative(_)
            | Condition::AssertBeforeHeightAbsolute(_)
            | Condition::AssertBeforeHeightRelative(_)
            // Benign announcement/concurrency ASSERTIONS (never the CREATE side): dig-account rings
            // a melt to the coin paying its network fee.
            | Condition::AssertCoinAnnouncement(_)
            | Condition::AssertPuzzleAnnouncement(_)
            | Condition::AssertConcurrentSpend(_)
            | Condition::AssertConcurrentPuzzle(_)
            // Benign self-introspection assertions — a real melt emits two of these.
            | Condition::AssertMyCoinId(_)
            | Condition::AssertMyParentId(_)
            | Condition::AssertMyPuzzleHash(_)
            | Condition::AssertMyAmount(_)
            | Condition::AssertMyBirthSeconds(_)
            | Condition::AssertMyBirthHeight(_)
            | Condition::AssertEphemeral(_)
    );
    if !permitted {
        return Err(reject(
            "singleton melt emits a condition outside the melt allowlist (an output, a reserved \
             fee, an announcement, or an unknown opcode); only a TERMINAL singleton spend is \
             signable; refusing to sign",
        ));
    }
    Ok(())
}

/// Defense-in-depth (#1058): a standard-XCH/CAT send's only legitimate signature requirement is the
/// per-coin standard-layer `AGG_SIG_ME`. Any OTHER agg_sig condition emitted by a coin's delegated
/// puzzle — `AGG_SIG_UNSAFE` (raw attacker-chosen message) or the Parent/Puzzle/Amount/… families —
/// is anomalous in these classes and could smuggle a drain authorization for another coin; reject it
/// fail-closed. `AGG_SIG_ME` is permitted (the signer re-derives + signs exactly those). This mirrors
/// the kind filter in the signer, one layer earlier.
fn reject_unexpected_agg_sig(condition: &Condition) -> WalletResult<()> {
    if is_non_me_agg_sig(condition) {
        return Err(reject(
            "unexpected non-AGG_SIG_ME signature condition in a send spend (refusing to sign)",
        ));
    }
    Ok(())
}

/// Default-DENY allowlist for an option TRANSFER's delegated-puzzle conditions (Case-A guard, #1511
/// PR-C). A transfer is signable precisely because it touches only the inner standard layer to
/// RE-HOME the singleton; the only conditions a legitimate transfer emits are the re-home
/// `CREATE_COIN`, its sole `AGG_SIG_ME`, and benign timelock/announcement/self assertions.
///
/// This is fail-CLOSED by construction — an UNRECOGNIZED opcode is REFUSED, not waved through — so a
/// future/unknown condition cannot smuggle unsignable behaviour into a transfer. In particular it
/// refuses the mode-23 exercise `SEND_MESSAGE`/`RECEIVE_MESSAGE` (which, paired with the singleton
/// MELT, is what unlocks the option underlying — SDK `option_contract.rs::test_incomplete_exercise`
/// proves the message ⟺ melt coupling is consensus-enforced), the `MeltSingleton`, and any
/// `CREATE_COIN_ANNOUNCEMENT`/`CREATE_PUZZLE_ANNOUNCEMENT`. Thus a transfer signature can never carry
/// the exercise message even inside a mixed spend. (`CreateCoin` + `AggSigMe` are permitted here and
/// accounted/enforced by the caller — the single-re-home count + sole-AGG_SIG_ME checks.)
fn reject_non_transfer_condition(condition: &Condition) -> WalletResult<()> {
    let permitted = matches!(
        condition,
        // The re-home output + its authorizing signature — accounted by the caller.
        Condition::CreateCoin(_)
            | Condition::AggSigMe(_)
            // Benign timelock assertions.
            | Condition::AssertSecondsAbsolute(_)
            | Condition::AssertSecondsRelative(_)
            | Condition::AssertHeightAbsolute(_)
            | Condition::AssertHeightRelative(_)
            | Condition::AssertBeforeSecondsAbsolute(_)
            | Condition::AssertBeforeSecondsRelative(_)
            | Condition::AssertBeforeHeightAbsolute(_)
            | Condition::AssertBeforeHeightRelative(_)
            // Benign announcement/concurrency ASSERTIONS (never the CREATE side).
            | Condition::AssertCoinAnnouncement(_)
            | Condition::AssertPuzzleAnnouncement(_)
            | Condition::AssertConcurrentSpend(_)
            | Condition::AssertConcurrentPuzzle(_)
            // Benign self-introspection assertions.
            | Condition::AssertMyCoinId(_)
            | Condition::AssertMyParentId(_)
            | Condition::AssertMyPuzzleHash(_)
            | Condition::AssertMyAmount(_)
            | Condition::AssertMyBirthSeconds(_)
            | Condition::AssertMyBirthHeight(_)
            | Condition::AssertEphemeral(_)
    );
    if !permitted {
        return Err(reject(
            "option transfer delegated puzzle emits a condition outside the transfer allowlist \
             (exercise message, melt, announcement, or an unknown opcode); refusing to sign",
        ));
    }
    Ok(())
}

/// Encode a puzzle hash as an `xch1…` bech32m address (the display form recipients are shown in).
fn encode_xch_address(puzzle_hash: Bytes32) -> WalletResult<Address> {
    Bech32Address::new(puzzle_hash, "xch".into())
        .encode()
        .map(Address)
        .map_err(|e| reject(format!("cannot encode recipient address: {e:?}")))
}

/// A [`WalletErrorCode::SpendValidationFailed`] — the fail-closed verdict for anything this module
/// cannot fully account for.
fn reject(message: impl Into<String>) -> WalletError {
    WalletError::new(WalletErrorCode::SpendValidationFailed, message)
}

/// Add `amount` to a running value total, refusing the spend if the sum is not representable.
///
/// # Why this is not an ordinary overflow (#1708)
/// Both operands are attacker-reachable: input amounts come from a caller-supplied unsigned
/// skeleton whose coins need not exist on chain, and OUTPUT amounts come from `CREATE_COIN`
/// conditions the puzzle emits, so they are bounded by nothing at all. A wrapped total is not
/// merely a wrong number — [`analyze`] compares these totals to decide whether value is
/// CONSERVED, so `u64::MAX + 1_001` wrapping to `1_000` makes a spend that creates more than
/// `u64::MAX` mojos look exactly like a conserving `1_000`-mojo transfer.
///
/// Neither of the two tempting shortcuts is acceptable here:
/// - wrapping/`saturating_add` fails **open** — it manufactures a representable total for an
///   unrepresentable spend, which is precisely the bypass;
/// - a bare `+=` fails by **panicking** in debug builds, a caller-triggerable abort in a custody
///   path.
///
/// So an unrepresentable total is a deterministic, fail-closed refusal
/// ([`WalletErrorCode::SpendValidationFailed`], the catalogued code for "this spend did not pass
/// pre-broadcast validation"). No honest Chia spend approaches this bound: the entire XCH supply
/// is roughly three orders of magnitude below `u64::MAX` mojos.
fn accumulate(total: u64, amount: u64, what: &str) -> WalletResult<u64> {
    total.checked_add(amount).ok_or_else(|| {
        reject(format!(
            "{what} exceeds u64::MAX and so cannot be totalled; refusing to sign a spend whose \
             value conservation cannot be decided"
        ))
    })
}

#[cfg(all(test, feature = "engine"))]
mod tests {
    use super::*;
    use crate::engine::build::{SdkSpendBuilder, SpendBuilder, SpendInputs};
    use crate::types::{IdentityRef, Network, SendCatRequest, SendXchRequest, WalletId};
    use chia_protocol::Coin;
    use chia_puzzle_types::standard::StandardArgs;
    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::driver::{Cat, SpendContext};
    use chia_wallet_sdk::types::Conditions;
    use std::sync::Arc;

    /// The compressed BLS12-381 G1 generator — a valid, non-infinity public key used to curry a
    /// standard puzzle in tests without any secret material (mirrors src/engine/build.rs).
    fn test_public_key() -> chia_bls::PublicKey {
        let mut g = [0u8; 48];
        for (i, b) in [
            0x97u8, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9,
            0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f,
            0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a,
            0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
        ]
        .into_iter()
        .enumerate()
        {
            g[i] = b;
        }
        chia_bls::PublicKey::from_bytes(&g).expect("valid G1 generator")
    }

    fn wallet_ph() -> Bytes32 {
        Bytes32::from(StandardArgs::curry_tree_hash(test_public_key()).to_bytes())
    }

    fn wallet_coin(amount: u64, seed: u8) -> Coin {
        Coin::new(Bytes32::new([seed; 32]), wallet_ph(), amount)
    }

    fn issued_cat(amount: u64) -> Cat {
        let mut ctx = SpendContext::new();
        let genesis = wallet_coin(amount, 42);
        let hint = ctx.hint(wallet_ph()).unwrap();
        let create = Conditions::new().create_coin(wallet_ph(), amount, hint);
        let (_, cats) =
            Cat::single_issuance(&mut ctx, genesis.coin_id(), None, amount, create).unwrap();
        cats[0]
    }

    struct TestInputs {
        xch: Vec<Coin>,
        cats: Vec<Cat>,
    }

    impl SpendInputs for TestInputs {
        fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<Coin>> {
            Ok(self.xch.clone())
        }
        fn spendable_cat(&self, _: &IdentityRef, _: &AssetId) -> WalletResult<Vec<Cat>> {
            Ok(self.cats.clone())
        }
        fn synthetic_key(&self, ph: Bytes32) -> Option<chia_bls::PublicKey> {
            (ph == wallet_ph()).then(test_public_key)
        }
        fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<Bytes32> {
            Ok(wallet_ph())
        }
    }

    fn builder(xch: Vec<Coin>, cats: Vec<Cat>) -> SdkSpendBuilder {
        SdkSpendBuilder::new(Arc::new(TestInputs { xch, cats }), Network::Mainnet, 500)
    }

    fn recipient() -> Address {
        Bech32Address::new(Bytes32::new([7u8; 32]), "xch".into())
            .encode()
            .map(Address)
            .unwrap()
    }

    fn xch_request(amount: u64, fee: u64) -> SendXchRequest {
        SendXchRequest {
            identity: IdentityRef::new(WalletId(1)),
            to: recipient(),
            amount: Amount(amount),
            fee: Amount(fee),
        }
    }

    /// #2239: the key-free `derive_summary` re-derives the engine's declared egress AND conservatively
    /// over-lists the wallet's own change (it has no keys to drop it). So it SURFACES the 600 payment
    /// the builder claimed, plus the 390 change, with the same fee. (The key-AWARE
    /// `LocalSigner::reviewable_summary` reproduces the engine summary exactly — covered in the signer
    /// tests.)
    #[tokio::test]
    async fn derive_summary_surfaces_the_xch_builders_egress_plus_change() {
        let unsigned = builder(vec![wallet_coin(1000, 1)], vec![])
            .build_send_xch(xch_request(600, 10))
            .await
            .unwrap();
        let derived = derive_summary(&unsigned.coin_spends).unwrap();
        assert_eq!(derived.fee, Amount(10));
        // The engine's declared recipient output is present in the (over-listed) key-free view.
        for claimed in &unsigned.summary.outputs {
            assert!(
                derived.outputs.contains(claimed),
                "key-free derive_summary must surface every engine-declared output"
            );
        }
        // Plus the 390 change (1000 − 600 − 10), which the key-free view cannot drop.
        assert!(derived.outputs.iter().any(|o| o.amount == Amount(390)));
    }

    /// #2239: the same over-listing property for a CAT send — the key-free view surfaces the builder's
    /// declared CAT egress (asset id = the real tail hash) among its undivided outputs.
    #[tokio::test]
    async fn derive_summary_surfaces_the_cat_builders_egress() {
        let cat = issued_cat(1000);
        let asset_hex = hex::encode(cat.info.asset_id);
        let unsigned = builder(vec![], vec![cat])
            .build_send_cat(SendCatRequest {
                identity: IdentityRef::new(WalletId(1)),
                asset_id: AssetId(asset_hex),
                to: recipient(),
                amount: Amount(600),
                fee: Amount(0),
            })
            .await
            .unwrap();
        let derived = derive_summary(&unsigned.coin_spends).unwrap();
        assert_eq!(derived.fee, Amount(0));
        for claimed in &unsigned.summary.outputs {
            assert!(
                derived.outputs.contains(claimed),
                "key-free derive_summary must surface every engine-declared CAT output"
            );
        }
    }

    /// #2239: `analyze` returns the created coins UNDIVIDED — BOTH the payment and the change land in
    /// one `outputs` bucket, with NO recipient/change verdict on `SpendEffect` (that split is
    /// key-relative and belongs to the key-holding signer). A 600-mojo payment + a 390-mojo change
    /// (1000 − 600 − 10 fee) from one coin yields exactly two undivided outputs.
    #[tokio::test]
    async fn analyze_returns_undivided_outputs() {
        let effect = analyze(
            &builder(vec![wallet_coin(1000, 1)], vec![])
                .build_send_xch(xch_request(600, 10))
                .await
                .unwrap()
                .coin_spends,
        )
        .unwrap();
        // Both created coins are present, undivided; the fee is still derived.
        assert_eq!(effect.outputs.len(), 2);
        assert_eq!(effect.fee, 10);
        let mut amounts: Vec<u64> = effect.outputs.iter().map(|o| o.amount).collect();
        amounts.sort_unstable();
        assert_eq!(amounts, vec![390, 600]);
        // The change coin (390, back to the wallet) is present as a plain output — NOT bucketed apart.
        assert!(effect
            .outputs
            .iter()
            .any(|o| o.amount == 390 && o.puzzle_hash == wallet_ph()));
    }

    /// An empty coin-spend set is refused fail-closed.
    #[test]
    fn empty_coin_spends_are_refused() {
        let err = analyze(&[]).unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// A coin spend that is neither a standard XCH nor a CAT spend is refused fail-closed.
    #[test]
    fn a_non_standard_puzzle_is_refused() {
        // `1` is the identity CLVM program (`(q)`-less quote): a valid puzzle that is neither a
        // standard nor a CAT layer, so it cannot be accounted for.
        let coin = Coin::new(Bytes32::new([1u8; 32]), Bytes32::new([2u8; 32]), 100);
        let spend = CoinSpend::new(coin, vec![0x01].into(), vec![0x80].into());
        let err = analyze(&[spend]).unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// Undecodable puzzle-reveal bytes are refused fail-closed.
    #[test]
    fn undecodable_bytes_are_refused() {
        let coin = Coin::new(Bytes32::new([1u8; 32]), Bytes32::new([2u8; 32]), 100);
        let spend = CoinSpend::new(coin, vec![0xff, 0xff].into(), vec![0xff, 0xff].into());
        assert_eq!(
            analyze(&[spend]).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
        );
    }

    /// #1518: a spend whose `puzzle_reveal` does NOT hash to the coin's committed `puzzle_hash` is a
    /// substituted puzzle the coin never authorized — refused fail-closed BEFORE any value is derived
    /// from it. (A legit spend is built, then the coin's committed puzzle hash is swapped so the
    /// unchanged reveal no longer matches.)
    #[tokio::test]
    async fn substituted_puzzle_reveal_is_refused_1518() {
        let unsigned = builder(vec![wallet_coin(1000, 1)], vec![])
            .build_send_xch(xch_request(600, 10))
            .await
            .unwrap();
        let mut spends = unsigned.coin_spends;
        // Point the coin at a DIFFERENT committed puzzle hash while leaving the reveal untouched.
        let original = spends[0].coin;
        spends[0].coin = Coin::new(
            original.parent_coin_info,
            Bytes32::new([0x99; 32]),
            original.amount,
        );
        assert_eq!(
            analyze(&spends).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
        );
    }

    /// #1519: a real standard-layer spend whose delegated puzzle emits a SECOND `AGG_SIG_ME` (over an
    /// attacker-chosen message for the same wallet key) — laundering a blank-check signature for
    /// another coin through this benign carrier — is refused: exactly one `AGG_SIG_ME` is permitted.
    #[tokio::test]
    async fn a_second_embedded_agg_sig_me_is_refused_1519() {
        use chia_protocol::Coin;
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
        use chia_wallet_sdk::types::conditions::AggSigMe;
        use chia_wallet_sdk::types::Conditions;

        let ph = wallet_ph();
        let coin = Coin::new(Bytes32::new([3u8; 32]), ph, 1_000);
        let mut ctx = SpendContext::new();
        // A conserving self-send (benign) PLUS a smuggled extra AGG_SIG_ME.
        let conditions =
            Conditions::new()
                .create_coin(ph, 1_000, Memos::None)
                .with(Condition::AggSigMe(AggSigMe::new(
                    test_public_key(),
                    vec![0xABu8; 32].into(),
                )));
        StandardLayer::new(test_public_key())
            .spend(&mut ctx, coin, conditions)
            .unwrap();
        assert_eq!(
            analyze(&ctx.take()).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
        );
    }

    // ---- #1519 sole-AGG_SIG_ME enforcer, exercised directly for the zero / wrong-hash branches a
    // real standard layer (which always emits exactly one correct AGG_SIG_ME) cannot produce. ----

    use chia_protocol::Bytes;
    use chia_wallet_sdk::types::conditions::AggSigMe;

    fn agg_sig_me(message: [u8; 32]) -> Condition {
        Condition::AggSigMe(AggSigMe::new(
            test_public_key(),
            Bytes::from(message.to_vec()),
        ))
    }

    /// #2282: the shared forbidden-set predicate recognizes exactly the seven non-ME agg_sig variants,
    /// treats `AGG_SIG_ME` as NOT part of the set, and ignores non-agg-sig conditions.
    #[test]
    fn is_non_me_agg_sig_covers_the_seven_variants_only_2282() {
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::types::conditions::{
            AggSigAmount, AggSigParent, AggSigParentAmount, AggSigParentPuzzle, AggSigPuzzle,
            AggSigPuzzleAmount, AggSigUnsafe, CreateCoin,
        };

        let pk = test_public_key();
        let msg = || Bytes::from(vec![0x01u8; 32]);
        let seven: Vec<Condition> = vec![
            Condition::AggSigUnsafe(AggSigUnsafe::new(pk, msg())),
            Condition::AggSigParent(AggSigParent::new(pk, msg())),
            Condition::AggSigPuzzle(AggSigPuzzle::new(pk, msg())),
            Condition::AggSigAmount(AggSigAmount::new(pk, msg())),
            Condition::AggSigPuzzleAmount(AggSigPuzzleAmount::new(pk, msg())),
            Condition::AggSigParentAmount(AggSigParentAmount::new(pk, msg())),
            Condition::AggSigParentPuzzle(AggSigParentPuzzle::new(pk, msg())),
        ];
        for condition in &seven {
            assert!(
                is_non_me_agg_sig(condition),
                "{condition:?} should be non-ME"
            );
        }
        // AGG_SIG_ME is deliberately excluded from the shared set.
        assert!(!is_non_me_agg_sig(&agg_sig_me([0x11u8; 32])));
        // A non-agg-sig condition is not in the set.
        assert!(!is_non_me_agg_sig(&Condition::CreateCoin(CreateCoin::new(
            Bytes32::new([0u8; 32]),
            1,
            Memos::None,
        ))));
    }

    /// #1519: exactly one AGG_SIG_ME committing to the expected delegated-puzzle hash is accepted.
    #[test]
    fn sole_matching_agg_sig_me_is_accepted_1519() {
        let expected = [0x11u8; 32];
        assert!(enforce_sole_agg_sig_me(&[agg_sig_me(expected)], expected).is_ok());
    }

    /// #1519: zero AGG_SIG_ME — nothing binds a signature to the coin — is refused.
    #[test]
    fn zero_agg_sig_me_is_refused_1519() {
        assert_eq!(
            enforce_sole_agg_sig_me(&[], [0x11u8; 32]).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
        );
    }

    /// #1519: two AGG_SIG_ME conditions are refused (blank-check laundering surface).
    #[test]
    fn duplicate_agg_sig_me_is_refused_1519() {
        let expected = [0x11u8; 32];
        assert_eq!(
            enforce_sole_agg_sig_me(&[agg_sig_me(expected), agg_sig_me(expected)], expected)
                .unwrap_err()
                .code,
            WalletErrorCode::SpendValidationFailed,
        );
    }

    /// #1519: a sole AGG_SIG_ME whose message is NOT the committed delegated-puzzle hash is refused.
    #[test]
    fn wrong_hash_agg_sig_me_is_refused_1519() {
        assert_eq!(
            enforce_sole_agg_sig_me(&[agg_sig_me([0xAAu8; 32])], [0x11u8; 32])
                .unwrap_err()
                .code,
            WalletErrorCode::SpendValidationFailed,
        );
    }

    // ---- #1708: value conservation must be TOTAL arithmetic, never modulo 2^64. ----
    //
    // Every fixture below is built so the unchecked-`+=` implementation WRAPS to a total that
    // satisfies conservation — i.e. the nearest wrong implementation returns `Ok` on a spend that
    // moves more than `u64::MAX`. Asserting merely "not a panic" would pass against wrapping, so
    // each test asserts the REFUSAL, and each is paired with a truthful non-wrapping control that
    // must still be accepted (so a guard that rejects everything cannot masquerade as the fix).

    /// Spend `coin` under the wallet's standard layer with hand-chosen conditions.
    fn standard_spend(coin: Coin, conditions: Conditions) -> Vec<CoinSpend> {
        let mut ctx = SpendContext::new();
        StandardLayer::new(test_public_key())
            .spend(&mut ctx, coin, conditions)
            .unwrap();
        ctx.take()
    }

    /// #1708: OUTPUT amounts come from CLVM `CREATE_COIN` conditions, not from coin amounts, so no
    /// input-side bound reaches them. `u64::MAX + 1_001` wraps to `1_000`, which equals the single
    /// `1_000`-mojo input — so the wrapping implementation reports value CONSERVED on a spend that
    /// creates more than `u64::MAX` mojos. Must be refused.
    #[test]
    fn xch_output_total_that_wraps_is_refused_1708() {
        let spends = standard_spend(
            wallet_coin(1_000, 1),
            Conditions::new()
                .create_coin(Bytes32::new([0xA1; 32]), u64::MAX, Memos::None)
                .create_coin(Bytes32::new([0xA2; 32]), 1_001, Memos::None),
        );
        let err =
            analyze(&spends).expect_err("a spend creating more than u64::MAX must be refused");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
        assert!(
            err.message.contains("cannot be totalled"),
            "expected an overflow refusal, got: {}",
            err.message
        );
    }

    /// #1708 control: the SAME two-output shape with truthful amounts still analyzes cleanly, so
    /// the overflow guard cannot be satisfied by rejecting every multi-output spend.
    #[test]
    fn xch_output_total_that_fits_is_accepted_1708() {
        let spends = standard_spend(
            wallet_coin(1_000, 1),
            Conditions::new()
                .create_coin(Bytes32::new([0xA1; 32]), 600, Memos::None)
                .create_coin(Bytes32::new([0xA2; 32]), 400, Memos::None),
        );
        let effect = analyze(&spends).expect("a conserving two-output spend is valid");
        assert_eq!(effect.outputs.len(), 2);
        assert_eq!(effect.fee, 0);
    }

    /// #1708: INPUT amounts wrap too. Two coins of `u64::MAX` and `1_001`, each creating its own
    /// amount back, wrap BOTH sides to `1_000` — conservation passes under the wrapping
    /// implementation on a spend that moves `2^64 + 1_000` mojos. Must be refused.
    #[test]
    fn xch_input_total_that_wraps_is_refused_1708() {
        let ph = wallet_ph();
        let mut spends = standard_spend(
            Coin::new(Bytes32::new([0xB1; 32]), ph, u64::MAX),
            Conditions::new().create_coin(ph, u64::MAX, Memos::None),
        );
        spends.extend(standard_spend(
            Coin::new(Bytes32::new([0xB2; 32]), ph, 1_001),
            Conditions::new().create_coin(ph, 1_001, Memos::None),
        ));
        let err = analyze(&spends).expect_err("an unrepresentable input total must be refused");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
        assert!(
            err.message.contains("cannot be totalled"),
            "expected an overflow refusal, got: {}",
            err.message
        );
    }

    /// #1708 control: two coins whose amounts DO fit are accepted, proving the input guard is
    /// keyed on representability and not on "more than one coin".
    #[test]
    fn xch_input_total_that_fits_is_accepted_1708() {
        let ph = wallet_ph();
        let mut spends = standard_spend(
            Coin::new(Bytes32::new([0xB1; 32]), ph, u64::MAX - 2_000),
            Conditions::new().create_coin(ph, u64::MAX - 2_000, Memos::None),
        );
        spends.extend(standard_spend(
            Coin::new(Bytes32::new([0xB2; 32]), ph, 1_001),
            Conditions::new().create_coin(ph, 1_001, Memos::None),
        ));
        assert_eq!(analyze(&spends).unwrap().outputs.len(), 2);
    }

    /// Spend `cat` with hand-chosen inner p2 conditions (the CAT ring the verifier re-derives).
    fn cat_spend(cat: Cat, conditions: Conditions) -> Vec<CoinSpend> {
        use chia_wallet_sdk::driver::{CatSpend, SpendWithConditions};
        let mut ctx = SpendContext::new();
        let inner = StandardLayer::new(test_public_key())
            .spend_with_conditions(&mut ctx, conditions)
            .unwrap();
        Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner)]).unwrap();
        ctx.take()
    }

    /// #1708: the CAT output total wraps exactly as the XCH one does — and a CAT's per-asset
    /// conservation is the only thing standing between a signature and a minted asset.
    #[test]
    fn cat_output_total_that_wraps_is_refused_1708() {
        let spends = cat_spend(
            issued_cat(1_000),
            Conditions::new()
                .create_coin(Bytes32::new([0xC1; 32]), u64::MAX, Memos::None)
                .create_coin(Bytes32::new([0xC2; 32]), 1_001, Memos::None),
        );
        let err = analyze(&spends).expect_err("a CAT spend minting past u64::MAX must be refused");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
        assert!(
            err.message.contains("cannot be totalled"),
            "expected an overflow refusal, got: {}",
            err.message
        );
    }

    /// #1708 control: the same two-output CAT shape with truthful amounts still conserves.
    #[test]
    fn cat_output_total_that_fits_is_accepted_1708() {
        let spends = cat_spend(
            issued_cat(1_000),
            Conditions::new()
                .create_coin(Bytes32::new([0xC1; 32]), 600, Memos::None)
                .create_coin(Bytes32::new([0xC2; 32]), 400, Memos::None),
        );
        assert_eq!(analyze(&spends).unwrap().outputs.len(), 2);
    }

    /// #1708: the accumulator itself, exercised at and one past its bound. A bound tested only from
    /// below can confirm nothing — `u64::MAX` must total, `u64::MAX + 1` must refuse. This also
    /// covers the CAT INPUT accumulation, for which no fixture exists: two CAT coins of the same
    /// asset summing past `u64::MAX` would have to be issued from a single tail, and every tail this
    /// crate can construct issues a supply that fits in a `u64` by construction.
    #[test]
    fn accumulate_is_total_at_and_past_its_bound_1708() {
        assert_eq!(accumulate(u64::MAX - 1, 1, "t").unwrap(), u64::MAX);
        let err = accumulate(u64::MAX, 1, "CAT input total").unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
        assert!(err.message.starts_with("CAT input total exceeds u64::MAX"));
    }

    /// A standard spend whose coin claims MORE value than the coin actually holds breaks
    /// conservation and is refused (the runner still yields conditions, but in != out+fee).
    #[tokio::test]
    async fn broken_conservation_is_refused() {
        // Build a legit spend, then lie about the input coin's amount by rebuilding the coin spend
        // with a smaller coin value than its create-coins spend.
        let unsigned = builder(vec![wallet_coin(1000, 1)], vec![])
            .build_send_xch(xch_request(600, 10))
            .await
            .unwrap();
        let mut spends = unsigned.coin_spends;
        // Shrink the input coin's amount: now inputs (500) < outputs+fee (1000) → not conserved.
        let original = spends[0].coin;
        spends[0].coin = Coin::new(original.parent_coin_info, original.puzzle_hash, 500);
        assert_eq!(
            analyze(&spends).unwrap_err().code,
            WalletErrorCode::SpendValidationFailed,
        );
    }

    // ---- #1511 PR-B: settlement-layer decode + the `protocol_sink` bucket. ----

    /// The canonical settlement-payments puzzle hash — the ONLY destination routed to `protocol_sink`.
    fn settlement_ph() -> Bytes32 {
        Bytes32::new(chia_wallet_sdk::puzzles::SETTLEMENT_PAYMENT_HASH)
    }

    /// A wallet coin that spends value INTO the settlement puzzle (with an offer-binding assertion)
    /// routes that egress to `protocol_sink` — not to recipients or change — leaving `recipients`
    /// empty. This is the maker's offered leg of a make.
    #[test]
    fn a_settlement_egress_routes_to_protocol_sink() {
        let effect = analyze(&standard_spend(
            wallet_coin(50_000, 1),
            Conditions::new()
                .create_coin(settlement_ph(), 50_000, Memos::None)
                .assert_puzzle_announcement(Bytes32::new([0x44; 32])),
        ))
        .expect("a bound settlement egress is a valid offered leg");
        assert!(
            effect.outputs.is_empty(),
            "offered value is a protocol sink, not a free-address output"
        );
        assert_eq!(effect.protocol_sink.len(), 1);
        assert_eq!(effect.protocol_sink[0].amount, 50_000);
        assert_eq!(effect.protocol_sink[0].puzzle_hash, settlement_ph());
    }

    /// A wallet coin committing value to settlement with NO offer-binding assertion
    /// (give-it-away-for-nothing) is refused fail-closed (#1511 MR-6). The control above proves the
    /// refusal is the missing assertion, not the settlement routing itself.
    #[test]
    fn a_settlement_egress_without_a_binding_assertion_is_refused() {
        let err = analyze(&standard_spend(
            wallet_coin(50_000, 1),
            Conditions::new().create_coin(settlement_ph(), 50_000, Memos::None),
        ))
        .expect_err("an unbound settlement egress must be refused");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// #2241 (bundle-level): a bundle whose settlement egress is bound ONLY by concurrency — two sink
    /// coins ringed to each other with `AssertConcurrentSpend` but with NO announcement anywhere — is
    /// REFUSED. Concurrency binds only that the coins are co-spent, never the VALUE received in
    /// return, so the ring could still be given away for nothing; only an ANNOUNCEMENT assertion
    /// (which the real dig-offers make emits on one offered coin) ties the egress to a requested
    /// payment. The accepted control (`a_multi_coin_make_bundle_with_one_announcement_is_accepted`)
    /// proves the refusal is the missing announcement, not the multi-coin ring itself.
    #[test]
    fn a_settlement_bundle_bound_only_by_concurrency_is_refused_2241() {
        let coin_a = wallet_coin(50_000, 1);
        let coin_b = wallet_coin(30_000, 2);
        let mut spends = standard_spend(
            coin_a,
            Conditions::new()
                .create_coin(settlement_ph(), 50_000, Memos::None)
                .assert_concurrent_spend(coin_b.coin_id()),
        );
        spends.extend(standard_spend(
            coin_b,
            Conditions::new()
                .create_coin(settlement_ph(), 30_000, Memos::None)
                .assert_concurrent_spend(coin_a.coin_id()),
        ));
        let err = analyze(&spends)
            .expect_err("a concurrency-only (announcement-free) settlement bundle must be refused");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// #2241 (bundle-level): a legitimate MULTI-coin make — two coins each spending into settlement,
    /// ONE carrying the requested-payment announcement and the pair ringed together with
    /// `AssertConcurrentSpend` (exactly how dig-offers binds an offer with more than one offered coin)
    /// — is ACCEPTED. The per-coin check wrongly refused the concurrency-only coin; the bundle-level
    /// check accepts it because it is transitively tied through the ring to the announcement-bearer.
    #[test]
    fn a_multi_coin_make_bundle_with_one_announcement_is_accepted_2241() {
        let coin_a = wallet_coin(50_000, 1);
        let coin_b = wallet_coin(30_000, 2);
        let mut spends = standard_spend(
            coin_a,
            Conditions::new()
                .create_coin(settlement_ph(), 50_000, Memos::None)
                .assert_puzzle_announcement(Bytes32::new([0x44; 32]))
                .assert_concurrent_spend(coin_b.coin_id()),
        );
        spends.extend(standard_spend(
            coin_b,
            Conditions::new()
                .create_coin(settlement_ph(), 30_000, Memos::None)
                .assert_concurrent_spend(coin_a.coin_id()),
        ));
        let effect =
            analyze(&spends).expect("a bundle-bound multi-coin make is a valid offered side");
        assert_eq!(effect.protocol_sink.len(), 2, "both offered legs are sinks");
    }

    /// #2241 (bundle-level): the concurrency tie also resolves through `AssertConcurrentPuzzle` (by
    /// puzzle hash), not only `AssertConcurrentSpend` (by coin id). A second sink coin tied by puzzle
    /// hash to the announcement-bearing coin is ACCEPTED — exercising the puzzle-hash edge of the
    /// reachability walk.
    #[test]
    fn a_sink_tied_by_concurrent_puzzle_to_the_announcement_is_accepted_2241() {
        let coin_a = wallet_coin(50_000, 1);
        let coin_b = wallet_coin(30_000, 2);
        let mut spends = standard_spend(
            coin_a,
            Conditions::new()
                .create_coin(settlement_ph(), 50_000, Memos::None)
                .assert_puzzle_announcement(Bytes32::new([0x44; 32])),
        );
        // coin_b asserts co-spend of a coin with coin_a's puzzle hash (both wallet coins share it),
        // so the reachability walk reaches the announcement-bearing coin_a through the puzzle edge.
        spends.extend(standard_spend(
            coin_b,
            Conditions::new()
                .create_coin(settlement_ph(), 30_000, Memos::None)
                .assert_concurrent_puzzle(coin_a.puzzle_hash),
        ));
        let effect = analyze(&spends)
            .expect("a sink tied by concurrent-puzzle to the announcement is bound");
        assert_eq!(effect.protocol_sink.len(), 2);
    }

    /// #2241 (bundle-level, true attack): a bundle carrying ONE announcement-bound sink coin PLUS a
    /// SECOND settlement-sink coin that is NEITHER announcement-bound NOR concurrency-tied to the
    /// bundle is REFUSED. This proves the bundle-level check did not become a blanket
    /// "accept if any announcement is present": the unbound second sink is the real give-it-away
    /// egress an attacker would smuggle beside a legitimately-bound leg.
    #[test]
    fn a_second_unbound_settlement_sink_in_the_bundle_is_refused_2241() {
        let mut spends = standard_spend(
            wallet_coin(50_000, 1),
            Conditions::new()
                .create_coin(settlement_ph(), 50_000, Memos::None)
                .assert_puzzle_announcement(Bytes32::new([0x44; 32])),
        );
        // A second settlement sink, bound to NOTHING — not its own announcement, not a concurrency
        // tie to the announcement-bearing coin.
        spends.extend(standard_spend(
            wallet_coin(30_000, 2),
            Conditions::new().create_coin(settlement_ph(), 30_000, Memos::None),
        ));
        let err = analyze(&spends)
            .expect_err("an unbound second settlement sink must be refused beside a bound one");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// A CLAIMED settlement (XCH) coin — the canonical settlement puzzle spent by announcement, no
    /// signature — is decoded and its notarized payment accounted, with the settlement coin's amount as
    /// input (so per-asset value still conserves).
    #[test]
    fn a_claimed_settlement_coin_is_decoded() {
        use chia_puzzle_types::offer::{NotarizedPayment, Payment, SettlementPaymentsSolution};
        use chia_wallet_sdk::driver::{Layer, SettlementLayer, Spend, SpendContext};

        let payee = Bytes32::new([0x77; 32]);
        let mut ctx = SpendContext::new();
        let puzzle = SettlementLayer.construct_puzzle(&mut ctx).unwrap();
        let payment = Payment::new(payee, 1_000, Memos::None);
        let solution = SettlementLayer
            .construct_solution(
                &mut ctx,
                SettlementPaymentsSolution::new(vec![NotarizedPayment::new(
                    Bytes32::new([0x33; 32]),
                    vec![payment],
                )]),
            )
            .unwrap();
        let coin = chia_protocol::Coin::new(Bytes32::new([0x22; 32]), settlement_ph(), 1_000);
        ctx.spend(coin, Spend::new(puzzle, solution)).unwrap();

        let effect = analyze(&ctx.take()).expect("a claimed settlement coin decodes");
        // The 1_000 leaves to the payee as a plain undivided output (a change/recipient split the
        // key-aware signer resolves); per-asset value conserves (in 1_000 == out 1_000), no sink.
        assert!(effect.protocol_sink.is_empty());
        let payout: u64 = effect.outputs.iter().map(|o| o.amount).sum();
        assert_eq!(payout, 1_000);
    }

    /// #1708 + #1511: value conservation stays TOTAL arithmetic when a `protocol_sink` leg is present.
    /// A settlement egress of `u64::MAX` plus a `1_001` change wraps to `1_000` (== the input) under a
    /// modulo accumulator — so the wrapping implementation would report a `protocol_sink`-inclusive
    /// conservation as balanced on a spend moving more than `u64::MAX`. Must be refused; the control
    /// (truthful amounts) is accepted.
    #[test]
    fn protocol_sink_inclusive_conservation_that_wraps_is_refused_1511() {
        let ph = wallet_ph();
        let err = analyze(&standard_spend(
            wallet_coin(1_000, 1),
            Conditions::new()
                .create_coin(settlement_ph(), u64::MAX, Memos::None)
                .create_coin(ph, 1_001, Memos::None)
                .assert_puzzle_announcement(Bytes32::new([0x44; 32])),
        ))
        .expect_err("a protocol-sink-inclusive spend past u64::MAX must be refused");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
        assert!(
            err.message.contains("cannot be totalled"),
            "got: {}",
            err.message
        );

        // Control: truthful amounts (600 to settlement + 400 change) conserve and are accepted.
        let effect = analyze(&standard_spend(
            wallet_coin(1_000, 1),
            Conditions::new()
                .create_coin(settlement_ph(), 600, Memos::None)
                .create_coin(ph, 400, Memos::None)
                .assert_puzzle_announcement(Bytes32::new([0x44; 32])),
        ))
        .expect("truthful protocol-sink-inclusive amounts conserve");
        assert_eq!(effect.protocol_sink[0].amount, 600);
        assert_eq!(effect.outputs[0].amount, 400);
    }

    /// #2285: a CAT coin whose inner p2 puzzle is NEITHER a standard layer NOR a settlement layer is
    /// refused fail-closed — a foreign inner puzzle is one whose authorized value flow the wallet
    /// cannot verify, so the sole-AGG_SIG_ME / quote-form commitment could not bind it. This covers the
    /// `account_cat_spend` else-branch (neither settlement-claim nor standard-send).
    ///
    /// The CAT is spent with an identity inner puzzle (`1`, which returns its own solution). Its
    /// solution conserves the CAT (a single same-value `CREATE_COIN`) so `Cat::spend_all` builds a
    /// well-formed ring; the refusal is reached on the inner-puzzle class check, BEFORE any conservation
    /// math runs.
    #[test]
    fn a_cat_inner_that_is_neither_standard_nor_settlement_is_refused_2285() {
        use chia_wallet_sdk::driver::{CatInfo, CatSpend, Spend};

        let mut ctx = SpendContext::new();
        // Build a CAT whose inner p2 puzzle is the identity puzzle (`1`, which returns its solution).
        // The CAT's committed coin puzzle hash is derived FROM that inner puzzle's hash, so the #1518
        // puzzle-reveal bind passes and `analyze` reaches the inner-puzzle-class refusal.
        let inner_puzzle = ctx.alloc(&1).unwrap();
        let inner_hash = Bytes32::new(tree_hash(&ctx, inner_puzzle).to_bytes());
        let base = issued_cat(1_000);
        let info = CatInfo::new(base.info.asset_id, None, inner_hash);
        let coin = Coin::new(
            base.coin.parent_coin_info,
            Bytes32::new(info.puzzle_hash().to_bytes()),
            1_000,
        );
        let cat = Cat::new(coin, base.lineage_proof, info);
        let inner_solution = ctx
            .alloc(&Conditions::new().create_coin(wallet_ph(), 1_000, Memos::None))
            .unwrap();
        Cat::spend_all(
            &mut ctx,
            &[CatSpend::new(cat, Spend::new(inner_puzzle, inner_solution))],
        )
        .unwrap();

        let err = analyze(&ctx.take()).expect_err("a foreign CAT inner puzzle must be refused");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
        assert!(
            err.message
                .contains("neither a standard layer nor a settlement layer"),
            "got: {}",
            err.message
        );
    }

    /// The `protocol_sink` recognizer accepts exactly the canonical structural hashes — the settlement
    /// puzzle and the singleton launcher (#1511 PR-C) — and nothing else (never a free/wallet address).
    #[test]
    fn only_canonical_structural_hashes_are_protocol_sinks() {
        assert!(is_protocol_sink_hash(settlement_ph()));
        assert!(is_protocol_sink_hash(Bytes32::new(
            chia_wallet_sdk::puzzles::SINGLETON_LAUNCHER_HASH
        )));
        assert!(!is_protocol_sink_hash(Bytes32::new([0x00; 32])));
        assert!(!is_protocol_sink_hash(wallet_ph()));
    }
}

/// **Singleton melt admission** (dig_ecosystem#3068) — the profile-deletion path.
///
/// Deleting a DIG profile terminally spends its two singletons, the DID and the dig-store. Both melt
/// spends are built here by the CANONICAL crates, so what these tests put in front of [`analyze`] is
/// byte-for-byte what dig-account will ask it to verify.
///
/// Two singleton kinds, deliberately: their inner layer stacks differ (a `DidLayer` versus the
/// DataLayer metadata layers), so a fixture of only one would prove the arm accepts that one stack.
#[cfg(test)]
pub(crate) mod singleton_melt_tests {
    use super::*;
    use chia_protocol::Coin;
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::driver::SpendContext;
    use chia_wallet_sdk::types::Conditions;
    use clvm_traits::ToClvm;
    use clvmr::serde::node_to_bytes;

    /// A non-infinity public key with no secret behind it — enough to curry a standard puzzle and to
    /// own a singleton, and never a key this crate could sign with.
    fn owner_pk() -> chia_bls::PublicKey {
        let mut g = [0u8; 48];
        for (i, b) in [
            0x97u8, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9,
            0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f,
            0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a,
            0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
        ]
        .into_iter()
        .enumerate()
        {
            g[i] = b;
        }
        chia_bls::PublicKey::from_bytes(&g).expect("valid G1 generator")
    }

    fn owner_ph() -> Bytes32 {
        Bytes32::from(StandardArgs::curry_tree_hash(owner_pk()).to_bytes())
    }

    /// A real DIG store singleton melt, built by `dig_merkle::melt`.
    ///
    /// `pub(crate)` so the signer's review-gate tests melt a REAL singleton through the real builder
    /// rather than a second, drifting copy of this fixture.
    pub(crate) fn store_melt() -> Vec<CoinSpend> {
        let store = dig_merkle::mint_datastore(
            Coin::new(Bytes32::new([0x11; 32]), owner_ph(), 1),
            dig_merkle::Owner::Standard(owner_pk()),
            Bytes32::new([0x5a; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph(),
            vec![],
            0,
        )
        .expect("the canonical store mint builder")
        .child
        .expect("a mint yields the eve store");

        dig_merkle::melt(&store, dig_merkle::Owner::Standard(owner_pk()))
            .expect("the canonical store melt builder")
            .coin_spends
    }

    /// A real DID singleton melt, built by `dig_did::melt`.
    fn did_melt() -> Vec<CoinSpend> {
        let mut ctx = SpendContext::new();
        let did = dig_did::create_simple_did(
            &mut ctx,
            Coin::new(Bytes32::new([0x22; 32]), owner_ph(), 1),
            dig_did::Owner::Standard(owner_pk()),
        )
        .expect("the canonical DID launch builder")
        .child
        .expect("a launch yields the settled DID");

        dig_did::melt(&mut ctx, did, dig_did::Owner::Standard(owner_pk()))
            .expect("the canonical DID melt builder")
            .coin_spends
    }

    /// A store melt is ACCOUNTED, not refused: the singleton's mojo enters, nothing leaves, and the
    /// destroyed amount is reported as the implicit fee.
    #[test]
    fn a_store_singleton_melt_is_accounted_with_its_mojo_as_the_implicit_fee() {
        let effect = analyze(&store_melt()).expect("a terminal store melt must be verifiable");
        assert!(
            effect.outputs.is_empty() && effect.protocol_sink.is_empty(),
            "a melt creates no coin, so nothing may be reported as leaving"
        );
        assert_eq!(
            effect.fee, 1,
            "the singleton's mojo is destroyed, and the only honest place to report it is the fee"
        );
    }

    /// The same, for a DID singleton — a different inner layer stack through the same arm.
    #[test]
    fn a_did_singleton_melt_is_accounted_with_its_mojo_as_the_implicit_fee() {
        let effect = analyze(&did_melt()).expect("a terminal DID melt must be verifiable");
        assert!(effect.outputs.is_empty() && effect.protocol_sink.is_empty());
        assert_eq!(effect.fee, 1);
    }

    /// A melt does not travel alone: dig-account pays its network fee from an ordinary wallet coin in
    /// the SAME bundle. Both legs must account together, and the reported fee must name every mojo
    /// the person is spending — the explicit reserve AND the destroyed singleton.
    #[test]
    fn a_melt_bundled_with_its_fee_paying_coin_accounts_both_legs() {
        let mut spends = store_melt();
        spends.extend(fee_paying_coin(1_000, 900, 100));

        let effect = analyze(&spends).expect("a melt beside its fee payer must be verifiable");
        assert_eq!(
            effect.fee, 101,
            "100 reserved plus the 1 destroyed mojo — a fee that omitted the melt would understate \
             what the person spends"
        );
    }

    /// **The abuse test for the widened conservation.** Admitting a melt added a third accounted
    /// destination to the value equality; this proves it did not become a hole.
    ///
    /// The fee-paying coin in this bundle leaks 500 mojos — it neither creates them as an output nor
    /// reserves them as a fee. Were the melt switched to the implicit-fee mode the option path uses
    /// (`fee = in - out`), the whole bundle would stop being held to the equality and this leak would
    /// be silently reported as a fee. It is refused instead, and the ONLY difference between this
    /// test and the one above is the leak.
    #[test]
    fn a_melt_does_not_excuse_a_value_leak_elsewhere_in_the_bundle() {
        let mut spends = store_melt();
        spends.extend(fee_paying_coin(1_000, 400, 100));

        let err = analyze(&spends)
            .expect_err("a melt in the bundle must not relax conservation for any other coin");
        assert!(
            err.message.contains("not conserved"),
            "the refusal must be the conservation one, not an incidental parse failure: {}",
            err.message
        );
    }

    /// An ordinary standard-layer coin of `amount` that returns `change` to the wallet and reserves
    /// `fee`. When `amount != change + fee` the coin LEAKS the difference, which is how the abuse
    /// test above is built from the same helper as its control.
    fn fee_paying_coin(amount: u64, change: u64, fee: u64) -> Vec<CoinSpend> {
        use chia_puzzle_types::Memos;
        use chia_wallet_sdk::driver::StandardLayer;
        use chia_wallet_sdk::types::Conditions;

        let mut ctx = SpendContext::new();
        StandardLayer::new(owner_pk())
            .spend(
                &mut ctx,
                Coin::new(Bytes32::new([0x44; 32]), owner_ph(), amount),
                Conditions::new()
                    .create_coin(owner_ph(), change, Memos::None)
                    .reserve_fee(fee),
            )
            .expect("a standard fee-paying spend");
        ctx.take()
    }

    /// **The control that makes the two tests above load-bearing.** A singleton spend that does NOT
    /// melt — the store's ordinary root UPDATE, which recreates the singleton — is still refused.
    ///
    /// Without this, admitting "a singleton spend" and admitting "a TERMINAL singleton spend" are
    /// indistinguishable, and the arm could have opened the whole singleton class to signing: an
    /// update re-homes the store to a new owner, so waving it through is a transfer of the profile's
    /// identity that no human reviewed.
    #[test]
    fn a_singleton_spend_that_recreates_the_singleton_is_still_refused() {
        let store = dig_merkle::mint_datastore(
            Coin::new(Bytes32::new([0x33; 32]), owner_ph(), 1),
            dig_merkle::Owner::Standard(owner_pk()),
            Bytes32::new([0x5a; 32]),
            None,
            None,
            None,
            None,
            None,
            owner_ph(),
            vec![],
            0,
        )
        .expect("the canonical store mint builder")
        .child
        .expect("a mint yields the eve store");

        let updated = dig_merkle::update_root(
            &store,
            dig_merkle::Owner::Standard(owner_pk()),
            dig_merkle::DigDataStoreMetadata {
                root_hash: Bytes32::new([0x77; 32]),
                ..Default::default()
            },
        )
        .expect("the canonical store update builder");

        let err = analyze(&updated.coin_spends)
            .expect_err("only a TERMINAL singleton spend is admissible; an update is not");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// Rewrite a spend's p2 delegated puzzle from the canonical quote form `(q . conditions)` into
    /// the non-quote IDENTITY puzzle `1`, which returns whatever solution it is handed — moving
    /// `conditions` (or `replacement`, when given) into the delegated SOLUTION beside it.
    ///
    /// This is the attacker's construction from dig_ecosystem#3068, expressed as a fixture: the
    /// standard layer signs `sha256tree(delegated_puzzle)`, so both variants produced here are
    /// covered by ONE signature while doing entirely different things — which is exactly what an
    /// outer-conditions check cannot see, and what the admission test must.
    fn with_malleable_delegated_puzzle(
        spend: &CoinSpend,
        replacement: Option<Conditions>,
    ) -> CoinSpend {
        let mut allocator = Allocator::new();
        let solution = node_from_bytes(&mut allocator, &spend.solution).expect("a valid solution");
        let rewritten = rewrite_delegated_puzzle(&mut allocator, solution, &replacement)
            .expect("the melt solution carries a quoted delegated puzzle to rewrite");
        CoinSpend {
            solution: node_to_bytes(&allocator, rewritten)
                .expect("a serializable solution")
                .into(),
            ..spend.clone()
        }
    }

    /// The recursive half of [`with_malleable_delegated_puzzle`]: find the
    /// `((q . melt_conditions) delegated_solution . rest)` shape anywhere in the solution tree and
    /// rebuild it as `(1 conditions . rest)`. Identifying the target by its QUOTED MELT CONDITIONS
    /// (not merely by being a quote pair) keeps the rewrite from landing on unrelated quoted data.
    fn rewrite_delegated_puzzle(
        allocator: &mut Allocator,
        node: clvmr::NodePtr,
        replacement: &Option<Conditions>,
    ) -> Option<clvmr::NodePtr> {
        let clvmr::SExp::Pair(first, rest) = allocator.sexp(node) else {
            return None;
        };

        if let clvmr::SExp::Pair(quote_op, quoted) = allocator.sexp(first) {
            let quotes_a_melt = allocator.small_number(quote_op) == Some(1)
                && Vec::<Condition>::from_clvm(allocator, quoted).is_ok_and(|conditions| {
                    conditions
                        .iter()
                        .any(|c| matches!(c, Condition::MeltSingleton(_)))
                });
            if quotes_a_melt {
                if let clvmr::SExp::Pair(_delegated_solution, tail) = allocator.sexp(rest) {
                    let conditions = match replacement {
                        Some(replacement) => replacement
                            .clone()
                            .to_clvm(allocator)
                            .expect("encodable replacement conditions"),
                        None => quoted,
                    };
                    let identity = allocator.new_small_number(1).ok()?;
                    let solution_and_rest = allocator.new_pair(conditions, tail).ok()?;
                    return allocator.new_pair(identity, solution_and_rest).ok();
                }
            }
        }

        if let Some(rewritten) = rewrite_delegated_puzzle(allocator, first, replacement) {
            return allocator.new_pair(rewritten, rest).ok();
        }
        let rewritten = rewrite_delegated_puzzle(allocator, rest, replacement)?;
        allocator.new_pair(first, rewritten).ok()
    }

    /// The AGG_SIG_ME message a spend's outer conditions carry — the delegated-puzzle tree hash the
    /// user's key would actually sign over.
    fn signed_message(spend: &CoinSpend) -> [u8; 32] {
        let mut allocator = Allocator::new();
        let puzzle = node_from_bytes(&mut allocator, &spend.puzzle_reveal).expect("a valid puzzle");
        let solution = node_from_bytes(&mut allocator, &spend.solution).expect("a valid solution");
        let conditions = run_conditions(&mut allocator, puzzle, solution).expect("a running spend");
        sole_agg_sig_me_message(&conditions).expect("a lone AGG_SIG_ME")
    }

    /// **THE malleability test (#3068 CRITICAL#3).** A melt whose signed delegated puzzle is the
    /// non-quote identity atom `1` emits the honest melt conditions under the solution PRESENTED —
    /// so every outer-condition check passes — while the signature it releases is a blank cheque
    /// over the coin, reusable with any other solution. It must be REFUSED on the ground that the
    /// signed puzzle does not pin its conditions.
    #[test]
    fn a_melt_whose_signed_delegated_puzzle_is_solution_malleable_is_refused() {
        let honest = store_melt();
        let malleable: Vec<CoinSpend> = honest
            .iter()
            .map(|spend| with_malleable_delegated_puzzle(spend, None))
            .collect();

        let err = analyze(&malleable)
            .expect_err("a signature that does not pin its conditions must never be released");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
        assert!(
            err.message.contains("quote-form") || err.message.contains("canonical quote form"),
            "the refusal must name the unpinned delegated puzzle, not an incidental failure: {}",
            err.message
        );
    }

    /// The control that makes the test above load-bearing rather than a coincidence: the malleable
    /// spend and the honest one emit the SAME outer conditions, differing only in the 32 opaque
    /// bytes of the `AGG_SIG_ME` message — a delegated-puzzle tree hash the outer layer has no
    /// independent expectation for, because the melt arm cannot derive it (the DID/DataLayer stacks
    /// between the singleton and its p2 layer are deliberately unmodelled, which is why
    /// [`committed_melt_conditions`] recovers it by preimage instead).
    ///
    /// So no outer-conditions check can separate these two spends. The refusal must come from
    /// descending into the signed delegated puzzle, and relocating that inspection outwards would
    /// make it disappear.
    #[test]
    fn the_malleable_melt_differs_from_the_honest_one_only_in_bytes_the_outer_layer_cannot_judge() {
        let honest = store_melt();
        let honest_spend = honest
            .iter()
            .find(|spend| {
                let mut allocator = Allocator::new();
                node_from_bytes(&mut allocator, &spend.puzzle_reveal)
                    .ok()
                    .and_then(|ptr| Puzzle::parse(&allocator, ptr).into())
                    .is_some_and(is_singleton_puzzle)
            })
            .expect("the melt bundle contains the singleton spend");
        let malleable = with_malleable_delegated_puzzle(honest_spend, None);

        // Everything the outer layer can actually JUDGE: the conditions, with the one opaque
        // delegated-puzzle hash replaced by the signer's public key (which is judgeable, and equal).
        let judgeable = |spend: &CoinSpend| {
            let mut allocator = Allocator::new();
            let puzzle =
                node_from_bytes(&mut allocator, &spend.puzzle_reveal).expect("a valid puzzle");
            let solution =
                node_from_bytes(&mut allocator, &spend.solution).expect("a valid solution");
            run_conditions(&mut allocator, puzzle, solution)
                .expect("a running spend")
                .iter()
                .map(|condition| match condition {
                    Condition::AggSigMe(sig) => format!("AggSigMe({:?})", sig.public_key),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
        };

        assert_eq!(
            judgeable(honest_spend),
            judgeable(&malleable),
            "the malleable variant must be outwardly identical everywhere the outer layer can form \
             an expectation, or this fixture proves nothing about where the check has to live"
        );
        assert_ne!(
            signed_message(honest_spend),
            signed_message(&malleable),
            "the two DO differ in the signed hash — but only there, and the melt arm has no \
             independently derived value to compare it against"
        );
        assert_ne!(
            honest_spend.solution, malleable.solution,
            "the variants must actually differ, in the solution rather than in what it emits"
        );
        assert!(
            analyze(&honest).is_ok(),
            "the honest melt must remain signable — a guard that refuses everything is not a guard"
        );
    }

    /// The exploit's second leg, and the answer to "are transfers still refused under a CRAFTED
    /// solution rather than a presented one": the SAME malleable delegated puzzle, replayed with an
    /// attacker's solution, re-homes the singleton under an odd-amount `CREATE_COIN` — and the
    /// signature covering it is byte-identical to the one the honest-looking variant would release.
    #[test]
    fn a_crafted_malleable_solution_that_re_homes_the_singleton_is_refused() {
        use chia_puzzle_types::Memos;

        let attacker_ph = Bytes32::new([0xaa; 32]);
        let honest = store_melt();
        let re_homing: Vec<CoinSpend> = honest
            .iter()
            .map(|spend| {
                with_malleable_delegated_puzzle(
                    spend,
                    Some(Conditions::new().create_coin(attacker_ph, 1, Memos::None)),
                )
            })
            .collect();
        let benign: Vec<CoinSpend> = honest
            .iter()
            .map(|spend| with_malleable_delegated_puzzle(spend, None))
            .collect();

        for (crafted, benign) in re_homing.iter().zip(benign.iter()) {
            assert_eq!(
                signed_message(crafted),
                signed_message(benign),
                "ONE signature must cover both solutions, or the replay this guard exists for is \
                 not what the fixture builds"
            );
        }

        let err = analyze(&re_homing)
            .expect_err("a spend that re-homes the singleton to an attacker must be refused");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// A melt whose outer conditions carry NO `AGG_SIG_ME` binds no signature to this coin, so it
    /// can be appended to any bundle and have its destroyed mojos land in someone else's displayed
    /// fee. The shared reader refuses it, which is what the melt arm relies on.
    #[test]
    fn a_melt_with_no_agg_sig_me_is_refused() {
        let err = sole_agg_sig_me_message(&[Condition::melt_singleton()])
            .expect_err("zero AGG_SIG_ME authorizes nothing and must never be admitted");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// The condition allowlist is default-DENY: an opcode outside it — here a coin announcement the
    /// melt does not need — is refused rather than waved through carrying the user's signature.
    #[test]
    fn a_melt_condition_outside_the_allowlist_is_refused() {
        for list in [MeltConditionList::Presented, MeltConditionList::Signed] {
            reject_non_melt_condition(
                &Condition::create_coin_announcement(vec![1, 2, 3].into()),
                list,
            )
            .expect_err("an unallowlisted condition must be refused, not tolerated");
            reject_non_melt_condition(&Condition::melt_singleton(), list)
                .expect("the melt marker itself is allowlisted");
        }
    }

    /// An `AGG_SIG_ME` inside the SIGNED quoted condition list is a blank cheque for a second
    /// delegated puzzle on the same coin, so it must be refused THERE — while the identical
    /// condition in the PRESENTED list is the p2 layer's own signature requirement and every honest
    /// melt carries it.
    ///
    /// Both halves are asserted together deliberately: a guard that refused `AGG_SIG_ME` in both
    /// lists would pass the abuse half and break every honest melt, and a guard that admitted it in
    /// both is the state before this change. Only the split is correct, and only asserting both
    /// sides can see the difference.
    #[test]
    fn an_agg_sig_me_is_refused_in_the_signed_list_and_admitted_in_the_presented_one() {
        let agg_sig_me = Condition::agg_sig_me(owner_pk(), vec![0x5a; 32].into());

        let err = reject_non_melt_condition(&agg_sig_me, MeltConditionList::Signed).expect_err(
            "a signed delegated puzzle that carries its own AGG_SIG_ME authorizes a second \
             delegated puzzle and must be refused",
        );
        assert!(
            err.message
                .contains("SIGNED delegated puzzle carries its own AGG_SIG_ME"),
            "the refusal must name the smuggled signature requirement, not an incidental parse \
             failure: {}",
            err.message
        );

        reject_non_melt_condition(&agg_sig_me, MeltConditionList::Presented)
            .expect("the p2 layer's own AGG_SIG_ME is what every honest melt presents");
    }

    // ---------------------------------------------------------------------------------------
    // NFT fixtures + the STEP-1 measurement of what the gate does with them today (#3077).
    // ---------------------------------------------------------------------------------------

    /// The p2 puzzle hash an NFT is transferred TO — a second free address, distinct from
    /// [`owner_ph`] so a re-home is observable as a change of destination.
    fn nft_recipient_ph() -> Bytes32 {
        Bytes32::new([0x7c; 32])
    }

    /// The coin that funds an NFT mint: an ordinary standard-layer wallet coin.
    fn nft_funding_coin() -> Coin {
        Coin::new(Bytes32::new([0x44; 32]), owner_ph(), 1)
    }

    /// Mint an NFT through the CANONICAL chia-wallet-sdk drivers (`Launcher::mint_nft`), returning
    /// the settled NFT plus the coin spends the mint consists of.
    ///
    /// dig-nft is deliberately NOT used: it is published at 0.1.0 against chia-protocol 0.26 /
    /// chia-wallet-sdk 0.30, so its `CoinSpend` is a DIFFERENT type from the 0.36.1 one this gate
    /// parses — the fixture could not be handed to `analyze` at all. The sdk drivers used here are
    /// the same ones dig-nft itself wraps and the same ones this module parses with, so nothing is
    /// hand-rolled.
    fn nft_mint_parts() -> (SpendContext, chia_wallet_sdk::driver::Nft, Vec<CoinSpend>) {
        use chia_puzzle_types::nft::NftMetadata;
        use chia_wallet_sdk::driver::{Launcher, NftMint, StandardLayer};

        let mut ctx = SpendContext::new();
        let funding = nft_funding_coin();
        let metadata = ctx
            .alloc_hashed(&NftMetadata::default())
            .expect("the default NFT metadata allocates");
        let launcher = Launcher::new(funding.coin_id(), 1);
        let mint = NftMint::new(metadata, owner_ph(), 300, None);
        let (mint_conditions, nft) = launcher
            .mint_nft(&mut ctx, &mint)
            .expect("the canonical sdk NFT mint builder");
        StandardLayer::new(owner_pk())
            .spend(&mut ctx, funding, mint_conditions)
            .expect("the funding coin spends under the standard layer");
        let spends = ctx.take();
        (ctx, nft, spends)
    }

    /// The coin spends of a real NFT MINT: the standard-layer funding coin, the singleton launcher,
    /// and the eve NFT spend.
    fn nft_mint() -> Vec<CoinSpend> {
        nft_mint_parts().2
    }

    /// The permanent launcher id of the NFT every fixture here acts on.
    fn nft_launcher_id() -> Bytes32 {
        nft_mint_parts().1.info.launcher_id
    }

    /// A SECOND mint's eve spend, descending from a launcher that is NOT spent in the bundle under
    /// test — the foreign-descent fixture for the eve half of the mint binding.
    fn foreign_eve_spend() -> CoinSpend {
        use chia_puzzle_types::nft::NftMetadata;
        use chia_wallet_sdk::driver::{Launcher, NftMint, StandardLayer};

        let mut ctx = SpendContext::new();
        // A different funding coin gives a different launcher, and so a different lineage.
        let funding = Coin::new(Bytes32::new([0x55; 32]), owner_ph(), 1);
        let metadata = ctx
            .alloc_hashed(&NftMetadata::default())
            .expect("the default NFT metadata allocates");
        let launcher = Launcher::new(funding.coin_id(), 1);
        let mint = NftMint::new(metadata, owner_ph(), 300, None);
        let (mint_conditions, _nft) = launcher
            .mint_nft(&mut ctx, &mint)
            .expect("the canonical sdk NFT mint builder");
        StandardLayer::new(owner_pk())
            .spend(&mut ctx, funding, mint_conditions)
            .expect("the funding coin spends under the standard layer");
        let spends = ctx.take();

        let launcher_id = spends
            .iter()
            .find(|spend| spend.coin.puzzle_hash == Bytes32::new(SINGLETON_LAUNCHER_HASH))
            .expect("the second mint spends a launcher")
            .coin
            .coin_id();
        spends
            .into_iter()
            .find(|spend| spend.coin.parent_coin_info == launcher_id)
            .expect("the second mint spends its eve NFT")
    }

    /// A settled NFT ready to be spent, plus a spend context — the starting point every
    /// non-transfer NFT fixture below re-homes differently.
    fn settled_nft() -> (SpendContext, chia_wallet_sdk::driver::Nft) {
        let (mut ctx, nft, _mint_spends) = nft_mint_parts();
        // The mint's eve spend already settled the NFT; `Nft::transfer` returns the settled child,
        // and taking the spends here discards the mint legs so each fixture is a lone NFT spend.
        let settled = nft
            .transfer(
                &mut ctx,
                &chia_wallet_sdk::driver::StandardLayer::new(owner_pk()),
                owner_ph(),
                Conditions::new(),
            )
            .expect("the canonical sdk NFT transfer builder");
        let _ = ctx.take();
        (ctx, settled)
    }

    /// An NFT METADATA UPDATE, built by the canonical sdk driver — a re-home carrying an extra
    /// `UPDATE_NFT_METADATA` condition.
    fn nft_metadata_update() -> Vec<CoinSpend> {
        use chia_wallet_sdk::driver::{MetadataUpdate, StandardLayer, UriKind};

        let (mut ctx, nft) = settled_nft();
        let update = MetadataUpdate {
            kind: UriKind::Data,
            uri: "https://example.invalid/nft".to_string(),
        }
        .spend(&mut ctx)
        .expect("the canonical sdk metadata-update builder");
        let _ = nft
            .transfer_with_metadata(
                &mut ctx,
                &StandardLayer::new(owner_pk()),
                nft_recipient_ph(),
                update,
                Conditions::new(),
            )
            .expect("the canonical sdk NFT metadata-update transfer builder");
        ctx.take()
    }

    /// An NFT OWNER ASSIGNMENT (a DID link), built by the canonical sdk driver — a re-home carrying
    /// the `TRANSFER_NFT` condition an offer's settlement lock also uses.
    fn nft_owner_assignment() -> Vec<CoinSpend> {
        use chia_wallet_sdk::driver::StandardLayer;
        use chia_wallet_sdk::types::conditions::TransferNft;

        let (mut ctx, nft) = settled_nft();
        let did_id = Bytes32::new([0x6d; 32]);
        let _ = nft
            .assign_owner(
                &mut ctx,
                &StandardLayer::new(owner_pk()),
                owner_ph(),
                TransferNft::new(Some(did_id), Vec::new(), Some(did_id)),
                Conditions::new(),
            )
            .expect("the canonical sdk NFT owner-assignment builder");
        ctx.take()
    }

    /// An NFT MELT — a terminal singleton spend of an NFT, which is neither of the two signable
    /// acts.
    fn nft_melt() -> Vec<CoinSpend> {
        use chia_wallet_sdk::driver::StandardLayer;

        let (mut ctx, nft) = settled_nft();
        // `spend_with` INSERTS the coin spend and only then tries to derive the child coin — which
        // a melt, by definition, does not create. The insertion is what this fixture needs, so the
        // child-derivation error is discarded and the resulting spend asserted instead.
        let _ = nft.spend_with(
            &mut ctx,
            &StandardLayer::new(owner_pk()),
            Conditions::new().melt_singleton(),
        );
        let spends = ctx.take();
        assert_eq!(
            spends.len(),
            1,
            "the melt fixture must be exactly the terminal NFT spend"
        );
        spends
    }

    /// An NFT transfer whose delegated puzzle is SOLUTION-MALLEABLE, plus the condition list it
    /// PRESENTS — the #1058 CRITICAL#3 shape, rebuilt against the NFT arm.
    ///
    /// The delegated puzzle is `1`, the CLVM identity program, so it returns whatever solution it is
    /// given. `sha256tree(1)` is what the signature commits to, and that hash says nothing at all
    /// about the conditions — so the same signature authorizes any condition list an attacker later
    /// chooses. The solution supplied here is a perfectly honest single odd-amount re-home, which is
    /// what makes the fixture load-bearing: every value-flow property the gate checks is satisfied,
    /// and only a check on the SIGNED artifact can tell the difference.
    fn malleable_nft_transfer() -> (Vec<CoinSpend>, Vec<Condition>) {
        use chia_puzzle_types::standard::StandardSolution;
        use chia_wallet_sdk::driver::Spend;

        let (mut ctx, nft) = settled_nft();

        // The re-home the delegated puzzle will emit — a well-formed transfer, so nothing but the
        // malleability can cause a refusal.
        let presented =
            Conditions::new().create_coin(nft_recipient_ph(), 1, chia_puzzle_types::Memos::None);

        // `1` returns its solution rather than quoting a fixed condition list.
        let echo = ctx.alloc(&1).expect("the identity program allocates");
        let solution_conditions = ctx
            .alloc(&presented)
            .expect("the presented conditions allocate");
        let standard_solution = ctx
            .alloc(&StandardSolution {
                original_public_key: None,
                delegated_puzzle: echo,
                solution: solution_conditions,
            })
            .expect("a standard-layer solution allocates");
        let p2_puzzle = ctx
            .curry(chia_puzzle_types::standard::StandardArgs::new(owner_pk()))
            .expect("the standard puzzle curries");

        let _ = nft
            .spend(&mut ctx, Spend::new(p2_puzzle, standard_solution))
            .expect("an NFT accepts an arbitrary inner spend");
        // Decoded from the SAME node the solution carries, so the list this test asserts is
        // honest is byte-identically the list the malleable puzzle presents.
        let decoded = Vec::<Condition>::from_clvm(&ctx, solution_conditions)
            .expect("the presented conditions decode");
        (ctx.take(), decoded)
    }

    /// The coin spends of a real NFT TRANSFER: one NFT singleton spend re-homing the NFT to
    /// [`nft_recipient_ph`] under the owner's standard layer.
    ///
    /// `pub(crate)` so the signer's review-gate tests transfer a REAL NFT through the real sdk
    /// builder rather than a second, drifting copy of this fixture.
    pub(crate) fn nft_transfer() -> Vec<CoinSpend> {
        use chia_wallet_sdk::driver::StandardLayer;

        let (mut ctx, nft, _mint_spends) = nft_mint_parts();
        let _child = nft
            .transfer(
                &mut ctx,
                &StandardLayer::new(owner_pk()),
                nft_recipient_ph(),
                Conditions::new(),
            )
            .expect("the canonical sdk NFT transfer builder");
        ctx.take()
    }

    /// An NFT TRANSFER is authorized, and is NAMED as a transfer of a specific NFT.
    ///
    /// Both halves matter. The gate accepting the bundle is only half a feature: a transfer nets ~0
    /// XCH, so if the effect did not name the NFT the confirm screen would show a person a
    /// one-mojo movement and nothing else — the invisible-act defect the melt arm was built to end
    /// (dig_ecosystem#3068), returning in a new form.
    #[test]
    fn an_nft_transfer_is_authorized_and_named() {
        let effect = analyze(&nft_transfer()).expect("an NFT transfer must be signable (#3077)");

        assert_eq!(
            effect.nft_operations,
            vec![NftOperation::Transfer(nft_launcher_id())],
            "the transfer must be named against the NFT's permanent launcher id"
        );
        assert_eq!(
            effect.outputs.len(),
            1,
            "a transfer re-homes exactly one singleton"
        );
        assert_eq!(
            effect.outputs[0].amount, 1,
            "the singleton's lone mojo flows through to the re-homed coin"
        );
        assert_eq!(
            effect.fee, 0,
            "a bare transfer takes no fee; a dust fee here would be the singleton mojo leaking"
        );
        assert!(
            effect.outputs[0].puzzle_hash != Bytes32::new(SINGLETON_LAUNCHER_HASH),
            "a re-home to a structural hash is a different act and must never be accounted here"
        );
    }

    /// An NFT MINT is authorized end to end — the funding coin, the singleton launcher, and the eve
    /// spend all accounting together — and is NAMED as a mint.
    #[test]
    fn an_nft_mint_is_authorized_and_named() {
        let effect = analyze(&nft_mint()).expect("an NFT mint must be signable (#3077)");

        assert_eq!(
            effect.nft_operations,
            vec![NftOperation::Mint(nft_launcher_id())],
            "the mint must be named against the NFT's permanent launcher id"
        );
        assert!(
            effect
                .protocol_sink
                .iter()
                .any(|output| output.puzzle_hash == Bytes32::new(SINGLETON_LAUNCHER_HASH)),
            "the funding coin's mojo goes to the canonical launcher, a sanctioned protocol sink"
        );
    }

    /// A human-facing NFT action must render as the NFT it acts on, never as a dust amount.
    #[test]
    fn an_nft_operation_describes_itself_as_a_named_nft_action() {
        let transfer = NftOperation::Transfer(nft_launcher_id())
            .describe()
            .expect("a launcher id encodes as an nft1 address");
        assert!(
            transfer.starts_with("transfer nft1"),
            "a transfer must read as an NFT action: {transfer}"
        );

        let mint = NftOperation::Mint(nft_launcher_id())
            .describe()
            .expect("a launcher id encodes as an nft1 address");
        assert!(
            mint.starts_with("mint nft1"),
            "a mint must read as an NFT action: {mint}"
        );
        assert_ne!(
            transfer, mint,
            "two different acts on the same NFT must never render identically"
        );
    }

    /// THE load-bearing test (#1058 CRITICAL#3, the defect the melt arm shipped with).
    ///
    /// The standard layer's `AGG_SIG_ME` commits to the delegated puzzle's TREE HASH, never to its
    /// SOLUTION. So a delegated puzzle that is NOT a bare quote turns one signature into a reusable
    /// blank cheque: it can emit an innocuous re-home under the solution presented for review and
    /// something else entirely under a replay of the same signature.
    ///
    /// The fixture is built to be exactly that and nothing else: the delegated puzzle is `1` — the
    /// CLVM identity program, which RETURNS ITS SOLUTION — solved with a well-formed re-home
    /// condition list. Every value-flow property the gate checks is therefore SATISFIED by what it
    /// emits today: one odd-amount `CREATE_COIN` to a free address, conserving value. A gate that
    /// decided admission on the presented conditions would accept it. Only a gate that decides on
    /// the artifact the signature commits to refuses it.
    #[test]
    fn a_solution_malleable_delegated_puzzle_is_refused_on_an_nft_transfer() {
        let (spends, presented) = malleable_nft_transfer();

        // The fixture is only load-bearing if the conditions it PRESENTS are an honest transfer;
        // otherwise it would be refused for being malformed and would prove nothing about
        // malleability. Assert that first.
        assert_eq!(
            presented.len(),
            1,
            "the presented condition list must be a single, well-formed re-home"
        );
        let create = presented[0]
            .as_create_coin()
            .expect("the presented condition must be the re-home CREATE_COIN");
        assert_eq!(
            create.amount % 2,
            1,
            "an honest odd-amount singleton re-home"
        );
        assert!(
            !is_protocol_sink_hash(create.puzzle_hash),
            "an honest re-home to a free address the gate has no other reason to refuse"
        );

        let err = analyze(&spends).expect_err(
            "a delegated puzzle that returns its solution is a blank cheque over the coin and \
             MUST be refused, however honest the presented solution looks",
        );
        assert!(
            err.message.contains("not the canonical quote form")
                || err.message.contains("not quote-form"),
            "the refusal must name the malleability, not an incidental parse failure: {}",
            err.message
        );
    }

    /// The widening stops at transfer and mint: an NFT METADATA UPDATE stays refused.
    ///
    /// An update is not a transfer, and a confirm screen saying "transfer NFT nft1…" would not
    /// describe it. It re-homes the singleton exactly as a transfer does, so nothing about the
    /// value flow distinguishes them — only the extra condition does, which is why the allowlist is
    /// default-DENY rather than a list of things to reject.
    #[test]
    fn an_nft_metadata_update_is_still_refused() {
        let err = analyze(&nft_metadata_update())
            .expect_err("a metadata update is not a transfer and must stay unsignable");
        assert!(
            err.message.contains("outside the re-home allowlist"),
            "the refusal must come from the default-deny allowlist: {}",
            err.message
        );
    }

    /// The widening stops at transfer and mint: assigning an NFT's OWNER — a DID link, and the same
    /// condition an offer's settlement lock emits — stays refused.
    #[test]
    fn an_nft_owner_assignment_is_still_refused() {
        let err = analyze(&nft_owner_assignment())
            .expect_err("an owner assignment is not a transfer and must stay unsignable");
        assert!(
            err.message.contains("outside the re-home allowlist"),
            "the refusal must come from the default-deny allowlist: {}",
            err.message
        );
    }

    /// The launcher/eve legs are UNSIGNED, so the only thing binding them to the user's intent is
    /// that this bundle performs the mint. An unrelated launcher+eve pair appended to a bundle the
    /// human approved for something else must be refused.
    ///
    /// The fixture varies exactly ONE actor and keeps a truthful control: the SAME two mint legs
    /// that are accepted in `an_nft_mint_is_authorized_and_named` are re-parented onto a foreign
    /// funding coin that this bundle does not spend. Everything else — the puzzles, the conditions,
    /// the amounts — is byte-identical to the accepted case, so a pass here could only come from
    /// the binding being absent.
    #[test]
    fn a_foreign_launcher_riding_along_is_refused() {
        let mut spends = nft_mint();
        // Drop the funding coin: the launcher and eve spends now descend from a coin outside the
        // bundle, which is precisely the ride-along shape.
        let launcher_hash = Bytes32::new(SINGLETON_LAUNCHER_HASH);
        let funding_index = spends
            .iter()
            .position(|spend| {
                spend.coin.puzzle_hash != launcher_hash
                    && spend.coin.parent_coin_info == nft_funding_coin().parent_coin_info
            })
            .expect("the mint bundle funds itself from an ordinary wallet coin");
        spends.remove(funding_index);

        let err = analyze(&spends)
            .expect_err("a launcher this bundle did not create must not ride along");
        assert!(
            err.message.contains("did not create the launcher")
                || err.message.contains("creates no launcher output"),
            "the refusal must name the missing launcher provenance: {}",
            err.message
        );
    }

    /// An eve spend whose parent is not a launcher THIS bundle spent is refused — the second edge
    /// of the mint binding, checked independently of the first.
    ///
    /// Two hops are needed to see it: with only the launcher edge under test, a gate that dropped
    /// the eve edge entirely would still pass. Here the launcher edge is fully SATISFIED (a real
    /// funding coin creates a real launcher, both spent in this bundle) and only the eve's descent
    /// is foreign, so the test can fail for exactly one reason.
    #[test]
    fn an_eve_spend_from_a_foreign_launcher_is_refused() {
        let mut spends = nft_mint();
        let launcher_hash = Bytes32::new(SINGLETON_LAUNCHER_HASH);
        let launcher_id = spends
            .iter()
            .find(|spend| spend.coin.puzzle_hash == launcher_hash)
            .expect("the mint spends a launcher")
            .coin
            .coin_id();

        // A SECOND, unrelated mint's eve spend, appended to a bundle whose own launcher edge is
        // intact. Its launcher is not spent here, so only the eve edge can refuse it.
        let foreign = foreign_eve_spend();
        assert_ne!(
            foreign.coin.parent_coin_info, launcher_id,
            "the fixture is only meaningful if the eve descends from a DIFFERENT launcher"
        );
        spends.push(foreign);

        let err = analyze(&spends)
            .expect_err("an eve spend from a launcher outside this bundle must be refused");
        assert!(
            err.message
                .contains("does not descend from a launcher spent in this bundle"),
            "the refusal must name the eve's foreign descent: {}",
            err.message
        );
    }

    /// A singleton MELT of an NFT is not a transfer and is not admitted by the new arms: the NFT
    /// arm refuses it (it does not re-home), and it never reaches the melt arm, which is reserved
    /// for the profile singletons it was built for.
    #[test]
    fn an_nft_melt_is_refused_by_the_nft_arm() {
        let err =
            analyze(&nft_melt()).expect_err("melting an NFT is not one of the two signable acts");
        assert!(
            err.message.contains("outside the re-home allowlist")
                || err.message.contains("does not re-home the singleton"),
            "the refusal must come from the NFT arm, not the melt arm: {}",
            err.message
        );
    }
}
