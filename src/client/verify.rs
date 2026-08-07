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

use std::collections::{BTreeMap, HashMap};

use chia_protocol::{Bytes32, CoinSpend};
use chia_wallet_sdk::driver::{
    Cat, Layer, OptionContract, P2OneOfManyLayer, Puzzle, SettlementLayer, StandardLayer,
};
use chia_wallet_sdk::puzzles::{SETTLEMENT_PAYMENT_HASH, SINGLETON_LAUNCHER_HASH};
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

/// Re-derive the value flow of `coin_spends` from the coin spends alone, fail-closed.
///
/// Each coin spend is parsed with the chia-wallet-sdk drivers: a CAT spend via [`Cat::parse`] (its
/// inner p2 conditions carry the CAT outputs), a standard spend via [`StandardLayer`] (its run
/// conditions carry the XCH outputs + fee). Value is checked to conserve per asset. Anything the
/// drivers cannot fully account for is rejected with [`WalletErrorCode::SpendValidationFailed`].
pub fn analyze(coin_spends: &[CoinSpend]) -> WalletResult<SpendEffect> {
    if coin_spends.is_empty() {
        return Err(reject("no coin spends to verify"));
    }

    let mut allocator = Allocator::new();
    let mut outputs = Vec::new();
    let mut protocol_sink = Vec::new();
    let mut fee: u64 = 0;

    // Per-asset value ledgers (None-keyed XCH is tracked separately below).
    let mut xch_in: u64 = 0;
    let mut xch_out: u64 = 0;
    let mut cat_in: BTreeMap<Bytes32, u64> = BTreeMap::new();
    let mut cat_out: BTreeMap<Bytes32, u64> = BTreeMap::new();

    // Offer-binding facts (#2241) gathered from every WALLET-SIGNED coin, checked at the bundle level
    // AFTER the loop. A make emits the requested-payment announcement on ONE offered coin and rings
    // the rest with concurrency, so the binding is a property of the whole bundle, never one coin.
    let mut bindings: Vec<CoinBinding> = Vec::new();

    // OPTION MODE is gated on the presence of an option-layer coin. For a signable option action that
    // means a TRANSFER's singleton ([`OptionContract`]); an EXERCISE bundle (its [`P2OneOfManyLayer`]
    // underlying leg) is detected here too but refused fail-closed in the loop below before conservation
    // runs. It selects IMPLICIT-fee conservation: the option builders emit no `RESERVE_FEE` and the
    // 1-mojo singleton flows through to the re-homed coin, so `in − out` IS the fee. The strict
    // XCH/CAT/offer path is byte-unchanged when this is false.
    let option_mode = is_option_bundle(&mut allocator, coin_spends)?;

    for spend in coin_spends {
        let puzzle_ptr = node_from_bytes(&mut allocator, &spend.puzzle_reveal)
            .map_err(|e| reject(format!("undecodable puzzle reveal: {e:?}")))?;
        let solution_ptr = node_from_bytes(&mut allocator, &spend.solution)
            .map_err(|e| reject(format!("undecodable solution: {e:?}")))?;

        // (#1518) Bind the reveal to the coin BEFORE trusting anything it decodes to. A coin commits
        // on-chain only to its puzzle HASH; the `puzzle_reveal` is caller-supplied bytes. If the
        // reveal does not hash to `coin.puzzle_hash` it is a substituted puzzle the coin never
        // authorized — a malicious engine could pair a benign-looking reveal (that `analyze` accounts
        // for cleanly) with a coin whose real puzzle does something else entirely. Reject fail-closed
        // so every value flow this module derives is the coin's OWN authorized program.
        let revealed_hash = Bytes32::new(tree_hash(&allocator, puzzle_ptr).to_bytes());
        if revealed_hash != spend.coin.puzzle_hash {
            return Err(reject(format!(
                "puzzle reveal hashes to {} but the coin commits to {} (substituted puzzle)",
                hex::encode(revealed_hash),
                hex::encode(spend.coin.puzzle_hash)
            )));
        }

        let puzzle = Puzzle::parse(&allocator, puzzle_ptr);

        // A CAT coin: the value flows through its INNER p2 conditions, denominated in the asset.
        if let Some(parsed) = Cat::parse(&allocator, spend.coin, puzzle, solution_ptr)
            .map_err(|e| reject(format!("malformed CAT spend: {e:?}")))?
        {
            // 0.34's `Cat::parse` returns a `ParsedCat` struct in place of the old
            // `(Cat, inner_puzzle, inner_solution)` tuple; `p2_puzzle`/`p2_solution` are the
            // exact same inner p2 puzzle/solution the tuple carried (non-revocable CAT path).
            let cat = parsed.cat;
            let inner_puzzle = parsed.p2_puzzle;
            let inner_solution = parsed.p2_solution;
            let asset = cat.info.asset_id;

            // Every CAT coin's own amount is value entering the spend, whoever authorizes it.
            let cat_in_total = cat_in.entry(asset).or_default();
            *cat_in_total = accumulate(*cat_in_total, spend.coin.amount, "CAT input total")?;

            // A CAT coin the wallet CLAIMS as part of taking/cancelling an offer wraps the canonical
            // settlement puzzle: it is spent by announcement, carries NO signature, and its notarized
            // payments are the outputs. Account those but skip the wallet-signed-coin guards (there is
            // nothing to sign, and the settlement puzzle is a fixed structure, not a delegated one).
            if SettlementLayer::parse_puzzle(&allocator, inner_puzzle)
                .map_err(|e| reject(format!("malformed CAT settlement puzzle: {e:?}")))?
                .is_some()
            {
                let conditions =
                    run_conditions(&mut allocator, inner_puzzle.ptr(), inner_solution)?;
                reject_any_agg_sig(&conditions)?;
                for create in conditions.iter().filter_map(Condition::as_create_coin) {
                    let cat_out_total = cat_out.entry(asset).or_default();
                    *cat_out_total = accumulate(*cat_out_total, create.amount, "CAT output total")?;
                    route_output(
                        &mut outputs,
                        &mut protocol_sink,
                        DecodedOutput {
                            puzzle_hash: create.puzzle_hash,
                            amount: create.amount,
                            asset_id: Some(asset),
                        },
                    );
                }
                continue;
            }

            // Otherwise it is a wallet-signed CAT send: its inner p2 MUST be a standard layer whose
            // delegated puzzle is quote-form — otherwise the signed message (tree-hash-only) would not
            // commit to the actual outputs (see `committed_delegated_puzzle_message`).
            if StandardLayer::parse_puzzle(&allocator, inner_puzzle)
                .map_err(|e| reject(format!("malformed CAT inner puzzle: {e:?}")))?
                .is_none()
            {
                return Err(reject(
                    "CAT inner puzzle is neither a standard layer nor a settlement layer; refusing \
                     to sign",
                ));
            }
            let committed_message = committed_delegated_puzzle_message(&allocator, inner_solution)?;
            let conditions = run_conditions(&mut allocator, inner_puzzle.ptr(), inner_solution)?;
            enforce_sole_agg_sig_me(&conditions, committed_message)?;
            bindings.push(coin_binding(&spend.coin, &conditions));
            for condition in &conditions {
                reject_unexpected_agg_sig(condition)?;
                if let Some(create) = condition.as_create_coin() {
                    let cat_out_total = cat_out.entry(asset).or_default();
                    *cat_out_total = accumulate(*cat_out_total, create.amount, "CAT output total")?;
                    route_output(
                        &mut outputs,
                        &mut protocol_sink,
                        DecodedOutput {
                            puzzle_hash: create.puzzle_hash,
                            amount: create.amount,
                            asset_id: Some(asset),
                        },
                    );
                }
            }
            continue;
        }

        // An OPTION SINGLETON spend (#1511 PR-C): the option contract is a singleton wrapping the current
        // owner's inner standard layer (the sole signed coin). Decode via `OptionContract::parse` to reach
        // that inner p2 and enforce the sole-AGG_SIG_ME commitment exactly as a standard/CAT send. ONLY a
        // re-homing TRANSFER (an odd-amount `CREATE_COIN` to the new owner) is signable; a spend that does
        // NOT re-home — a melt/exercise (mode-23 `SEND_MESSAGE` + `MeltSingleton`) or a clawback — is
        // refused fail-closed below, at the signature source, so the wallet never signs the leg that
        // unlocks the option underlying (Case-A guard, #1511 PR-C).
        if let Some((_option, inner_puzzle, inner_solution)) =
            OptionContract::parse(&allocator, spend.coin, puzzle, solution_ptr)
                .map_err(|e| reject(format!("malformed option singleton spend: {e:?}")))?
        {
            if StandardLayer::parse_puzzle(&allocator, inner_puzzle)
                .map_err(|e| reject(format!("malformed option inner puzzle: {e:?}")))?
                .is_none()
            {
                return Err(reject(
                    "option singleton inner puzzle is not a standard layer; refusing to sign",
                ));
            }
            let committed_message = committed_delegated_puzzle_message(&allocator, inner_solution)?;
            let conditions = run_conditions(&mut allocator, inner_puzzle.ptr(), inner_solution)?;
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
                // attack (omit the underlying leg to dodge the `P2OneOfManyLayer` refusal below) cannot
                // obtain the wallet's signature on the melt+message spend that unlocks the underlying.
                // (A plain transfer decodes an odd-amount `CREATE_COIN(amount = 1)` and takes the
                // re-home branch above, so it is unaffected.)
                return Err(reject(
                    "option singleton spend does not re-home (melt/exercise or clawback); only a \
                     re-homing TRANSFER is signable; refusing to sign",
                ));
            }

            // TRANSFER: the singleton's 1 mojo flows through to the re-homed coin — count both.
            xch_in = accumulate(xch_in, spend.coin.amount, "XCH input total")?;
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
                    xch_out = accumulate(xch_out, create.amount, "XCH output total")?;
                    route_output(
                        &mut outputs,
                        &mut protocol_sink,
                        DecodedOutput {
                            puzzle_hash: create.puzzle_hash,
                            amount: create.amount,
                            asset_id: None,
                        },
                    );
                }
            }
            continue;
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
        if P2OneOfManyLayer::parse_puzzle(&allocator, puzzle)
            .map_err(|e| reject(format!("malformed option underlying spend: {e:?}")))?
            .is_some()
        {
            return Err(reject(
                "option exercise is not signable: the unlocked underlying's reclaim to the holder is \
                 not consensus-forced, so a compromised engine could strip it after the wallet funds \
                 the strike (deferred to #2245); refusing to sign",
            ));
        }

        // A standard-layer XCH coin: its run conditions carry the XCH outputs + the fee.
        if StandardLayer::parse_puzzle(&allocator, puzzle)
            .map_err(|e| reject(format!("malformed standard spend: {e:?}")))?
            .is_some()
        {
            let committed_message = committed_delegated_puzzle_message(&allocator, solution_ptr)?;
            xch_in = accumulate(xch_in, spend.coin.amount, "XCH input total")?;
            let conditions = run_conditions(&mut allocator, puzzle_ptr, solution_ptr)?;
            enforce_sole_agg_sig_me(&conditions, committed_message)?;
            // In an option TRANSFER a standard-layer XCH coin only ever appears as the OPTIONAL farmer-fee
            // coin the engine links to the singleton via `assert_concurrent_spend` (transfer itself takes
            // no fee). It legitimately commits no value to the settlement puzzle, so MR-6's
            // give-it-away-for-nothing binding does not apply — skip it in option mode. Only the strict
            // offer path requires MR-6. (Exercise never reaches here: its option-singleton melt/message
            // leg is refused fail-closed above, at the signature source.) The binding is now enforced
            // at the bundle level after the loop; an option-mode farmer-fee coin commits no value to
            // settlement (no sink), so it is inert in that pass.
            bindings.push(coin_binding(&spend.coin, &conditions));
            for condition in &conditions {
                reject_unexpected_agg_sig(condition)?;
                if let Some(reserve) = condition.as_reserve_fee() {
                    fee = accumulate(fee, reserve.amount, "reserved fee total")?;
                    continue;
                }
                if let Some(create) = condition.as_create_coin() {
                    xch_out = accumulate(xch_out, create.amount, "XCH output total")?;
                    route_output(
                        &mut outputs,
                        &mut protocol_sink,
                        DecodedOutput {
                            puzzle_hash: create.puzzle_hash,
                            amount: create.amount,
                            asset_id: None,
                        },
                    );
                }
            }
            continue;
        }

        // A settlement-payments (XCH) coin the wallet CLAIMS while taking/cancelling an offer: the
        // canonical, immutable settlement puzzle, spent by announcement with NO signature. Account its
        // notarized-payment outputs into the XCH ledger; there is nothing to sign here.
        if SettlementLayer::parse_puzzle(&allocator, puzzle)
            .map_err(|e| reject(format!("malformed settlement spend: {e:?}")))?
            .is_some()
        {
            xch_in = accumulate(xch_in, spend.coin.amount, "XCH input total")?;
            let conditions = run_conditions(&mut allocator, puzzle_ptr, solution_ptr)?;
            reject_any_agg_sig(&conditions)?;
            for condition in &conditions {
                if let Some(create) = condition.as_create_coin() {
                    xch_out = accumulate(xch_out, create.amount, "XCH output total")?;
                    route_output(
                        &mut outputs,
                        &mut protocol_sink,
                        DecodedOutput {
                            puzzle_hash: create.puzzle_hash,
                            amount: create.amount,
                            asset_id: None,
                        },
                    );
                }
            }
            continue;
        }

        return Err(reject(
            "coin spend is not a standard-layer XCH, a CAT, an option, nor a settlement spend; \
             refusing to sign",
        ));
    }

    // Bundle-level offer-binding (#2241): every settlement-sink egress must be tied — directly or
    // through the concurrency ring — to an announcement that binds the requested payment.
    //
    // This pass is enforced UNCONDITIONALLY — never gated on `option_mode` (#2249). The MR-6 binding
    // was once disabled for the whole bundle whenever an option-layer coin flipped `option_mode` on,
    // which let an attacker include any option coin to route a standard coin's value into a settlement
    // sink with no binding enforced. The gate is per-EGRESS instead: `bindings` holds only the
    // WALLET-SIGNED coins that can commit value to settlement (standard-XCH + CAT sends) — an option
    // TRANSFER's singleton re-home never targets a structural sink hash (refused above at #345) and is
    // not pushed here, so it is inert in this pass. The one leg that legitimately carries no
    // offer-binding — the consensus-forced option EXERCISE strike — never reaches this pass at all:
    // exercise is refused fail-closed at the signature source (the non-re-home / `P2OneOfManyLayer`
    // refusals above), so no strike-leg exemption is needed here and none is granted.
    enforce_bundle_settlement_binding(&bindings)?;

    // XCH value conservation. Two modes:
    // - STRICT (XCH/CAT/offer, byte-unchanged): `in == out + reserve_fee`, a leak/mint is refused.
    // - OPTION (transfer): the builders emit no `RESERVE_FEE`, so the network-absorbed excess `in − out`
    //   IS the implicit fee. `out > in` (a mint) is still refused (checked_sub). The implicit fee is
    //   compared to the reviewed `summary.fee` by the signer (an MR-11-style implicit-fee guard).
    let effective_fee = if option_mode {
        xch_in.checked_sub(xch_out).ok_or_else(|| {
            reject(format!(
                "option spend mints value: outputs {xch_out} exceed inputs {xch_in}"
            ))
        })?
    } else {
        let xch_out_plus_fee = accumulate(xch_out, fee, "XCH output + fee total")?;
        if xch_in != xch_out_plus_fee {
            return Err(reject(format!(
                "XCH value not conserved: in {xch_in} != out+fee {xch_out_plus_fee}"
            )));
        }
        fee
    };
    // Conservation is checked in BOTH directions over the union of assets seen as inputs or outputs:
    // an output whose asset was never an input is a mint from thin air; an input asset with no (or a
    // smaller) matching output is a melt/leak. Iterating only one side would miss the other.
    for asset in cat_in.keys().chain(cat_out.keys()) {
        let input = cat_in.get(asset).copied().unwrap_or(0);
        let output = cat_out.get(asset).copied().unwrap_or(0);
        if input != output {
            return Err(reject(format!(
                "CAT {} value not conserved: in {input} != out {output}",
                hex::encode(asset)
            )));
        }
    }

    Ok(SpendEffect {
        outputs,
        protocol_sink,
        fee: effective_fee,
    })
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
    summarize_egress(&effect.outputs, &effect.protocol_sink, effect.fee)
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
    let solution = StandardLayer::parse_solution(allocator, standard_solution)
        .map_err(|e| reject(format!("malformed standard-layer solution: {e:?}")))?;
    // A quote is a pair whose first element is the atom `1`.
    let clvmr::SExp::Pair(quote_op, _) = allocator.sexp(solution.delegated_puzzle) else {
        return Err(reject(
            "delegated puzzle is not quote-form (not a pair) — signature would not commit to outputs",
        ));
    };
    if allocator.small_number(quote_op) != Some(1) {
        return Err(reject(
            "delegated puzzle is not the canonical quote form — signature would not commit to outputs",
        ));
    }
    Ok(tree_hash(allocator, solution.delegated_puzzle).to_bytes())
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
    if sole.message.as_ref() != expected_message.as_slice() {
        return Err(reject(
            "AGG_SIG_ME does not commit to the delegated-puzzle hash the outputs derive from \
             (refusing to sign)",
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
