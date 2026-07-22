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
//! Four spend classes are decodable: a standard-layer XCH send, a CAT send, and an NFT or DID
//! singleton spend (each optionally with standard-layer XCH fee/support coins). Every class is
//! owner-controlled through the SAME standard-layer p2 puzzle, so all four share ONE fail-closed
//! accounting core ([`Ledger::account_p2`]): the p2 MUST be a quote-form standard layer carrying
//! exactly one committed `AGG_SIG_ME` and no other signature condition (controls #1058/#1519). A
//! singleton's mojo amount is native XCH locked in the singleton, so NFT/DID spends fold into the
//! same XCH value ledger as a plain send — an NFT/DID that melts value to an unaccounted output
//! surfaces either as a visible recipient or as broken conservation, never a silent drain. Any coin
//! spend the drivers cannot FULLY parse+account for — a foreign puzzle, a value leak, a minted CAT,
//! a non-standard singleton owner, a mint/launcher spend — yields
//! [`WalletErrorCode::SpendValidationFailed`]; the signer refuses to sign it. (Offers/options/tips
//! and NFT/DID MINT bundles reaching the signer are refused here until their decoders land — that is
//! intended: B2 decodes the TRANSFER/update of an existing NFT/DID singleton, not launcher mints.)

use std::collections::BTreeMap;

use chia::clvm_traits::FromClvm;
use chia::clvm_utils::tree_hash;
use chia::protocol::{Bytes32, CoinSpend};
use chia::puzzles::Memos;
use chia_wallet_sdk::driver::{Cat, Did, Layer, Nft, Puzzle, StandardLayer};
use chia_wallet_sdk::types::{run_puzzle, Condition};
use chia_wallet_sdk::utils::Address as Bech32Address;
use clvmr::serde::node_from_bytes;
use clvmr::Allocator;

use crate::types::{
    Address, Amount, AssetId, SpendOutput, TransactionSummary, WalletError, WalletErrorCode,
    WalletResult,
};

/// One coin the spend creates, re-derived from a coin spend's own puzzle + solution.
#[derive(Debug, Clone, PartialEq, Eq)]
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
/// [`recipients`](SpendEffect::recipients) are the HINTED (memo-carrying) outputs a payment sends to
/// a counterparty; [`change`](SpendEffect::change) are the un-hinted outputs a well-formed spend
/// returns to itself. The signer requires every change output to be wallet-owned, so no value can
/// silently leave the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendEffect {
    /// The hinted outputs (payments to counterparties).
    pub recipients: Vec<DecodedOutput>,
    /// The un-hinted outputs (change back to the spender).
    pub change: Vec<DecodedOutput>,
    /// The farmer fee (XCH mojos), summed from the spend's `RESERVE_FEE` conditions.
    pub fee: u64,
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
    let mut ledger = Ledger::default();

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
        if let Some((cat, inner_puzzle, inner_solution)) =
            Cat::parse(&allocator, spend.coin, puzzle, solution_ptr)
                .map_err(|e| reject(format!("malformed CAT spend: {e:?}")))?
        {
            ledger.account_p2(
                &mut allocator,
                spend.coin.amount,
                Some(cat.info.asset_id),
                inner_puzzle,
                inner_solution,
            )?;
            continue;
        }

        // An NFT coin: an owner-controlled singleton. `Nft::parse` unwraps the singleton +
        // state/ownership layers and hands back the SAME standard-layer p2 puzzle+solution the owner
        // authorizes the spend through; its mojo amount is native XCH locked in the singleton, so it
        // folds into the XCH ledger. A transfer recreates the singleton (1 mojo out) to the new
        // owner; any value melted to an extra output surfaces there and is conserved-checked.
        if let Some((_nft, inner_puzzle, inner_solution)) =
            Nft::parse(&allocator, spend.coin, puzzle, solution_ptr)
                .map_err(|e| reject(format!("malformed NFT spend: {e:?}")))?
        {
            ledger.account_p2(
                &mut allocator,
                spend.coin.amount,
                None,
                inner_puzzle,
                inner_solution,
            )?;
            continue;
        }

        // A DID coin: an owner-controlled singleton, accounted exactly like an NFT. `Did::parse`
        // yields the inner p2 spend only when the DID solution is a normal spend; a recovery/augmented
        // solution (no p2 spend) cannot be value-accounted, so it is refused fail-closed.
        if let Some((_did, inner_spend)) =
            Did::parse(&allocator, spend.coin, puzzle, solution_ptr)
                .map_err(|e| reject(format!("malformed DID spend: {e:?}")))?
        {
            let Some((inner_puzzle, inner_solution)) = inner_spend else {
                return Err(reject(
                    "DID spend carries no inner p2 spend (recovery/augmented); refusing to sign",
                ));
            };
            ledger.account_p2(
                &mut allocator,
                spend.coin.amount,
                None,
                inner_puzzle,
                inner_solution,
            )?;
            continue;
        }

        // A plain standard-layer XCH coin: its own run conditions carry the XCH outputs + the fee.
        if StandardLayer::parse_puzzle(&allocator, puzzle)
            .map_err(|e| reject(format!("malformed standard spend: {e:?}")))?
            .is_some()
        {
            ledger.account_p2(&mut allocator, spend.coin.amount, None, puzzle, solution_ptr)?;
            continue;
        }

        return Err(reject(
            "coin spend is not a standard-XCH, CAT, NFT, or DID spend; refusing to sign",
        ));
    }

    ledger.into_effect()
}

/// The mutable value-flow accounting state threaded through every coin spend in a bundle.
///
/// Fungible value is tracked per asset (`None`-keyed XCH separately from each CAT tail); NFT/DID
/// singletons fold into the XCH ledger because a singleton's mojo amount IS native XCH. Recipients
/// (hinted outputs) and change (un-hinted, owner-retained) are separated for the signer's gate.
#[derive(Default)]
struct Ledger {
    recipients: Vec<DecodedOutput>,
    change: Vec<DecodedOutput>,
    fee: u64,
    xch_in: u64,
    xch_out: u64,
    cat_in: BTreeMap<Bytes32, u64>,
    cat_out: BTreeMap<Bytes32, u64>,
}

impl Ledger {
    /// Account one owner-controlled standard-layer p2 spend — the common decode shared by a plain
    /// XCH send, a CAT inner spend, and an NFT/DID singleton inner spend. `coin_amount` is the mojos
    /// the (outer) coin carries; `asset` denominates them (`None` = native XCH, incl. singletons).
    ///
    /// Fail-closed custody controls, identical for every class (#1058/#1519): the p2 puzzle MUST be a
    /// standard layer whose delegated puzzle is the canonical quote form, carrying EXACTLY ONE
    /// `AGG_SIG_ME` committed to that quote's tree hash and no other signature condition — otherwise
    /// the signed message would not commit to the exact outputs this decode accounts for.
    fn account_p2(
        &mut self,
        allocator: &mut Allocator,
        coin_amount: u64,
        asset: Option<Bytes32>,
        p2_puzzle: Puzzle,
        p2_solution: clvmr::NodePtr,
    ) -> WalletResult<()> {
        if StandardLayer::parse_puzzle(allocator, p2_puzzle)
            .map_err(|e| reject(format!("malformed standard/p2 puzzle: {e:?}")))?
            .is_none()
        {
            return Err(reject(
                "spend's owner puzzle is not a standard layer; refusing to sign",
            ));
        }
        let committed_message = committed_delegated_puzzle_message(allocator, p2_solution)?;

        self.credit_input(asset, coin_amount)?;

        let conditions = run_conditions(allocator, p2_puzzle.ptr(), p2_solution)?;
        enforce_sole_agg_sig_me(&conditions, committed_message)?;
        for condition in &conditions {
            reject_unexpected_agg_sig(condition)?;
            // A singleton (NFT/DID) inner spend cannot emit its own fee (it holds only its odd mojo);
            // a RESERVE_FEE only ever appears in a plain XCH-denominated spend, so folding it into the
            // XCH fee is correct for every class (a singleton that under-recreates fails conservation).
            if let Some(reserve) = condition.as_reserve_fee() {
                self.fee = self
                    .fee
                    .checked_add(reserve.amount)
                    .ok_or_else(|| reject("fee overflow"))?;
                continue;
            }
            if let Some(create) = condition.as_create_coin() {
                self.debit_output(asset, create.amount)?;
                classify(
                    &mut self.recipients,
                    &mut self.change,
                    DecodedOutput {
                        puzzle_hash: create.puzzle_hash,
                        amount: create.amount,
                        asset_id: asset,
                    },
                    &create.memos,
                );
            }
        }
        Ok(())
    }

    /// Add `amount` to the input side of `asset`'s ledger (XCH when `None`), overflow-checked.
    fn credit_input(&mut self, asset: Option<Bytes32>, amount: u64) -> WalletResult<()> {
        match asset {
            None => {
                self.xch_in = self
                    .xch_in
                    .checked_add(amount)
                    .ok_or_else(|| reject("XCH input overflow"))?;
            }
            Some(id) => *self.cat_in.entry(id).or_default() += amount,
        }
        Ok(())
    }

    /// Add `amount` to the output side of `asset`'s ledger (XCH when `None`), overflow-checked.
    fn debit_output(&mut self, asset: Option<Bytes32>, amount: u64) -> WalletResult<()> {
        match asset {
            None => {
                self.xch_out = self
                    .xch_out
                    .checked_add(amount)
                    .ok_or_else(|| reject("XCH output overflow"))?;
            }
            Some(id) => *self.cat_out.entry(id).or_default() += amount,
        }
        Ok(())
    }

    /// Enforce per-asset value conservation and produce the [`SpendEffect`]. Value must conserve or
    /// the spend leaks/mints: XCH `in == out + fee`, and every CAT tail `in == out`.
    fn into_effect(self) -> WalletResult<SpendEffect> {
        let xch_out_plus_fee = self
            .xch_out
            .checked_add(self.fee)
            .ok_or_else(|| reject("XCH output + fee overflow"))?;
        if self.xch_in != xch_out_plus_fee {
            return Err(reject(format!(
                "XCH value not conserved: in {} != out+fee {xch_out_plus_fee}",
                self.xch_in
            )));
        }
        // Conservation is checked in BOTH directions over the union of assets seen as inputs or
        // outputs: an output whose asset was never an input is a mint from thin air; an input asset
        // with no (or a smaller) matching output is a melt/leak. Iterating one side would miss the
        // other.
        for asset in self.cat_in.keys().chain(self.cat_out.keys()) {
            let input = self.cat_in.get(asset).copied().unwrap_or(0);
            let output = self.cat_out.get(asset).copied().unwrap_or(0);
            if input != output {
                return Err(reject(format!(
                    "CAT {} value not conserved: in {input} != out {output}",
                    hex::encode(asset)
                )));
            }
        }
        Ok(SpendEffect {
            recipients: self.recipients,
            change: self.change,
            fee: self.fee,
        })
    }
}

/// Re-derive the human-facing [`TransactionSummary`] from `coin_spends` alone — the authoritative
/// summary the confirm surface renders and the signer gates on (never the engine's claim).
pub fn derive_summary(coin_spends: &[CoinSpend]) -> WalletResult<TransactionSummary> {
    let effect = analyze(coin_spends)?;
    let outputs = effect
        .recipients
        .iter()
        .map(|output| {
            Ok(SpendOutput {
                address: encode_xch_address(output.puzzle_hash)?,
                amount: Amount(output.amount),
                asset_id: output.asset_id.map(|asset| AssetId(hex::encode(asset))),
            })
        })
        .collect::<WalletResult<Vec<_>>>()?;
    Ok(TransactionSummary {
        outputs,
        fee: Amount(effect.fee),
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

/// Sort a decoded output into recipients (hinted) vs change (un-hinted). The engine hints every
/// counterparty payment with a memo and leaves change memo-less, so the memo presence is the
/// recipient/change discriminator.
fn classify(
    recipients: &mut Vec<DecodedOutput>,
    change: &mut Vec<DecodedOutput>,
    output: DecodedOutput,
    memos: &Memos<clvmr::NodePtr>,
) {
    if matches!(memos, Memos::Some(_)) {
        recipients.push(output);
    } else {
        change.push(output);
    }
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
    let forbidden = matches!(
        condition,
        Condition::AggSigUnsafe(_)
            | Condition::AggSigParent(_)
            | Condition::AggSigPuzzle(_)
            | Condition::AggSigAmount(_)
            | Condition::AggSigPuzzleAmount(_)
            | Condition::AggSigParentAmount(_)
            | Condition::AggSigParentPuzzle(_)
    );
    if forbidden {
        return Err(reject(
            "unexpected non-AGG_SIG_ME signature condition in a send spend (refusing to sign)",
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

#[cfg(all(test, feature = "engine"))]
mod tests {
    use super::*;
    use crate::engine::build::{SdkSpendBuilder, SpendBuilder, SpendInputs};
    use crate::types::{IdentityRef, Network, SendCatRequest, SendXchRequest, WalletId};
    use chia::protocol::Coin;
    use chia::puzzles::standard::StandardArgs;
    use chia_wallet_sdk::driver::{Cat, SpendContext};
    use chia_wallet_sdk::types::Conditions;
    use std::sync::Arc;

    /// The compressed BLS12-381 G1 generator — a valid, non-infinity public key used to curry a
    /// standard puzzle in tests without any secret material (mirrors src/engine/build.rs).
    fn test_public_key() -> chia::bls::PublicKey {
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
        chia::bls::PublicKey::from_bytes(&g).expect("valid G1 generator")
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
        let (_, cats) = Cat::issue_with_coin(&mut ctx, genesis.coin_id(), amount, create).unwrap();
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
        fn synthetic_key(&self, ph: Bytes32) -> Option<chia::bls::PublicKey> {
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

    /// Golden: the re-derived summary reproduces exactly what the XCH builder claimed.
    #[tokio::test]
    async fn derive_summary_matches_the_xch_builder() {
        let unsigned = builder(vec![wallet_coin(1000, 1)], vec![])
            .build_send_xch(xch_request(600, 10))
            .await
            .unwrap();
        let derived = derive_summary(&unsigned.coin_spends).unwrap();
        assert_eq!(derived, unsigned.summary);
    }

    /// Golden: the re-derived summary reproduces exactly what the CAT builder claimed (the engine
    /// summary's asset id must be the real tail hash for byte-equality).
    #[tokio::test]
    async fn derive_summary_matches_the_cat_builder() {
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
        assert_eq!(derived, unsigned.summary);
    }

    /// The change output is classified as change (un-hinted) and the recipient as a recipient.
    #[tokio::test]
    async fn analyze_separates_recipient_from_change() {
        let effect = analyze(
            &builder(vec![wallet_coin(1000, 1)], vec![])
                .build_send_xch(xch_request(600, 10))
                .await
                .unwrap()
                .coin_spends,
        )
        .unwrap();
        assert_eq!(effect.recipients.len(), 1);
        assert_eq!(effect.recipients[0].amount, 600);
        assert_eq!(effect.fee, 10);
        // Change (1000 - 600 - 10 = 390) goes back to the wallet, un-hinted.
        assert_eq!(effect.change.len(), 1);
        assert_eq!(effect.change[0].amount, 390);
        assert_eq!(effect.change[0].puzzle_hash, wallet_ph());
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
        use chia::protocol::Coin;
        use chia::puzzles::Memos;
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

    use chia::protocol::Bytes;
    use chia_wallet_sdk::types::conditions::AggSigMe;

    fn agg_sig_me(message: [u8; 32]) -> Condition {
        Condition::AggSigMe(AggSigMe::new(
            test_public_key(),
            Bytes::from(message.to_vec()),
        ))
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
}
