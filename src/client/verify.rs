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
//! Only the two spend classes the engine builds today are decodable: a standard-layer XCH send and
//! a CAT send (each optionally with standard-layer XCH fee/support coins). Any coin spend the driver
//! cannot fully parse+account for — a foreign puzzle, a value leak, a minted CAT — yields
//! [`WalletErrorCode::SpendValidationFailed`]; the signer refuses to sign it. (Offers/options/tips
//! reaching the signer are refused here until their decoders land — that is intended.)

use std::collections::BTreeMap;

use chia::clvm_traits::FromClvm;
use chia::protocol::{Bytes32, CoinSpend};
use chia::puzzles::Memos;
use chia_wallet_sdk::driver::{Cat, Layer, Puzzle, StandardLayer};
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
    let mut recipients = Vec::new();
    let mut change = Vec::new();
    let mut fee: u64 = 0;

    // Per-asset value ledgers (None-keyed XCH is tracked separately below).
    let mut xch_in: u64 = 0;
    let mut xch_out: u64 = 0;
    let mut cat_in: BTreeMap<Bytes32, u64> = BTreeMap::new();
    let mut cat_out: BTreeMap<Bytes32, u64> = BTreeMap::new();

    for spend in coin_spends {
        let puzzle_ptr = node_from_bytes(&mut allocator, &spend.puzzle_reveal)
            .map_err(|e| reject(format!("undecodable puzzle reveal: {e:?}")))?;
        let solution_ptr = node_from_bytes(&mut allocator, &spend.solution)
            .map_err(|e| reject(format!("undecodable solution: {e:?}")))?;
        let puzzle = Puzzle::parse(&allocator, puzzle_ptr);

        // A CAT coin: the value flows through its INNER p2 conditions, denominated in the asset.
        if let Some((cat, inner_puzzle, inner_solution)) =
            Cat::parse(&allocator, spend.coin, puzzle, solution_ptr)
                .map_err(|e| reject(format!("malformed CAT spend: {e:?}")))?
        {
            let asset = cat.info.asset_id;
            *cat_in.entry(asset).or_default() += spend.coin.amount;
            for condition in run_conditions(&mut allocator, inner_puzzle.ptr(), inner_solution)? {
                if let Some(create) = condition.into_create_coin() {
                    *cat_out.entry(asset).or_default() += create.amount;
                    classify(
                        &mut recipients,
                        &mut change,
                        DecodedOutput {
                            puzzle_hash: create.puzzle_hash,
                            amount: create.amount,
                            asset_id: Some(asset),
                        },
                        &create.memos,
                    );
                }
            }
            continue;
        }

        // A standard-layer XCH coin: its run conditions carry the XCH outputs + the fee.
        if StandardLayer::parse_puzzle(&allocator, puzzle)
            .map_err(|e| reject(format!("malformed standard spend: {e:?}")))?
            .is_some()
        {
            xch_in += spend.coin.amount;
            for condition in run_conditions(&mut allocator, puzzle_ptr, solution_ptr)? {
                if let Some(reserve) = condition.as_reserve_fee() {
                    fee = fee
                        .checked_add(reserve.amount)
                        .ok_or_else(|| reject("fee overflow"))?;
                    continue;
                }
                if let Some(create) = condition.into_create_coin() {
                    xch_out += create.amount;
                    classify(
                        &mut recipients,
                        &mut change,
                        DecodedOutput {
                            puzzle_hash: create.puzzle_hash,
                            amount: create.amount,
                            asset_id: None,
                        },
                        &create.memos,
                    );
                }
            }
            continue;
        }

        return Err(reject(
            "coin spend is neither a standard-layer XCH nor a CAT spend; refusing to sign",
        ));
    }

    // Value must conserve per asset, or the spend leaks/mints value.
    let xch_out_plus_fee = xch_out
        .checked_add(fee)
        .ok_or_else(|| reject("XCH output + fee overflow"))?;
    if xch_in != xch_out_plus_fee {
        return Err(reject(format!(
            "XCH value not conserved: in {xch_in} != out+fee {xch_out_plus_fee}"
        )));
    }
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
        recipients,
        change,
        fee,
    })
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
