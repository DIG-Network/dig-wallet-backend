//! `engine::build` — unsigned-spend construction (SPEC §3).
//!
//! The engine builds transactions with chia-wallet-sdk driver constructors and returns an
//! [`UnsignedSpend`] — the coin spends, the signatures they require, and a review summary. It
//! NEVER signs (that is the client-side [`super::signer::RemoteSigner`]) and NEVER hand-rolls
//! CLVM (§4.1): every spend flows through [`StandardLayer`]/[`Cat`]/[`Conditions`]/[`SpendContext`],
//! and the required signatures are extracted key-free via chia-wallet-sdk's
//! [`RequiredSignature`](chia_wallet_sdk::signer::RequiredSignature). A build is deterministic
//! given the same inputs + coin set, and is validated fail-closed (value conservation + a
//! non-empty signature set) before it can ever reach the broadcaster.
//!
//! # Where the public key material comes from
//! Building a valid `CoinSpend` needs the full input coins (with parent) and the *public*
//! synthetic key that controls each coin's puzzle hash. The engine holds no key, so this PUBLIC
//! material is supplied by an injected [`SpendInputs`] provider (implemented client-side from
//! public key material at engine start). The secret never enters here — the client's signer
//! later matches each [`RequiredSignature`](crate::types::RequiredSignature) back to the secret
//! it holds and produces the [`SignedBundle`](crate::types::SignedBundle).

use std::sync::Arc;

use async_trait::async_trait;
use chia::bls::PublicKey;
use chia::protocol::{Bytes32, Coin, CoinSpend};
use chia::puzzles::Memos;
use chia_wallet_sdk::driver::{Cat, CatSpend, SpendContext, SpendWithConditions, StandardLayer};
use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature as SdkRequiredSignature};
use chia_wallet_sdk::types::Conditions;
use chia_wallet_sdk::utils::Address as Bech32Address;
use clvmr::Allocator;

use crate::types::{
    Address, AssetId, IdentityRef, Network, RequiredSignature, SendCatRequest, SendXchRequest,
    SpendOutput, TransactionSummary, UnsignedSpend, WalletError, WalletErrorCode, WalletResult,
};

use super::selection::{select_for_spend, SelectionOutcome};

/// Builds unsigned spends. Every method returns an [`UnsignedSpend`] for client review + signing.
#[async_trait]
pub trait SpendBuilder: Send + Sync {
    /// Build an unsigned native-XCH send.
    async fn build_send_xch(&self, request: SendXchRequest) -> WalletResult<UnsignedSpend>;

    /// Build an unsigned CAT send.
    async fn build_send_cat(&self, request: SendCatRequest) -> WalletResult<UnsignedSpend>;
}

/// The PUBLIC spend-input material the engine builds against (SPEC §1.4 key isolation).
///
/// Supplied by the client seam at engine start from PUBLIC key material only: the full input
/// coins the wallet controls (with parent, so a valid `CoinSpend` can be constructed), the
/// synthetic standard-layer PUBLIC key controlling each coin's puzzle hash, and the wallet's
/// change puzzle hash. It NEVER carries a secret key — the engine holds an `Arc<dyn SpendInputs>`
/// and reads public material out of it.
pub trait SpendInputs: Send + Sync {
    /// The unspent XCH coins the `identity` controls, each with its parent (needed to build a
    /// spend). Used for native sends and to pay a CAT-send fee.
    fn spendable_xch(&self, identity: &IdentityRef) -> WalletResult<Vec<Coin>>;

    /// The unspent CAT coins (of `asset_id`) the `identity` controls, resolved with the lineage
    /// proof a CAT spend requires.
    fn spendable_cat(&self, identity: &IdentityRef, asset_id: &AssetId) -> WalletResult<Vec<Cat>>;

    /// The synthetic standard-layer PUBLIC key controlling `puzzle_hash`, if the wallet holds it.
    fn synthetic_key(&self, puzzle_hash: Bytes32) -> Option<PublicKey>;

    /// The puzzle hash change (and any wallet-retained output) is returned to.
    fn change_puzzle_hash(&self, identity: &IdentityRef) -> WalletResult<Bytes32>;
}

/// The concrete [`SpendBuilder`] — constructs unsigned spends via chia-wallet-sdk drivers.
///
/// Holds only PUBLIC material: the injected [`SpendInputs`] provider, the network (for the
/// aggregate-signature domain), and the coin-count cap selection is bounded by. No secret key.
pub struct SdkSpendBuilder {
    pub(crate) inputs: Arc<dyn SpendInputs>,
    pub(crate) network: Network,
    pub(crate) coin_cap: usize,
}

impl SdkSpendBuilder {
    /// Create a builder over an input provider, for `network`, bounding selection at `coin_cap`.
    pub fn new(inputs: Arc<dyn SpendInputs>, network: Network, coin_cap: usize) -> Self {
        Self {
            inputs,
            network,
            coin_cap,
        }
    }

    /// The aggregate-signature domain for the builder's network (the AGG_SIG_ME additional data
    /// each required signature is bound to).
    pub(crate) fn agg_sig_constants(&self) -> AggSigConstants {
        // Sourced from `dig-constants` — the SAME constant the client signer binds to
        // (`crate::client::signer`), so the message the engine builds and the message the signer
        // will accept are byte-identical by construction (no hand-copied hex to drift). The
        // `CHIA_L1_*` values are the Chia L1 genesis, NOT the DIG L2 genesis.
        let agg_sig_me = match self.network {
            Network::Mainnet => Bytes32::new(dig_constants::CHIA_L1_MAINNET_AGG_SIG_ME),
            // Testnet11 + the simulator share the testnet aggregate-signature domain.
            Network::Testnet | Network::Simulator => {
                Bytes32::new(dig_constants::CHIA_L1_TESTNET11_AGG_SIG_ME)
            }
        };
        AggSigConstants::new(agg_sig_me)
    }

    /// The synthetic PUBLIC key controlling `coin`, or a fail-closed error when the wallet does
    /// not hold it (a spend of a coin the wallet cannot authorize must never be built).
    fn key_for(&self, coin: &Coin) -> WalletResult<PublicKey> {
        self.inputs.synthetic_key(coin.puzzle_hash).ok_or_else(|| {
            WalletError::new(
                WalletErrorCode::SpendValidationFailed,
                "no public key for an input coin's puzzle hash",
            )
        })
    }

    /// Spend `coin` under its owning key with `conditions` (the standard-layer spend).
    fn spend_standard(
        &self,
        ctx: &mut SpendContext,
        coin: Coin,
        conditions: Conditions,
    ) -> WalletResult<()> {
        let key = self.key_for(&coin)?;
        StandardLayer::new(key)
            .spend(ctx, coin, conditions)
            .map_err(|e| spend_failed(format!("standard spend: {e:?}")))
    }

    /// Link every input after the first to the lead coin via `assert_concurrent_spend`, so the
    /// whole set must be spent together (the lead coin carries the payment conditions).
    fn link_supporting_coins(&self, ctx: &mut SpendContext, coins: &[Coin]) -> WalletResult<()> {
        let Some(lead) = coins.first() else {
            return Ok(());
        };
        let lead_id = lead.coin_id();
        for coin in &coins[1..] {
            self.spend_standard(
                ctx,
                *coin,
                Conditions::new().assert_concurrent_spend(lead_id),
            )?;
        }
        Ok(())
    }

    /// Extract the key-free required-signature descriptors for `coin_spends`.
    ///
    /// Runs each puzzle through chia-wallet-sdk's [`RequiredSignature`] extractor (no secret
    /// key), producing the `(public_key, message)` pairs the client signer must satisfy. A
    /// standard/CAT spend is BLS-only; a secp requirement is unexpected and rejected fail-closed.
    pub(crate) fn required_signatures(
        &self,
        coin_spends: &[CoinSpend],
    ) -> WalletResult<Vec<RequiredSignature>> {
        let mut allocator = Allocator::new();
        let constants = self.agg_sig_constants();
        let extracted =
            SdkRequiredSignature::from_coin_spends(&mut allocator, coin_spends, &constants)
                .map_err(|e| spend_failed(format!("required-signature extraction: {e:?}")))?;

        let mut required = Vec::with_capacity(extracted.len());
        for item in extracted {
            match item {
                SdkRequiredSignature::Bls(bls) => required.push(RequiredSignature {
                    public_key: bls.public_key,
                    message: bls.message(),
                }),
                SdkRequiredSignature::Secp(_) => {
                    return Err(spend_failed("unexpected secp signature in a wallet spend"))
                }
            }
        }
        Ok(required)
    }
}

#[async_trait]
impl SpendBuilder for SdkSpendBuilder {
    async fn build_send_xch(&self, request: SendXchRequest) -> WalletResult<UnsignedSpend> {
        let SendXchRequest {
            identity,
            to,
            amount,
            fee,
        } = request;
        let amount = amount.mojos();
        let fee = fee.mojos();
        let target = checked_target(amount, fee)?;

        let destination = decode_address(&to)?;
        let change_ph = self.inputs.change_puzzle_hash(&identity)?;
        let coins = self.inputs.spendable_xch(&identity)?;
        let selected = select_or_fail(&coins, target, self.coin_cap, "XCH")?;
        let total: u64 = selected.iter().map(|c| c.amount).sum();
        let change_amount = total - target;

        let mut ctx = SpendContext::new();
        let hint = ctx
            .hint(destination)
            .map_err(|e| spend_failed(format!("hint: {e:?}")))?;
        let mut conditions = Conditions::new().create_coin(destination, amount, hint);
        if change_amount > 0 {
            conditions = conditions.create_coin(change_ph, change_amount, Memos::None);
        }
        if fee > 0 {
            conditions = conditions.reserve_fee(fee);
        }
        self.spend_standard(&mut ctx, selected[0], conditions)?;
        self.link_supporting_coins(&mut ctx, &selected)?;
        let coin_spends = ctx.take();

        // Fail-closed: inputs must equal outputs + fee, and the spend must actually require
        // signatures. A conservation break or a signatureless spend never reaches broadcast.
        assert_conserved(total, amount + change_amount, fee)?;
        let required_signatures = self.required_signatures(&coin_spends)?;
        ensure_signed_offline(&coin_spends, &required_signatures)?;

        Ok(UnsignedSpend {
            coin_spends,
            required_signatures,
            summary: TransactionSummary {
                outputs: vec![SpendOutput {
                    address: to,
                    amount: crate::types::Amount(amount),
                    asset_id: None,
                }],
                fee: crate::types::Amount(fee),
            },
        })
    }

    async fn build_send_cat(&self, request: SendCatRequest) -> WalletResult<UnsignedSpend> {
        let SendCatRequest {
            identity,
            asset_id,
            to,
            amount,
            fee,
        } = request;
        let send_amount = amount.mojos();
        let fee = fee.mojos();
        if send_amount == 0 {
            return Err(WalletError::invalid_input(
                "a CAT send must move a non-zero amount",
            ));
        }

        let destination = decode_address(&to)?;
        let change_ph = self.inputs.change_puzzle_hash(&identity)?;
        let cats = self.inputs.spendable_cat(&identity, &asset_id)?;
        if cats.is_empty() {
            return Err(WalletError::new(
                WalletErrorCode::InsufficientFunds,
                format!("no spendable {} coins", asset_id.0),
            ));
        }
        let cat_total: u64 = cats.iter().map(|c| c.coin.amount).sum();
        if cat_total < send_amount {
            return Err(WalletError::new(
                WalletErrorCode::InsufficientFunds,
                format!("insufficient CAT: have {cat_total}, need {send_amount}"),
            ));
        }

        let mut ctx = SpendContext::new();
        let cat_change = cat_total - send_amount;
        let cat_spends = self.build_cat_inner_spends(
            &mut ctx,
            &cats,
            destination,
            send_amount,
            change_ph,
            cat_change,
        )?;
        Cat::spend_all(&mut ctx, &cat_spends)
            .map_err(|e| spend_failed(format!("cat spend_all: {e:?}")))?;

        if fee > 0 {
            self.add_xch_fee(&mut ctx, &identity, fee, change_ph, cats[0].coin.coin_id())?;
        }
        let coin_spends = ctx.take();

        let required_signatures = self.required_signatures(&coin_spends)?;
        ensure_signed_offline(&coin_spends, &required_signatures)?;

        Ok(UnsignedSpend {
            coin_spends,
            required_signatures,
            summary: TransactionSummary {
                outputs: vec![SpendOutput {
                    address: to,
                    amount,
                    asset_id: Some(asset_id),
                }],
                fee: crate::types::Amount(fee),
            },
        })
    }
}

impl SdkSpendBuilder {
    /// Build the per-CAT inner standard-layer spends: the lead CAT carries the recipient output
    /// (+ CAT change back to the wallet); the rest carry empty conditions (value flows via the
    /// CAT ring). Mirrors the canonical dig-node CAT builder.
    fn build_cat_inner_spends(
        &self,
        ctx: &mut SpendContext,
        cats: &[Cat],
        destination: Bytes32,
        send_amount: u64,
        change_ph: Bytes32,
        cat_change: u64,
    ) -> WalletResult<Vec<CatSpend>> {
        let mut cat_spends = Vec::with_capacity(cats.len());
        for (index, cat) in cats.iter().enumerate() {
            let key = self
                .inputs
                .synthetic_key(cat.info.p2_puzzle_hash)
                .ok_or_else(|| spend_failed("no public key for a CAT coin's inner puzzle hash"))?;
            let conditions = if index == 0 {
                let hint = ctx
                    .hint(destination)
                    .map_err(|e| spend_failed(format!("hint: {e:?}")))?;
                let mut conds = Conditions::new().create_coin(destination, send_amount, hint);
                if cat_change > 0 {
                    conds = conds.create_coin(change_ph, cat_change, Memos::None);
                }
                conds
            } else {
                Conditions::new()
            };
            let inner = StandardLayer::new(key)
                .spend_with_conditions(ctx, conditions)
                .map_err(|e| spend_failed(format!("cat inner spend: {e:?}")))?;
            cat_spends.push(CatSpend::new(*cat, inner));
        }
        Ok(cat_spends)
    }

    /// Pay a CAT-send `fee` from the wallet's XCH coins, linked to the CAT ring via
    /// `assert_concurrent_spend` so the fee is spent atomically with the CAT send.
    fn add_xch_fee(
        &self,
        ctx: &mut SpendContext,
        identity: &IdentityRef,
        fee: u64,
        change_ph: Bytes32,
        cat_lead_id: Bytes32,
    ) -> WalletResult<()> {
        let xch = self.inputs.spendable_xch(identity)?;
        let selected = select_or_fail(&xch, fee, self.coin_cap, "XCH (fee)")?;
        let total: u64 = selected.iter().map(|c| c.amount).sum();
        let mut conditions = Conditions::new()
            .reserve_fee(fee)
            .assert_concurrent_spend(cat_lead_id);
        let change_amount = total - fee;
        if change_amount > 0 {
            conditions = conditions.create_coin(change_ph, change_amount, Memos::None);
        }
        self.spend_standard(ctx, selected[0], conditions)?;
        self.link_supporting_coins(ctx, &selected)
    }
}

/// The spend target: `amount + fee`, rejecting overflow.
fn checked_target(amount: u64, fee: u64) -> WalletResult<u64> {
    let target = amount
        .checked_add(fee)
        .ok_or_else(|| WalletError::invalid_input("amount + fee overflows"))?;
    if target == 0 {
        return Err(WalletError::invalid_input(
            "a spend must move a non-zero amount",
        ));
    }
    Ok(target)
}

/// Select coins covering `target`, translating a non-`Selected` outcome into the right error.
///
/// `NeedsConsolidation` surfaces as [`WalletErrorCode::InsufficientFunds`] (the frozen error
/// catalogue has no dedicated code) with a message directing the caller to consolidate.
fn select_or_fail(coins: &[Coin], target: u64, cap: usize, asset: &str) -> WalletResult<Vec<Coin>> {
    match select_for_spend(coins, target, cap) {
        SelectionOutcome::Selected { coins, .. } => Ok(coins),
        SelectionOutcome::NeedsConsolidation {
            available_total,
            required,
            cap,
            ..
        } => Err(WalletError::new(
            WalletErrorCode::InsufficientFunds,
            format!(
                "{asset} needs consolidation: {available_total} available across too many coins \
                 to reach {required} within the {cap}-coin cap"
            ),
        )),
        SelectionOutcome::InsufficientFunds {
            available_total,
            required,
        } => Err(WalletError::new(
            WalletErrorCode::InsufficientFunds,
            format!("insufficient {asset}: have {available_total}, need {required}"),
        )),
    }
}

/// Decode a bech32m address to its 32-byte puzzle hash, fail-closed on a malformed address.
fn decode_address(address: &Address) -> WalletResult<Bytes32> {
    Bech32Address::decode(&address.0)
        .map(|decoded| decoded.puzzle_hash)
        .map_err(|e| WalletError::invalid_input(format!("bad address {}: {e:?}", address.0)))
}

/// Fail-closed value conservation: inputs must exactly equal outputs + fee.
fn assert_conserved(inputs: u64, outputs: u64, fee: u64) -> WalletResult<()> {
    let out = outputs
        .checked_add(fee)
        .ok_or_else(|| spend_failed("output + fee overflow"))?;
    if inputs != out {
        return Err(spend_failed(format!(
            "value not conserved: inputs {inputs} != outputs+fee {out}"
        )));
    }
    Ok(())
}

/// Fail-closed structural check: a real spend produces coin spends AND requires at least one
/// signature. A signatureless "unsigned" spend would broadcast to nothing — reject it here.
pub(crate) fn ensure_signed_offline(
    coin_spends: &[CoinSpend],
    required: &[RequiredSignature],
) -> WalletResult<()> {
    if coin_spends.is_empty() {
        return Err(spend_failed("spend produced no coin spends"));
    }
    if required.is_empty() {
        return Err(spend_failed("spend requires no signatures"));
    }
    Ok(())
}

/// Shorthand for a [`WalletErrorCode::SpendValidationFailed`] error.
pub(crate) fn spend_failed(message: impl Into<String>) -> WalletError {
    WalletError::new(WalletErrorCode::SpendValidationFailed, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Amount, WalletId};
    use chia::puzzles::standard::StandardArgs;

    /// The BLS12-381 G1 generator, compressed — a valid, non-infinity public key. Used to curry
    /// a standard puzzle in tests WITHOUT any secret material (the key-isolation invariant
    /// forbids naming a secret type anywhere under `src/engine`). Deriving it from the generator
    /// keeps the value self-explanatory and avoids a bare literal being read as a key.
    fn test_public_key() -> PublicKey {
        let mut generator = [0u8; 48];
        generator[0] = 0x97;
        generator[1] = 0xf1;
        generator[2] = 0xd3;
        generator[3] = 0xa7;
        generator[4] = 0x31;
        generator[5] = 0x97;
        generator[6] = 0xd7;
        generator[7] = 0x94;
        generator[8] = 0x26;
        generator[9] = 0x95;
        generator[10] = 0x63;
        generator[11] = 0x8c;
        generator[12] = 0x4f;
        generator[13] = 0xa9;
        generator[14] = 0xac;
        generator[15] = 0x0f;
        generator[16] = 0xc3;
        generator[17] = 0x68;
        generator[18] = 0x8c;
        generator[19] = 0x4f;
        generator[20] = 0x97;
        generator[21] = 0x74;
        generator[22] = 0xb9;
        generator[23] = 0x05;
        generator[24] = 0xa1;
        generator[25] = 0x4e;
        generator[26] = 0x3a;
        generator[27] = 0x3f;
        generator[28] = 0x17;
        generator[29] = 0x1b;
        generator[30] = 0xac;
        generator[31] = 0x58;
        generator[32] = 0x6c;
        generator[33] = 0x55;
        generator[34] = 0xe8;
        generator[35] = 0x3f;
        generator[36] = 0xf9;
        generator[37] = 0x7a;
        generator[38] = 0x1a;
        generator[39] = 0xef;
        generator[40] = 0xfb;
        generator[41] = 0x3a;
        generator[42] = 0xf0;
        generator[43] = 0x0a;
        generator[44] = 0xdb;
        generator[45] = 0x22;
        generator[46] = 0xc6;
        generator[47] = 0xbb;
        PublicKey::from_bytes(&generator).expect("valid G1 generator")
    }

    /// The standard-layer puzzle hash the test key controls.
    fn wallet_puzzle_hash() -> Bytes32 {
        Bytes32::from(StandardArgs::curry_tree_hash(test_public_key()).to_bytes())
    }

    /// A coin at the wallet's puzzle hash, distinguished by `seed` and holding `amount`.
    fn wallet_coin(amount: u64, seed: u8) -> Coin {
        Coin::new(Bytes32::new([seed; 32]), wallet_puzzle_hash(), amount)
    }

    /// Issue a real CAT owned by the test wallet key and return its spendable coin.
    ///
    /// Uses chia-wallet-sdk's genesis-by-coin-id issuance in a throwaway context to mint a valid
    /// [`Cat`] (with lineage proof + inner p2 puzzle hash = the wallet key) that the CAT-send
    /// builder can spend — no simulator, no secret material.
    fn issued_cat(amount: u64) -> Cat {
        let mut ctx = SpendContext::new();
        let genesis = wallet_coin(amount, 42);
        let hint = ctx.hint(wallet_puzzle_hash()).unwrap();
        let create = Conditions::new().create_coin(wallet_puzzle_hash(), amount, hint);
        let (_, cats) = Cat::issue_with_coin(&mut ctx, genesis.coin_id(), amount, create).unwrap();
        cats[0]
    }

    /// A test input provider: canned XCH + CAT coins at the wallet key, and that one synthetic key.
    struct TestInputs {
        xch: Vec<Coin>,
        cats: Vec<Cat>,
    }

    impl TestInputs {
        /// An input provider with no coins — for tests that only exercise the network domain.
        fn empty() -> Self {
            TestInputs {
                xch: vec![],
                cats: vec![],
            }
        }
    }

    impl SpendInputs for TestInputs {
        fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<Coin>> {
            Ok(self.xch.clone())
        }
        fn spendable_cat(&self, _: &IdentityRef, _: &AssetId) -> WalletResult<Vec<Cat>> {
            Ok(self.cats.clone())
        }
        fn synthetic_key(&self, puzzle_hash: Bytes32) -> Option<PublicKey> {
            (puzzle_hash == wallet_puzzle_hash()).then(test_public_key)
        }
        fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<Bytes32> {
            Ok(wallet_puzzle_hash())
        }
    }

    fn builder(xch: Vec<Coin>) -> SdkSpendBuilder {
        builder_with_cats(xch, vec![])
    }

    fn builder_with_cats(xch: Vec<Coin>, cats: Vec<Cat>) -> SdkSpendBuilder {
        SdkSpendBuilder::new(Arc::new(TestInputs { xch, cats }), Network::Mainnet, 500)
    }

    fn cat_request(asset: &str, amount: u64, fee: u64) -> SendCatRequest {
        SendCatRequest {
            identity: IdentityRef::new(WalletId(1)),
            asset_id: AssetId(asset.into()),
            to: recipient(),
            amount: Amount(amount),
            fee: Amount(fee),
        }
    }

    /// A valid mainnet address (a real xch1… bech32m) for the recipient.
    fn recipient() -> Address {
        let ph = Bytes32::new([7u8; 32]);
        Address(Bech32Address::new(ph, "xch".into()).encode().unwrap())
    }

    fn xch_request(amount: u64, fee: u64) -> SendXchRequest {
        SendXchRequest {
            identity: IdentityRef::new(WalletId(1)),
            to: recipient(),
            amount: Amount(amount),
            fee: Amount(fee),
        }
    }

    #[tokio::test]
    async fn builds_an_unsigned_xch_send_with_change_and_required_signatures() {
        let b = builder(vec![wallet_coin(1000, 1)]);
        let unsigned = b.build_send_xch(xch_request(600, 10)).await.unwrap();

        // One input coin → one coin spend; it requires at least one signature.
        assert_eq!(unsigned.coin_spends.len(), 1);
        assert!(!unsigned.required_signatures.is_empty());
        // The summary reflects the send.
        assert_eq!(unsigned.summary.fee, Amount(10));
        assert_eq!(unsigned.summary.outputs[0].amount, Amount(600));
        assert!(unsigned.summary.outputs[0].asset_id.is_none());
    }

    #[tokio::test]
    async fn unsigned_spend_carries_no_signature() {
        // The UnsignedSpend type structurally cannot hold a SignedBundle; assert the required
        // signatures are DESCRIPTORS (a public key + message to sign), never a produced signature.
        let b = builder(vec![wallet_coin(1000, 1)]);
        let unsigned = b.build_send_xch(xch_request(500, 0)).await.unwrap();
        for req in &unsigned.required_signatures {
            assert!(
                !req.message.is_empty(),
                "a signature is still required, not produced"
            );
        }
    }

    #[tokio::test]
    async fn build_is_deterministic() {
        let coins = vec![wallet_coin(1000, 1), wallet_coin(500, 2)];
        let a = builder(coins.clone())
            .build_send_xch(xch_request(1200, 5))
            .await
            .unwrap();
        let b = builder(coins)
            .build_send_xch(xch_request(1200, 5))
            .await
            .unwrap();
        assert_eq!(
            a, b,
            "identical inputs must yield an identical unsigned spend"
        );
    }

    #[tokio::test]
    async fn multiple_inputs_produce_one_spend_each() {
        let b = builder(vec![wallet_coin(700, 1), wallet_coin(600, 2)]);
        let unsigned = b.build_send_xch(xch_request(1000, 0)).await.unwrap();
        // 700 + 600 needed to cover 1000; both coins are spent.
        assert_eq!(unsigned.coin_spends.len(), 2);
    }

    #[tokio::test]
    async fn insufficient_funds_is_reported() {
        let b = builder(vec![wallet_coin(100, 1)]);
        let err = b.build_send_xch(xch_request(500, 0)).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }

    #[tokio::test]
    async fn needs_consolidation_surfaces_as_insufficient_funds() {
        // 51 coins of 1, cap 50, target 51 → NeedsConsolidation → InsufficientFunds with a
        // consolidation message.
        let coins: Vec<Coin> = (0..51).map(|i| wallet_coin(1, i as u8)).collect();
        let b = SdkSpendBuilder::new(
            Arc::new(TestInputs {
                xch: coins,
                cats: vec![],
            }),
            Network::Mainnet,
            50,
        );
        let err = b.build_send_xch(xch_request(51, 0)).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
        assert!(err.message.contains("consolidation"));
    }

    #[tokio::test]
    async fn zero_amount_is_rejected() {
        let b = builder(vec![wallet_coin(1000, 1)]);
        let err = b.build_send_xch(xch_request(0, 0)).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn amount_plus_fee_overflow_is_rejected() {
        let b = builder(vec![wallet_coin(1000, 1)]);
        let err = b
            .build_send_xch(xch_request(u64::MAX, 1))
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn bad_address_is_rejected() {
        let b = builder(vec![wallet_coin(1000, 1)]);
        let req = SendXchRequest {
            identity: IdentityRef::new(WalletId(1)),
            to: Address("not-a-real-address".into()),
            amount: Amount(500),
            fee: Amount(0),
        };
        let err = b.build_send_xch(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn a_coin_the_wallet_cannot_authorize_fails_closed() {
        // A coin at a puzzle hash the provider has no key for must not be buildable.
        let foreign = Coin::new(Bytes32::new([1u8; 32]), Bytes32::new([9u8; 32]), 1000);
        let b = builder(vec![foreign]);
        let err = b.build_send_xch(xch_request(500, 0)).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    #[tokio::test]
    async fn cat_send_with_no_coins_is_insufficient() {
        let b = builder(vec![]);
        let req = SendCatRequest {
            identity: IdentityRef::new(WalletId(1)),
            asset_id: AssetId("tail".into()),
            to: recipient(),
            amount: Amount(5),
            fee: Amount(0),
        };
        let err = b.build_send_cat(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }

    #[tokio::test]
    async fn cat_send_zero_amount_is_rejected() {
        let b = builder(vec![]);
        let req = SendCatRequest {
            identity: IdentityRef::new(WalletId(1)),
            asset_id: AssetId("tail".into()),
            to: recipient(),
            amount: Amount(0),
            fee: Amount(0),
        };
        let err = b.build_send_cat(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn builds_an_unsigned_cat_send_with_change() {
        let b = builder_with_cats(vec![], vec![issued_cat(1000)]);
        let unsigned = b.build_send_cat(cat_request("tail", 600, 0)).await.unwrap();

        // The CAT coin is spent and requires a signature; the summary carries the asset id.
        assert!(!unsigned.coin_spends.is_empty());
        assert!(!unsigned.required_signatures.is_empty());
        assert_eq!(unsigned.summary.outputs[0].amount, Amount(600));
        assert!(unsigned.summary.outputs[0].asset_id.is_some());
    }

    #[tokio::test]
    async fn cat_send_with_a_fee_spends_xch_too() {
        let b = builder_with_cats(vec![wallet_coin(1000, 1)], vec![issued_cat(1000)]);
        let unsigned = b
            .build_send_cat(cat_request("tail", 500, 50))
            .await
            .unwrap();
        // The CAT coin plus at least one XCH fee coin are spent.
        assert!(unsigned.coin_spends.len() >= 2);
        assert_eq!(unsigned.summary.fee, Amount(50));
    }

    #[tokio::test]
    async fn cat_send_is_deterministic() {
        let cat = issued_cat(1000);
        let a = builder_with_cats(vec![], vec![cat])
            .build_send_cat(cat_request("tail", 400, 0))
            .await
            .unwrap();
        let b = builder_with_cats(vec![], vec![cat])
            .build_send_cat(cat_request("tail", 400, 0))
            .await
            .unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn cat_fee_without_xch_is_insufficient() {
        let b = builder_with_cats(vec![], vec![issued_cat(1000)]);
        let err = b
            .build_send_cat(cat_request("tail", 500, 50))
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }

    #[test]
    fn conservation_rejects_a_mismatch() {
        assert!(assert_conserved(100, 90, 5).is_err());
        assert!(assert_conserved(100, 90, 10).is_ok());
    }

    /// signer == engine byte-KAT (engine half). The whole point of #1101: the AGG_SIG_ME suffix the
    /// engine binds into REAL mainnet unsigned-spend messages MUST be byte-identical to what the
    /// client signer requires — else every mainnet spend the engine builds would be rejected by the
    /// signer (custody deadlock). This half proves the engine binds exactly
    /// `dig_constants::CHIA_L1_MAINNET_AGG_SIG_ME` into a real message; the signer half
    /// (`signer_requires_the_dig_constants_agg_sig_me`, src/client/signer.rs) proves the signer
    /// requires that SAME constant. Both anchored to one source ⇒ signer == engine. Key-free, so it
    /// respects the SPEC §1.4 engine key-isolation invariant (tests/key_isolation.rs).
    #[tokio::test]
    async fn engine_binds_the_dig_constants_mainnet_agg_sig_me() {
        let unsigned = builder(vec![wallet_coin(1000, 1)])
            .build_send_xch(xch_request(600, 10))
            .await
            .unwrap();
        assert!(!unsigned.required_signatures.is_empty());
        for req in &unsigned.required_signatures {
            assert!(
                req.message
                    .ends_with(&dig_constants::CHIA_L1_MAINNET_AGG_SIG_ME),
                "engine-built message not bound to the dig-constants Chia-L1 mainnet AGG_SIG_ME",
            );
        }
    }

    /// The engine's aggregate-signature domain for each network is byte-identical to the
    /// `dig-constants` Chia-L1 value the client signer requires (mainnet + testnet11) — the same
    /// SSOT both seams read, so no drift can desync signer and engine.
    #[test]
    fn engine_agg_sig_me_matches_dig_constants_per_network() {
        let mainnet = SdkSpendBuilder::new(Arc::new(TestInputs::empty()), Network::Mainnet, 500);
        let testnet = SdkSpendBuilder::new(Arc::new(TestInputs::empty()), Network::Testnet, 500);
        assert_eq!(
            mainnet.agg_sig_constants().me(),
            Bytes32::new(dig_constants::CHIA_L1_MAINNET_AGG_SIG_ME),
        );
        assert_eq!(
            testnet.agg_sig_constants().me(),
            Bytes32::new(dig_constants::CHIA_L1_TESTNET11_AGG_SIG_ME),
        );
    }
}
