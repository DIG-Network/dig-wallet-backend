//! `engine::build_extended` — the extended send suite (SPEC §3, #43).
//!
//! [`super::build::SpendBuilder`] covers the two single-destination sends. Real wallets also need
//! to pay MANY destinations at once, and to reshape their own coin set:
//!
//! | operation | what it is |
//! |---|---|
//! | [`ExtendedSpendBuilder::build_multi_send_xch`] | pay an arbitrary set of XCH destinations in one spend |
//! | [`ExtendedSpendBuilder::build_multi_send_cat`] | the same for one CAT asset |
//! | [`ExtendedSpendBuilder::build_combine_xch`] | merge the wallet's own coins into one |
//! | [`ExtendedSpendBuilder::build_split_xch`] | split the wallet's value into `parts` coins |
//!
//! A *bulk* send is not a separate operation: it is a multi-send whose legs were generated rather
//! than hand-listed, so it shares one implementation and one set of guarantees.
//!
//! # Why a SEPARATE trait
//! `SpendBuilder` is implemented outside this crate by five consumers. Adding methods to it would
//! break every one of them; a new trait is purely additive, so an existing implementor keeps
//! compiling and opts in when it wants the suite.
//!
//! # The guarantees every builder here keeps
//! Identical to the core builders, and for the same reason — an unsigned spend that reaches the
//! broadcaster must already be structurally sound:
//! - **value conservation**, checked fail-closed: inputs equal outputs plus fee, exactly;
//! - **a non-empty required-signature set**, so a signature-less spend can never be broadcast;
//! - **no hand-rolled CLVM** — every condition goes through chia-wallet-sdk drivers (§4.1);
//! - **no key**, ever. The engine builds; the client seam signs.

use async_trait::async_trait;
use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::Memos;
use chia_wallet_sdk::driver::{Cat, SpendContext};
use chia_wallet_sdk::types::Conditions;

use crate::types::{
    Amount, CombineXchRequest, MultiSendCatRequest, MultiSendXchRequest, SendLeg, SpendOutput,
    SplitXchRequest, TransactionSummary, UnsignedSpend, WalletError, WalletErrorCode, WalletResult,
};

use super::build::{
    assert_conserved, decode_address, ensure_signed_offline, select_or_fail, spend_failed,
    SdkSpendBuilder,
};
use super::selection::select_for_consolidation;

/// The extended send suite, layered over [`super::build::SpendBuilder`].
///
/// Every method returns an [`UnsignedSpend`] for client review and signing — this trait, like the
/// core builder, never signs and never holds a key.
#[async_trait]
pub trait ExtendedSpendBuilder: Send + Sync {
    /// Pay an arbitrary set of XCH destinations in a single spend.
    async fn build_multi_send_xch(
        &self,
        request: MultiSendXchRequest,
    ) -> WalletResult<UnsignedSpend>;

    /// Pay an arbitrary set of destinations of one CAT asset in a single spend.
    async fn build_multi_send_cat(
        &self,
        request: MultiSendCatRequest,
    ) -> WalletResult<UnsignedSpend>;

    /// Merge the wallet's own XCH coins into a single coin.
    async fn build_combine_xch(&self, request: CombineXchRequest) -> WalletResult<UnsignedSpend>;

    /// Split the wallet's XCH into `parts` coins of its own.
    async fn build_split_xch(&self, request: SplitXchRequest) -> WalletResult<UnsignedSpend>;
}

#[async_trait]
impl ExtendedSpendBuilder for SdkSpendBuilder {
    async fn build_multi_send_xch(
        &self,
        request: MultiSendXchRequest,
    ) -> WalletResult<UnsignedSpend> {
        let MultiSendXchRequest {
            identity,
            legs,
            fee,
        } = request;
        let fee = fee.mojos();
        let destinations = resolve_legs(&legs)?;
        let payout = total_of(&legs)?;
        let target = payout
            .checked_add(fee)
            .ok_or_else(|| WalletError::invalid_input("legs + fee overflows"))?;

        let change_ph = self.inputs.change_puzzle_hash(&identity)?;
        let coins = self.inputs.spendable_xch(&identity)?;
        let selected = select_or_fail(&coins, target, self.coin_cap, "XCH")?;
        let total: u64 = selected.iter().map(|c| c.amount).sum();
        let change_amount = total - target;

        let mut ctx = SpendContext::new();
        let mut conditions = Conditions::new();
        for (puzzle_hash, amount) in &destinations {
            let hint = ctx
                .hint(*puzzle_hash)
                .map_err(|e| spend_failed(format!("hint: {e:?}")))?;
            conditions = conditions.create_coin(*puzzle_hash, *amount, hint);
        }
        if change_amount > 0 {
            conditions = conditions.create_coin(change_ph, change_amount, Memos::None);
        }
        if fee > 0 {
            conditions = conditions.reserve_fee(fee);
        }
        self.spend_standard(&mut ctx, selected[0], conditions)?;
        self.link_supporting_coins(&mut ctx, &selected)?;
        let coin_spends = ctx.take();

        assert_conserved(total, payout + change_amount, fee)?;
        let required_signatures = self.required_signatures(&coin_spends)?;
        ensure_signed_offline(&coin_spends, &required_signatures)?;

        Ok(UnsignedSpend {
            coin_spends,
            required_signatures,
            summary: TransactionSummary {
                melted_singletons: Vec::new(),
                nft_operations: Vec::new(),
                outputs: legs
                    .iter()
                    .map(|leg| SpendOutput {
                        address: leg.to.clone(),
                        amount: leg.amount,
                        asset_id: None,
                    })
                    .collect(),
                received: vec![],
                fee: Amount(fee),
            },
        })
    }

    async fn build_multi_send_cat(
        &self,
        request: MultiSendCatRequest,
    ) -> WalletResult<UnsignedSpend> {
        let MultiSendCatRequest {
            identity,
            asset_id,
            legs,
            fee,
        } = request;
        let fee = fee.mojos();
        let destinations = resolve_legs(&legs)?;
        let payout = total_of(&legs)?;

        let change_ph = self.inputs.change_puzzle_hash(&identity)?;
        let cats = self.inputs.spendable_cat(&identity, &asset_id)?;
        let cat_total: u64 = cats.iter().map(|c| c.coin.amount).sum();
        if cats.is_empty() || cat_total < payout {
            return Err(WalletError::new(
                WalletErrorCode::InsufficientFunds,
                format!(
                    "insufficient {}: have {cat_total}, need {payout}",
                    asset_id.0
                ),
            ));
        }

        let mut ctx = SpendContext::new();
        let cat_change = cat_total - payout;
        let cat_spends =
            self.cat_ring_paying(&mut ctx, &cats, &destinations, change_ph, cat_change)?;
        Cat::spend_all(&mut ctx, &cat_spends)
            .map_err(|e| spend_failed(format!("cat spend_all: {e:?}")))?;

        if fee > 0 {
            self.add_xch_fee(&mut ctx, &identity, fee, change_ph, cats[0].coin.coin_id())?;
        }
        let coin_spends = ctx.take();

        // The CAT ring conserves its own asset; only the XCH leg carries a fee.
        assert_conserved(cat_total, payout + cat_change, 0)?;
        let required_signatures = self.required_signatures(&coin_spends)?;
        ensure_signed_offline(&coin_spends, &required_signatures)?;

        Ok(UnsignedSpend {
            coin_spends,
            required_signatures,
            summary: TransactionSummary {
                melted_singletons: Vec::new(),
                nft_operations: Vec::new(),
                outputs: legs
                    .iter()
                    .map(|leg| SpendOutput {
                        address: leg.to.clone(),
                        amount: leg.amount,
                        asset_id: Some(asset_id.clone()),
                    })
                    .collect(),
                received: vec![],
                fee: Amount(fee),
            },
        })
    }

    async fn build_combine_xch(&self, request: CombineXchRequest) -> WalletResult<UnsignedSpend> {
        let CombineXchRequest { identity, fee } = request;
        let fee = fee.mojos();
        let change_ph = self.inputs.change_puzzle_hash(&identity)?;
        let coins = self.inputs.spendable_xch(&identity)?;
        let selected = select_for_consolidation(&coins, self.coin_cap)?;
        let total: u64 = selected.iter().map(|c| c.amount).sum();
        let merged = total.checked_sub(fee).filter(|m| *m > 0).ok_or_else(|| {
            WalletError::new(
                WalletErrorCode::InsufficientFunds,
                format!("combining {total} mojos cannot also pay a {fee} mojo fee"),
            )
        })?;

        let mut ctx = SpendContext::new();
        let mut conditions = Conditions::new().create_coin(change_ph, merged, Memos::None);
        if fee > 0 {
            conditions = conditions.reserve_fee(fee);
        }
        self.spend_standard(&mut ctx, selected[0], conditions)?;
        self.link_supporting_coins(&mut ctx, &selected)?;
        let coin_spends = ctx.take();

        assert_conserved(total, merged, fee)?;
        self.finish_self_directed(coin_spends, fee)
    }

    async fn build_split_xch(&self, request: SplitXchRequest) -> WalletResult<UnsignedSpend> {
        let SplitXchRequest {
            identity,
            parts,
            fee,
        } = request;
        let fee = fee.mojos();
        let parts = u64::from(parts);
        if parts < 2 {
            return Err(WalletError::invalid_input(
                "a split must produce at least two coins",
            ));
        }

        let change_ph = self.inputs.change_puzzle_hash(&identity)?;
        let coins = self.inputs.spendable_xch(&identity)?;
        // Splitting spends the wallet's largest coin: taking only what a `parts + fee` target
        // needs would leave the wallet with a dust-sized set, which is the opposite of the intent.
        let selected = largest_spendable(&coins)?;
        let total = selected.amount;
        let divisible =
            total
                .checked_sub(fee)
                .filter(|d| *d >= parts)
                .ok_or_else(|| {
                    WalletError::new(
                WalletErrorCode::InsufficientFunds,
                format!("{total} mojos cannot pay a {fee} mojo fee and still split {parts} ways"),
            )
                })?;

        // Integer division leaves a remainder; it goes to the FIRST coin rather than being lost,
        // which is what keeps conservation exact.
        let each = divisible / parts;
        let remainder = divisible % parts;

        let mut ctx = SpendContext::new();
        let mut conditions = Conditions::new();
        for index in 0..parts {
            let amount = if index == 0 { each + remainder } else { each };
            conditions = conditions.create_coin(change_ph, amount, Memos::None);
        }
        if fee > 0 {
            conditions = conditions.reserve_fee(fee);
        }
        self.spend_standard(&mut ctx, selected, conditions)?;
        let coin_spends = ctx.take();

        assert_conserved(total, divisible, fee)?;
        self.finish_self_directed(coin_spends, fee)
    }
}

impl SdkSpendBuilder {
    /// Build the CAT ring for a MULTI-destination payment: the lead CAT carries every recipient
    /// output plus the CAT change, the rest carry empty conditions (value flows through the ring).
    ///
    /// The single-destination [`SdkSpendBuilder::build_send_cat`](super::build::SpendBuilder) case
    /// is this with one destination.
    fn cat_ring_paying(
        &self,
        ctx: &mut SpendContext,
        cats: &[Cat],
        destinations: &[(Bytes32, u64)],
        change_ph: Bytes32,
        cat_change: u64,
    ) -> WalletResult<Vec<chia_wallet_sdk::driver::CatSpend>> {
        use chia_wallet_sdk::driver::{CatSpend, SpendWithConditions, StandardLayer};

        let mut cat_spends = Vec::with_capacity(cats.len());
        for (index, cat) in cats.iter().enumerate() {
            let key = self
                .inputs
                .synthetic_key(cat.info.p2_puzzle_hash)
                .ok_or_else(|| spend_failed("no public key for a CAT coin's inner puzzle hash"))?;
            let conditions = if index == 0 {
                let mut conds = Conditions::new();
                for (puzzle_hash, amount) in destinations {
                    let hint = ctx
                        .hint(*puzzle_hash)
                        .map_err(|e| spend_failed(format!("hint: {e:?}")))?;
                    conds = conds.create_coin(*puzzle_hash, *amount, hint);
                }
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

    /// Finish a spend whose whole value stays with the wallet (a combine or a split).
    ///
    /// The review summary lists NO outputs and NO receipts, because a self-directed reshape pays
    /// nobody and gains nobody anything: the only thing the user is consenting to is the fee.
    /// Listing the wallet's own change coins as "outputs" would ask for consent to a payment that
    /// is not happening, and listing them as "received" would imply incoming value that is really
    /// the user's own money moving sideways. The client signer re-derives the true value flow from
    /// the coin spends independently (`client::verify`), so nothing is hidden by saying less here.
    fn finish_self_directed(
        &self,
        coin_spends: Vec<chia_protocol::CoinSpend>,
        fee: u64,
    ) -> WalletResult<UnsignedSpend> {
        let required_signatures = self.required_signatures(&coin_spends)?;
        ensure_signed_offline(&coin_spends, &required_signatures)?;
        Ok(UnsignedSpend {
            coin_spends,
            required_signatures,
            summary: TransactionSummary {
                melted_singletons: Vec::new(),
                nft_operations: Vec::new(),
                outputs: Vec::new(),
                received: Vec::new(),
                fee: Amount(fee),
            },
        })
    }
}

/// Decode every leg to a `(puzzle_hash, amount)` pair, rejecting an empty set and any zero leg.
///
/// A zero-amount leg is rejected rather than dropped: silently omitting a destination the caller
/// listed would make the built spend disagree with the reviewed summary.
fn resolve_legs(legs: &[SendLeg]) -> WalletResult<Vec<(Bytes32, u64)>> {
    if legs.is_empty() {
        return Err(WalletError::invalid_input(
            "a multi-send must have at least one destination",
        ));
    }
    legs.iter()
        .map(|leg| {
            let amount = leg.amount.mojos();
            if amount == 0 {
                return Err(WalletError::invalid_input(format!(
                    "destination {} was given a zero amount",
                    leg.to.0
                )));
            }
            Ok((decode_address(&leg.to)?, amount))
        })
        .collect()
}

/// The total the legs pay out, rejecting overflow.
fn total_of(legs: &[SendLeg]) -> WalletResult<u64> {
    legs.iter().try_fold(0u64, |sum, leg| {
        sum.checked_add(leg.amount.mojos())
            .ok_or_else(|| WalletError::invalid_input("multi-send total overflows"))
    })
}

/// The wallet's largest spendable coin — the one a split reshapes.
fn largest_spendable(coins: &[Coin]) -> WalletResult<Coin> {
    coins
        .iter()
        .max_by(|a, b| {
            a.amount
                .cmp(&b.amount)
                .then_with(|| b.coin_id().cmp(&a.coin_id()))
        })
        .copied()
        .ok_or_else(|| {
            WalletError::new(
                WalletErrorCode::InsufficientFunds,
                "no spendable XCH coin to split",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, AssetId, IdentityRef, WalletId};
    use chia_wallet_sdk::utils::Address as Bech32Address;
    use clvm_traits::ToClvm;

    use super::super::test_support::{
        builder, builder_with_cats, issued_cat, wallet_coin, wallet_puzzle_hash,
    };

    fn identity() -> IdentityRef {
        IdentityRef::new(WalletId(1))
    }

    /// A distinct destination address per `seed`, so a test can tell the legs apart.
    fn destination(seed: u8) -> Address {
        let ph = Bytes32::new([seed; 32]);
        Address(Bech32Address::new(ph, "xch".into()).encode().unwrap())
    }

    fn leg(seed: u8, amount: u64) -> SendLeg {
        SendLeg {
            to: destination(seed),
            amount: Amount(amount),
        }
    }

    fn multi(legs: Vec<SendLeg>, fee: u64) -> MultiSendXchRequest {
        MultiSendXchRequest {
            identity: identity(),
            legs,
            fee: Amount(fee),
        }
    }

    /// The coins an unsigned spend actually creates, read back off the BUILT coin spends.
    ///
    /// Deliberately NOT read off the summary: a test that checks the summary is asking the
    /// builder to grade its own homework, and would keep passing if the built spend and the
    /// summary drifted apart.
    fn created_coins(spend: &UnsignedSpend) -> Vec<(Bytes32, u64)> {
        use chia_wallet_sdk::types::Condition;
        use clvmr::Allocator;

        let mut allocator = Allocator::new();
        let mut created = Vec::new();
        for coin_spend in &spend.coin_spends {
            let puzzle = coin_spend.puzzle_reveal.to_clvm(&mut allocator).unwrap();
            let solution = coin_spend.solution.to_clvm(&mut allocator).unwrap();
            let output = clvmr::run_program(
                &mut allocator,
                &clvmr::ChiaDialect::new(0),
                puzzle,
                solution,
                u64::MAX,
            )
            .unwrap()
            .1;
            let conditions: Vec<Condition> =
                clvm_traits::FromClvm::from_clvm(&allocator, output).unwrap();
            for condition in conditions {
                if let Some(create) = condition.into_create_coin() {
                    created.push((create.puzzle_hash, create.amount));
                }
            }
        }
        created
    }

    #[tokio::test]
    async fn a_multi_send_pays_every_leg_its_own_amount() {
        let spend = builder(vec![wallet_coin(1_000, 1)])
            .build_multi_send_xch(multi(vec![leg(7, 100), leg(8, 250), leg(9, 30)], 5))
            .await
            .unwrap();

        let created = created_coins(&spend);
        for (seed, amount) in [(7u8, 100u64), (8, 250), (9, 30)] {
            assert!(
                created.contains(&(Bytes32::new([seed; 32]), amount)),
                "leg {seed} was not paid {amount}: {created:?}"
            );
        }
    }

    /// Load-bearing against a builder that pays only the FIRST leg (the shape both existing
    /// single-destination builders have) and returns the rest as change: three distinct amounts
    /// to three distinct addresses cannot be satisfied by one payment plus a change coin.
    #[tokio::test]
    async fn a_multi_send_conserves_value_across_legs_change_and_fee() {
        let spend = builder(vec![wallet_coin(1_000, 1)])
            .build_multi_send_xch(multi(vec![leg(7, 100), leg(8, 250), leg(9, 30)], 5))
            .await
            .unwrap();

        let paid: u64 = created_coins(&spend).iter().map(|(_, a)| a).sum();
        // 1000 in, 5 to the farmer, so exactly 995 must be re-created as coins.
        assert_eq!(paid, 995);
    }

    #[tokio::test]
    async fn a_multi_send_summary_lists_one_output_per_leg() {
        let spend = builder(vec![wallet_coin(1_000, 1)])
            .build_multi_send_xch(multi(vec![leg(7, 100), leg(8, 250)], 5))
            .await
            .unwrap();

        let listed: Vec<_> = spend
            .summary
            .outputs
            .iter()
            .map(|o| (o.address.clone(), o.amount))
            .collect();
        assert_eq!(
            listed,
            vec![(destination(7), Amount(100)), (destination(8), Amount(250))]
        );
        assert_eq!(spend.summary.fee, Amount(5));
    }

    #[tokio::test]
    async fn a_multi_send_requires_signatures() {
        let spend = builder(vec![wallet_coin(1_000, 1)])
            .build_multi_send_xch(multi(vec![leg(7, 100)], 0))
            .await
            .unwrap();
        assert!(!spend.required_signatures.is_empty());
    }

    #[tokio::test]
    async fn a_multi_send_with_no_legs_is_rejected() {
        let err = builder(vec![wallet_coin(1_000, 1)])
            .build_multi_send_xch(multi(vec![], 0))
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    /// A zero leg is REJECTED, not silently dropped: dropping it would build a spend that
    /// disagrees with the destination list the user reviewed.
    #[tokio::test]
    async fn a_zero_amount_leg_is_rejected_rather_than_dropped() {
        let err = builder(vec![wallet_coin(1_000, 1)])
            .build_multi_send_xch(multi(vec![leg(7, 100), leg(8, 0)], 0))
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn a_multi_send_beyond_the_balance_is_insufficient_funds() {
        let err = builder(vec![wallet_coin(100, 1)])
            .build_multi_send_xch(multi(vec![leg(7, 90), leg(8, 90)], 0))
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }

    #[tokio::test]
    async fn a_multi_send_with_a_malformed_address_is_rejected() {
        let request = MultiSendXchRequest {
            identity: identity(),
            legs: vec![SendLeg {
                to: Address("not-an-address".into()),
                amount: Amount(10),
            }],
            fee: Amount(0),
        };
        let err = builder(vec![wallet_coin(1_000, 1)])
            .build_multi_send_xch(request)
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn a_cat_multi_send_pays_every_leg() {
        let cat = issued_cat(1_000);
        let spend = builder_with_cats(vec![wallet_coin(500, 1)], vec![cat])
            .build_multi_send_cat(MultiSendCatRequest {
                identity: identity(),
                asset_id: AssetId("tail".into()),
                legs: vec![leg(7, 100), leg(8, 250)],
                fee: Amount(0),
            })
            .await
            .unwrap();

        let created = created_coins(&spend);
        for (seed, amount) in [(7u8, 100u64), (8, 250)] {
            assert!(
                created.iter().any(|(_, a)| *a == amount),
                "leg {seed} amount {amount} missing from {created:?}"
            );
        }
        assert!(spend
            .summary
            .outputs
            .iter()
            .all(|o| o.asset_id == Some(AssetId("tail".into()))));
        assert_eq!(spend.summary.outputs.len(), 2);
        assert!(!spend.required_signatures.is_empty());
    }

    #[tokio::test]
    async fn a_cat_multi_send_beyond_the_balance_is_insufficient_funds() {
        let cat = issued_cat(100);
        let err = builder_with_cats(vec![wallet_coin(500, 1)], vec![cat])
            .build_multi_send_cat(MultiSendCatRequest {
                identity: identity(),
                asset_id: AssetId("tail".into()),
                legs: vec![leg(7, 90), leg(8, 90)],
                fee: Amount(0),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }

    /// Load-bearing against a combine that merely re-spends each coin unchanged: that would
    /// create THREE output coins, and the point of a combine is that it creates one.
    #[tokio::test]
    async fn a_combine_merges_every_coin_into_one() {
        let spend = builder(vec![
            wallet_coin(100, 1),
            wallet_coin(250, 2),
            wallet_coin(30, 3),
        ])
        .build_combine_xch(CombineXchRequest {
            identity: identity(),
            fee: Amount(5),
        })
        .await
        .unwrap();

        // 380 in, 5 to the farmer, and the remainder must land as exactly ONE coin.
        assert_eq!(created_coins(&spend), vec![(wallet_puzzle_hash(), 375)]);
        assert_eq!(spend.coin_spends.len(), 3);
    }

    /// A combine pays nobody, so consenting to it is consenting to the fee alone.
    #[tokio::test]
    async fn a_combine_summary_lists_no_payment() {
        let spend = builder(vec![wallet_coin(100, 1), wallet_coin(250, 2)])
            .build_combine_xch(CombineXchRequest {
                identity: identity(),
                fee: Amount(5),
            })
            .await
            .unwrap();
        assert!(spend.summary.outputs.is_empty());
        assert!(spend.summary.received.is_empty());
        assert_eq!(spend.summary.fee, Amount(5));
    }

    #[tokio::test]
    async fn a_combine_of_a_single_coin_is_rejected() {
        let err = builder(vec![wallet_coin(100, 1)])
            .build_combine_xch(CombineXchRequest {
                identity: identity(),
                fee: Amount(0),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn a_combine_that_cannot_cover_its_fee_is_insufficient_funds() {
        let err = builder(vec![wallet_coin(3, 1), wallet_coin(2, 2)])
            .build_combine_xch(CombineXchRequest {
                identity: identity(),
                fee: Amount(5),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }

    #[tokio::test]
    async fn a_split_produces_exactly_the_requested_number_of_coins() {
        let spend = builder(vec![wallet_coin(1_000, 1)])
            .build_split_xch(SplitXchRequest {
                identity: identity(),
                parts: 4,
                fee: Amount(0),
            })
            .await
            .unwrap();
        assert_eq!(created_coins(&spend), vec![(wallet_puzzle_hash(), 250); 4]);
    }

    /// An indivisible remainder must be KEPT, on the first coin. Dropping it would silently burn
    /// the user money into the farmer reward, which no caller consented to.
    #[tokio::test]
    async fn a_split_with_a_remainder_keeps_every_mojo() {
        let spend = builder(vec![wallet_coin(1_003, 1)])
            .build_split_xch(SplitXchRequest {
                identity: identity(),
                parts: 4,
                fee: Amount(0),
            })
            .await
            .unwrap();
        let amounts: Vec<u64> = created_coins(&spend).iter().map(|(_, a)| *a).collect();
        assert_eq!(amounts, vec![253, 250, 250, 250]);
        assert_eq!(amounts.iter().sum::<u64>(), 1_003);
    }

    #[tokio::test]
    async fn a_split_pays_its_fee_out_of_the_split_value() {
        let spend = builder(vec![wallet_coin(1_000, 1)])
            .build_split_xch(SplitXchRequest {
                identity: identity(),
                parts: 2,
                fee: Amount(10),
            })
            .await
            .unwrap();
        let total: u64 = created_coins(&spend).iter().map(|(_, a)| a).sum();
        assert_eq!(total, 990);
        assert_eq!(spend.summary.fee, Amount(10));
    }

    #[tokio::test]
    async fn a_split_into_fewer_than_two_parts_is_rejected() {
        for parts in [0u32, 1] {
            let err = builder(vec![wallet_coin(1_000, 1)])
                .build_split_xch(SplitXchRequest {
                    identity: identity(),
                    parts,
                    fee: Amount(0),
                })
                .await
                .unwrap_err();
            assert_eq!(err.code, WalletErrorCode::InvalidInput);
        }
    }

    #[tokio::test]
    async fn a_split_too_small_to_give_each_part_a_mojo_is_insufficient_funds() {
        let err = builder(vec![wallet_coin(3, 1)])
            .build_split_xch(SplitXchRequest {
                identity: identity(),
                parts: 4,
                fee: Amount(0),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }

    #[tokio::test]
    async fn a_split_with_no_coins_is_insufficient_funds() {
        let err = builder(vec![])
            .build_split_xch(SplitXchRequest {
                identity: identity(),
                parts: 2,
                fee: Amount(0),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }
}
