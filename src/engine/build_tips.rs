//! `engine::build_tips` — unsigned $DIG tip construction (SPEC §3c, dig_ecosystem#377).
//!
//! A tip is a single CAT payment (typically $DIG) to a recipient — built the same way as every
//! other engine spend: the engine constructs an UNSIGNED spend and returns it for client review +
//! signing. It NEVER signs and NEVER hand-rolls CAT CLVM (§4.1) — every tip flows through the
//! canonical [`dig-tips`](https://crates.io/crates/dig-tips) builders (`build_tip` /
//! `build_tip_if_allowed`), and the required signatures are extracted key-free through the SAME
//! [`SdkSpendBuilder::required_signatures`] path the XCH/CAT/option builders use.
//!
//! # The honest auto-tip (§6.0 $DIG North Star)
//! [`TipBuilder::build_auto_tip`] runs the capped decision FIRST and only builds a spend when the
//! decision is [`TipDecision::Tip`] — a capped/disabled/declined tip is never constructed, so the
//! default-on money movement can never exceed its honest ceiling, and consuming content is never
//! gated by a tip.

use async_trait::async_trait;
use chia::bls::PublicKey;
use chia::protocol::Bytes32;
use chia_wallet_sdk::driver::Cat;
use dig_cat::CatError;
use dig_tips::{
    build_tip, build_tip_if_allowed, AutoTipPolicy as DigAutoTipPolicy, CapReason as DigCapReason,
    LedgerSnapshot, TipDecision as DigTipDecision, TipMode as DigTipMode,
    TipRequest as DigTipRequest,
};

use crate::types::{
    Address, Amount, AssetId, AutoTipOutcome, AutoTipPolicy, AutoTipRequest, CapReason,
    IdentityRef, Puzzlehash, SpendOutput, TipDecision, TipRequest, TransactionSummary,
    UnsignedSpend, WalletError, WalletErrorCode, WalletResult,
};

use super::build::{ensure_signed_offline, spend_failed, SdkSpendBuilder};

/// Builds unsigned tip spends. Every method returns a client-reviewable, unsigned result — the
/// engine never signs (SPEC §1.4, the key-isolation invariant).
#[async_trait]
pub trait TipBuilder: Send + Sync {
    /// Build an unsigned explicit tip: a single CAT payment of `request.amount` to `request.recipient`.
    async fn build_tip(&self, request: TipRequest) -> WalletResult<UnsignedSpend>;

    /// Run the capped auto-tip decision and build the unsigned tip ONLY when the decision permits it.
    ///
    /// Returns the [`TipDecision`] the caps produced and, iff it was [`TipDecision::Tip`], the
    /// unsigned spend. A skip builds nothing — the cap cannot be bypassed.
    async fn build_auto_tip(&self, request: AutoTipRequest) -> WalletResult<AutoTipOutcome>;
}

#[async_trait]
impl TipBuilder for SdkSpendBuilder {
    async fn build_tip(&self, request: TipRequest) -> WalletResult<UnsignedSpend> {
        let TipRequest {
            identity,
            asset_id,
            recipient,
            amount,
        } = request;

        let inputs = self.resolve_tip_inputs(&identity, &asset_id)?;
        let recipient_ph = parse_puzzle_hash(&recipient)?;

        let unsigned = build_tip(DigTipRequest {
            cats: inputs.cats,
            owner_pk: inputs.owner_pk,
            asset_id: inputs.asset_id,
            recipient: recipient_ph,
            amount: amount.mojos(),
            change_p2_puzzle_hash: inputs.change_puzzle_hash,
        })
        .map_err(map_tip_error)?;

        self.finish_tip(unsigned.coin_spends, recipient_ph, amount, asset_id)
    }

    async fn build_auto_tip(&self, request: AutoTipRequest) -> WalletResult<AutoTipOutcome> {
        let AutoTipRequest {
            identity,
            policy,
            primary_send_amount,
            ledger,
        } = request;

        let asset_id = policy.asset_id.clone();
        let recipient_ph = parse_puzzle_hash(&policy.recipient)?;
        let inputs = self.resolve_tip_inputs(&identity, &asset_id)?;
        let dig_policy = to_dig_policy(&policy, recipient_ph, inputs.asset_id)?;

        let (decision, spend) = build_tip_if_allowed(
            &dig_policy,
            primary_send_amount.mojos(),
            &LedgerSnapshot {
                tips_today: ledger.tips_today,
                amount_today: ledger.amount_today.mojos(),
            },
            inputs.cats,
            inputs.owner_pk,
            inputs.change_puzzle_hash,
        )
        .map_err(map_tip_error)?;

        let unsigned = match spend {
            Some(cat_spend) => Some(self.finish_tip(
                cat_spend.coin_spends,
                recipient_ph,
                Amount(dig_policy.tip_amount),
                asset_id,
            )?),
            None => None,
        };

        Ok(AutoTipOutcome {
            decision: from_dig_decision(decision),
            unsigned,
        })
    }
}

/// The resolved public inputs a tip is built against: the single-key CAT coin group, the key that
/// authorizes it, the asset id, and where change returns.
struct TipInputs {
    cats: Vec<Cat>,
    owner_pk: PublicKey,
    asset_id: Bytes32,
    change_puzzle_hash: Bytes32,
}

impl SdkSpendBuilder {
    /// Resolve the tip inputs from the injected provider: the spendable CATs of `asset_id` grouped
    /// to a SINGLE authorizing key (dig-tips authorizes every input coin with one `owner_pk`), and
    /// the change puzzle hash.
    ///
    /// Groups the wallet's CATs by inner (p2) puzzle hash, keeps only groups the wallet holds a key
    /// for, and picks the largest such group — a v0.9.0 single-key tip. Fail-closed:
    /// [`WalletErrorCode::InsufficientFunds`] when no spendable, key-controlled CAT of the asset
    /// exists.
    fn resolve_tip_inputs(
        &self,
        identity: &IdentityRef,
        asset_id: &AssetId,
    ) -> WalletResult<TipInputs> {
        let asset = parse_asset_id(asset_id)?;
        let cats: Vec<Cat> = self
            .inputs
            .spendable_cat(identity, asset_id)?
            .into_iter()
            .filter(|cat| cat.info.asset_id == asset)
            .collect();

        let (owner_pk, group) = self.largest_single_key_group(&cats).ok_or_else(|| {
            WalletError::new(
                WalletErrorCode::InsufficientFunds,
                format!(
                    "no spendable, key-controlled {} coins to tip with",
                    asset_id.0
                ),
            )
        })?;

        Ok(TipInputs {
            cats: group,
            owner_pk,
            asset_id: asset,
            change_puzzle_hash: self.inputs.change_puzzle_hash(identity)?,
        })
    }

    /// The largest-by-total group of CATs sharing one inner puzzle hash the wallet holds a key for,
    /// with that key. `None` when the wallet controls none of the coins.
    fn largest_single_key_group(&self, cats: &[Cat]) -> Option<(PublicKey, Vec<Cat>)> {
        let mut best: Option<(PublicKey, Vec<Cat>, u64)> = None;
        let mut seen: Vec<Bytes32> = Vec::new();
        for cat in cats {
            let p2 = cat.info.p2_puzzle_hash;
            if seen.contains(&p2) {
                continue;
            }
            seen.push(p2);
            let Some(key) = self.inputs.synthetic_key(p2) else {
                continue;
            };
            let group: Vec<Cat> = cats
                .iter()
                .filter(|c| c.info.p2_puzzle_hash == p2)
                .copied()
                .collect();
            let total: u64 = group.iter().map(|c| c.coin.amount).sum();
            if best
                .as_ref()
                .map_or(true, |(_, _, best_total)| total > *best_total)
            {
                best = Some((key, group, total));
            }
        }
        best.map(|(key, group, _)| (key, group))
    }

    /// Wrap a tip's unsigned coin spends into a reviewable [`UnsignedSpend`]: extract the required
    /// signatures through the shared key-free extractor, assert it is a real signed-offline spend,
    /// and summarize the single CAT payment (a tip reserves no separate XCH fee).
    fn finish_tip(
        &self,
        coin_spends: Vec<chia::protocol::CoinSpend>,
        recipient_ph: Bytes32,
        amount: Amount,
        asset_id: AssetId,
    ) -> WalletResult<UnsignedSpend> {
        let required_signatures = self.required_signatures(&coin_spends)?;
        ensure_signed_offline(&coin_spends, &required_signatures)?;
        Ok(UnsignedSpend {
            coin_spends,
            required_signatures,
            summary: TransactionSummary {
                outputs: vec![SpendOutput {
                    address: encode_address(recipient_ph)?,
                    amount,
                    asset_id: Some(asset_id),
                }],
                fee: Amount(0),
            },
        })
    }
}

/// Build the `dig_tips::AutoTipPolicy` from the wire policy, resolving the recipient + asset id to
/// their byte forms.
fn to_dig_policy(
    policy: &AutoTipPolicy,
    recipient_ph: Bytes32,
    asset_id: Bytes32,
) -> WalletResult<DigAutoTipPolicy> {
    Ok(DigAutoTipPolicy {
        enabled: policy.enabled,
        mode: match policy.mode {
            crate::types::TipMode::Auto => DigTipMode::Auto,
            crate::types::TipMode::Manual => DigTipMode::Manual,
        },
        asset_id,
        recipient: recipient_ph,
        tip_amount: policy.tip_amount.mojos(),
        threshold: policy.threshold.mojos(),
        max_tips_per_day: policy.max_tips_per_day,
        max_amount_per_day: policy.max_amount_per_day.mojos(),
    })
}

/// Translate a `dig_tips::TipDecision` into the wire [`TipDecision`].
fn from_dig_decision(decision: DigTipDecision) -> TipDecision {
    match decision {
        DigTipDecision::Tip { amount } => TipDecision::Tip {
            amount: Amount(amount),
        },
        DigTipDecision::SkipDisabled => TipDecision::SkipDisabled,
        DigTipDecision::SkipBelowThreshold => TipDecision::SkipBelowThreshold,
        DigTipDecision::SkipManualNotApproved => TipDecision::SkipManualNotApproved,
        DigTipDecision::SkipCapReached { reason } => TipDecision::SkipCapReached {
            reason: match reason {
                DigCapReason::FrequencyCap => CapReason::Frequency,
                DigCapReason::AmountCap => CapReason::Amount,
            },
        },
    }
}

/// Parse a 32-byte value from its lowercase-hex wire form, fail-closed on a bad value.
fn parse_hex32(value: &str, label: &str) -> WalletResult<Bytes32> {
    let bytes = hex::decode(value)
        .map_err(|e| WalletError::invalid_input(format!("bad {label} {value}: {e}")))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| WalletError::invalid_input(format!("{label} {value} is not 32 bytes")))?;
    Ok(Bytes32::new(array))
}

/// Parse a 32-byte puzzle hash from its hex wire form.
fn parse_puzzle_hash(ph: &Puzzlehash) -> WalletResult<Bytes32> {
    parse_hex32(&ph.0, "puzzle hash")
}

/// Parse a 32-byte CAT asset id (TAIL hash) from its hex wire form.
fn parse_asset_id(asset_id: &AssetId) -> WalletResult<Bytes32> {
    parse_hex32(&asset_id.0, "asset id")
}

/// Encode a puzzle hash as an `xch1…` bech32m address for the review summary.
fn encode_address(puzzle_hash: Bytes32) -> WalletResult<Address> {
    use chia_wallet_sdk::utils::Address as Bech32Address;
    Bech32Address::new(puzzle_hash, "xch".into())
        .encode()
        .map(Address)
        .map_err(|e| spend_failed(format!("encode address: {e:?}")))
}

/// Translate a `dig-tips` error into the wallet-backend error catalogue.
fn map_tip_error(error: dig_tips::Error) -> WalletError {
    let dig_tips::Error::Cat(cat) = error;
    match cat {
        CatError::ZeroAmount => WalletError::invalid_input("a tip must move a non-zero amount"),
        CatError::InsufficientFunds { need, have } => WalletError::new(
            WalletErrorCode::InsufficientFunds,
            format!("insufficient CAT to tip: need {need}, have {have}"),
        ),
        CatError::TooManyInputs { needed, cap } => WalletError::new(
            WalletErrorCode::InsufficientFunds,
            format!("tip needs {needed} CAT inputs, over the {cap}-coin cap; consolidate first"),
        ),
        other => spend_failed(format!("dig-tips: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::build::SpendInputs;
    use crate::types::{Network, WalletId};
    use chia::protocol::Coin;
    use chia::puzzles::standard::StandardArgs;
    use chia::puzzles::LineageProof;
    use chia_wallet_sdk::driver::{CatInfo, SpendContext};
    use chia_wallet_sdk::types::Conditions;
    use std::sync::Arc;

    /// The BLS12-381 G1 generator (compressed) — a valid, non-infinity public key with NO secret,
    /// so a test drives the builder without naming any secret type (key-isolation, SPEC §1.4).
    fn test_public_key() -> PublicKey {
        const GENERATOR: [u8; 48] = [
            0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9,
            0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f,
            0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a,
            0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
        ];
        PublicKey::from_bytes(&GENERATOR).expect("valid G1 generator")
    }

    fn wallet_puzzle_hash() -> Bytes32 {
        Bytes32::from(StandardArgs::curry_tree_hash(test_public_key()).to_bytes())
    }

    /// The fixed test CAT asset id (TAIL hash) used for the fabricated-coin error-path tests —
    /// decoupled from any coin amount so a test can size coins freely.
    const ASSET: [u8; 32] = [0xABu8; 32];

    /// A structurally-spendable (fabricated-lineage) CAT of [`ASSET`] at the given inner (p2)
    /// `puzzle_hash`, holding `amount` base units. Enough to drive the builder's SELECTION + key
    /// resolution (which fail before any puzzle is run) — NOT valid for a full spend evaluation, so
    /// it is used only in tests that error before `required_signatures`.
    fn fabricated_cat(puzzle_hash: Bytes32, amount: u64) -> Cat {
        let coin = Coin::new(
            Bytes32::new([0x33u8; 32]),
            Bytes32::new([0xEEu8; 32]),
            amount,
        );
        let proof = LineageProof {
            parent_parent_coin_info: Bytes32::new([0x01u8; 32]),
            parent_inner_puzzle_hash: Bytes32::new([0x02u8; 32]),
            parent_amount: amount,
        };
        Cat::new(
            coin,
            Some(proof),
            CatInfo::new(Bytes32::new(ASSET), None, puzzle_hash),
        )
    }

    /// A CAT at a puzzle hash the wallet holds NO key for (fabricated; error-path only).
    fn foreign_cat(amount: u64) -> Cat {
        fabricated_cat(Bytes32::new([0x99u8; 32]), amount)
    }

    /// Issue a REAL CAT owned by the test wallet key (valid lineage proof + inner p2 = the wallet
    /// key), so the produced spend actually evaluates through `required_signatures` — no simulator,
    /// no secret material. Deterministic in `(amount, seed)`.
    fn issued_cat(amount: u64, seed: u8) -> Cat {
        let mut ctx = SpendContext::new();
        let genesis = Coin::new(Bytes32::new([seed; 32]), wallet_puzzle_hash(), amount);
        let hint = ctx.hint(wallet_puzzle_hash()).unwrap();
        let create = Conditions::new().create_coin(wallet_puzzle_hash(), amount, hint);
        let (_, cats) = Cat::issue_with_coin(&mut ctx, genesis.coin_id(), amount, create).unwrap();
        cats[0]
    }

    /// The wire asset id of a CAT — the request's `asset_id` must match the coin's for selection.
    fn asset_of(cat: &Cat) -> AssetId {
        AssetId(hex::encode(cat.info.asset_id))
    }

    struct TestInputs {
        cats: Vec<Cat>,
    }

    impl SpendInputs for TestInputs {
        fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<Coin>> {
            Ok(vec![])
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

    fn builder(cats: Vec<Cat>) -> SdkSpendBuilder {
        SdkSpendBuilder::new(Arc::new(TestInputs { cats }), Network::Mainnet, 500)
    }

    fn tip_request(asset: AssetId, amount: u64) -> TipRequest {
        TipRequest {
            identity: IdentityRef::new(WalletId(1)),
            asset_id: asset,
            recipient: Puzzlehash(hex::encode([0x77u8; 32])),
            amount: Amount(amount),
        }
    }

    fn auto_request(policy: AutoTipPolicy, primary: u64, ledger: TipLedger) -> AutoTipRequest {
        AutoTipRequest {
            identity: IdentityRef::new(WalletId(1)),
            policy,
            primary_send_amount: Amount(primary),
            ledger,
        }
    }

    use crate::types::{AutoTipPolicy, TipLedger, TipMode};

    fn policy(asset: AssetId) -> AutoTipPolicy {
        AutoTipPolicy {
            enabled: true,
            mode: TipMode::Auto,
            asset_id: asset,
            recipient: Puzzlehash(hex::encode([0x77u8; 32])),
            tip_amount: Amount(1_000),
            threshold: Amount(0),
            max_tips_per_day: 3,
            max_amount_per_day: Amount(5_000),
        }
    }

    #[tokio::test]
    async fn builds_an_unsigned_tip_with_change_and_required_signatures() {
        let cat = issued_cat(10_000, 1);
        let asset = asset_of(&cat);
        let unsigned = builder(vec![cat])
            .build_tip(tip_request(asset.clone(), 1_000))
            .await
            .unwrap();

        assert!(!unsigned.coin_spends.is_empty());
        assert!(!unsigned.required_signatures.is_empty());
        assert_eq!(unsigned.summary.fee, Amount(0));
        assert_eq!(unsigned.summary.outputs[0].amount, Amount(1_000));
        assert_eq!(unsigned.summary.outputs[0].asset_id, Some(asset));
    }

    #[tokio::test]
    async fn tip_is_deterministic() {
        let asset = asset_of(&issued_cat(10_000, 1));
        let a = builder(vec![issued_cat(10_000, 1)])
            .build_tip(tip_request(asset.clone(), 1_000))
            .await
            .unwrap();
        let b = builder(vec![issued_cat(10_000, 1)])
            .build_tip(tip_request(asset, 1_000))
            .await
            .unwrap();
        assert_eq!(a, b, "identical inputs must yield an identical tip");
    }

    /// The engine binds the SAME `dig-constants` mainnet AGG_SIG_ME the client signer requires into
    /// a real tip message — the byte-KAT that keeps signer == engine for tips (custody, #1101).
    #[tokio::test]
    async fn tip_binds_the_dig_constants_mainnet_agg_sig_me() {
        let cat = issued_cat(10_000, 1);
        let asset = asset_of(&cat);
        let unsigned = builder(vec![cat])
            .build_tip(tip_request(asset, 1_000))
            .await
            .unwrap();
        assert!(!unsigned.required_signatures.is_empty());
        for req in &unsigned.required_signatures {
            assert!(
                req.message
                    .ends_with(&dig_constants::CHIA_L1_MAINNET_AGG_SIG_ME),
                "tip message not bound to the dig-constants Chia-L1 mainnet AGG_SIG_ME",
            );
        }
    }

    #[tokio::test]
    async fn zero_amount_tip_is_rejected() {
        let cat = issued_cat(10_000, 1);
        let asset = asset_of(&cat);
        let err = builder(vec![cat])
            .build_tip(tip_request(asset, 0))
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn tip_without_enough_cat_is_insufficient_funds() {
        let cat = issued_cat(100, 1);
        let asset = asset_of(&cat);
        let err = builder(vec![cat])
            .build_tip(tip_request(asset, 1_000))
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }

    #[tokio::test]
    async fn tip_with_no_key_controlled_cat_is_insufficient_funds() {
        // A foreign CAT of ASSET the wallet holds no key for → no key-controlled group.
        let err = builder(vec![foreign_cat(10_000)])
            .build_tip(tip_request(AssetId(hex::encode(ASSET)), 1_000))
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }

    #[tokio::test]
    async fn bad_recipient_puzzle_hash_is_rejected() {
        let cat = issued_cat(10_000, 1);
        let asset = asset_of(&cat);
        let req = TipRequest {
            recipient: Puzzlehash("not-hex".into()),
            ..tip_request(asset, 1_000)
        };
        let err = builder(vec![cat]).build_tip(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn auto_tip_builds_a_spend_when_within_caps() {
        let cat = issued_cat(10_000, 1);
        let asset = asset_of(&cat);
        let outcome = builder(vec![cat])
            .build_auto_tip(auto_request(policy(asset), 100_000, TipLedger::default()))
            .await
            .unwrap();
        assert_eq!(
            outcome.decision,
            TipDecision::Tip {
                amount: Amount(1_000)
            }
        );
        let spend = outcome.unsigned.expect("a Tip decision must build a spend");
        assert_eq!(spend.summary.outputs[0].amount, Amount(1_000));
    }

    #[tokio::test]
    async fn auto_tip_builds_nothing_when_disabled() {
        let cat = issued_cat(10_000, 1);
        let disabled = AutoTipPolicy {
            enabled: false,
            ..policy(asset_of(&cat))
        };
        let outcome = builder(vec![cat])
            .build_auto_tip(auto_request(disabled, 100_000, TipLedger::default()))
            .await
            .unwrap();
        assert_eq!(outcome.decision, TipDecision::SkipDisabled);
        assert!(
            outcome.unsigned.is_none(),
            "a disabled auto-tip must build nothing"
        );
    }

    #[tokio::test]
    async fn auto_tip_builds_nothing_when_the_amount_cap_is_reached() {
        let cat = issued_cat(10_000, 1);
        let asset = asset_of(&cat);
        let outcome = builder(vec![cat])
            .build_auto_tip(auto_request(
                policy(asset),
                100_000,
                TipLedger {
                    tips_today: 0,
                    amount_today: Amount(4_500), // 4_500 + 1_000 > 5_000 cap
                },
            ))
            .await
            .unwrap();
        assert_eq!(
            outcome.decision,
            TipDecision::SkipCapReached {
                reason: CapReason::Amount
            }
        );
        assert!(
            outcome.unsigned.is_none(),
            "a capped tip must build nothing"
        );
    }

    /// A capped auto-tip cannot be bypassed by omitting the spend build — the decision is made
    /// first and NOTHING is constructed on a skip (the honesty ceiling, §6.0).
    #[tokio::test]
    async fn auto_tip_frequency_cap_blocks_at_the_limit() {
        let cat = issued_cat(10_000, 1);
        let asset = asset_of(&cat);
        let outcome = builder(vec![cat])
            .build_auto_tip(auto_request(
                policy(asset),
                100_000,
                TipLedger {
                    tips_today: 3, // == max_tips_per_day
                    amount_today: Amount(0),
                },
            ))
            .await
            .unwrap();
        assert_eq!(
            outcome.decision,
            TipDecision::SkipCapReached {
                reason: CapReason::Frequency
            }
        );
        assert!(outcome.unsigned.is_none());
    }
}
