//! `engine::build_options` — unsigned covered-option spend construction (issue #1123, SPEC §3a).
//!
//! The options suite — **mint**, **transfer**, **exercise** — built the same way as every other
//! engine spend: the engine constructs an UNSIGNED spend and returns it for client review +
//! signing. It NEVER signs and NEVER hand-rolls option CLVM (§4.1) — every option spend flows
//! through the canonical [`dig-options`](https://crates.io/crates/dig-options) CHIP-0042 builders,
//! and the required signatures are extracted key-free through the same
//! [`SdkSpendBuilder::required_signatures`] path the XCH/CAT builders use.
//!
//! # Scope (v0.9.0)
//! **Mint** is fully wired over `dig_options::create`. **Transfer** and **exercise** have their
//! seam types + validation in place but return [`WalletErrorCode::NotImplemented`] pending two
//! `dig-options` additions (release-first, §4.1), because building them without hand-rolling
//! option internals requires crate support that 0.1.0 does not expose:
//! - **transfer** needs a `dig_options::transfer` builder over `OptionContract::transfer`
//!   (the SDK has the method; `dig-options` 0.1.0 does not expose a builder for it);
//! - **exercise** needs to reconstruct `dig_options::CreatedOption` from on-chain state, which
//!   needs a `dig-options` rehydration helper (`parse` alone cannot recover an option's terms).
//!
//! The wire surface exists now so consumers can code against it and the two ops light up when the
//! `dig-options` builders land — no consumer-facing shape change.

use async_trait::async_trait;
use chia::protocol::{Bytes32, Coin};
use dig_options::{create, OptionTerms, OptionType, Owner, SpendContext};

use crate::types::{
    Amount, ExerciseOptionRequest, MintOptionRequest, MintedOption, OptionHandle, OptionStrike,
    Puzzlehash, SpendOutput, TransactionSummary, TransferOptionRequest, UnsignedSpend, WalletError,
    WalletErrorCode, WalletResult,
};

use super::build::{ensure_signed_offline, spend_failed, SdkSpendBuilder};

/// Builds unsigned covered-option spends. Every method returns a client-reviewable, unsigned
/// result — the engine never signs (SPEC §1d, the key-isolation invariant).
#[async_trait]
pub trait OptionBuilder: Send + Sync {
    /// Build an unsigned option MINT: lock an XCH underlying and issue the option singleton.
    /// Returns the unsigned spend plus the [`OptionHandle`] the client retains to operate it.
    async fn build_mint_option(&self, request: MintOptionRequest) -> WalletResult<MintedOption>;

    /// Build an unsigned option TRANSFER to a new owner puzzle hash.
    async fn build_transfer_option(
        &self,
        request: TransferOptionRequest,
    ) -> WalletResult<UnsignedSpend>;

    /// Build an unsigned option EXERCISE: pay the strike and unlock the underlying to the holder.
    async fn build_exercise_option(
        &self,
        request: ExerciseOptionRequest,
    ) -> WalletResult<UnsignedSpend>;
}

#[async_trait]
impl OptionBuilder for SdkSpendBuilder {
    async fn build_mint_option(&self, request: MintOptionRequest) -> WalletResult<MintedOption> {
        let MintOptionRequest {
            identity,
            creator_puzzle_hash,
            owner_puzzle_hash,
            underlying_amount,
            strike,
            expiry_seconds,
            fee,
        } = request;

        let underlying = underlying_amount.mojos();
        if underlying == 0 {
            return Err(WalletError::invalid_input(
                "an option underlying amount must be non-zero",
            ));
        }
        let fee_max = fee.mojos();

        // Resolve the two parties. The creator (clawback recipient) defaults to the identity's
        // change puzzle hash; the owner (initial holder) defaults to the creator (self-minted).
        let creator_ph = match creator_puzzle_hash {
            Some(ph) => parse_puzzle_hash(&ph)?,
            None => self.inputs.change_puzzle_hash(&identity)?,
        };
        let owner_ph = match owner_puzzle_hash {
            Some(ph) => parse_puzzle_hash(&ph)?,
            None => creator_ph,
        };
        let strike_type = strike_to_option_type(&strike);

        // `dig_options::create` funds two outputs (the locked underlying + the 1-mojo singleton)
        // from ONE funding-coin spend and has no change output — its excess is an implicit fee.
        // Pick the smallest single coin covering `underlying + 1`, and REJECT one whose excess
        // would exceed `fee` so a mint never burns more than the caller consented to.
        let needed = underlying
            .checked_add(1)
            .ok_or_else(|| WalletError::invalid_input("underlying amount overflows"))?;
        let fee_ceiling = needed
            .checked_add(fee_max)
            .ok_or_else(|| WalletError::invalid_input("underlying + fee overflows"))?;
        let funding_coin = self.pick_funding_coin(&identity, needed, fee_ceiling)?;
        let implicit_fee = funding_coin.amount - needed;

        let creator_key = self
            .inputs
            .synthetic_key(funding_coin.puzzle_hash)
            .ok_or_else(|| spend_failed("no public key for the mint funding coin's puzzle hash"))?;

        let terms = OptionTerms {
            creator_puzzle_hash: creator_ph,
            owner_puzzle_hash: owner_ph,
            underlying_amount: underlying,
            strike_type,
            expiry_seconds,
        };

        let mut ctx = SpendContext::new();
        let option_spend = create(
            &mut ctx,
            &Owner::Standard(creator_key),
            funding_coin,
            &terms,
        )
        .map_err(map_options_error)?;
        let created = option_spend
            .created
            .ok_or_else(|| spend_failed("dig-options create did not return the created option"))?;

        let coin_spends = option_spend.coin_spends;
        let required_signatures = self.required_signatures(&coin_spends)?;
        ensure_signed_offline(&coin_spends, &required_signatures)?;

        let handle = OptionHandle {
            launcher_id: hex::encode(created.option.info.launcher_id),
            creator_puzzle_hash: Puzzlehash(hex::encode(creator_ph)),
            owner_puzzle_hash: Puzzlehash(hex::encode(owner_ph)),
            underlying_amount,
            strike,
            expiry_seconds,
            underlying_coin_id: hex::encode(created.underlying_coin.coin_id()),
            funding_coin_id: hex::encode(funding_coin.coin_id()),
        };

        let unsigned = UnsignedSpend {
            coin_spends,
            required_signatures,
            summary: TransactionSummary {
                outputs: vec![SpendOutput {
                    address: encode_address(owner_ph)?,
                    amount: underlying_amount,
                    asset_id: None,
                }],
                fee: Amount(implicit_fee),
            },
        };

        Ok(MintedOption { unsigned, handle })
    }

    async fn build_transfer_option(
        &self,
        request: TransferOptionRequest,
    ) -> WalletResult<UnsignedSpend> {
        // Validate inputs so the request shape is exercised even before the builder lands.
        parse_puzzle_hash(&request.to_puzzle_hash)?;
        Err(WalletError::new(
            WalletErrorCode::NotImplemented,
            "option transfer requires a dig_options::transfer builder (release-first, #1123)",
        ))
    }

    async fn build_exercise_option(
        &self,
        request: ExerciseOptionRequest,
    ) -> WalletResult<UnsignedSpend> {
        parse_puzzle_hash(&request.handle.owner_puzzle_hash)?;
        Err(WalletError::new(
            WalletErrorCode::NotImplemented,
            "option exercise requires a dig_options CreatedOption rehydration helper \
             (release-first, #1123)",
        ))
    }
}

impl SdkSpendBuilder {
    /// Pick the smallest single spendable XCH coin whose amount covers `needed` and whose excess
    /// over `needed` (the implicit fee) does not exceed the caller's fee ceiling.
    ///
    /// Fail-closed: no coin reaching `needed` is [`WalletErrorCode::InsufficientFunds`]; a coin
    /// that reaches `needed` only above the fee ceiling is a consolidation/split case (the mint
    /// path has no change output), surfaced with an actionable message.
    fn pick_funding_coin(
        &self,
        identity: &crate::types::IdentityRef,
        needed: u64,
        fee_ceiling: u64,
    ) -> WalletResult<Coin> {
        let coins = self.inputs.spendable_xch(identity)?;
        let smallest_covering = coins
            .iter()
            .filter(|c| c.amount >= needed)
            .min_by_key(|c| c.amount);

        let Some(coin) = smallest_covering else {
            let total: u64 = coins.iter().map(|c| c.amount).sum();
            return Err(WalletError::new(
                WalletErrorCode::InsufficientFunds,
                format!(
                    "no single XCH coin covers the option underlying + singleton ({needed}); \
                     largest available across {} coins totals {total}",
                    coins.len()
                ),
            ));
        };

        if coin.amount > fee_ceiling {
            return Err(WalletError::new(
                WalletErrorCode::InsufficientFunds,
                format!(
                    "smallest funding coin ({}) exceeds underlying + singleton + max fee \
                     ({fee_ceiling}); split a coin to that size first (mint has no change output)",
                    coin.amount
                ),
            ));
        }
        Ok(*coin)
    }
}

/// Map an [`OptionStrike`] wire value to the SDK's `OptionType` (XCH-only in v0.9.0).
fn strike_to_option_type(strike: &OptionStrike) -> OptionType {
    match strike {
        OptionStrike::Xch { amount } => OptionType::Xch {
            amount: amount.mojos(),
        },
    }
}

/// Parse a 32-byte puzzle hash from its lowercase-hex wire form, fail-closed on a bad value.
fn parse_puzzle_hash(ph: &Puzzlehash) -> WalletResult<Bytes32> {
    let bytes = hex::decode(&ph.0)
        .map_err(|e| WalletError::invalid_input(format!("bad puzzle hash {}: {e}", ph.0)))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| WalletError::invalid_input(format!("puzzle hash {} is not 32 bytes", ph.0)))?;
    Ok(Bytes32::new(array))
}

/// Encode a puzzle hash as an `xch1…` bech32m address for the review summary.
fn encode_address(puzzle_hash: Bytes32) -> WalletResult<crate::types::Address> {
    use chia_wallet_sdk::utils::Address as Bech32Address;
    Bech32Address::new(puzzle_hash, "xch".into())
        .encode()
        .map(crate::types::Address)
        .map_err(|e| spend_failed(format!("encode address: {e:?}")))
}

/// Translate a `dig-options` builder error into the wallet-backend error catalogue.
fn map_options_error(error: dig_options::Error) -> WalletError {
    match error {
        dig_options::Error::InvalidInput(message) => WalletError::invalid_input(message),
        other => spend_failed(format!("dig-options: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::build::SpendInputs;
    use crate::types::{IdentityRef, Network, WalletId};
    use chia::bls::PublicKey;
    use chia::puzzles::standard::StandardArgs;
    use chia_wallet_sdk::driver::Cat;
    use std::sync::Arc;

    /// The BLS12-381 G1 generator (compressed) — a valid non-infinity public key with NO secret,
    /// so a test can curry a standard puzzle without naming any secret type (key-isolation).
    fn test_public_key() -> PublicKey {
        let mut generator = [0u8; 48];
        const PREFIX: [u8; 48] = [
            0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9,
            0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f,
            0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a,
            0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
        ];
        generator.copy_from_slice(&PREFIX);
        PublicKey::from_bytes(&generator).expect("valid G1 generator")
    }

    fn wallet_puzzle_hash() -> Bytes32 {
        Bytes32::from(StandardArgs::curry_tree_hash(test_public_key()).to_bytes())
    }

    fn wallet_coin(amount: u64, seed: u8) -> Coin {
        Coin::new(Bytes32::new([seed; 32]), wallet_puzzle_hash(), amount)
    }

    struct TestInputs {
        xch: Vec<Coin>,
    }

    impl SpendInputs for TestInputs {
        fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<Coin>> {
            Ok(self.xch.clone())
        }
        fn spendable_cat(
            &self,
            _: &IdentityRef,
            _: &crate::types::AssetId,
        ) -> WalletResult<Vec<Cat>> {
            Ok(vec![])
        }
        fn synthetic_key(&self, puzzle_hash: Bytes32) -> Option<PublicKey> {
            (puzzle_hash == wallet_puzzle_hash()).then(test_public_key)
        }
        fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<Bytes32> {
            Ok(wallet_puzzle_hash())
        }
    }

    fn builder(xch: Vec<Coin>) -> SdkSpendBuilder {
        SdkSpendBuilder::new(Arc::new(TestInputs { xch }), Network::Mainnet, 500)
    }

    fn mint_request(underlying: u64, strike: u64, fee: u64) -> MintOptionRequest {
        MintOptionRequest {
            identity: IdentityRef::new(WalletId(1)),
            creator_puzzle_hash: None,
            owner_puzzle_hash: None,
            underlying_amount: Amount(underlying),
            strike: OptionStrike::Xch {
                amount: Amount(strike),
            },
            expiry_seconds: 1_800_000_000,
            fee: Amount(fee),
        }
    }

    #[tokio::test]
    async fn builds_an_unsigned_mint_with_handle_and_required_signatures() {
        // Funding coin = underlying(1000) + 1 singleton + 10 implicit fee = 1011.
        let b = builder(vec![wallet_coin(1011, 1)]);
        let minted = b
            .build_mint_option(mint_request(1000, 500, 10))
            .await
            .unwrap();

        assert!(!minted.unsigned.coin_spends.is_empty());
        assert!(!minted.unsigned.required_signatures.is_empty());
        assert_eq!(minted.unsigned.summary.fee, Amount(10));
        assert_eq!(minted.unsigned.summary.outputs[0].amount, Amount(1000));
        // The retained handle carries the terms + on-chain ids.
        assert_eq!(minted.handle.underlying_amount, Amount(1000));
        assert_eq!(minted.handle.launcher_id.len(), 64);
        assert_eq!(minted.handle.underlying_coin_id.len(), 64);
        assert_eq!(
            minted.handle.strike,
            OptionStrike::Xch {
                amount: Amount(500)
            }
        );
    }

    #[tokio::test]
    async fn mint_is_deterministic() {
        let coins = vec![wallet_coin(1011, 1)];
        let a = builder(coins.clone())
            .build_mint_option(mint_request(1000, 500, 10))
            .await
            .unwrap();
        let b = builder(coins)
            .build_mint_option(mint_request(1000, 500, 10))
            .await
            .unwrap();
        assert_eq!(a, b, "identical inputs must yield an identical mint");
    }

    #[tokio::test]
    async fn mint_picks_the_smallest_covering_coin() {
        // 1005 (excess 4 <= fee 10) is chosen over 2000; implicit fee = 1005 - 1001 = 4.
        let b = builder(vec![wallet_coin(2000, 1), wallet_coin(1005, 2)]);
        let minted = b
            .build_mint_option(mint_request(1000, 500, 10))
            .await
            .unwrap();
        assert_eq!(minted.unsigned.summary.fee, Amount(4));
    }

    #[tokio::test]
    async fn mint_zero_underlying_is_rejected() {
        let b = builder(vec![wallet_coin(1011, 1)]);
        let err = b
            .build_mint_option(mint_request(0, 500, 10))
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn mint_without_a_covering_coin_is_insufficient_funds() {
        let b = builder(vec![wallet_coin(100, 1)]);
        let err = b
            .build_mint_option(mint_request(1000, 500, 10))
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }

    #[tokio::test]
    async fn mint_rejects_a_coin_whose_excess_exceeds_the_fee() {
        // Only a 2000 coin: excess over 1001 = 999 > fee 10 → split-required error.
        let b = builder(vec![wallet_coin(2000, 1)]);
        let err = b
            .build_mint_option(mint_request(1000, 500, 10))
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
        assert!(err.message.contains("split"), "message: {}", err.message);
    }

    #[tokio::test]
    async fn transfer_reports_not_implemented() {
        let b = builder(vec![]);
        let req = TransferOptionRequest {
            identity: IdentityRef::new(WalletId(1)),
            handle: sample_handle(),
            to_puzzle_hash: Puzzlehash(hex::encode([9u8; 32])),
            fee: Amount(1),
        };
        let err = b.build_transfer_option(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::NotImplemented);
    }

    #[tokio::test]
    async fn exercise_reports_not_implemented() {
        let b = builder(vec![]);
        let req = ExerciseOptionRequest {
            identity: IdentityRef::new(WalletId(1)),
            handle: sample_handle(),
            fee: Amount(1),
        };
        let err = b.build_exercise_option(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::NotImplemented);
    }

    #[tokio::test]
    async fn transfer_rejects_a_bad_destination_before_not_implemented() {
        let b = builder(vec![]);
        let req = TransferOptionRequest {
            identity: IdentityRef::new(WalletId(1)),
            handle: sample_handle(),
            to_puzzle_hash: Puzzlehash("not-hex".into()),
            fee: Amount(1),
        };
        let err = b.build_transfer_option(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    fn sample_handle() -> OptionHandle {
        OptionHandle {
            launcher_id: hex::encode([1u8; 32]),
            creator_puzzle_hash: Puzzlehash(hex::encode([2u8; 32])),
            owner_puzzle_hash: Puzzlehash(hex::encode([3u8; 32])),
            underlying_amount: Amount(1000),
            strike: OptionStrike::Xch {
                amount: Amount(500),
            },
            expiry_seconds: 1_800_000_000,
            underlying_coin_id: hex::encode([4u8; 32]),
            funding_coin_id: hex::encode([5u8; 32]),
        }
    }
}
