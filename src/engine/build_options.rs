//! `engine::build_options` — unsigned covered-option spend construction (issue #1123, SPEC §3a).
//!
//! The options suite — **mint**, **transfer**, **exercise** — built the same way as every other
//! engine spend: the engine constructs an UNSIGNED spend and returns it for client review +
//! signing. It NEVER signs and NEVER hand-rolls option CLVM (§4.1) — every option spend flows
//! through the canonical [`dig-options`](https://crates.io/crates/dig-options) CHIP-0042 builders,
//! and the required signatures are extracted key-free through the same
//! [`SdkSpendBuilder::required_signatures`] path the XCH/CAT builders use.
//!
//! # Scope
//! All three actions — **mint**, **transfer**, **exercise** — are fully wired over `dig-options`
//! v0.2.0. Mint composes `dig_options::create`; transfer + exercise compose
//! `dig_options::{parse_child, rehydrate, transfer, exercise}`.
//!
//! ## The on-chain-projection seam (transfer + exercise)
//! The engine is chain-agnostic and key-free (#908): it cannot fetch an option's live singleton or
//! recover a `dig_options::CreatedOption` on its own. So a chain-reading CLIENT supplies the option's
//! current on-chain state as an [`OptionOnChainState`] projection — the option singleton's current
//! parent spend (its coin + serialized puzzle reveal + solution) plus the locked-underlying coin.
//! The engine decodes it, `parse_child`s the live option, and `rehydrate`s + VERIFIES its terms
//! fail-closed against the retained [`OptionHandle`] before composing the spend (see
//! [`SdkSpendBuilder::rehydrate_option`]). The engine never trusts the projection blindly (NC-9):
//! a substituted option, a tampered underlying coin, or a wrong strike/term is rejected.

use async_trait::async_trait;
use chia::bls::PublicKey;
use chia::protocol::{Bytes32, Coin, Program};
use dig_options::{
    create, exercise, parse_child, rehydrate, transfer, CreatedOption, OptionTerms, OptionType,
    Owner, RehydratedTerms, SpendContext, StrikePayment,
};

use crate::types::{
    Amount, ExerciseOptionRequest, IdentityRef, MintOptionRequest, MintedOption, OptionHandle,
    OptionOnChainState, OptionStrike, Puzzlehash, SpendOutput, TransactionSummary,
    TransferOptionRequest, UnsignedSpend, WalletError, WalletErrorCode, WalletResult, WireCoin,
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
        let TransferOptionRequest {
            identity,
            handle,
            on_chain,
            to_puzzle_hash,
            fee,
        } = request;
        let destination = parse_puzzle_hash(&to_puzzle_hash)?;

        // Rehydrate + verify the option from its on-chain projection, fail-closed against the
        // handle (NC-9). `holder_key` authorizes the CURRENT owner's singleton spend.
        let mut ctx = SpendContext::new();
        let (created, holder_key) = self.rehydrate_option(&mut ctx, &handle, &on_chain)?;

        // `dig_options::transfer` re-homes only the singleton (the underlying + terms are
        // unchanged) and rejects a `holder_key` that is not the option's current owner.
        let transferred = transfer(
            &mut ctx,
            &Owner::Standard(holder_key),
            &created,
            destination,
        )
        .map_err(map_options_error)?;
        let mut coin_spends = transferred.coin_spends;

        // `dig_options::transfer` takes no fee (it spends only the 1-mojo singleton). A requested
        // farmer fee is honoured with a SEPARATE engine-side fee-coin spend, linked to the
        // singleton via `assert_concurrent_spend` so it is atomic with the transfer — never
        // silently dropped.
        let fee = fee.mojos();
        if fee > 0 {
            let change_ph = self.inputs.change_puzzle_hash(&identity)?;
            let singleton_id = created.option.coin.coin_id();
            self.add_xch_fee(&mut ctx, &identity, fee, change_ph, singleton_id)?;
            coin_spends.extend(ctx.take());
        }

        let required_signatures = self.required_signatures(&coin_spends)?;
        ensure_signed_offline(&coin_spends, &required_signatures)?;

        Ok(UnsignedSpend {
            coin_spends,
            required_signatures,
            summary: TransactionSummary {
                outputs: vec![SpendOutput {
                    address: encode_address(destination)?,
                    amount: Amount(created.option.coin.amount),
                    asset_id: None,
                }],
                fee: Amount(fee),
            },
        })
    }

    async fn build_exercise_option(
        &self,
        request: ExerciseOptionRequest,
    ) -> WalletResult<UnsignedSpend> {
        let ExerciseOptionRequest {
            identity,
            handle,
            on_chain,
            fee,
        } = request;
        // Keep the early handle validation so a malformed request fails before any chain decode.
        parse_puzzle_hash(&handle.owner_puzzle_hash)?;
        let strike_amount = strike_amount_mojos(&handle.strike);

        // Rehydrate + verify the option from its on-chain projection, fail-closed (NC-9).
        let mut ctx = SpendContext::new();
        let (created, holder_key) = self.rehydrate_option(&mut ctx, &handle, &on_chain)?;

        // Fund the XCH strike from a coin the CURRENT owner controls (at the option's live p2
        // puzzle hash). `dig_options::exercise` emits only `create_coin(SETTLEMENT, strike)` from
        // this coin with no change output, so its excess over the strike is an implicit fee —
        // bounded above by the caller's `fee` (mirrors the mint path; never burns more than
        // consented).
        let p2_puzzle_hash = created.option.info.p2_puzzle_hash;
        let fee_ceiling = strike_amount
            .checked_add(fee.mojos())
            .ok_or_else(|| WalletError::invalid_input("strike + fee overflows"))?;
        let funding_coin =
            self.pick_strike_coin(&identity, p2_puzzle_hash, strike_amount, fee_ceiling)?;
        let implicit_fee = funding_coin.amount - strike_amount;

        // Build the exercise. Its bundle carries BOTH settlement legs (the underlying claimed back
        // to the holder AND the strike paid to the creator) in one atomic spend — see the
        // atomicity conformance test below.
        let exercised = exercise(
            &mut ctx,
            &Owner::Standard(holder_key),
            &created,
            &StrikePayment { funding_coin },
        )
        .map_err(map_options_error)?;

        let coin_spends = exercised.coin_spends;
        let required_signatures = self.required_signatures(&coin_spends)?;
        ensure_signed_offline(&coin_spends, &required_signatures)?;

        Ok(UnsignedSpend {
            coin_spends,
            required_signatures,
            summary: TransactionSummary {
                outputs: vec![SpendOutput {
                    // The unlocked underlying is claimed to the option's current owner (p2).
                    address: encode_address(p2_puzzle_hash)?,
                    amount: handle.underlying_amount,
                    asset_id: None,
                }],
                fee: Amount(implicit_fee),
            },
        })
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

    /// Pick the strike-funding coin for an exercise: the smallest spendable XCH coin AT the option's
    /// current-owner puzzle hash (the exercise authorizes it through that owner's key) covering the
    /// strike, whose excess over the strike (the implicit fee) does not exceed `fee_ceiling`.
    ///
    /// Filtering by `p2_puzzle_hash` is load-bearing: `dig_options::exercise` spends the funding coin
    /// through the holder's standard layer, so a coin at any other puzzle hash could not be
    /// authorized by `holder_key`. Fail-closed like [`Self::pick_funding_coin`] — the exercise path
    /// has no change output, so an oversized-only coin is a split case, not silently over-burned.
    fn pick_strike_coin(
        &self,
        identity: &IdentityRef,
        p2_puzzle_hash: Bytes32,
        strike_amount: u64,
        fee_ceiling: u64,
    ) -> WalletResult<Coin> {
        let coins = self.inputs.spendable_xch(identity)?;
        let smallest_covering = coins
            .iter()
            .filter(|c| c.puzzle_hash == p2_puzzle_hash && c.amount >= strike_amount)
            .min_by_key(|c| c.amount);

        let Some(coin) = smallest_covering else {
            return Err(WalletError::new(
                WalletErrorCode::InsufficientFunds,
                format!(
                    "no spendable XCH coin at the option owner's puzzle hash covers the strike \
                     ({strike_amount})"
                ),
            ));
        };

        if coin.amount > fee_ceiling {
            return Err(WalletError::new(
                WalletErrorCode::InsufficientFunds,
                format!(
                    "smallest strike coin ({}) exceeds strike + max fee ({fee_ceiling}); split a \
                     coin to that size first (exercise has no change output)",
                    coin.amount
                ),
            ));
        }
        Ok(*coin)
    }

    /// Decode + fail-closed VERIFY an option's on-chain projection into an operable
    /// [`CreatedOption`], returning it alongside the CURRENT owner's authorizing public key.
    ///
    /// This is the shared spine of transfer + exercise. It NEVER trusts the projection (NC-9): it
    /// `parse_child`s the live option from the supplied parent spend, asserts the parsed launcher id
    /// matches the handle we intend to operate (rejecting a substituted option), then `rehydrate`s
    /// the terms — which independently re-derives and checks the option's three on-chain commitments
    /// (the 1-of-2 exercise/clawback path, the underlying delegated-puzzle hash, and the
    /// underlying-coin-id binding), so a tampered coin, term, or strike is rejected here.
    ///
    /// The authorizing key is resolved from the PARSED option's current `p2_puzzle_hash`, not the
    /// handle's original owner — the singleton may have been transferred since mint. A wallet that
    /// does not hold that key is not the current owner and cannot operate the option.
    fn rehydrate_option(
        &self,
        ctx: &mut SpendContext,
        handle: &OptionHandle,
        on_chain: &OptionOnChainState,
    ) -> WalletResult<(CreatedOption, PublicKey)> {
        let parent_coin = decode_wire_coin(&on_chain.option_parent_coin)?;
        let parent_reveal = decode_program(&on_chain.option_parent_puzzle_reveal, "puzzle reveal")?;
        let parent_solution = decode_program(&on_chain.option_parent_solution, "solution")?;
        let underlying_coin = decode_wire_coin(&on_chain.underlying_coin)?;

        let parsed = parse_child(ctx, parent_coin, &parent_reveal, &parent_solution)
            .map_err(|e| spend_failed(format!("parse option child from parent spend: {e}")))?
            .ok_or_else(|| spend_failed("on-chain parent did not create an option child"))?;

        // NC-9 fail-closed: the handle names the option we intend to operate; the on-chain parent
        // MUST produce THAT option's launcher, never a substituted one.
        let expected_launcher = parse_bytes32(&handle.launcher_id, "launcher id")?;
        if parsed.option.info.launcher_id != expected_launcher {
            return Err(spend_failed(
                "on-chain option launcher does not match the handle's launcher id",
            ));
        }

        let terms = RehydratedTerms {
            creator_puzzle_hash: parse_puzzle_hash(&handle.creator_puzzle_hash)?,
            expiry_seconds: handle.expiry_seconds,
            strike_type: strike_to_option_type(&handle.strike),
        };
        // Fail-closed: `rehydrate` re-derives + checks the option's three on-chain commitments
        // (1-of-2 path, delegated-puzzle hash, underlying-coin-id binding). A tampered coin, term,
        // or strike is rejected here — a validation failure against untrusted chain data, not a
        // caller input-shape error.
        let created = rehydrate(&parsed.option, &terms, underlying_coin).map_err(|e| {
            spend_failed(format!(
                "option rehydration rejected the on-chain projection: {e}"
            ))
        })?;

        let holder_key = self
            .inputs
            .synthetic_key(parsed.option.info.p2_puzzle_hash)
            .ok_or_else(|| {
                spend_failed("not the current option owner (no key for its puzzle hash)")
            })?;

        Ok((created, holder_key))
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

/// The strike amount in mojos (XCH-only in v0.9.0).
fn strike_amount_mojos(strike: &OptionStrike) -> u64 {
    match strike {
        OptionStrike::Xch { amount } => amount.mojos(),
    }
}

/// Parse a 32-byte hash from its lowercase-hex wire form, fail-closed with a `label`ed message.
fn parse_bytes32(hex_str: &str, label: &str) -> WalletResult<Bytes32> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| WalletError::invalid_input(format!("bad {label} {hex_str}: {e}")))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| WalletError::invalid_input(format!("{label} {hex_str} is not 32 bytes")))?;
    Ok(Bytes32::new(array))
}

/// Parse a 32-byte puzzle hash from its lowercase-hex wire form, fail-closed on a bad value.
fn parse_puzzle_hash(ph: &Puzzlehash) -> WalletResult<Bytes32> {
    parse_bytes32(&ph.0, "puzzle hash")
}

/// Decode a [`WireCoin`] projection into a `chia_protocol::Coin`, fail-closed on any bad field.
fn decode_wire_coin(coin: &WireCoin) -> WalletResult<Coin> {
    Ok(Coin::new(
        parse_bytes32(&coin.parent_coin_info, "coin parent id")?,
        parse_bytes32(&coin.puzzle_hash, "coin puzzle hash")?,
        coin.amount,
    ))
}

/// Decode a serialized-CLVM `Program` from its lowercase-hex wire form, fail-closed with a `label`.
fn decode_program(hex_str: &str, label: &str) -> WalletResult<Program> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| WalletError::invalid_input(format!("bad {label} hex: {e}")))?;
    Ok(Program::from(bytes))
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

    // ---- Transfer + exercise: real, key-free fixtures ----
    //
    // A minted option's on-chain projection is built by minting via `dig_options::create` in-test
    // (public G1 owner, no secret, no simulator) and extracting the option child's parent spend
    // from the create bundle — exactly what a chain-reading client would fetch and pass as an
    // `OptionOnChainState`. The engine then rehydrates + composes transfer/exercise against it.

    const TEST_EXPIRY: u64 = 1_800_000_000;

    fn wire_coin(coin: &Coin) -> WireCoin {
        WireCoin {
            parent_coin_info: hex::encode(coin.parent_coin_info),
            puzzle_hash: hex::encode(coin.puzzle_hash),
            amount: coin.amount,
        }
    }

    fn program_hex(program: &Program) -> String {
        hex::encode(Vec::<u8>::from(program.clone()))
    }

    /// Mint a real option to `owner_ph` (creator `creator_ph`) and return the handle a client
    /// retains plus the on-chain projection it would fetch to later operate the option.
    fn minted_fixture(
        underlying: u64,
        strike: u64,
        creator_ph: Bytes32,
        owner_ph: Bytes32,
    ) -> (OptionHandle, OptionOnChainState) {
        let mut ctx = SpendContext::new();
        let funding_coin = wallet_coin(underlying + 1, 1);
        let terms = OptionTerms {
            creator_puzzle_hash: creator_ph,
            owner_puzzle_hash: owner_ph,
            underlying_amount: underlying,
            strike_type: OptionType::Xch { amount: strike },
            expiry_seconds: TEST_EXPIRY,
        };
        let spend = create(
            &mut ctx,
            &Owner::Standard(test_public_key()),
            funding_coin,
            &terms,
        )
        .expect("mint option");
        let created = spend.created.clone().expect("created option");

        // The option child's parent coin is spent inside the same create bundle; find that spend to
        // build the `parse_child` projection.
        let parent_id = created.option.coin.parent_coin_info;
        let parent_spend = spend
            .coin_spends
            .iter()
            .find(|cs| cs.coin.coin_id() == parent_id)
            .expect("create bundle contains the option child's parent spend");

        let handle = OptionHandle {
            launcher_id: hex::encode(created.option.info.launcher_id),
            creator_puzzle_hash: Puzzlehash(hex::encode(creator_ph)),
            owner_puzzle_hash: Puzzlehash(hex::encode(owner_ph)),
            underlying_amount: Amount(underlying),
            strike: OptionStrike::Xch {
                amount: Amount(strike),
            },
            expiry_seconds: TEST_EXPIRY,
            underlying_coin_id: hex::encode(created.underlying_coin.coin_id()),
            funding_coin_id: hex::encode(funding_coin.coin_id()),
        };
        let on_chain = OptionOnChainState {
            option_parent_coin: wire_coin(&parent_spend.coin),
            option_parent_puzzle_reveal: program_hex(&parent_spend.puzzle_reveal),
            option_parent_solution: program_hex(&parent_spend.solution),
            underlying_coin: wire_coin(&created.underlying_coin),
        };
        (handle, on_chain)
    }

    /// A self-minted option owned + created by the test wallet (the common single-party case).
    fn self_minted(underlying: u64, strike: u64) -> (OptionHandle, OptionOnChainState) {
        let ph = wallet_puzzle_hash();
        minted_fixture(underlying, strike, ph, ph)
    }

    fn settlement_payment_hash() -> Bytes32 {
        use chia_wallet_sdk::types::puzzles::SettlementPayment;
        use chia_wallet_sdk::types::Mod;
        Bytes32::from(<[u8; 32]>::from(SettlementPayment::mod_hash()))
    }

    #[tokio::test]
    async fn builds_an_unsigned_exercise_with_the_underlying_claim_and_implicit_fee() {
        let (handle, on_chain) = self_minted(1_000, 500);
        // Strike-funding coin at the wallet: 500 strike + 5 excess (implicit fee), within fee=10.
        let b = builder(vec![wallet_coin(505, 7)]);
        let unsigned = b
            .build_exercise_option(ExerciseOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                fee: Amount(10),
            })
            .await
            .unwrap();

        assert!(!unsigned.coin_spends.is_empty());
        assert!(!unsigned.required_signatures.is_empty());
        assert_eq!(unsigned.summary.fee, Amount(5));
        assert_eq!(unsigned.summary.outputs[0].amount, Amount(1_000));
    }

    /// WIRED atomicity guard (SPEC §3a): the engine-built exercise bundle MUST carry the settlement
    /// leg claiming the FULL underlying back to the holder — pinned through the engine, not just the
    /// raw `dig_options::exercise` call, so no engine wiring can ever drop or reorder it.
    #[tokio::test]
    async fn wired_exercise_bundle_includes_the_underlying_claim_leg() {
        let (handle, on_chain) = self_minted(1_000, 500);
        let b = builder(vec![wallet_coin(500, 7)]);
        let unsigned = b
            .build_exercise_option(ExerciseOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                fee: Amount(0),
            })
            .await
            .unwrap();

        let settlement_ph = settlement_payment_hash();
        let has_underlying_claim = unsigned
            .coin_spends
            .iter()
            .any(|cs| cs.coin.puzzle_hash == settlement_ph && cs.coin.amount == 1_000);
        assert!(
            has_underlying_claim,
            "wired exercise bundle is missing the underlying-claim settlement leg (amount 1000)"
        );
    }

    /// Two-party (creator ≠ holder): the wallet is the HOLDER; the creator is a foreign puzzle hash.
    /// Both settlement legs must be present — the underlying (claimed to the holder) AND the strike
    /// (settled to the creator) — proving amounts are not misrouted.
    #[tokio::test]
    async fn exercise_two_party_routes_underlying_and_strike_without_misrouting() {
        let creator_ph = Bytes32::new([0xC1; 32]);
        let (handle, on_chain) = minted_fixture(1_000, 300, creator_ph, wallet_puzzle_hash());
        let b = builder(vec![wallet_coin(300, 7)]);
        let unsigned = b
            .build_exercise_option(ExerciseOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                fee: Amount(0),
            })
            .await
            .unwrap();

        let settlement_ph = settlement_payment_hash();
        let has_underlying = unsigned
            .coin_spends
            .iter()
            .any(|cs| cs.coin.puzzle_hash == settlement_ph && cs.coin.amount == 1_000);
        let has_strike = unsigned
            .coin_spends
            .iter()
            .any(|cs| cs.coin.puzzle_hash == settlement_ph && cs.coin.amount == 300);
        assert!(has_underlying, "underlying claim leg (1000) missing");
        assert!(has_strike, "strike settlement leg (300) missing");
    }

    #[tokio::test]
    async fn exercise_without_the_owner_key_is_rejected() {
        // Option owned by a foreign puzzle hash — the wallet holds no key for it.
        let foreign = Bytes32::new([0xF0; 32]);
        let (handle, on_chain) = minted_fixture(1_000, 500, foreign, foreign);
        let b = builder(vec![wallet_coin(500, 7)]);
        let err = b
            .build_exercise_option(ExerciseOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                fee: Amount(10),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    #[tokio::test]
    async fn exercise_without_a_strike_coin_is_insufficient_funds() {
        let (handle, on_chain) = self_minted(1_000, 500);
        let b = builder(vec![]); // no strike-funding coin
        let err = b
            .build_exercise_option(ExerciseOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                fee: Amount(10),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
    }

    // ---- NC-9 fail-closed: the engine never trusts the on-chain projection ----

    #[tokio::test]
    async fn exercise_rejects_a_handle_launcher_mismatch() {
        let (mut handle, on_chain) = self_minted(1_000, 500);
        // Tamper the handle's launcher id — it no longer names the option the projection produces.
        handle.launcher_id = hex::encode([0xAB; 32]);
        let b = builder(vec![wallet_coin(500, 7)]);
        let err = b
            .build_exercise_option(ExerciseOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                fee: Amount(10),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
        assert!(err.message.contains("launcher"), "message: {}", err.message);
    }

    #[tokio::test]
    async fn exercise_rejects_a_tampered_underlying_coin() {
        let (handle, mut on_chain) = self_minted(1_000, 500);
        // Tamper the underlying coin amount — rehydrate's coin-id + path checks must reject it.
        on_chain.underlying_coin.amount = 999;
        let b = builder(vec![wallet_coin(500, 7)]);
        let err = b
            .build_exercise_option(ExerciseOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                fee: Amount(10),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    #[tokio::test]
    async fn exercise_rejects_a_wrong_strike_in_the_handle() {
        let (mut handle, on_chain) = self_minted(1_000, 500);
        // Tamper the strike — rehydrate's delegated-puzzle-hash check must reject it.
        handle.strike = OptionStrike::Xch {
            amount: Amount(499),
        };
        let b = builder(vec![wallet_coin(500, 7)]);
        let err = b
            .build_exercise_option(ExerciseOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                fee: Amount(10),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    // ---- Transfer ----

    #[tokio::test]
    async fn builds_an_unsigned_transfer_with_a_fee() {
        let (handle, on_chain) = self_minted(1_000, 500);
        // A fee coin at the wallet to fund the separate farmer-fee leg.
        let b = builder(vec![wallet_coin(50, 8)]);
        let unsigned = b
            .build_transfer_option(TransferOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                to_puzzle_hash: Puzzlehash(hex::encode([9u8; 32])),
                fee: Amount(5),
            })
            .await
            .unwrap();
        assert!(!unsigned.coin_spends.is_empty());
        assert!(!unsigned.required_signatures.is_empty());
        assert_eq!(unsigned.summary.fee, Amount(5));
    }

    #[tokio::test]
    async fn builds_an_unsigned_transfer_without_a_fee() {
        let (handle, on_chain) = self_minted(1_000, 500);
        let b = builder(vec![]); // no fee → no fee coin needed
        let unsigned = b
            .build_transfer_option(TransferOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                to_puzzle_hash: Puzzlehash(hex::encode([9u8; 32])),
                fee: Amount(0),
            })
            .await
            .unwrap();
        assert_eq!(unsigned.summary.fee, Amount(0));
        assert!(!unsigned.required_signatures.is_empty());
    }

    #[tokio::test]
    async fn transfer_rejects_a_bad_destination() {
        let (handle, on_chain) = self_minted(1_000, 500);
        let b = builder(vec![]);
        let err = b
            .build_transfer_option(TransferOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                to_puzzle_hash: Puzzlehash("not-hex".into()),
                fee: Amount(1),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn transfer_without_the_owner_key_is_rejected() {
        let foreign = Bytes32::new([0xF0; 32]);
        let (handle, on_chain) = minted_fixture(1_000, 500, foreign, foreign);
        let b = builder(vec![]);
        let err = b
            .build_transfer_option(TransferOptionRequest {
                identity: IdentityRef::new(WalletId(1)),
                handle,
                on_chain,
                to_puzzle_hash: Puzzlehash(hex::encode([9u8; 32])),
                fee: Amount(0),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// SECURITY-CRITICAL dependency guard for option-exercise atomicity (SPEC §3a).
    ///
    /// On exercise, the unlocked underlying lands on a BARE anyone-can-claim settlement coin;
    /// consensus forces the strike payment to the creator but does NOT force the underlying claim
    /// back to the holder — that leg is BUILDER-ENFORCED ONLY. If any path ever dropped or
    /// reordered it, the underlying would be stranded for a mempool watcher to steal while the
    /// holder has paid the strike and received nothing. This test pins the invariant our future
    /// engine exercise wiring composes: `dig_options::exercise` MUST emit the underlying-claim
    /// settlement leg (a settlement-puzzle coin of the underlying amount) inside the SAME bundle,
    /// so a `dig-options` bump that regressed it fails here before it can reach custody code.
    ///
    /// Key-free: `create` + `exercise` build UNSIGNED spends from a public [`Owner::Standard`] key
    /// (the G1 generator), never a secret — honouring the SPEC §1.4 engine key-isolation invariant.
    #[test]
    fn exercise_bundle_includes_the_underlying_claim_leg() {
        use chia_wallet_sdk::types::puzzles::SettlementPayment;
        use chia_wallet_sdk::types::Mod;
        use dig_options::{exercise, StrikePayment};

        let pk = test_public_key();
        let holder_ph = wallet_puzzle_hash();
        let underlying_amount: u64 = 1_000;
        let strike_amount: u64 = 500;

        // Mint an option to the holder (self-minted), locking the underlying.
        let mut ctx = SpendContext::new();
        let funding_coin = wallet_coin(underlying_amount + 1, 1);
        let terms = OptionTerms {
            creator_puzzle_hash: holder_ph,
            owner_puzzle_hash: holder_ph,
            underlying_amount,
            strike_type: OptionType::Xch {
                amount: strike_amount,
            },
            expiry_seconds: 1_800_000_000,
        };
        let created = create(&mut ctx, &Owner::Standard(pk), funding_coin, &terms)
            .expect("create option")
            .created
            .expect("created option");

        // Exercise it, paying the strike from a holder-owned coin.
        let strike_funding = wallet_coin(strike_amount, 2);
        let exercised = exercise(
            &mut ctx,
            &Owner::Standard(pk),
            &created,
            &StrikePayment {
                funding_coin: strike_funding,
            },
        )
        .expect("exercise option");

        // The bundle MUST carry a settlement-puzzle coin spend of the FULL underlying amount — the
        // claim leg routing the unlocked underlying back to the holder. Its absence would strand
        // the underlying on a public settlement coin.
        let settlement_ph = Bytes32::from(<[u8; 32]>::from(SettlementPayment::mod_hash()));
        let has_underlying_claim = exercised
            .coin_spends
            .iter()
            .any(|cs| cs.coin.puzzle_hash == settlement_ph && cs.coin.amount == underlying_amount);
        assert!(
            has_underlying_claim,
            "exercise bundle is missing the underlying-claim settlement leg (amount {underlying_amount}); \
             the unlocked underlying would be stranded for anyone to claim",
        );
    }
}
