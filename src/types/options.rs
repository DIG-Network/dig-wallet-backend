//! Options-suite request/response types — the seam contract for covered options (issue #1123).
//!
//! These are the pure, serializable value types both seams speak in to build the covered-option
//! (CHIP-0042) actions — **mint**, **transfer**, and **exercise** — that the engine constructs by
//! composing the canonical [`dig-options`](https://crates.io/crates/dig-options) crate (never by
//! re-implementing option CLVM, §4.1). Like every other type in this layer they carry only PUBLIC
//! material: parties are named by their puzzle hashes, keys never appear.
//!
//! # The option handle
//! An option's on-chain singleton commits to its *identity* (launcher id, underlying coin,
//! current owner) but NOT to its *terms* (creator, expiry, underlying amount, strike) — those are
//! not invertible from the coin (see `dig_options::parse`). So a client that mints an option
//! receives an [`OptionHandle`] carrying both, and retains it to later transfer or exercise the
//! option. The handle is the serializable stand-in for `dig_options::CreatedOption` (whose SDK
//! internals do not cross the IPC seam).

use serde::{Deserialize, Serialize};

use super::identity::IdentityRef;
use super::value::Puzzlehash;
use super::{Amount, UnsignedSpend};

/// The strike an option holder must pay to exercise it.
///
/// v0.1.0 supports an **XCH** strike only (matching `dig-options` 0.1.0's exercise envelope);
/// CAT/NFT strikes are a documented follow-up gated on the `dig-options` extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OptionStrike {
    /// A native-XCH strike of `amount` mojos.
    Xch {
        /// The XCH (mojos) the holder pays to exercise.
        amount: Amount,
    },
}

/// A request to MINT a covered option: lock an XCH underlying and issue the option singleton.
///
/// The funding is drawn from `identity`'s spendable XCH. The excess of the chosen funding coin
/// over `underlying_amount + 1` mojo (the singleton) is paid as the farmer fee — bounded above by
/// `fee`, so a mint never silently burns more than the caller consented to (`dig-options` 0.1.0's
/// `create` has no change output; see the crate's SPEC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintOptionRequest {
    /// The minting (creator) identity — pays the underlying + fee (public material).
    pub identity: IdentityRef,
    /// The puzzle hash the creator reclaims the underlying to on clawback. Defaults to the
    /// identity's change puzzle hash when `None`.
    pub creator_puzzle_hash: Option<Puzzlehash>,
    /// The puzzle hash the option singleton is minted to (its initial holder). Defaults to the
    /// creator's puzzle hash when `None` (a self-minted option).
    pub owner_puzzle_hash: Option<Puzzlehash>,
    /// The XCH (mojos) locked as the underlying.
    pub underlying_amount: Amount,
    /// The strike the holder must pay to exercise.
    pub strike: OptionStrike,
    /// The absolute unix timestamp (seconds) at which the option expires: exercise is valid
    /// strictly before it, clawback strictly after it.
    pub expiry_seconds: u64,
    /// The maximum farmer fee to pay (the funding coin's excess over the underlying + singleton).
    pub fee: Amount,
}

/// The serializable identity + terms of a minted option, retained by the client to later
/// transfer or exercise it.
///
/// This is the seam-crossing stand-in for `dig_options::CreatedOption`: it carries the terms
/// (which are not recoverable from the on-chain singleton) plus the ids needed to locate the
/// option and its locked underlying on chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionHandle {
    /// The option singleton launcher id (hex) — its stable identity.
    pub launcher_id: String,
    /// The puzzle hash the creator reclaims the underlying to on clawback.
    pub creator_puzzle_hash: Puzzlehash,
    /// The puzzle hash the option was minted to (its initial owner).
    pub owner_puzzle_hash: Puzzlehash,
    /// The XCH (mojos) locked as the underlying.
    pub underlying_amount: Amount,
    /// The strike the holder must pay to exercise.
    pub strike: OptionStrike,
    /// The option's expiry (absolute unix seconds).
    pub expiry_seconds: u64,
    /// The coin id (hex) of the locked-underlying XCH coin this option unlocks on exercise.
    pub underlying_coin_id: String,
    /// The coin id (hex) of the funding coin the mint spent — the parent of both the launcher
    /// and the locked underlying.
    pub funding_coin_id: String,
}

/// The result of a [`MintOptionRequest`]: the unsigned mint spend plus the [`OptionHandle`] the
/// client retains to operate the option later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintedOption {
    /// The unsigned mint spend (coin spends + required signatures + review summary).
    pub unsigned: UnsignedSpend,
    /// The handle to retain — needed to transfer or exercise this option.
    pub handle: OptionHandle,
}

/// A request to TRANSFER an option singleton to a new owner.
///
/// Carries the [`OptionHandle`] retained from the mint plus the destination puzzle hash. Building
/// the transfer requires a `dig_options::transfer` builder that composes `OptionContract::transfer`
/// — not present in `dig-options` 0.1.0 (see the crate's follow-up); until it ships this request is
/// accepted but the build returns [`crate::types::WalletErrorCode::NotImplemented`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferOptionRequest {
    /// The current owner identity authorizing the transfer (public material).
    pub identity: IdentityRef,
    /// The option to transfer.
    pub handle: OptionHandle,
    /// The puzzle hash to transfer the option singleton to.
    pub to_puzzle_hash: Puzzlehash,
    /// The farmer fee to pay.
    pub fee: Amount,
}

/// A request to EXERCISE an option: pay the strike, unlock the underlying to the holder.
///
/// Carries the [`OptionHandle`] plus the strike-funding source. Building the exercise requires
/// reconstructing `dig_options::CreatedOption` from on-chain state — a `dig-options` rehydration
/// helper not present in 0.1.0 (see the crate's follow-up); until it ships this request is accepted
/// but the build returns [`crate::types::WalletErrorCode::NotImplemented`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExerciseOptionRequest {
    /// The holder identity exercising the option (public material).
    pub identity: IdentityRef,
    /// The option to exercise.
    pub handle: OptionHandle,
    /// The farmer fee to pay.
    pub fee: Amount,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WalletId;

    fn sample_handle() -> OptionHandle {
        OptionHandle {
            launcher_id: "ab".repeat(32),
            creator_puzzle_hash: Puzzlehash("cd".repeat(32)),
            owner_puzzle_hash: Puzzlehash("ef".repeat(32)),
            underlying_amount: Amount(1_000),
            strike: OptionStrike::Xch {
                amount: Amount(500),
            },
            expiry_seconds: 1_800_000_000,
            underlying_coin_id: "12".repeat(32),
            funding_coin_id: "34".repeat(32),
        }
    }

    #[test]
    fn mint_request_round_trips() {
        let req = MintOptionRequest {
            identity: IdentityRef::new(WalletId(1)),
            creator_puzzle_hash: None,
            owner_puzzle_hash: None,
            underlying_amount: Amount(1_000),
            strike: OptionStrike::Xch {
                amount: Amount(500),
            },
            expiry_seconds: 1_800_000_000,
            fee: Amount(10),
        };
        let back: MintOptionRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn strike_serializes_tagged() {
        let json = serde_json::to_string(&OptionStrike::Xch { amount: Amount(7) }).unwrap();
        assert!(json.contains("\"kind\":\"xch\""), "unexpected form: {json}");
    }

    #[test]
    fn handle_round_trips() {
        let handle = sample_handle();
        let back: OptionHandle =
            serde_json::from_str(&serde_json::to_string(&handle).unwrap()).unwrap();
        assert_eq!(handle, back);
    }

    #[test]
    fn transfer_and_exercise_requests_round_trip() {
        let transfer = TransferOptionRequest {
            identity: IdentityRef::new(WalletId(2)),
            handle: sample_handle(),
            to_puzzle_hash: Puzzlehash("99".repeat(32)),
            fee: Amount(3),
        };
        let back: TransferOptionRequest =
            serde_json::from_str(&serde_json::to_string(&transfer).unwrap()).unwrap();
        assert_eq!(transfer, back);

        let exercise = ExerciseOptionRequest {
            identity: IdentityRef::new(WalletId(3)),
            handle: sample_handle(),
            fee: Amount(4),
        };
        let back: ExerciseOptionRequest =
            serde_json::from_str(&serde_json::to_string(&exercise).unwrap()).unwrap();
        assert_eq!(exercise, back);
    }
}
