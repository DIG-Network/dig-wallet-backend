//! `engine::build_offers` — Chia offer construction surface (SPEC §3b, #1122).
//!
//! Offer actions — **make**, **take**, **cancel** — are built by composing the canonical
//! [`dig-offers`](https://crates.io/crates/dig-offers) crate (never by re-implementing settlement
//! CLVM, §4.1). The engine constructs UNSIGNED spends only; it NEVER signs (identity boundary #908).
//!
//! # v0.9.0 scope — the two-phase assemble seam
//! A Chia offer is inherently **build → sign → assemble/combine**: `dig_offers::make_build` returns
//! the maker's unsigned spends plus a `RequestedPayments`/`AssetInfo` context that
//! `make_assemble` folds into the final `offer1…` string AFTER signing; taking mirrors it
//! (`take_build` then `take_combine`). Those assemble artifacts are SDK allocator objects that do
//! NOT cross the serde IPC seam, and the assemble step sits on the client side of the signer
//! boundary. So v0.9.0 ACCEPTS + fail-closed VALIDATES every offer request (rejecting a bad amount,
//! puzzle hash, or non-offer string before any build) and returns
//! [`WalletErrorCode::NotImplemented`] until the wire-serializable assemble/combine seam lands — a
//! documented fast-follow (#1122). The request surface is stable now so consumers can code against
//! it and the actions light up with no shape change. Cancel additionally awaits native-layer reclaim
//! for CAT/NFT-offered coins.

use async_trait::async_trait;
use chia::protocol::Bytes32;
use dig_offers::decode;

use crate::types::{
    CancelOfferRequest, MakeOfferRequest, OfferLeg, Puzzlehash, TakeOfferRequest, UnsignedSpend,
    WalletError, WalletErrorCode, WalletResult,
};

use super::build::SdkSpendBuilder;

/// Builds unsigned offer spends. Every method returns a client-reviewable, unsigned result — the
/// engine never signs (SPEC §1.4, the key-isolation invariant).
#[async_trait]
pub trait OfferBuilder: Send + Sync {
    /// Build an unsigned MAKE-offer: spend the offered coins into settlement, assert the requested
    /// payments.
    async fn build_make_offer(&self, request: MakeOfferRequest) -> WalletResult<UnsignedSpend>;

    /// Build an unsigned TAKE of an existing offer: claim the offered coins, fund the requested side.
    async fn build_take_offer(&self, request: TakeOfferRequest) -> WalletResult<UnsignedSpend>;

    /// Build an unsigned CANCEL: reclaim the maker's offered coins, invalidating the offer.
    async fn build_cancel_offer(&self, request: CancelOfferRequest) -> WalletResult<UnsignedSpend>;
}

#[async_trait]
impl OfferBuilder for SdkSpendBuilder {
    async fn build_make_offer(&self, request: MakeOfferRequest) -> WalletResult<UnsignedSpend> {
        validate_side(&request.offered, "offered")?;
        validate_side(&request.requested, "requested")?;
        parse_puzzle_hash(&request.payee_puzzle_hash)?;
        Err(not_implemented(
            "make-offer requires the wire-serializable make_assemble seam (release-first, #1122)",
        ))
    }

    async fn build_take_offer(&self, request: TakeOfferRequest) -> WalletResult<UnsignedSpend> {
        // Fail-closed: reject a non-offer string before promising a build.
        decode(&request.offer).map_err(map_decode_error)?;
        Err(not_implemented(
            "take-offer requires the wire-serializable take_combine seam (release-first, #1122)",
        ))
    }

    async fn build_cancel_offer(&self, request: CancelOfferRequest) -> WalletResult<UnsignedSpend> {
        parse_puzzle_hash(&request.reclaim_puzzle_hash)?;
        decode(&request.offer).map_err(map_decode_error)?;
        Err(not_implemented(
            "cancel-offer requires native-layer reclaim for the offered coins (release-first, #1122)",
        ))
    }
}

/// Reject an empty offer side or a zero-amount leg before any build (an offer side must carry value).
fn validate_side(legs: &[OfferLeg], side: &str) -> WalletResult<()> {
    if legs.is_empty() {
        return Err(WalletError::invalid_input(format!(
            "an offer's {side} side must carry at least one asset"
        )));
    }
    for leg in legs {
        let amount = match leg {
            OfferLeg::Xch { amount } | OfferLeg::Cat { amount, .. } => amount.mojos(),
        };
        if amount == 0 {
            return Err(WalletError::invalid_input(format!(
                "an offer's {side} leg must carry a non-zero amount"
            )));
        }
        if let OfferLeg::Cat { asset_id, .. } = leg {
            parse_hex32(&asset_id.0, "asset id")?;
        }
    }
    Ok(())
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

/// Translate a `dig-offers` decode error into an [`WalletErrorCode::InvalidInput`] (a bad offer
/// string is caller input, not a spend-construction failure).
fn map_decode_error(error: dig_offers::Error) -> WalletError {
    WalletError::invalid_input(format!("not a valid offer: {error}"))
}

/// Shorthand for a [`WalletErrorCode::NotImplemented`] error.
fn not_implemented(message: impl Into<String>) -> WalletError {
    WalletError::new(WalletErrorCode::NotImplemented, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Amount, AssetId, IdentityRef, Network, WalletId};
    use std::sync::Arc;

    use crate::engine::build::SpendInputs;
    use chia::bls::PublicKey;
    use chia::protocol::Coin;
    use chia_wallet_sdk::driver::Cat;

    struct NoInputs;
    impl SpendInputs for NoInputs {
        fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<Coin>> {
            Ok(vec![])
        }
        fn spendable_cat(&self, _: &IdentityRef, _: &AssetId) -> WalletResult<Vec<Cat>> {
            Ok(vec![])
        }
        fn synthetic_key(&self, _: Bytes32) -> Option<PublicKey> {
            None
        }
        fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<Bytes32> {
            Ok(Bytes32::new([1u8; 32]))
        }
    }

    fn builder() -> SdkSpendBuilder {
        SdkSpendBuilder::new(Arc::new(NoInputs), Network::Mainnet, 500)
    }

    fn identity() -> IdentityRef {
        IdentityRef::new(WalletId(1))
    }

    #[tokio::test]
    async fn make_offer_is_reserved_pending_the_assemble_seam() {
        let req = MakeOfferRequest {
            identity: identity(),
            offered: vec![OfferLeg::Xch {
                amount: Amount(100),
            }],
            requested: vec![OfferLeg::Cat {
                asset_id: AssetId("ab".repeat(32)),
                amount: Amount(50),
            }],
            payee_puzzle_hash: Puzzlehash(hex::encode([9u8; 32])),
            fee: Amount(0),
        };
        let err = builder().build_make_offer(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::NotImplemented);
    }

    #[tokio::test]
    async fn make_offer_rejects_an_empty_side_before_not_implemented() {
        let req = MakeOfferRequest {
            identity: identity(),
            offered: vec![],
            requested: vec![OfferLeg::Xch { amount: Amount(1) }],
            payee_puzzle_hash: Puzzlehash(hex::encode([9u8; 32])),
            fee: Amount(0),
        };
        let err = builder().build_make_offer(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn make_offer_rejects_a_zero_amount_leg() {
        let req = MakeOfferRequest {
            identity: identity(),
            offered: vec![OfferLeg::Xch { amount: Amount(0) }],
            requested: vec![OfferLeg::Xch { amount: Amount(1) }],
            payee_puzzle_hash: Puzzlehash(hex::encode([9u8; 32])),
            fee: Amount(0),
        };
        let err = builder().build_make_offer(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn take_offer_rejects_a_non_offer_string() {
        let req = TakeOfferRequest {
            identity: identity(),
            offer: "definitely not an offer".into(),
            fee: Amount(0),
        };
        let err = builder().build_take_offer(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn cancel_offer_rejects_a_bad_reclaim_hash_before_decoding() {
        let req = CancelOfferRequest {
            identity: identity(),
            offer: "offer1whatever".into(),
            reclaim_puzzle_hash: Puzzlehash("not-hex".into()),
            fee: Amount(0),
        };
        let err = builder().build_cancel_offer(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn cancel_offer_rejects_a_non_offer_string() {
        let req = CancelOfferRequest {
            identity: identity(),
            offer: "not an offer".into(),
            reclaim_puzzle_hash: Puzzlehash(hex::encode([2u8; 32])),
            fee: Amount(0),
        };
        let err = builder().build_cancel_offer(req).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }
}
