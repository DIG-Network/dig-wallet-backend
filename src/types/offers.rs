//! Offers request types — the seam contract for Chia offers (SPEC §3b).
//!
//! These are the pure, serializable value types both seams speak to build offer actions — **make**,
//! **take**, **cancel** — that the engine constructs by composing the canonical
//! [`dig-offers`](https://crates.io/crates/dig-offers) crate (never by re-implementing settlement
//! CLVM, §4.1). Like every type in this layer they carry only PUBLIC material: parties are named by
//! puzzle hashes, keys never appear.
//!
//! # Why make/take are a two-phase surface (v0.9.0 scope)
//! A Chia offer is inherently **build → sign → assemble/combine**: `dig_offers::make_build` returns
//! the maker's UNSIGNED spends plus a `RequestedPayments`/`AssetInfo` context that
//! `dig_offers::make_assemble` folds into the final `offer1…` string AFTER the caller signs; taking
//! is the mirror (`take_build` then `take_combine`). Those assemble artifacts are SDK allocator
//! objects that do not cross the serde IPC seam, and the assemble step belongs on the client side of
//! the signer boundary (#908). So v0.9.0 reserves the make/take request surface (accepted +
//! fail-closed validated) and returns [`crate::types::WalletErrorCode::NotImplemented`] until the
//! wire-serializable assemble/combine seam lands (a documented fast-follow). **Cancel** is likewise
//! reserved pending that seam plus native-layer reclaim for CAT/NFT-offered coins.

use serde::{Deserialize, Serialize};

use super::identity::IdentityRef;
use super::value::Puzzlehash;
use super::{Amount, AssetId};

/// One asset leg of an offer side: native XCH, or a CAT identified by its asset id.
///
/// v0.9.0 models the fungible legs (XCH + CAT); NFT legs are a documented follow-up gated on the
/// same assemble seam.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OfferLeg {
    /// A native-XCH leg of `amount` mojos.
    Xch {
        /// The XCH (mojos).
        amount: Amount,
    },
    /// A CAT leg of `amount` base units of `asset_id`.
    Cat {
        /// The CAT asset id (TAIL hash, hex).
        asset_id: AssetId,
        /// The amount in the CAT's base units.
        amount: Amount,
    },
}

/// A request to MAKE an offer: offer `offered`, request `requested` paid to `payee_puzzle_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakeOfferRequest {
    /// The maker identity — its coins fund the offered side (public material).
    pub identity: IdentityRef,
    /// The assets the maker offers.
    pub offered: Vec<OfferLeg>,
    /// The assets the maker requests in return.
    pub requested: Vec<OfferLeg>,
    /// The puzzle hash the requested payments are paid to (the maker's receive address).
    pub payee_puzzle_hash: Puzzlehash,
    /// The farmer fee to reserve (mojos).
    pub fee: Amount,
}

/// A request to TAKE an existing offer, funding its requested side from `identity`'s coins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakeOfferRequest {
    /// The taker identity — its coins fund the requested payments (public material).
    pub identity: IdentityRef,
    /// The `offer1…` string to take.
    pub offer: String,
    /// The farmer fee to reserve (mojos).
    pub fee: Amount,
}

/// A request to CANCEL an offer the caller made, reclaiming its offered coins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelOfferRequest {
    /// The maker identity authorizing the reclaim (public material).
    pub identity: IdentityRef,
    /// The `offer1…` string to cancel.
    pub offer: String,
    /// The puzzle hash to reclaim the offered coins to.
    pub reclaim_puzzle_hash: Puzzlehash,
    /// The farmer fee to reserve (mojos).
    pub fee: Amount,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WalletId;

    #[test]
    fn offer_leg_serializes_tagged() {
        let xch = serde_json::to_string(&OfferLeg::Xch { amount: Amount(5) }).unwrap();
        assert!(xch.contains("\"kind\":\"xch\""), "unexpected: {xch}");
        let cat = serde_json::to_string(&OfferLeg::Cat {
            asset_id: AssetId("ab".repeat(32)),
            amount: Amount(9),
        })
        .unwrap();
        assert!(cat.contains("\"kind\":\"cat\""), "unexpected: {cat}");
    }

    #[test]
    fn make_offer_request_round_trips() {
        let req = MakeOfferRequest {
            identity: IdentityRef::new(WalletId(1)),
            offered: vec![OfferLeg::Xch {
                amount: Amount(100),
            }],
            requested: vec![OfferLeg::Cat {
                asset_id: AssetId("cd".repeat(32)),
                amount: Amount(50),
            }],
            payee_puzzle_hash: Puzzlehash("ef".repeat(32)),
            fee: Amount(1),
        };
        let back: MakeOfferRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn take_and_cancel_requests_round_trip() {
        let take = TakeOfferRequest {
            identity: IdentityRef::new(WalletId(2)),
            offer: "offer1abc".into(),
            fee: Amount(2),
        };
        let back: TakeOfferRequest =
            serde_json::from_str(&serde_json::to_string(&take).unwrap()).unwrap();
        assert_eq!(take, back);

        let cancel = CancelOfferRequest {
            identity: IdentityRef::new(WalletId(3)),
            offer: "offer1def".into(),
            reclaim_puzzle_hash: Puzzlehash("77".repeat(32)),
            fee: Amount(3),
        };
        let back: CancelOfferRequest =
            serde_json::from_str(&serde_json::to_string(&cancel).unwrap()).unwrap();
        assert_eq!(cancel, back);
    }
}
