//! Spend-intent request types — the shared inputs to a build.
//!
//! These cross the seam boundary in both directions: the client seam's [`crate::client::WalletClient`]
//! sends them to ask the engine to build, and the engine seam's [`crate::engine::SpendBuilder`]
//! consumes them. Pure data (public material only), so both seams import them from `types`.

use serde::{Deserialize, Serialize};

use super::identity::IdentityRef;
use super::value::Address;
use super::{Amount, AssetId};

/// A request to send native XCH.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendXchRequest {
    /// The paying identity (public material).
    pub identity: IdentityRef,
    /// The destination address.
    pub to: Address,
    /// The amount to send.
    pub amount: Amount,
    /// The fee to pay the farmer.
    pub fee: Amount,
}

/// A request to send a CAT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendCatRequest {
    /// The paying identity (public material).
    pub identity: IdentityRef,
    /// The CAT asset id.
    pub asset_id: AssetId,
    /// The destination address.
    pub to: Address,
    /// The amount to send.
    pub amount: Amount,
    /// The fee to pay the farmer.
    pub fee: Amount,
}

/// One leg of a multi-output send: an address and the amount it receives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendLeg {
    /// The destination address.
    pub to: Address,
    /// The amount that destination receives.
    pub amount: Amount,
}

/// A request to pay an arbitrary set of XCH destinations in ONE spend.
///
/// The generalisation `bulk_xch_send` and `multi_send` both reduce to: a bulk send is a
/// multi-send whose legs happen to be generated rather than hand-listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiSendXchRequest {
    /// The paying identity (public material).
    pub identity: IdentityRef,
    /// The destinations, in payment order. Must be non-empty.
    pub legs: Vec<SendLeg>,
    /// The fee to pay the farmer.
    pub fee: Amount,
}

/// A request to pay an arbitrary set of destinations of ONE CAT asset in one spend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiSendCatRequest {
    /// The paying identity (public material).
    pub identity: IdentityRef,
    /// The CAT asset id.
    pub asset_id: AssetId,
    /// The destinations, in payment order. Must be non-empty.
    pub legs: Vec<SendLeg>,
    /// The fee to pay the farmer (paid in XCH).
    pub fee: Amount,
}

/// A request to merge several of the wallet's own XCH coins into one.
///
/// Combining moves no value to a third party: every mojo not spent on the fee returns to the
/// wallet as a single coin. This is what unblocks a later send that would otherwise fail the
/// coin-count cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CombineXchRequest {
    /// The identity whose coins are merged (public material).
    pub identity: IdentityRef,
    /// The fee to pay the farmer.
    pub fee: Amount,
}

/// A request to split the wallet's XCH into `parts` coins of its own.
///
/// The inverse of a combine: it raises the wallet's coin count so several spends can proceed
/// concurrently. Value stays with the wallet apart from the fee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitXchRequest {
    /// The identity whose coins are split (public material).
    pub identity: IdentityRef,
    /// How many output coins to produce. Must be at least two.
    pub parts: u32,
    /// The fee to pay the farmer.
    pub fee: Amount,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WalletId;

    #[test]
    fn send_xch_request_round_trips() {
        let req = SendXchRequest {
            identity: IdentityRef::new(WalletId(1)),
            to: Address("xch1dest".into()),
            amount: Amount(1000),
            fee: Amount(1),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: SendXchRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn send_cat_request_round_trips() {
        let req = SendCatRequest {
            identity: IdentityRef::new(WalletId(2)),
            asset_id: AssetId("tail".into()),
            to: Address("xch1dest".into()),
            amount: Amount(5),
            fee: Amount(0),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: SendCatRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }
}
