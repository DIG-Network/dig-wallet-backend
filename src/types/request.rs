//! Spend-intent request types — the shared inputs to a build.
//!
//! These cross the seam boundary in both directions: the client seam's [`crate::client::WalletClient`]
//! sends them to ask the engine to build, and the engine seam's [`crate::engine::SpendBuilder`]
//! consumes them. Pure data (public material only), so both seams import them from `types`.

use serde::{Deserialize, Serialize};

use super::identity::IdentityRef;
use super::value::{Address, Amount, AssetId};

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
