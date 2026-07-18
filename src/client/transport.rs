//! `client::transport` — the [`WalletClient`] implementation over the control IPC (SPEC §6).
//!
//! [`IpcWalletClient`] is the concrete dig-app-side [`WalletClient`]: it marshals each read /
//! spend-intent as a named JSON request over a [`ControlTransport`] and deserializes the typed
//! response. The transport itself (the paired-token control channel, or the in-process DIG-Browser
//! bridge) is injected — this module owns only the request/response marshalling + the stable
//! method-name contract, so the same client works over any transport.
//!
//! # Key isolation
//! Only public material crosses here: an [`IdentityRef`] or a spend-intent request goes out; a
//! read result or an [`UnsignedSpend`] (for the local signer to sign) comes back. No secret ever
//! travels over this channel (SPEC §1.4).

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::types::{
    Balance, CatRecord, CoinRecord, IdentityRef, SendCatRequest, SendXchRequest, SyncStatus,
    TransactionRecord, UnsignedSpend, WalletError, WalletErrorCode, WalletResult,
};

use super::WalletClient;

/// The stable method names the client marshals over the control IPC. A machine consumer branches
/// on these exact strings (§6.2); they are an append-only contract.
pub mod method {
    /// Proxied read: an identity's native-asset balance.
    pub const BALANCE: &str = "wallet.balance";
    /// Proxied read: an identity's unspent coins.
    pub const COINS: &str = "wallet.coins";
    /// Proxied read: an identity's CAT balances.
    pub const CATS: &str = "wallet.cats";
    /// Proxied read: an identity's transaction history.
    pub const HISTORY: &str = "wallet.history";
    /// Proxied read: an identity's sync status.
    pub const SYNC_STATUS: &str = "wallet.sync_status";
    /// Spend-intent: ask the engine to build an unsigned native-XCH send.
    pub const REQUEST_SEND_XCH: &str = "wallet.request_send_xch";
    /// Spend-intent: ask the engine to build an unsigned CAT send.
    pub const REQUEST_SEND_CAT: &str = "wallet.request_send_cat";
}

/// A request/response transport to the engine over the control IPC.
///
/// Implemented by dig-app over its concrete channel (the paired-token control socket, or the
/// in-process bridge). The client passes a method name + JSON params and expects a JSON result.
#[async_trait]
pub trait ControlTransport: Send + Sync {
    /// Send `method` with `params` and await the JSON result, or a transport-level error.
    async fn request(&self, method: &str, params: Value) -> WalletResult<Value>;
}

/// A [`WalletClient`] that marshals each call as a named JSON request over a [`ControlTransport`].
pub struct IpcWalletClient<T: ControlTransport> {
    transport: T,
}

impl<T: ControlTransport> IpcWalletClient<T> {
    /// Wrap a control transport as a wallet client.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Marshal `params`, invoke `method`, and deserialize the typed result. Serialization and
    /// deserialization failures map to [`WalletErrorCode::InvalidInput`] (a wire-shape violation).
    async fn call<P, R>(&self, method: &str, params: &P) -> WalletResult<R>
    where
        P: Serialize + Sync,
        R: DeserializeOwned,
    {
        let params = serde_json::to_value(params).map_err(encode_error)?;
        let result = self.transport.request(method, params).await?;
        serde_json::from_value(result).map_err(decode_error)
    }
}

/// Map a request-encoding failure to a wire-shape error.
fn encode_error(err: serde_json::Error) -> WalletError {
    WalletError::new(
        WalletErrorCode::InvalidInput,
        format!("failed to encode IPC request: {err}"),
    )
}

/// Map a response-decoding failure to a wire-shape error.
fn decode_error(err: serde_json::Error) -> WalletError {
    WalletError::new(
        WalletErrorCode::InvalidInput,
        format!("failed to decode IPC response: {err}"),
    )
}

#[async_trait]
impl<T: ControlTransport> WalletClient for IpcWalletClient<T> {
    async fn balance(&self, identity: &IdentityRef) -> WalletResult<Balance> {
        self.call(method::BALANCE, identity).await
    }

    async fn coins(&self, identity: &IdentityRef) -> WalletResult<Vec<CoinRecord>> {
        self.call(method::COINS, identity).await
    }

    async fn cats(&self, identity: &IdentityRef) -> WalletResult<Vec<CatRecord>> {
        self.call(method::CATS, identity).await
    }

    async fn history(&self, identity: &IdentityRef) -> WalletResult<Vec<TransactionRecord>> {
        self.call(method::HISTORY, identity).await
    }

    async fn sync_status(&self, identity: &IdentityRef) -> WalletResult<SyncStatus> {
        self.call(method::SYNC_STATUS, identity).await
    }

    async fn request_send_xch(&self, request: SendXchRequest) -> WalletResult<UnsignedSpend> {
        self.call(method::REQUEST_SEND_XCH, &request).await
    }

    async fn request_send_cat(&self, request: SendCatRequest) -> WalletResult<UnsignedSpend> {
        self.call(method::REQUEST_SEND_CAT, &request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, Amount, AssetId, SyncLifecycle, TransactionSummary, WalletId};
    use std::sync::Mutex;

    /// A transport that records the last (method, params) and replays a canned JSON response.
    struct MockTransport {
        response: Value,
        seen: Mutex<Option<(String, Value)>>,
    }

    impl MockTransport {
        fn returning(response: Value) -> Self {
            Self {
                response,
                seen: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl ControlTransport for MockTransport {
        async fn request(&self, method: &str, params: Value) -> WalletResult<Value> {
            *self.seen.lock().unwrap() = Some((method.to_string(), params));
            Ok(self.response.clone())
        }
    }

    fn identity() -> IdentityRef {
        IdentityRef::new(WalletId(1))
    }

    #[tokio::test]
    async fn balance_marshals_method_and_identity_and_decodes_result() {
        let balance = Balance {
            confirmed: Amount(500),
            spendable: Amount(400),
        };
        let mock = MockTransport::returning(serde_json::to_value(balance).unwrap());
        let client = IpcWalletClient::new(mock);

        let got = client.balance(&identity()).await.unwrap();
        assert_eq!(got, balance);

        let (method, params) = client.transport.seen.lock().unwrap().clone().unwrap();
        assert_eq!(method, method::BALANCE);
        assert_eq!(params, serde_json::to_value(identity()).unwrap());
    }

    #[tokio::test]
    async fn request_send_xch_marshals_the_request_and_returns_unsigned() {
        let unsigned = UnsignedSpend {
            coin_spends: vec![],
            required_signatures: vec![],
            summary: TransactionSummary {
                outputs: vec![xch_output()],
                fee: Amount(1),
            },
        };
        let mock = MockTransport::returning(serde_json::to_value(&unsigned).unwrap());
        let client = IpcWalletClient::new(mock);

        let request = SendXchRequest {
            identity: identity(),
            to: Address("xch1dest".into()),
            amount: Amount(10),
            fee: Amount(1),
        };
        let got = client.request_send_xch(request.clone()).await.unwrap();
        assert_eq!(got, unsigned);

        let (method, params) = client.transport.seen.lock().unwrap().clone().unwrap();
        assert_eq!(method, method::REQUEST_SEND_XCH);
        assert_eq!(params, serde_json::to_value(&request).unwrap());
    }

    fn xch_output() -> crate::types::SpendOutput {
        crate::types::SpendOutput {
            address: Address("xch1dest".into()),
            amount: Amount(10),
            asset_id: None,
        }
    }

    #[tokio::test]
    async fn coins_and_cats_decode_lists() {
        let coins = vec![CoinRecord {
            coin_id: "c".into(),
            puzzle_hash: crate::types::value::Puzzlehash("ph".into()),
            amount: Amount(7),
            created_height: Some(1),
            spent_height: None,
        }];
        let mock = MockTransport::returning(serde_json::to_value(&coins).unwrap());
        let client = IpcWalletClient::new(mock);
        assert_eq!(client.coins(&identity()).await.unwrap(), coins);

        let cats = vec![CatRecord {
            asset_id: AssetId("tail".into()),
            balance: Amount(3),
            name: Some("DBX".into()),
        }];
        let client = IpcWalletClient::new(MockTransport::returning(
            serde_json::to_value(&cats).unwrap(),
        ));
        assert_eq!(client.cats(&identity()).await.unwrap(), cats);
    }

    #[tokio::test]
    async fn sync_status_and_history_round_trip() {
        let status = SyncStatus {
            state: SyncLifecycle::Synced,
            peak_height: 100,
            target_height: 100,
        };
        let client = IpcWalletClient::new(MockTransport::returning(
            serde_json::to_value(status).unwrap(),
        ));
        assert_eq!(client.sync_status(&identity()).await.unwrap(), status);

        let history: Vec<TransactionRecord> = vec![];
        let client = IpcWalletClient::new(MockTransport::returning(
            serde_json::to_value(&history).unwrap(),
        ));
        assert_eq!(client.history(&identity()).await.unwrap(), history);
    }

    #[tokio::test]
    async fn request_send_cat_marshals_method() {
        let unsigned = UnsignedSpend {
            coin_spends: vec![],
            required_signatures: vec![],
            summary: TransactionSummary {
                outputs: vec![],
                fee: Amount(0),
            },
        };
        let client = IpcWalletClient::new(MockTransport::returning(
            serde_json::to_value(&unsigned).unwrap(),
        ));
        let request = SendCatRequest {
            identity: identity(),
            asset_id: AssetId("tail".into()),
            to: Address("xch1dest".into()),
            amount: Amount(5),
            fee: Amount(0),
        };
        client.request_send_cat(request).await.unwrap();
        assert_eq!(
            client.transport.seen.lock().unwrap().clone().unwrap().0,
            method::REQUEST_SEND_CAT,
        );
    }

    #[tokio::test]
    async fn transport_error_propagates() {
        struct Failing;
        #[async_trait]
        impl ControlTransport for Failing {
            async fn request(&self, _: &str, _: Value) -> WalletResult<Value> {
                Err(WalletError::new(WalletErrorCode::Transport, "dial failed"))
            }
        }
        let client = IpcWalletClient::new(Failing);
        let err = client.balance(&identity()).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::Transport);
    }

    #[tokio::test]
    async fn malformed_response_is_a_wire_error() {
        // A JSON string where a Balance object is expected -> decode error.
        let client = IpcWalletClient::new(MockTransport::returning(Value::String("nope".into())));
        let err = client.balance(&identity()).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }
}
