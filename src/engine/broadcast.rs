//! `engine::broadcast` — submitting an already-signed bundle to the network (SPEC §3).
//!
//! The broadcaster takes a [`SignedBundle`] (produced client-side via the
//! [`super::signer::RemoteSigner`] callback) and pushes it to the mempool. It NEVER signs — it
//! only relays a bundle that is already fully signed. The network transport is injected as a
//! [`MempoolClient`] trait so the acceptance/rejection routing is deterministic and unit-testable
//! without a live peer, and a real mainnet submission is gated behind a concrete client.

use std::sync::Arc;

use async_trait::async_trait;

use crate::types::{SignedBundle, WalletError, WalletErrorCode, WalletResult};

/// Submits a signed spend bundle to the network mempool.
#[async_trait]
pub trait Broadcaster: Send + Sync {
    /// Submit `signed` and return once the node has accepted (or rejected) it.
    async fn submit(&self, signed: SignedBundle) -> WalletResult<()>;
}

/// How the mempool responded to a submitted bundle.
///
/// Distinct outcomes so the caller can tell "in the mempool, awaiting a block" apart from a
/// hard rejection it must surface to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolStatus {
    /// The bundle was accepted into the mempool (it will be farmed into a block).
    Accepted,
    /// The bundle is a known duplicate already in the mempool — idempotent success.
    AlreadyInMempool,
    /// The mempool rejected the bundle; `reason` is the node's explanation.
    Rejected {
        /// The node's stated rejection reason (e.g. `DOUBLE_SPEND`, `ASSERT_*_FAILED`).
        reason: String,
    },
}

/// The network sink a signed bundle is pushed to — a Chia peer's `send_transaction` / mempool.
///
/// Injected into [`MempoolBroadcaster`] so the routing logic is testable; the concrete peer
/// client (a later lane) is the only place a live network call happens.
#[async_trait]
pub trait MempoolClient: Send + Sync {
    /// Push a signed bundle and report the mempool's response. A network/transport failure is a
    /// [`WalletErrorCode::Transport`] error; a mempool *rejection* is a
    /// [`MempoolStatus::Rejected`] (not an `Err`) so the broadcaster classifies it.
    async fn push_tx(&self, signed: &SignedBundle) -> WalletResult<MempoolStatus>;
}

/// The concrete [`Broadcaster`] — relays an already-signed bundle via an injected mempool client.
///
/// Holds no key and never signs (SPEC §3): it only forwards the finished [`SignedBundle`] and
/// classifies the mempool's response. Acceptance (including a duplicate already in the mempool)
/// is success; a rejection becomes a fail-closed [`WalletErrorCode::SpendValidationFailed`].
pub struct MempoolBroadcaster {
    client: Arc<dyn MempoolClient>,
}

impl MempoolBroadcaster {
    /// Create a broadcaster over a mempool client.
    pub fn new(client: Arc<dyn MempoolClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Broadcaster for MempoolBroadcaster {
    async fn submit(&self, signed: SignedBundle) -> WalletResult<()> {
        match self.client.push_tx(&signed).await? {
            MempoolStatus::Accepted | MempoolStatus::AlreadyInMempool => Ok(()),
            MempoolStatus::Rejected { reason } => Err(WalletError::new(
                WalletErrorCode::SpendValidationFailed,
                format!("mempool rejected the bundle: {reason}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia::bls::Signature;
    use chia::protocol::SpendBundle;
    use std::sync::Mutex;

    fn signed() -> SignedBundle {
        SignedBundle {
            bundle: SpendBundle::new(vec![], Signature::default()),
        }
    }

    /// A mempool client returning a canned status, recording how many times it was called.
    struct MockClient {
        status: WalletResult<MempoolStatus>,
        calls: Mutex<usize>,
    }

    impl MockClient {
        fn new(status: WalletResult<MempoolStatus>) -> Self {
            Self {
                status,
                calls: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl MempoolClient for MockClient {
        async fn push_tx(&self, _: &SignedBundle) -> WalletResult<MempoolStatus> {
            *self.calls.lock().unwrap() += 1;
            self.status.clone()
        }
    }

    fn broadcaster(status: WalletResult<MempoolStatus>) -> (MempoolBroadcaster, Arc<MockClient>) {
        let client = Arc::new(MockClient::new(status));
        (MempoolBroadcaster::new(client.clone()), client)
    }

    #[tokio::test]
    async fn accepted_is_success() {
        let (b, client) = broadcaster(Ok(MempoolStatus::Accepted));
        assert!(b.submit(signed()).await.is_ok());
        assert_eq!(
            *client.calls.lock().unwrap(),
            1,
            "the bundle was pushed once"
        );
    }

    #[tokio::test]
    async fn a_duplicate_already_in_mempool_is_idempotent_success() {
        let (b, _) = broadcaster(Ok(MempoolStatus::AlreadyInMempool));
        assert!(b.submit(signed()).await.is_ok());
    }

    #[tokio::test]
    async fn a_rejection_fails_closed_with_the_reason() {
        let (b, _) = broadcaster(Ok(MempoolStatus::Rejected {
            reason: "DOUBLE_SPEND".into(),
        }));
        let err = b.submit(signed()).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
        assert!(err.message.contains("DOUBLE_SPEND"));
    }

    #[tokio::test]
    async fn a_transport_failure_propagates() {
        let (b, _) = broadcaster(Err(WalletError::new(
            WalletErrorCode::Transport,
            "peer unreachable",
        )));
        let err = b.submit(signed()).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::Transport);
    }
}
