//! `engine::broadcast` — submitting an already-signed bundle to the network.
//!
//! The broadcaster takes a [`SignedBundle`] (produced client-side via the [`super::signer::RemoteSigner`]
//! callback) and pushes it to the mempool. It is a trait so tests use a mock and mainnet
//! submission is gated behind a concrete implementation (a later lane). The broadcaster never
//! signs — it only relays an already-signed bundle.

use async_trait::async_trait;

use crate::types::{SignedBundle, WalletResult};

/// Submits a signed spend bundle to the network mempool.
#[async_trait]
pub trait Broadcaster: Send + Sync {
    /// Submit `signed` and return once the node has accepted (or rejected) it.
    async fn submit(&self, signed: SignedBundle) -> WalletResult<()>;
}
