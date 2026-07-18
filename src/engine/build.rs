//! `engine::build` — unsigned-spend construction (SPEC §3).
//!
//! The engine builds transactions with chia-wallet-sdk driver constructors and returns an
//! [`UnsignedSpend`] — the coin spends plus the signatures they require plus a review summary.
//! It NEVER signs (that is the client-side [`super::signer::RemoteSigner`]) and NEVER hand-rolls
//! CLVM (§4.1). Every builder output is deterministic given the same inputs + coin set, and
//! is validated fail-closed before it can broadcast. The concrete builders are a later lane.

use async_trait::async_trait;

use crate::types::{SendCatRequest, SendXchRequest, UnsignedSpend, WalletResult};

/// Builds unsigned spends. Every method returns an [`UnsignedSpend`] for client review + signing.
#[async_trait]
pub trait SpendBuilder: Send + Sync {
    /// Build an unsigned native-XCH send.
    async fn build_send_xch(&self, request: SendXchRequest) -> WalletResult<UnsignedSpend>;

    /// Build an unsigned CAT send.
    async fn build_send_cat(&self, request: SendCatRequest) -> WalletResult<UnsignedSpend>;
}
