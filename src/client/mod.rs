//! The `client` seam — used by dig-app (SPEC §4).
//!
//! The dig-app-side of the wallet: a [`WalletClient`] handle that proxies reads + spend-intent
//! to the engine over the control IPC, the event [`subscribe`]r, spend [`review`]/decode, the
//! [`signer`] (which HOLDS the key), the [`identity`] provider, and the local [`addressbook`].
//!
//! # Key isolation
//! The private key lives ONLY here (behind [`signer::LocalSigner`]). The client seam sends the engine
//! public [`crate::types::IdentityRef`]s and receives [`crate::types::UnsignedSpend`]s to sign; it
//! returns [`crate::types::SignedBundle`]s. No secret crosses to the engine (SPEC §1d).

pub mod addressbook;
pub mod identity;
pub mod review;
pub mod signer;
pub mod subscribe;

pub use addressbook::AddressBook;
pub use identity::IdentityProvider;
pub use review::{decode, HumanReadableSummary};
pub use signer::{IdentitySigner, LocalSigner};
pub use subscribe::{filter_events, CatchUp};

use async_trait::async_trait;

use crate::types::{
    Balance, CatRecord, CoinRecord, IdentityRef, SendCatRequest, SendXchRequest, SyncStatus,
    TransactionRecord, UnsignedSpend, WalletResult,
};

/// The dig-app-side handle to the single engine instance, over the control IPC (SPEC §6).
///
/// Read methods proxy the engine's state store; the spend-intent methods ask the engine to
/// BUILD a transaction and return an [`UnsignedSpend`] for the user to review + sign (via
/// [`signer::IdentitySigner`]) — the client never builds or signs locally.
#[async_trait]
pub trait WalletClient: Send + Sync {
    /// Proxied: the native-asset balance for an identity.
    async fn balance(&self, identity: &IdentityRef) -> WalletResult<Balance>;

    /// Proxied: the unspent coins for an identity.
    async fn coins(&self, identity: &IdentityRef) -> WalletResult<Vec<CoinRecord>>;

    /// Proxied: the CAT balances for an identity.
    async fn cats(&self, identity: &IdentityRef) -> WalletResult<Vec<CatRecord>>;

    /// Proxied: the transaction history for an identity.
    async fn history(&self, identity: &IdentityRef) -> WalletResult<Vec<TransactionRecord>>;

    /// Proxied: the current sync status for an identity.
    async fn sync_status(&self, identity: &IdentityRef) -> WalletResult<SyncStatus>;

    /// Ask the engine to build an unsigned native-XCH send for review + signing.
    async fn request_send_xch(&self, request: SendXchRequest) -> WalletResult<UnsignedSpend>;

    /// Ask the engine to build an unsigned CAT send for review + signing.
    async fn request_send_cat(&self, request: SendCatRequest) -> WalletResult<UnsignedSpend>;
}
