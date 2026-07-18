//! `engine::state` — the wallet state store (SPEC §3).
//!
//! The engine indexes coins/CATs/NFTs/DIDs/transactions for each tracked identity and answers
//! read queries against them. The concrete store (SQLite-backed, with reorg rollback) is a
//! later lane; this seam defines the READ contract the client seam proxies over IPC.

use async_trait::async_trait;

use crate::types::{
    Balance, CatRecord, CoinRecord, DidRecord, IdentityRef, NftRecord, SyncStatus,
    TransactionRecord, WalletResult,
};

/// The read surface over the engine's indexed wallet state.
///
/// All queries are scoped to an [`IdentityRef`] (public material); no method returns or
/// accepts secret material.
#[async_trait]
pub trait WalletStore: Send + Sync {
    /// The native-asset balance for an identity.
    async fn balance(&self, identity: &IdentityRef) -> WalletResult<Balance>;

    /// The unspent coins for an identity.
    async fn coins(&self, identity: &IdentityRef) -> WalletResult<Vec<CoinRecord>>;

    /// The CAT balances for an identity.
    async fn cats(&self, identity: &IdentityRef) -> WalletResult<Vec<CatRecord>>;

    /// The NFTs an identity controls.
    async fn nfts(&self, identity: &IdentityRef) -> WalletResult<Vec<NftRecord>>;

    /// The DIDs an identity controls.
    async fn dids(&self, identity: &IdentityRef) -> WalletResult<Vec<DidRecord>>;

    /// The transaction history for an identity.
    async fn history(&self, identity: &IdentityRef) -> WalletResult<Vec<TransactionRecord>>;

    /// The current sync status for an identity.
    async fn sync_status(&self, identity: &IdentityRef) -> WalletResult<SyncStatus>;
}
