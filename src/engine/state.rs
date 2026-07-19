//! `engine::state` — the wallet state store (SPEC §3).
//!
//! The engine indexes coins/CATs/NFTs/DIDs/transactions for each tracked identity and answers
//! read queries against them. [`WalletStore`] is the READ contract the client seam proxies over
//! IPC; [`InMemoryWalletStore`] is the concrete backing the sync loop ([`super::sync`]) writes
//! into as chain state arrives.
//!
//! # Why in-memory (for now)
//! The store is a narrow, well-typed surface: a read trait plus a small mutation API the sync
//! loop drives ([`InMemoryWalletStore::apply_coin_state`], [`InMemoryWalletStore::rollback_to`],
//! …). A persistent (SQLite) backing is a drop-in later lane — it need only implement the same
//! mutation surface and [`WalletStore`]. Keeping the first implementation in-memory keeps the
//! data-layer logic (indexing, balance derivation, reorg rollback) deterministic and fully
//! unit-testable without a database or a network.
//!
//! # Key isolation (SPEC §1.4)
//! No method here accepts or returns secret material. State is scoped by [`WalletId`] (public).

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::types::{
    Amount, Balance, CatRecord, CoinRecord, DidRecord, IdentityRef, NftRecord, SyncLifecycle,
    SyncStatus, TransactionRecord, WalletId, WalletResult,
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

/// How a coin-state update changed the store — returned by [`InMemoryWalletStore::apply_coin_state`]
/// so the caller (the sync loop) can emit the right [`crate::types::WalletEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinChange {
    /// A previously-unknown, still-unspent coin appeared (inbound value).
    Created,
    /// A coin became spent (either newly-known-and-spent, or a known coin now spent).
    Spent,
    /// A known coin's fields changed without a spent transition (e.g. its confirmation height).
    Updated,
    /// The update carried no new information.
    Unchanged,
}

/// The per-identity slice of wallet state.
#[derive(Debug)]
struct WalletState {
    /// Tracked coins, keyed by coin id. Spent coins are retained (with `spent_height` set) so
    /// history and reorg rollback have the full picture.
    coins: HashMap<String, CoinRecord>,
    cats: HashMap<String, CatRecord>,
    nfts: HashMap<String, NftRecord>,
    dids: HashMap<String, DidRecord>,
    history: Vec<TransactionRecord>,
    /// The height the wallet has processed up to.
    peak_height: u32,
    /// The chain tip the wallet is syncing toward.
    target_height: u32,
    /// The tri-state sync lifecycle.
    lifecycle: SyncLifecycle,
}

impl Default for WalletState {
    fn default() -> Self {
        Self {
            coins: HashMap::new(),
            cats: HashMap::new(),
            nfts: HashMap::new(),
            dids: HashMap::new(),
            history: Vec::new(),
            peak_height: 0,
            target_height: 0,
            // A freshly-tracked wallet has not started syncing.
            lifecycle: SyncLifecycle::Idle,
        }
    }
}

impl WalletState {
    /// The native balance: the sum of every unspent coin's value. `confirmed` and `spendable`
    /// are equal until a pending-spend model is added (a later lane).
    fn balance(&self) -> Balance {
        let total: u64 = self
            .coins
            .values()
            .filter(|c| c.spent_height.is_none())
            .map(|c| c.amount.mojos())
            .sum();
        Balance {
            confirmed: Amount(total),
            spendable: Amount(total),
        }
    }

    fn sync_status(&self) -> SyncStatus {
        SyncStatus {
            state: self.lifecycle,
            peak_height: self.peak_height,
            target_height: self.target_height,
        }
    }
}

/// An in-memory, thread-safe [`WalletStore`] — the concrete state backing the sync loop writes into.
///
/// Cheap to share behind an `Arc`. The mutation API ([`Self::apply_coin_state`],
/// [`Self::rollback_to`], [`Self::set_sync_status`], …) is what the sync loop drives; the
/// [`WalletStore`] trait is the read side the client seam proxies.
#[derive(Default)]
pub struct InMemoryWalletStore {
    wallets: Mutex<HashMap<WalletId, WalletState>>,
}

impl InMemoryWalletStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `f` against the (created-on-demand) state slice for `wallet_id`.
    fn with_wallet<T>(&self, wallet_id: WalletId, f: impl FnOnce(&mut WalletState) -> T) -> T {
        let mut wallets = self.wallets.lock().expect("state store mutex poisoned");
        f(wallets.entry(wallet_id).or_default())
    }

    /// Apply a coin-state update, upserting the coin and reporting how it changed.
    ///
    /// A brand-new unspent coin is [`CoinChange::Created`]; any transition into spent is
    /// [`CoinChange::Spent`]; an identical re-delivery is [`CoinChange::Unchanged`].
    pub fn apply_coin_state(&self, wallet_id: WalletId, record: CoinRecord) -> CoinChange {
        self.with_wallet(wallet_id, |state| {
            let previous = state.coins.get(&record.coin_id);
            let change = classify_coin_change(previous, &record);
            state.coins.insert(record.coin_id.clone(), record);
            change
        })
    }

    /// Roll the wallet back to `fork_height` after a reorg: forget coins created above it and
    /// un-spend coins whose spend was rolled back. Returns the ids of every coin the rollback
    /// touched, so the caller can emit `CoinStateChanged` events. `peak_height` is reset to
    /// `fork_height`.
    pub fn rollback_to(&self, wallet_id: WalletId, fork_height: u32) -> Vec<String> {
        self.with_wallet(wallet_id, |state| {
            let mut affected = Vec::new();

            // Forget coins created after the fork — they never existed on the winning chain.
            state.coins.retain(|coin_id, coin| {
                let created_after_fork = coin.created_height.is_some_and(|h| h > fork_height);
                if created_after_fork {
                    affected.push(coin_id.clone());
                }
                !created_after_fork
            });

            // Un-spend coins whose spend was undone by the reorg.
            for (coin_id, coin) in state.coins.iter_mut() {
                if coin.spent_height.is_some_and(|h| h > fork_height) {
                    coin.spent_height = None;
                    affected.push(coin_id.clone());
                }
            }

            state.peak_height = fork_height;
            affected
        })
    }

    /// Advance the processed peak, never moving it backwards (rollback owns going back).
    pub fn set_peak(&self, wallet_id: WalletId, peak_height: u32) {
        self.with_wallet(wallet_id, |state| {
            state.peak_height = state.peak_height.max(peak_height);
        });
    }

    /// Record the sync lifecycle + the tip the wallet is syncing toward.
    pub fn set_sync_status(&self, wallet_id: WalletId, lifecycle: SyncLifecycle, target: u32) {
        self.with_wallet(wallet_id, |state| {
            state.lifecycle = lifecycle;
            state.target_height = target;
        });
    }

    /// Upsert a CAT balance line (keyed by asset id).
    pub fn upsert_cat(&self, wallet_id: WalletId, record: CatRecord) {
        self.with_wallet(wallet_id, |state| {
            state.cats.insert(record.asset_id.0.clone(), record);
        });
    }

    /// Upsert an NFT (keyed by launcher id).
    pub fn upsert_nft(&self, wallet_id: WalletId, record: NftRecord) {
        self.with_wallet(wallet_id, |state| {
            state.nfts.insert(record.launcher_id.clone(), record);
        });
    }

    /// Upsert a DID (keyed by launcher id).
    pub fn upsert_did(&self, wallet_id: WalletId, record: DidRecord) {
        self.with_wallet(wallet_id, |state| {
            state.dids.insert(record.launcher_id.clone(), record);
        });
    }

    /// Append a settled transaction to history.
    pub fn record_transaction(&self, wallet_id: WalletId, record: TransactionRecord) {
        self.with_wallet(wallet_id, |state| state.history.push(record));
    }

    /// Look up a single tracked coin (used by the sync loop's local-first read).
    pub fn coin(&self, wallet_id: WalletId, coin_id: &str) -> Option<CoinRecord> {
        self.with_wallet(wallet_id, |state| state.coins.get(coin_id).cloned())
    }

    /// The height the wallet has processed up to.
    pub fn peak_height(&self, wallet_id: WalletId) -> u32 {
        self.with_wallet(wallet_id, |state| state.peak_height)
    }
}

/// Decide how an incoming coin-state update changes a (possibly-existing) coin.
///
/// Shared by both backings so the persistent [`super::persist::SqliteWalletStore`] classifies a
/// coin update identically to [`InMemoryWalletStore`] (backend-parity, SPEC §3).
pub(crate) fn classify_coin_change(
    previous: Option<&CoinRecord>,
    incoming: &CoinRecord,
) -> CoinChange {
    match previous {
        None if incoming.spent_height.is_some() => CoinChange::Spent,
        None => CoinChange::Created,
        Some(prev) if prev == incoming => CoinChange::Unchanged,
        Some(prev) if prev.spent_height.is_none() && incoming.spent_height.is_some() => {
            CoinChange::Spent
        }
        Some(_) => CoinChange::Updated,
    }
}

#[async_trait]
impl WalletStore for InMemoryWalletStore {
    async fn balance(&self, identity: &IdentityRef) -> WalletResult<Balance> {
        Ok(self.with_wallet(identity.wallet_id, |state| state.balance()))
    }

    async fn coins(&self, identity: &IdentityRef) -> WalletResult<Vec<CoinRecord>> {
        Ok(self.with_wallet(identity.wallet_id, |state| {
            state
                .coins
                .values()
                .filter(|c| c.spent_height.is_none())
                .cloned()
                .collect()
        }))
    }

    async fn cats(&self, identity: &IdentityRef) -> WalletResult<Vec<CatRecord>> {
        Ok(self.with_wallet(identity.wallet_id, |state| {
            state.cats.values().cloned().collect()
        }))
    }

    async fn nfts(&self, identity: &IdentityRef) -> WalletResult<Vec<NftRecord>> {
        Ok(self.with_wallet(identity.wallet_id, |state| {
            state.nfts.values().cloned().collect()
        }))
    }

    async fn dids(&self, identity: &IdentityRef) -> WalletResult<Vec<DidRecord>> {
        Ok(self.with_wallet(identity.wallet_id, |state| {
            state.dids.values().cloned().collect()
        }))
    }

    async fn history(&self, identity: &IdentityRef) -> WalletResult<Vec<TransactionRecord>> {
        Ok(self.with_wallet(identity.wallet_id, |state| state.history.clone()))
    }

    async fn sync_status(&self, identity: &IdentityRef) -> WalletResult<SyncStatus> {
        Ok(self.with_wallet(identity.wallet_id, |state| state.sync_status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::value::Puzzlehash;
    use crate::types::{Address, AssetId, SpendOutput, TransactionSummary};

    fn identity(id: u32) -> IdentityRef {
        IdentityRef::new(WalletId(id))
    }

    fn coin(id: &str, amount: u64, created: Option<u32>, spent: Option<u32>) -> CoinRecord {
        CoinRecord {
            coin_id: id.into(),
            puzzle_hash: Puzzlehash("ph".into()),
            amount: Amount(amount),
            created_height: created,
            spent_height: spent,
        }
    }

    #[tokio::test]
    async fn new_store_reports_empty_balance_and_idle_sync() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        assert_eq!(store.balance(&id).await.unwrap(), Balance::default());
        assert!(store.coins(&id).await.unwrap().is_empty());
        let status = store.sync_status(&id).await.unwrap();
        assert_eq!(status.state, SyncLifecycle::Idle);
        assert_eq!(status.peak_height, 0);
    }

    #[tokio::test]
    async fn applying_a_new_unspent_coin_is_created_and_counts_toward_balance() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        let change = store.apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None));
        assert_eq!(change, CoinChange::Created);
        assert_eq!(store.balance(&id).await.unwrap().confirmed, Amount(100));
        assert_eq!(store.coins(&id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn re_delivering_an_identical_coin_is_unchanged() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        store.apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None));
        let change = store.apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None));
        assert_eq!(change, CoinChange::Unchanged);
    }

    #[tokio::test]
    async fn spending_a_known_coin_is_spent_and_drops_from_balance() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        store.apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None));
        let change = store.apply_coin_state(id.wallet_id, coin("a", 100, Some(5), Some(9)));
        assert_eq!(change, CoinChange::Spent);
        assert_eq!(store.balance(&id).await.unwrap().confirmed, Amount(0));
        assert!(
            store.coins(&id).await.unwrap().is_empty(),
            "spent coin excluded"
        );
    }

    #[tokio::test]
    async fn a_coin_first_seen_already_spent_is_spent() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        let change = store.apply_coin_state(id.wallet_id, coin("a", 100, Some(5), Some(6)));
        assert_eq!(change, CoinChange::Spent);
    }

    #[tokio::test]
    async fn a_non_spend_field_change_is_updated() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        store.apply_coin_state(id.wallet_id, coin("a", 100, None, None));
        let change = store.apply_coin_state(id.wallet_id, coin("a", 100, Some(7), None));
        assert_eq!(change, CoinChange::Updated);
    }

    #[tokio::test]
    async fn rollback_forgets_coins_created_after_the_fork() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        store.apply_coin_state(id.wallet_id, coin("keep", 10, Some(3), None));
        store.apply_coin_state(id.wallet_id, coin("drop", 20, Some(8), None));
        store.set_peak(id.wallet_id, 8);

        let affected = store.rollback_to(id.wallet_id, 5);
        assert_eq!(affected, vec!["drop".to_string()]);
        assert_eq!(store.balance(&id).await.unwrap().confirmed, Amount(10));
        assert_eq!(store.sync_status(&id).await.unwrap().peak_height, 5);
    }

    #[tokio::test]
    async fn rollback_unspends_coins_spent_after_the_fork() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        store.apply_coin_state(id.wallet_id, coin("a", 100, Some(2), Some(9)));
        assert_eq!(store.balance(&id).await.unwrap().confirmed, Amount(0));

        let affected = store.rollback_to(id.wallet_id, 5);
        assert_eq!(affected, vec!["a".to_string()]);
        // The spend above the fork is undone → the coin is spendable again.
        assert_eq!(store.balance(&id).await.unwrap().confirmed, Amount(100));
    }

    #[tokio::test]
    async fn set_peak_never_moves_backwards() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        store.set_peak(id.wallet_id, 10);
        store.set_peak(id.wallet_id, 4);
        assert_eq!(store.sync_status(&id).await.unwrap().peak_height, 10);
    }

    #[tokio::test]
    async fn sync_status_reflects_lifecycle_and_target() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        store.set_sync_status(id.wallet_id, SyncLifecycle::Syncing, 200);
        let status = store.sync_status(&id).await.unwrap();
        assert_eq!(status.state, SyncLifecycle::Syncing);
        assert_eq!(status.target_height, 200);
    }

    #[tokio::test]
    async fn cat_nft_did_and_history_round_trip() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        store.upsert_cat(
            id.wallet_id,
            CatRecord {
                asset_id: AssetId("tail".into()),
                balance: Amount(50),
                name: Some("DBX".into()),
            },
        );
        store.upsert_nft(
            id.wallet_id,
            NftRecord {
                launcher_id: "nft".into(),
                data_uri: Some("ipfs://x".into()),
            },
        );
        store.upsert_did(
            id.wallet_id,
            DidRecord {
                launcher_id: "did".into(),
                name: None,
            },
        );
        store.record_transaction(
            id.wallet_id,
            TransactionRecord {
                tx_id: "t".into(),
                confirmed_height: Some(11),
                summary: TransactionSummary {
                    outputs: vec![SpendOutput {
                        address: Address("xch1".into()),
                        amount: Amount(5),
                        asset_id: None,
                    }],
                    fee: Amount(1),
                },
            },
        );

        assert_eq!(store.cats(&id).await.unwrap().len(), 1);
        assert_eq!(store.nfts(&id).await.unwrap().len(), 1);
        assert_eq!(store.dids(&id).await.unwrap().len(), 1);
        assert_eq!(store.history(&id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn upsert_cat_replaces_by_asset_id() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        let asset = AssetId("tail".into());
        store.upsert_cat(
            id.wallet_id,
            CatRecord {
                asset_id: asset.clone(),
                balance: Amount(10),
                name: None,
            },
        );
        store.upsert_cat(
            id.wallet_id,
            CatRecord {
                asset_id: asset,
                balance: Amount(99),
                name: Some("DBX".into()),
            },
        );
        let cats = store.cats(&id).await.unwrap();
        assert_eq!(cats.len(), 1);
        assert_eq!(cats[0].balance, Amount(99));
    }

    #[tokio::test]
    async fn coin_lookup_finds_a_tracked_coin() {
        let store = InMemoryWalletStore::new();
        let id = identity(1);
        store.apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None));
        assert!(store.coin(id.wallet_id, "a").is_some());
        assert!(store.coin(id.wallet_id, "missing").is_none());
    }

    #[tokio::test]
    async fn state_is_isolated_per_wallet() {
        let store = InMemoryWalletStore::new();
        store.apply_coin_state(WalletId(1), coin("a", 100, Some(5), None));
        assert_eq!(
            store.balance(&identity(2)).await.unwrap().confirmed,
            Amount(0)
        );
        assert_eq!(
            store.balance(&identity(1)).await.unwrap().confirmed,
            Amount(100)
        );
    }
}
