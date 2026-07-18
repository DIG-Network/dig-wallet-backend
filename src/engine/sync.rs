//! `engine::sync` — the peer sync loop + fallback routing (SPEC §7).
//!
//! The sync layer follows the chain and keeps [`super::state::InMemoryWalletStore`] current:
//! it ingests coin-state updates from a [`PeerCoinSource`] (dialed IPv6-first per §5.2), applies
//! them to the store, handles reorgs by rolling back to the fork point, and emits a
//! [`crate::types::WalletEvent`] at every state change (via [`super::events::EventSink`]) so the
//! client seam's subscribers are driven event-first. A [`ChainFallback`] point-read source
//! (chia-query / coinset) serves reads not yet in the local store or when the peer is unavailable.
//!
//! The transports themselves (a live peer socket, an HTTP fallback client) are injected as traits,
//! so the routing + ingestion + reorg logic is deterministic and fully testable without a network.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::types::value::Puzzlehash;
use crate::types::{
    CoinRecord, IdentityRef, SyncLifecycle, WalletErrorCode, WalletEvent, WalletResult,
};

use super::events::EventSink;
use super::state::{CoinChange, InMemoryWalletStore};

/// Configuration for the peer sync loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncConfig {
    /// Prefer IPv6 candidates when dialing peers, falling back to IPv4 (§5.2).
    pub ipv6_first: bool,
    /// The maximum number of coins to track before the coin-cap consolidation kicks in.
    pub coin_cap: usize,
    /// Fallback point-read endpoints (chia-query / coinset) used only while syncing.
    pub fallback_endpoints: Vec<String>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            ipv6_first: true,
            coin_cap: 500,
            fallback_endpoints: Vec::new(),
        }
    }
}

/// Order dial candidates IPv6-first, IPv4 as fallback (§5.2 ecosystem rule).
///
/// Peer comms are IPv6-first: a peer's candidate addresses are dialed IPv6 before IPv4, so the
/// happy-eyeballs path tries the preferred family first and only falls back to IPv4 on failure.
/// With `ipv6_first = false` the input order is preserved (the OS decides).
pub fn order_dial_candidates(candidates: &[SocketAddr], ipv6_first: bool) -> Vec<SocketAddr> {
    if !ipv6_first {
        return candidates.to_vec();
    }
    let (ipv6, ipv4): (Vec<_>, Vec<_>) = candidates.iter().partition(|addr| addr.is_ipv6());
    ipv6.into_iter().chain(ipv4).copied().collect()
}

/// A live peer source of coin-state updates (the primary sync transport).
///
/// The concrete implementation subscribes to peer puzzle-state (`request_puzzle_state`,
/// `subscribe = true`) and streams `coin_state_update`s; here it is a trait so the sync logic is
/// testable and the real socket is a later lane.
#[async_trait]
pub trait PeerCoinSource: Send + Sync {
    /// Fetch the current coin states for the given puzzle hashes (subscribing to future updates).
    async fn coin_states(&self, puzzle_hashes: &[Puzzlehash]) -> WalletResult<Vec<CoinRecord>>;
}

/// A point-read fallback source (chia-query / coinset), used only while syncing or for reads not
/// yet in the local store (SPEC §7). Engine-internal — never exposed on the client seam.
#[async_trait]
pub trait ChainFallback: Send + Sync {
    /// Point-read the current state of a single coin, if the source knows it.
    async fn coin_state(&self, coin_id: &str) -> WalletResult<Option<CoinRecord>>;
}

/// Drives the wallet store from chain state: peer ingestion, reorg rollback, fallback routing.
///
/// Holds the state store and the event sink; the peer + fallback transports are passed in per call
/// so one engine can sync many identities from different sources.
pub struct SyncEngine {
    config: SyncConfig,
    store: Arc<InMemoryWalletStore>,
    events: EventSink,
}

impl SyncEngine {
    /// Create a sync engine over a shared store + event sink.
    pub fn new(config: SyncConfig, store: Arc<InMemoryWalletStore>, events: EventSink) -> Self {
        Self {
            config,
            store,
            events,
        }
    }

    /// The sync configuration.
    pub fn config(&self) -> &SyncConfig {
        &self.config
    }

    /// Ingest a batch of coin-state updates for an identity: apply each to the store, emit the
    /// matching event, and advance the processed peak. Returns the number of coins that changed.
    pub fn ingest(&self, identity: &IdentityRef, records: Vec<CoinRecord>) -> usize {
        let mut changed = 0;
        let mut max_height = 0;
        for record in records {
            max_height = max_height
                .max(record.created_height.unwrap_or(0))
                .max(record.spent_height.unwrap_or(0));
            let change = self
                .store
                .apply_coin_state(identity.wallet_id, record.clone());
            if self.emit_for_change(identity, &record, change) {
                changed += 1;
            }
        }
        if max_height > 0 {
            self.store.set_peak(identity.wallet_id, max_height);
        }
        changed
    }

    /// Emit the event a coin change warrants. Returns whether anything changed (an `Unchanged`
    /// re-delivery emits nothing and does not count).
    fn emit_for_change(
        &self,
        identity: &IdentityRef,
        record: &CoinRecord,
        change: CoinChange,
    ) -> bool {
        match change {
            CoinChange::Unchanged => return false,
            CoinChange::Created => {
                if let Some(height) = record.created_height {
                    self.events.publish(WalletEvent::FundsReceived {
                        wallet_id: identity.wallet_id,
                        asset: None,
                        amount: record.amount,
                        coin_id: record.coin_id.clone(),
                        confirmed_height: height,
                    });
                }
            }
            CoinChange::Spent | CoinChange::Updated => {}
        }
        self.events.publish(WalletEvent::CoinStateChanged {
            coin_id: record.coin_id.clone(),
            spent: record.spent_height.is_some(),
            created_height: record.created_height,
            spent_height: record.spent_height,
        });
        true
    }

    /// Sync from the primary peer source: fetch coin states, ingest them, and mark the wallet
    /// synced. This is the happy path when a peer is reachable.
    pub async fn sync_from_peer(
        &self,
        identity: &IdentityRef,
        puzzle_hashes: &[Puzzlehash],
        peer: &dyn PeerCoinSource,
    ) -> WalletResult<usize> {
        let records = peer.coin_states(puzzle_hashes).await?;
        let changed = self.ingest(identity, records);
        self.mark_synced(identity);
        Ok(changed)
    }

    /// Refresh a set of coins, preferring the peer but falling back to the point-read source when
    /// the peer is unavailable (a transport failure) — SPEC §7's "fallback used while the peer is
    /// out of reach". Returns the number of coins that changed.
    pub async fn sync_with_fallback(
        &self,
        identity: &IdentityRef,
        puzzle_hashes: &[Puzzlehash],
        coin_ids: &[String],
        peer: &dyn PeerCoinSource,
        fallback: &dyn ChainFallback,
    ) -> WalletResult<usize> {
        match peer.coin_states(puzzle_hashes).await {
            Ok(records) => {
                let changed = self.ingest(identity, records);
                self.mark_synced(identity);
                Ok(changed)
            }
            Err(err) if err.code == WalletErrorCode::Transport => {
                // Peer unreachable — route each coin through the point-read fallback.
                let mut changed = 0;
                for coin_id in coin_ids {
                    if self
                        .resolve_via_fallback(identity, coin_id, fallback)
                        .await?
                        .is_some()
                    {
                        changed += 1;
                    }
                }
                Ok(changed)
            }
            Err(err) => Err(err),
        }
    }

    /// Read a coin local-first: return it from the store if present, else point-read the fallback
    /// source and ingest the result (SPEC §7 out-of-DB read). Returns the resolved coin, if any.
    pub async fn resolve_coin(
        &self,
        identity: &IdentityRef,
        coin_id: &str,
        fallback: &dyn ChainFallback,
    ) -> WalletResult<Option<CoinRecord>> {
        if let Some(local) = self.store.coin(identity.wallet_id, coin_id) {
            return Ok(Some(local));
        }
        self.resolve_via_fallback(identity, coin_id, fallback).await
    }

    /// Point-read a coin through the fallback source and ingest it if found.
    async fn resolve_via_fallback(
        &self,
        identity: &IdentityRef,
        coin_id: &str,
        fallback: &dyn ChainFallback,
    ) -> WalletResult<Option<CoinRecord>> {
        match fallback.coin_state(coin_id).await? {
            Some(record) => {
                self.ingest(identity, vec![record.clone()]);
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Handle a reorg: roll the store back to `fork_height`, emit a `CoinStateChanged` for every
    /// affected coin, and push a `SyncProgress` reflecting the reverted peak.
    pub fn handle_reorg(&self, identity: &IdentityRef, fork_height: u32) -> Vec<String> {
        let affected = self.store.rollback_to(identity.wallet_id, fork_height);
        for coin_id in &affected {
            // After rollback the coin is either gone or un-spent; report its current store value.
            let coin = self.store.coin(identity.wallet_id, coin_id);
            self.events.publish(WalletEvent::CoinStateChanged {
                coin_id: coin_id.clone(),
                spent: coin.as_ref().is_some_and(|c| c.spent_height.is_some()),
                created_height: coin.as_ref().and_then(|c| c.created_height),
                spent_height: coin.as_ref().and_then(|c| c.spent_height),
            });
        }
        self.store
            .set_sync_status(identity.wallet_id, SyncLifecycle::Syncing, fork_height);
        self.publish_progress(identity, SyncLifecycle::Syncing, fork_height);
        affected
    }

    /// Mark the wallet caught up to the tip and announce it.
    fn mark_synced(&self, identity: &IdentityRef) {
        let peak = self.store.peak_height(identity.wallet_id);
        self.store
            .set_sync_status(identity.wallet_id, SyncLifecycle::Synced, peak);
        self.publish_progress(identity, SyncLifecycle::Synced, peak);
    }

    fn publish_progress(&self, identity: &IdentityRef, state: SyncLifecycle, peak: u32) {
        self.events.publish(WalletEvent::SyncProgress {
            wallet_id: identity.wallet_id,
            state,
            peak_height: peak,
            target_height: peak,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::state::WalletStore;
    use crate::types::{Amount, EmittedEvent, EventKind, WalletError, WalletId};
    use std::sync::Mutex;
    use tokio::sync::broadcast::error::TryRecvError;

    fn engine() -> SyncEngine {
        SyncEngine::new(
            SyncConfig::default(),
            Arc::new(InMemoryWalletStore::new()),
            EventSink::new(64),
        )
    }

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

    /// Collect the event kinds currently queued on a receiver (drains it).
    fn drain_kinds(rx: &mut tokio::sync::broadcast::Receiver<EmittedEvent>) -> Vec<EventKind> {
        let mut kinds = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(e) => kinds.push(e.event.kind()),
                Err(TryRecvError::Empty | TryRecvError::Closed) => break,
                Err(TryRecvError::Lagged(_)) => continue,
            }
        }
        kinds
    }

    // --- A test peer that returns a canned coin set, or an injected error. ---
    struct MockPeer(WalletResult<Vec<CoinRecord>>);

    #[async_trait]
    impl PeerCoinSource for MockPeer {
        async fn coin_states(&self, _: &[Puzzlehash]) -> WalletResult<Vec<CoinRecord>> {
            self.0.clone()
        }
    }

    // --- A test fallback that records how many times it was queried. ---
    struct MockFallback {
        coins: Vec<CoinRecord>,
        calls: Mutex<usize>,
    }

    impl MockFallback {
        fn new(coins: Vec<CoinRecord>) -> Self {
            Self {
                coins,
                calls: Mutex::new(0),
            }
        }
        fn call_count(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl ChainFallback for MockFallback {
        async fn coin_state(&self, coin_id: &str) -> WalletResult<Option<CoinRecord>> {
            *self.calls.lock().unwrap() += 1;
            Ok(self.coins.iter().find(|c| c.coin_id == coin_id).cloned())
        }
    }

    #[test]
    fn defaults_are_ipv6_first() {
        let cfg = SyncConfig::default();
        assert!(cfg.ipv6_first, "peer comms are IPv6-first (§5.2)");
        assert_eq!(cfg.coin_cap, 500);
        assert!(cfg.fallback_endpoints.is_empty());
    }

    #[test]
    fn dial_candidates_put_ipv6_first() {
        let v4: SocketAddr = "1.2.3.4:9256".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:9256".parse().unwrap();
        let ordered = order_dial_candidates(&[v4, v6], true);
        assert!(
            ordered[0].is_ipv6(),
            "IPv6 must be dialed before IPv4 (§5.2)"
        );
        assert!(ordered[1].is_ipv4());
    }

    #[test]
    fn dial_candidates_preserve_order_when_not_ipv6_first() {
        let v4: SocketAddr = "1.2.3.4:9256".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:9256".parse().unwrap();
        let ordered = order_dial_candidates(&[v4, v6], false);
        assert!(ordered[0].is_ipv4());
    }

    #[test]
    fn config_accessor_returns_the_config() {
        let e = engine();
        assert!(e.config().ipv6_first);
    }

    #[tokio::test]
    async fn ingest_a_new_coin_emits_funds_received_and_coin_state_changed() {
        let e = engine();
        let id = identity(1);
        let mut rx = e.events.subscribe();

        let changed = e.ingest(&id, vec![coin("a", 100, Some(5), None)]);
        assert_eq!(changed, 1);

        let kinds = drain_kinds(&mut rx);
        assert!(kinds.contains(&EventKind::FundsReceived));
        assert!(kinds.contains(&EventKind::CoinStateChanged));
        assert_eq!(e.store.peak_height(id.wallet_id), 5);
    }

    #[tokio::test]
    async fn re_ingesting_an_identical_coin_emits_nothing() {
        let e = engine();
        let id = identity(1);
        e.ingest(&id, vec![coin("a", 100, Some(5), None)]);
        let mut rx = e.events.subscribe();
        let changed = e.ingest(&id, vec![coin("a", 100, Some(5), None)]);
        assert_eq!(changed, 0);
        assert!(drain_kinds(&mut rx).is_empty());
    }

    #[tokio::test]
    async fn spending_a_coin_emits_only_coin_state_changed() {
        let e = engine();
        let id = identity(1);
        e.ingest(&id, vec![coin("a", 100, Some(5), None)]);
        let mut rx = e.events.subscribe();
        e.ingest(&id, vec![coin("a", 100, Some(5), Some(9))]);
        let kinds = drain_kinds(&mut rx);
        assert_eq!(kinds, vec![EventKind::CoinStateChanged]);
    }

    #[tokio::test]
    async fn sync_from_peer_ingests_and_marks_synced() {
        let e = engine();
        let id = identity(1);
        let peer = MockPeer(Ok(vec![coin("a", 100, Some(5), None)]));
        let changed = e.sync_from_peer(&id, &[], &peer).await.unwrap();
        assert_eq!(changed, 1);
        assert_eq!(
            e.store.sync_status(&id).await.unwrap().state,
            SyncLifecycle::Synced
        );
    }

    #[tokio::test]
    async fn sync_from_peer_propagates_a_transport_error() {
        let e = engine();
        let peer = MockPeer(Err(WalletError::new(WalletErrorCode::Transport, "no peer")));
        let err = e
            .sync_from_peer(&identity(1), &[], &peer)
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::Transport);
    }

    #[tokio::test]
    async fn resolve_coin_reads_local_without_touching_fallback() {
        let e = engine();
        let id = identity(1);
        e.ingest(&id, vec![coin("a", 100, Some(5), None)]);
        let fallback = MockFallback::new(vec![]);
        let got = e.resolve_coin(&id, "a", &fallback).await.unwrap();
        assert!(got.is_some());
        assert_eq!(fallback.call_count(), 0, "in-DB read must not hit fallback");
    }

    #[tokio::test]
    async fn resolve_coin_falls_back_for_an_out_of_db_read() {
        let e = engine();
        let id = identity(1);
        let fallback = MockFallback::new(vec![coin("z", 7, Some(3), None)]);
        let got = e.resolve_coin(&id, "z", &fallback).await.unwrap();
        assert_eq!(got.unwrap().amount, Amount(7));
        assert_eq!(fallback.call_count(), 1);
        // The fallback read is ingested into the store.
        assert!(e.store.coin(id.wallet_id, "z").is_some());
    }

    #[tokio::test]
    async fn resolve_coin_returns_none_when_neither_source_has_it() {
        let e = engine();
        let fallback = MockFallback::new(vec![]);
        let got = e
            .resolve_coin(&identity(1), "ghost", &fallback)
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn sync_with_fallback_uses_the_peer_when_it_is_reachable() {
        let e = engine();
        let id = identity(1);
        let peer = MockPeer(Ok(vec![coin("a", 100, Some(5), None)]));
        let fallback = MockFallback::new(vec![]);
        let changed = e
            .sync_with_fallback(&id, &[], &["a".into()], &peer, &fallback)
            .await
            .unwrap();
        assert_eq!(changed, 1);
        assert_eq!(fallback.call_count(), 0, "peer reachable → no fallback");
    }

    #[tokio::test]
    async fn sync_with_fallback_routes_to_chain_query_when_peer_unavailable() {
        let e = engine();
        let id = identity(1);
        let peer = MockPeer(Err(WalletError::new(WalletErrorCode::Transport, "no peer")));
        let fallback = MockFallback::new(vec![coin("a", 42, Some(3), None)]);
        let changed = e
            .sync_with_fallback(&id, &[], &["a".into()], &peer, &fallback)
            .await
            .unwrap();
        assert_eq!(changed, 1, "coin resolved via fallback");
        assert_eq!(fallback.call_count(), 1, "peer down → chia-query used (§7)");
        assert_eq!(e.store.balance(&id).await.unwrap().confirmed, Amount(42));
    }

    #[tokio::test]
    async fn sync_with_fallback_propagates_non_transport_errors() {
        let e = engine();
        let peer = MockPeer(Err(WalletError::new(
            WalletErrorCode::Storage,
            "db exploded",
        )));
        let fallback = MockFallback::new(vec![]);
        let err = e
            .sync_with_fallback(&identity(1), &[], &[], &peer, &fallback)
            .await
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::Storage);
    }

    #[tokio::test]
    async fn reorg_rolls_back_emits_events_and_reverts_peak() {
        let e = engine();
        let id = identity(1);
        e.ingest(&id, vec![coin("keep", 10, Some(3), None)]);
        e.ingest(&id, vec![coin("drop", 20, Some(8), None)]);
        assert_eq!(e.store.balance(&id).await.unwrap().confirmed, Amount(30));

        let mut rx = e.events.subscribe();
        let affected = e.handle_reorg(&id, 5);
        assert_eq!(affected, vec!["drop".to_string()]);

        // Balance reflects only the pre-fork coin, and the peak reverted.
        assert_eq!(e.store.balance(&id).await.unwrap().confirmed, Amount(10));
        let status = e.store.sync_status(&id).await.unwrap();
        assert_eq!(status.peak_height, 5);
        assert_eq!(status.state, SyncLifecycle::Syncing);

        let kinds = drain_kinds(&mut rx);
        assert!(kinds.contains(&EventKind::CoinStateChanged));
        assert!(kinds.contains(&EventKind::SyncProgress));
    }

    #[tokio::test]
    async fn reorg_unspends_a_coin_spent_above_the_fork() {
        let e = engine();
        let id = identity(1);
        e.ingest(&id, vec![coin("a", 100, Some(2), Some(9))]);
        assert_eq!(e.store.balance(&id).await.unwrap().confirmed, Amount(0));
        e.handle_reorg(&id, 5);
        assert_eq!(e.store.balance(&id).await.unwrap().confirmed, Amount(100));
    }
}
