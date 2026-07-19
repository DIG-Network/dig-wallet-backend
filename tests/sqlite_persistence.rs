//! Integration tests for the persistent (SQLite) wallet-store + event-log backings (#1118).
//!
//! These exercise the DURABLE guarantees a unit test over an in-memory DB cannot:
//! - state written by one store handle survives being dropped and re-opened (restart survival);
//! - the persistent `CatchUp` backfills events beyond the in-memory ring's bounded window;
//! - the SQLite backing is observably identical to the in-memory backing over the same operations;
//! - NO secret material is ever written to disk (the custody line, SPEC §1.4).
#![cfg(feature = "engine")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dig_wallet_backend::engine::{
    EventSink, InMemoryWalletStore, SqliteDeltaLog, SqliteWalletStore, WalletStore,
};
use dig_wallet_backend::types::value::Puzzlehash;
use dig_wallet_backend::types::{
    Amount, AssetId, CatRecord, CatchUp, CoinRecord, Cursor, DidRecord, IdentityRef, NftRecord,
    SyncLifecycle, TransactionRecord, TransactionSummary, WalletEvent, WalletId,
};
use enumset::EnumSet;

/// A unique temp path for a test DB file, cleaned up by [`TempDb`] on drop.
struct TempDb {
    path: std::path::PathBuf,
}

impl TempDb {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("dwb-{tag}-{pid}-{n}.sqlite"));
        Self { path }
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        // Best-effort cleanup of the DB + its WAL/SHM sidecars.
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

fn coin(id: &str, amount: u64, created: Option<u32>, spent: Option<u32>) -> CoinRecord {
    CoinRecord {
        coin_id: id.into(),
        puzzle_hash: Puzzlehash("abcd".into()),
        amount: Amount(amount),
        created_height: created,
        spent_height: spent,
    }
}

fn identity(id: u32) -> IdentityRef {
    IdentityRef::new(WalletId(id))
}

#[tokio::test]
async fn state_survives_a_restart() {
    let db = TempDb::new("restart");
    let id = identity(1);

    // Write coins/CAT/sync state, then drop the handle (simulating shutdown).
    {
        let store = SqliteWalletStore::open(&db.path).unwrap();
        store
            .apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None))
            .unwrap();
        store
            .apply_coin_state(id.wallet_id, coin("b", 50, Some(6), None))
            .unwrap();
        store
            .upsert_cat(
                id.wallet_id,
                CatRecord {
                    asset_id: AssetId("tail".into()),
                    balance: Amount(9),
                    name: Some("DBX".into()),
                },
            )
            .unwrap();
        store
            .set_sync_status(id.wallet_id, SyncLifecycle::Synced, 321)
            .unwrap();
        store.set_peak(id.wallet_id, 300).unwrap();
    }

    // Re-open the same file: every fact is still there.
    let store = SqliteWalletStore::open(&db.path).unwrap();
    assert_eq!(store.balance(&id).await.unwrap().confirmed, Amount(150));
    assert_eq!(store.coins(&id).await.unwrap().len(), 2);
    assert_eq!(store.cats(&id).await.unwrap()[0].balance, Amount(9));
    let status = store.sync_status(&id).await.unwrap();
    assert_eq!(status.state, SyncLifecycle::Synced);
    assert_eq!(status.peak_height, 300);
    assert_eq!(status.target_height, 321);
}

#[tokio::test]
async fn reopening_applies_no_destructive_migration() {
    // Opening an existing, current-schema DB must preserve its data (the forward-compatible,
    // idempotent migration path; cross-version upgrades are exercised when a v2 migration lands).
    let db = TempDb::new("migrate");
    {
        let store = SqliteWalletStore::open(&db.path).unwrap();
        store
            .apply_coin_state(identity(1).wallet_id, coin("keep", 7, Some(1), None))
            .unwrap();
    }
    let store = SqliteWalletStore::open(&db.path).unwrap();
    assert_eq!(
        store.balance(&identity(1)).await.unwrap().confirmed,
        Amount(7)
    );
}

#[tokio::test]
async fn persistent_catch_up_backfills_beyond_the_in_memory_window() {
    let db = TempDb::new("catchup");

    // A TINY in-memory ring (capacity 2) that would drop older events, wired to dual-write every
    // published event into the durable SQLite log.
    let persistent = Arc::new(SqliteDeltaLog::open(&db.path).unwrap());
    let sink = EventSink::with_persistent_log(8, 2, persistent.clone());

    for height in 1..=10 {
        sink.publish(WalletEvent::NewTip {
            height,
            header_hash: format!("{height:064x}"),
        });
    }

    // The in-memory ring retained only the last 2 events...
    let in_mem = sink
        .catch_up_log()
        .catch_up(Cursor::default(), EnumSet::all())
        .await
        .unwrap();
    assert_eq!(in_mem.len(), 2, "in-memory ring is bounded to capacity 2");

    // ...but the durable log has ALL 10, in order, from the sentinel.
    let durable = persistent
        .catch_up(Cursor::default(), EnumSet::all())
        .await
        .unwrap();
    assert_eq!(durable.len(), 10);
    assert_eq!(durable[0].cursor, Cursor(1));
    assert_eq!(durable[9].cursor, Cursor(10));

    // And it survives a "restart": a fresh handle on the same file still backfills the full range.
    drop(persistent);
    drop(sink);
    let reopened = SqliteDeltaLog::open(&db.path).unwrap();
    let after_restart = reopened.catch_up(Cursor(5), EnumSet::all()).await.unwrap();
    assert_eq!(after_restart.len(), 5, "events strictly after cursor 5");
    assert_eq!(after_restart[0].cursor, Cursor(6));
}

/// Drive an identical operation sequence against both backings and assert the observable reads match
/// — the backend-parity contract (SPEC §3: a persistent backing is a drop-in over the same surface).
#[tokio::test]
async fn in_memory_and_sqlite_are_observably_identical() {
    let mem = InMemoryWalletStore::new();
    let sql = SqliteWalletStore::open_in_memory().unwrap();
    let id = identity(1);

    // Same sequence of mutations, asserting each mutation's OBSERVABLE result matches.
    assert_eq!(
        mem.apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None)),
        sql.apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None))
            .unwrap()
    );
    assert_eq!(
        mem.apply_coin_state(id.wallet_id, coin("a", 100, Some(5), Some(9))),
        sql.apply_coin_state(id.wallet_id, coin("a", 100, Some(5), Some(9)))
            .unwrap()
    );
    mem.apply_coin_state(id.wallet_id, coin("b", 42, Some(7), None));
    sql.apply_coin_state(id.wallet_id, coin("b", 42, Some(7), None))
        .unwrap();
    mem.upsert_nft(
        id.wallet_id,
        NftRecord {
            launcher_id: "nft".into(),
            data_uri: None,
        },
    );
    sql.upsert_nft(
        id.wallet_id,
        NftRecord {
            launcher_id: "nft".into(),
            data_uri: None,
        },
    )
    .unwrap();
    mem.set_sync_status(id.wallet_id, SyncLifecycle::Syncing, 88);
    sql.set_sync_status(id.wallet_id, SyncLifecycle::Syncing, 88)
        .unwrap();

    assert_eq!(
        mem.balance(&id).await.unwrap(),
        sql.balance(&id).await.unwrap()
    );
    assert_eq!(
        mem.coins(&id).await.unwrap().len(),
        sql.coins(&id).await.unwrap().len()
    );
    assert_eq!(
        mem.nfts(&id).await.unwrap().len(),
        sql.nfts(&id).await.unwrap().len()
    );
    assert_eq!(
        mem.sync_status(&id).await.unwrap(),
        sql.sync_status(&id).await.unwrap()
    );
}

#[tokio::test]
async fn no_secret_material_is_ever_persisted() {
    let db = TempDb::new("nosecret");
    let id = identity(1);

    let store = SqliteWalletStore::open(&db.path).unwrap();
    store
        .apply_coin_state(id.wallet_id, coin("coin", 1_000, Some(1), None))
        .unwrap();
    store
        .upsert_cat(
            id.wallet_id,
            CatRecord {
                asset_id: AssetId("tail".into()),
                balance: Amount(5),
                name: Some("DBX".into()),
            },
        )
        .unwrap();
    store
        .upsert_did(
            id.wallet_id,
            DidRecord {
                launcher_id: "did".into(),
                name: Some("me".into()),
            },
        )
        .unwrap();
    store
        .record_transaction(
            id.wallet_id,
            TransactionRecord {
                tx_id: "tx".into(),
                confirmed_height: Some(2),
                summary: TransactionSummary {
                    outputs: vec![],
                    fee: Amount(1),
                },
            },
        )
        .unwrap();

    let log = SqliteDeltaLog::open(&db.path).unwrap();
    log.append(&dig_wallet_backend::types::EmittedEvent {
        cursor: Cursor(1),
        event: WalletEvent::NewTip {
            height: 1,
            header_hash: "aa".into(),
        },
    })
    .unwrap();

    // Structural guarantee: NO table column is named after secret-bearing material.
    let column_names = {
        let conn = rusqlite::Connection::open(&db.path).unwrap();
        let mut names: Vec<String> = Vec::new();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for table in &tables {
            let mut stmt = conn
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap();
            let cols: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            names.extend(cols);
            names.push(table.clone());
        }
        names
    };

    // Byte guarantee: the raw DB file never contains a secret-bearing identifier — catches a secret
    // accidentally serialized into any JSON blob column, not just a mis-named column.
    let raw = std::fs::read(&db.path).unwrap();
    let raw_lower = String::from_utf8_lossy(&raw).to_lowercase();

    for forbidden in [
        "secret",
        "private",
        "mnemonic",
        "seed_phrase",
        "signingkey",
        "keypair",
        "master_sk",
    ] {
        assert!(
            !column_names
                .iter()
                .any(|n| n.to_lowercase().contains(forbidden)),
            "a column/table is named after secret material: {forbidden}"
        );
        assert!(
            !raw_lower.contains(forbidden),
            "the on-disk DB bytes contain forbidden secret marker: {forbidden}"
        );
    }
}
