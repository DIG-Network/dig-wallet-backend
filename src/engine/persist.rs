//! `engine::persist` — persistent (SQLite) backing for the engine state store + event delta log.
//!
//! The engine's read/write state ([`super::state::WalletStore`]) and its catch-up delta log
//! ([`super::events::CatchUp`]) have in-memory backings ([`super::state::InMemoryWalletStore`],
//! [`super::events::DeltaLog`]) that are deterministic and fully unit-testable without a database.
//! This module adds the DURABLE backings that survive a process restart and lift the in-memory
//! catch-up window bound (#1118):
//!
//! - [`SqliteWalletStore`] — a persistent [`WalletStore`] with the SAME mutation surface the sync
//!   loop drives, so it is a drop-in for [`InMemoryWalletStore`]. Coin/CAT/NFT/DID/transaction/sync
//!   state is written to SQLite and read back identically after a restart.
//! - [`SqliteDeltaLog`] — a persistent [`CatchUp`] over an unbounded on-disk event log. It swaps in
//!   behind a consumer's `&dyn CatchUp<Error = WalletError>` with no call-site change, so a
//!   subscriber that was offline longer than the in-memory ring can still backfill every missed
//!   event. It ALSO implements [`super::events::PersistentEventLog`], so an
//!   [`super::events::EventSink`] can dual-write every published event to it for durability.
//!
//! # Design (mirrors the reference `dig-wallet` SQLite store, adapted to this crate's types)
//! - **Amounts are stored as decimal TEXT** — the full `u64` range with no `i64` overflow; heights
//!   are `INTEGER`, narrowed to `u32` at the type boundary.
//! - **Versioned, forward-compatible migrations** ([`MIGRATIONS`]) run on open; a table records the
//!   applied schema version so an older on-disk DB is upgraded additively (§5.1 spirit — never a
//!   destructive rewrite).
//! - **WAL journaling** gives crash-safe atomic writes + rollback; every migration runs in a
//!   transaction so a partial upgrade can never corrupt the store.
//! - **A single guarded connection** (`Mutex<Connection>`) — the workload is one small local wallet
//!   DB with a single writer (the sync loop), so a serialized connection is the simplest correct
//!   design; WAL still allows concurrent readers. A multi-connection pool adds no throughput here.
//!
//! # Key isolation (SPEC §1.4)
//! This module is engine-seam code: it persists ONLY public coin/asset/transaction/sync/event
//! state. No column, row, or serialized value is or contains a secret key, mnemonic, or seed. The
//! `no_secret_material_is_ever_persisted` integration test asserts the on-disk bytes never contain
//! key material, and `tests/key_isolation.rs` asserts this source names no secret identifier.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;

use async_trait::async_trait;
use enumset::EnumSet;
use rusqlite::{params, Connection, OptionalExtension};

use super::events::PersistentEventLog;
use super::state::{classify_coin_change, CoinChange, WalletStore};
use crate::types::value::Puzzlehash;
use crate::types::{
    Amount, AssetId, Balance, CatRecord, CatchUp, CoinRecord, Cursor, DidRecord, EmittedEvent,
    EventKind, IdentityRef, NftRecord, SyncLifecycle, SyncStatus, TransactionRecord, WalletError,
    WalletErrorCode, WalletId, WalletResult,
};

/// The ordered list of schema migrations. The DB's applied version is its length; index `i` is the
/// SQL that upgrades version `i` to version `i + 1`. Migrations are append-only and additive:
/// a new capability adds a migration, never edits a released one (§5.1 backwards-compatibility).
const MIGRATIONS: &[&str] = &[
    // v1 — the initial schema: per-wallet coin/asset/tx/sync state + the global event log.
    // Every statement is `IF NOT EXISTS` so a re-run (e.g. after a crash left the DDL committed but
    // the version unrecorded) is a harmless no-op rather than a fatal "table already exists".
    "
    CREATE TABLE IF NOT EXISTS coins (
        wallet_id      INTEGER NOT NULL,
        coin_id        TEXT    NOT NULL,
        puzzle_hash    TEXT    NOT NULL,
        amount         TEXT    NOT NULL,
        created_height INTEGER,
        spent_height   INTEGER,
        PRIMARY KEY (wallet_id, coin_id)
    );
    CREATE INDEX IF NOT EXISTS coins_unspent ON coins (wallet_id) WHERE spent_height IS NULL;

    CREATE TABLE IF NOT EXISTS cats (
        wallet_id INTEGER NOT NULL,
        asset_id  TEXT    NOT NULL,
        balance   TEXT    NOT NULL,
        name      TEXT,
        PRIMARY KEY (wallet_id, asset_id)
    );

    CREATE TABLE IF NOT EXISTS nfts (
        wallet_id   INTEGER NOT NULL,
        launcher_id TEXT    NOT NULL,
        data_uri    TEXT,
        PRIMARY KEY (wallet_id, launcher_id)
    );

    CREATE TABLE IF NOT EXISTS dids (
        wallet_id   INTEGER NOT NULL,
        launcher_id TEXT    NOT NULL,
        name        TEXT,
        PRIMARY KEY (wallet_id, launcher_id)
    );

    CREATE TABLE IF NOT EXISTS transactions (
        seq              INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_id        INTEGER NOT NULL,
        tx_id            TEXT    NOT NULL,
        confirmed_height INTEGER,
        summary_json     TEXT    NOT NULL
    );
    CREATE INDEX IF NOT EXISTS transactions_wallet ON transactions (wallet_id);

    CREATE TABLE IF NOT EXISTS sync_state (
        wallet_id     INTEGER PRIMARY KEY,
        peak_height   INTEGER NOT NULL DEFAULT 0,
        target_height INTEGER NOT NULL DEFAULT 0,
        lifecycle     TEXT    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events (
        cursor     INTEGER PRIMARY KEY,
        event_json TEXT NOT NULL
    );
    ",
];

/// Map any storage-layer failure to the catalogued [`WalletErrorCode::Storage`] error.
fn storage_err(context: impl std::fmt::Display) -> WalletError {
    WalletError::new(WalletErrorCode::Storage, context.to_string())
}

/// Serialize a value the store persists as JSON, mapping a failure to a storage error.
fn to_json<T: serde::Serialize>(value: &T) -> WalletResult<String> {
    serde_json::to_string(value).map_err(storage_err)
}

/// Deserialize a JSON value the store read back, mapping a failure to a storage error.
fn from_json<T: serde::de::DeserializeOwned>(json: &str) -> WalletResult<T> {
    serde_json::from_str(json).map_err(storage_err)
}

/// The shared SQLite handle: one guarded connection with the schema migrated to the current version.
struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Open (creating if absent) a file-backed store at `path`, enabling WAL + running migrations.
    fn open(path: impl AsRef<Path>) -> WalletResult<Self> {
        let conn = Connection::open(path).map_err(storage_err)?;
        Self::init(conn)
    }

    /// Open an ephemeral in-memory store (each connection is its own private DB) — used by tests.
    fn open_in_memory() -> WalletResult<Self> {
        let conn = Connection::open_in_memory().map_err(storage_err)?;
        Self::init(conn)
    }

    /// Apply pragmas + migrations to a freshly-opened connection.
    fn init(conn: Connection) -> WalletResult<Self> {
        // WAL = crash-safe atomic commits + concurrent readers; foreign_keys on for integrity.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage_err)?;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(storage_err)?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Run `f` against the guarded connection.
    fn with<T>(&self, f: impl FnOnce(&Connection) -> WalletResult<T>) -> WalletResult<T> {
        let conn = self.conn.lock().expect("sqlite connection mutex poisoned");
        f(&conn)
    }
}

/// Bring a connection's schema up to [`MIGRATIONS`]`.len()`, applying each pending migration inside
/// a transaction. Idempotent: an already-current DB applies nothing; an older DB upgrades additively.
fn migrate(conn: &Connection) -> WalletResult<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
        [],
    )
    .map_err(storage_err)?;

    let current: Option<i64> = conn
        .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .optional()
        .map_err(storage_err)?;
    let current = current.unwrap_or(0);
    let target = MIGRATIONS.len() as i64;

    if current > target {
        return Err(storage_err(format!(
            "database schema version {current} is newer than this build supports ({target})"
        )));
    }

    for (index, statements) in MIGRATIONS.iter().enumerate() {
        let version = index as i64 + 1;
        if version <= current {
            continue;
        }
        // Apply the DDL AND record the new version in ONE transaction. If the process crashes
        // mid-migration the whole batch rolls back atomically, so the DB is never left with the
        // schema upgraded but the version unrecorded (which would re-run the migration on reopen).
        conn.execute_batch(&format!(
            "BEGIN;\
             {statements}\
             DELETE FROM schema_version;\
             INSERT INTO schema_version (version) VALUES ({version});\
             COMMIT;"
        ))
        .map_err(storage_err)?;
    }
    Ok(())
}

/// Reconstruct a [`CoinRecord`] from a `coins` row (columns: coin_id, puzzle_hash, amount,
/// created_height, spent_height).
fn row_to_coin(row: &rusqlite::Row) -> rusqlite::Result<CoinRecord> {
    let amount: String = row.get(2)?;
    let created: Option<i64> = row.get(3)?;
    let spent: Option<i64> = row.get(4)?;
    Ok(CoinRecord {
        coin_id: row.get(0)?,
        puzzle_hash: Puzzlehash(row.get(1)?),
        // A malformed amount is a corrupted store; surface it as an SQLite type error which the
        // caller maps to WalletErrorCode::Storage (never a silent zero).
        amount: Amount(amount.parse().map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                format!("invalid amount {amount:?}").into(),
            )
        })?),
        created_height: created.map(|h| h as u32),
        spent_height: spent.map(|h| h as u32),
    })
}

/// A persistent [`WalletStore`] backed by SQLite — a drop-in for
/// [`super::state::InMemoryWalletStore`] whose state survives a process restart.
///
/// It exposes the SAME mutation surface the sync loop drives ([`Self::apply_coin_state`],
/// [`Self::rollback_to`], …) and, via the [`WalletStore`] trait, the read surface the client seam
/// proxies. A coin update is classified with the shared [`classify_coin_change`], so the observable
/// [`CoinChange`] result matches the in-memory backing exactly (backend-parity).
pub struct SqliteWalletStore {
    db: Db,
}

impl SqliteWalletStore {
    /// Open (creating if absent) a persistent store at `path`.
    pub fn open(path: impl AsRef<Path>) -> WalletResult<Self> {
        Ok(Self {
            db: Db::open(path)?,
        })
    }

    /// Open an ephemeral in-memory store — deterministic, DB-file-free, for tests + parity checks.
    pub fn open_in_memory() -> WalletResult<Self> {
        Ok(Self {
            db: Db::open_in_memory()?,
        })
    }

    /// Apply a coin-state update, upserting the coin and reporting how it changed — the persistent
    /// analogue of [`super::state::InMemoryWalletStore::apply_coin_state`].
    pub fn apply_coin_state(
        &self,
        wallet_id: WalletId,
        record: CoinRecord,
    ) -> WalletResult<CoinChange> {
        self.db.with(|conn| {
            let previous = fetch_coin(conn, wallet_id, &record.coin_id)?;
            let change = classify_coin_change(previous.as_ref(), &record);
            conn.execute(
                "INSERT INTO coins (wallet_id, coin_id, puzzle_hash, amount, created_height, spent_height)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(wallet_id, coin_id) DO UPDATE SET
                   puzzle_hash = excluded.puzzle_hash,
                   amount = excluded.amount,
                   created_height = excluded.created_height,
                   spent_height = excluded.spent_height",
                params![
                    wallet_id.0,
                    record.coin_id,
                    record.puzzle_hash.0,
                    record.amount.mojos().to_string(),
                    record.created_height,
                    record.spent_height,
                ],
            )
            .map_err(storage_err)?;
            Ok(change)
        })
    }

    /// Roll the wallet back to `fork_height` after a reorg — forget coins created above the fork and
    /// un-spend coins whose spend was rolled back. Returns every touched coin id; resets the peak.
    pub fn rollback_to(&self, wallet_id: WalletId, fork_height: u32) -> WalletResult<Vec<String>> {
        self.db.with(|conn| {
            let mut affected = HashSet::new();

            // Coins created after the fork never existed on the winning chain — forget them.
            for id in query_coin_ids(
                conn,
                "SELECT coin_id FROM coins WHERE wallet_id = ?1 AND created_height > ?2",
                wallet_id,
                fork_height,
            )? {
                affected.insert(id);
            }
            conn.execute(
                "DELETE FROM coins WHERE wallet_id = ?1 AND created_height > ?2",
                params![wallet_id.0, fork_height],
            )
            .map_err(storage_err)?;

            // Coins spent after the fork are spendable again — un-spend them.
            for id in query_coin_ids(
                conn,
                "SELECT coin_id FROM coins WHERE wallet_id = ?1 AND spent_height > ?2",
                wallet_id,
                fork_height,
            )? {
                affected.insert(id);
            }
            conn.execute(
                "UPDATE coins SET spent_height = NULL WHERE wallet_id = ?1 AND spent_height > ?2",
                params![wallet_id.0, fork_height],
            )
            .map_err(storage_err)?;

            set_peak_absolute(conn, wallet_id, fork_height)?;
            Ok(affected.into_iter().collect())
        })
    }

    /// Advance the processed peak, never moving it backwards (rollback owns going back).
    pub fn set_peak(&self, wallet_id: WalletId, peak_height: u32) -> WalletResult<()> {
        self.db.with(|conn| {
            let current = fetch_peak(conn, wallet_id)?;
            set_peak_absolute(conn, wallet_id, current.max(peak_height))
        })
    }

    /// Record the sync lifecycle + the tip the wallet is syncing toward.
    pub fn set_sync_status(
        &self,
        wallet_id: WalletId,
        lifecycle: SyncLifecycle,
        target: u32,
    ) -> WalletResult<()> {
        let lifecycle_json = to_json(&lifecycle)?;
        self.db.with(|conn| {
            conn.execute(
                "INSERT INTO sync_state (wallet_id, peak_height, target_height, lifecycle)
                 VALUES (?1, 0, ?2, ?3)
                 ON CONFLICT(wallet_id) DO UPDATE SET
                   target_height = excluded.target_height,
                   lifecycle = excluded.lifecycle",
                params![wallet_id.0, target, lifecycle_json],
            )
            .map_err(storage_err)?;
            Ok(())
        })
    }

    /// Upsert a CAT balance line (keyed by asset id).
    pub fn upsert_cat(&self, wallet_id: WalletId, record: CatRecord) -> WalletResult<()> {
        self.db.with(|conn| {
            conn.execute(
                "INSERT INTO cats (wallet_id, asset_id, balance, name) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(wallet_id, asset_id) DO UPDATE SET
                   balance = excluded.balance, name = excluded.name",
                params![
                    wallet_id.0,
                    record.asset_id.0,
                    record.balance.mojos().to_string(),
                    record.name,
                ],
            )
            .map_err(storage_err)?;
            Ok(())
        })
    }

    /// Upsert an NFT (keyed by launcher id).
    pub fn upsert_nft(&self, wallet_id: WalletId, record: NftRecord) -> WalletResult<()> {
        self.db.with(|conn| {
            conn.execute(
                "INSERT INTO nfts (wallet_id, launcher_id, data_uri) VALUES (?1, ?2, ?3)
                 ON CONFLICT(wallet_id, launcher_id) DO UPDATE SET data_uri = excluded.data_uri",
                params![wallet_id.0, record.launcher_id, record.data_uri],
            )
            .map_err(storage_err)?;
            Ok(())
        })
    }

    /// Upsert a DID (keyed by launcher id).
    pub fn upsert_did(&self, wallet_id: WalletId, record: DidRecord) -> WalletResult<()> {
        self.db.with(|conn| {
            conn.execute(
                "INSERT INTO dids (wallet_id, launcher_id, name) VALUES (?1, ?2, ?3)
                 ON CONFLICT(wallet_id, launcher_id) DO UPDATE SET name = excluded.name",
                params![wallet_id.0, record.launcher_id, record.name],
            )
            .map_err(storage_err)?;
            Ok(())
        })
    }

    /// Append a settled transaction to history.
    pub fn record_transaction(
        &self,
        wallet_id: WalletId,
        record: TransactionRecord,
    ) -> WalletResult<()> {
        let summary_json = to_json(&record.summary)?;
        self.db.with(|conn| {
            conn.execute(
                "INSERT INTO transactions (wallet_id, tx_id, confirmed_height, summary_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    wallet_id.0,
                    record.tx_id,
                    record.confirmed_height,
                    summary_json
                ],
            )
            .map_err(storage_err)?;
            Ok(())
        })
    }

    /// Look up a single tracked coin (the sync loop's local-first read).
    pub fn coin(&self, wallet_id: WalletId, coin_id: &str) -> WalletResult<Option<CoinRecord>> {
        self.db.with(|conn| fetch_coin(conn, wallet_id, coin_id))
    }

    /// The height the wallet has processed up to.
    pub fn peak_height(&self, wallet_id: WalletId) -> WalletResult<u32> {
        self.db.with(|conn| fetch_peak(conn, wallet_id))
    }
}

/// Run a `SELECT coin_id …` returning the coin ids matching a `(wallet_id, height)` predicate.
fn query_coin_ids(
    conn: &Connection,
    sql: &str,
    wallet_id: WalletId,
    height: u32,
) -> WalletResult<Vec<String>> {
    conn.prepare(sql)
        .map_err(storage_err)?
        .query_map(params![wallet_id.0, height], |row| row.get(0))
        .map_err(storage_err)?
        .collect::<rusqlite::Result<_>>()
        .map_err(storage_err)
}

/// Fetch a single coin row for a wallet, if present.
fn fetch_coin(
    conn: &Connection,
    wallet_id: WalletId,
    coin_id: &str,
) -> WalletResult<Option<CoinRecord>> {
    conn.query_row(
        "SELECT coin_id, puzzle_hash, amount, created_height, spent_height
         FROM coins WHERE wallet_id = ?1 AND coin_id = ?2",
        params![wallet_id.0, coin_id],
        row_to_coin,
    )
    .optional()
    .map_err(storage_err)
}

/// The wallet's recorded peak height (0 if it has no sync-state row yet).
fn fetch_peak(conn: &Connection, wallet_id: WalletId) -> WalletResult<u32> {
    let peak: Option<i64> = conn
        .query_row(
            "SELECT peak_height FROM sync_state WHERE wallet_id = ?1",
            params![wallet_id.0],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_err)?;
    Ok(peak.unwrap_or(0) as u32)
}

/// Set the wallet's peak height to an exact value, creating the sync-state row if needed.
fn set_peak_absolute(conn: &Connection, wallet_id: WalletId, peak: u32) -> WalletResult<()> {
    let idle = to_json(&SyncLifecycle::Idle)?;
    conn.execute(
        "INSERT INTO sync_state (wallet_id, peak_height, target_height, lifecycle)
         VALUES (?1, ?2, 0, ?3)
         ON CONFLICT(wallet_id) DO UPDATE SET peak_height = excluded.peak_height",
        params![wallet_id.0, peak, idle],
    )
    .map_err(storage_err)?;
    Ok(())
}

#[async_trait]
impl WalletStore for SqliteWalletStore {
    async fn balance(&self, identity: &IdentityRef) -> WalletResult<Balance> {
        let wallet_id = identity.wallet_id;
        self.db.with(|conn| {
            // Sum unspent amounts in Rust (decimal-TEXT amounts hold the full u64 range that a
            // SQL SUM over TEXT could not).
            let total: u64 = conn
                .prepare("SELECT amount FROM coins WHERE wallet_id = ?1 AND spent_height IS NULL")
                .map_err(storage_err)?
                .query_map(params![wallet_id.0], |row| row.get::<_, String>(0))
                .map_err(storage_err)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_err)?
                .iter()
                .map(|a| a.parse::<u64>().map_err(storage_err))
                .sum::<WalletResult<u64>>()?;
            Ok(Balance {
                confirmed: Amount(total),
                spendable: Amount(total),
            })
        })
    }

    async fn coins(&self, identity: &IdentityRef) -> WalletResult<Vec<CoinRecord>> {
        let wallet_id = identity.wallet_id;
        self.db.with(|conn| {
            conn.prepare(
                "SELECT coin_id, puzzle_hash, amount, created_height, spent_height
                 FROM coins WHERE wallet_id = ?1 AND spent_height IS NULL",
            )
            .map_err(storage_err)?
            .query_map(params![wallet_id.0], row_to_coin)
            .map_err(storage_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage_err)
        })
    }

    async fn cats(&self, identity: &IdentityRef) -> WalletResult<Vec<CatRecord>> {
        let wallet_id = identity.wallet_id;
        self.db.with(|conn| {
            conn.prepare("SELECT asset_id, balance, name FROM cats WHERE wallet_id = ?1")
                .map_err(storage_err)?
                .query_map(params![wallet_id.0], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })
                .map_err(storage_err)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_err)?
                .into_iter()
                .map(|(asset_id, balance, name)| {
                    Ok(CatRecord {
                        asset_id: AssetId(asset_id),
                        balance: Amount(balance.parse().map_err(storage_err)?),
                        name,
                    })
                })
                .collect()
        })
    }

    async fn nfts(&self, identity: &IdentityRef) -> WalletResult<Vec<NftRecord>> {
        let wallet_id = identity.wallet_id;
        self.db.with(|conn| {
            conn.prepare("SELECT launcher_id, data_uri FROM nfts WHERE wallet_id = ?1")
                .map_err(storage_err)?
                .query_map(params![wallet_id.0], |row| {
                    Ok(NftRecord {
                        launcher_id: row.get(0)?,
                        data_uri: row.get(1)?,
                    })
                })
                .map_err(storage_err)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_err)
        })
    }

    async fn dids(&self, identity: &IdentityRef) -> WalletResult<Vec<DidRecord>> {
        let wallet_id = identity.wallet_id;
        self.db.with(|conn| {
            conn.prepare("SELECT launcher_id, name FROM dids WHERE wallet_id = ?1")
                .map_err(storage_err)?
                .query_map(params![wallet_id.0], |row| {
                    Ok(DidRecord {
                        launcher_id: row.get(0)?,
                        name: row.get(1)?,
                    })
                })
                .map_err(storage_err)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_err)
        })
    }

    async fn history(&self, identity: &IdentityRef) -> WalletResult<Vec<TransactionRecord>> {
        let wallet_id = identity.wallet_id;
        self.db.with(|conn| {
            let rows: Vec<(String, Option<i64>, String)> = conn
                .prepare(
                    "SELECT tx_id, confirmed_height, summary_json FROM transactions
                     WHERE wallet_id = ?1 ORDER BY seq",
                )
                .map_err(storage_err)?
                .query_map(params![wallet_id.0], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(storage_err)?
                .collect::<rusqlite::Result<_>>()
                .map_err(storage_err)?;
            rows.into_iter()
                .map(|(tx_id, confirmed_height, summary_json)| {
                    Ok(TransactionRecord {
                        tx_id,
                        confirmed_height: confirmed_height.map(|h| h as u32),
                        summary: from_json(&summary_json)?,
                    })
                })
                .collect()
        })
    }

    async fn sync_status(&self, identity: &IdentityRef) -> WalletResult<SyncStatus> {
        let wallet_id = identity.wallet_id;
        self.db.with(|conn| {
            let row: Option<(i64, i64, String)> = conn
                .query_row(
                    "SELECT peak_height, target_height, lifecycle FROM sync_state WHERE wallet_id = ?1",
                    params![wallet_id.0],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(storage_err)?;
            match row {
                Some((peak, target, lifecycle)) => Ok(SyncStatus {
                    state: from_json(&lifecycle)?,
                    peak_height: peak as u32,
                    target_height: target as u32,
                }),
                // A never-synced wallet is Idle at height 0 (parity with InMemoryWalletStore).
                None => Ok(SyncStatus {
                    state: SyncLifecycle::Idle,
                    peak_height: 0,
                    target_height: 0,
                }),
            }
        })
    }
}

/// A persistent [`CatchUp`] over an unbounded on-disk event log.
///
/// Unlike the in-memory [`super::events::DeltaLog`] (a bounded ring), this retains EVERY appended
/// event across restarts, so a subscriber offline longer than the in-memory window can still
/// backfill the full missed range. It implements the same [`CatchUp`] trait with
/// `Error = WalletError`, so a consumer holding `&dyn CatchUp<Error = WalletError>` swaps to it with
/// no call-site change; and it implements [`PersistentEventLog`] so an [`super::events::EventSink`]
/// can dual-write published events into it.
pub struct SqliteDeltaLog {
    db: Db,
}

impl SqliteDeltaLog {
    /// Open (creating if absent) a persistent event log at `path`.
    pub fn open(path: impl AsRef<Path>) -> WalletResult<Self> {
        Ok(Self {
            db: Db::open(path)?,
        })
    }

    /// Open an ephemeral in-memory event log — used by tests.
    pub fn open_in_memory() -> WalletResult<Self> {
        Ok(Self {
            db: Db::open_in_memory()?,
        })
    }

    /// Persist one emitted event. Idempotent on the cursor: re-appending the same cursor is ignored,
    /// so a replay during recovery never duplicates or errors.
    pub fn append(&self, emitted: &EmittedEvent) -> WalletResult<()> {
        let event_json = to_json(&emitted.event)?;
        self.db.with(|conn| {
            conn.execute(
                "INSERT INTO events (cursor, event_json) VALUES (?1, ?2)
                 ON CONFLICT(cursor) DO NOTHING",
                params![emitted.cursor.0, event_json],
            )
            .map_err(storage_err)?;
            Ok(())
        })
    }
}

impl PersistentEventLog for SqliteDeltaLog {
    fn append(&self, emitted: &EmittedEvent) -> WalletResult<()> {
        SqliteDeltaLog::append(self, emitted)
    }
}

#[async_trait]
impl CatchUp for SqliteDeltaLog {
    type Error = WalletError;

    /// Every persisted event with a cursor STRICTLY GREATER than `since`, in cursor order, narrowed
    /// to `filter` — the same view rule as the in-memory delta log (so live and persistent catch-up
    /// deliver an identical filtered view), but over the full on-disk history.
    async fn catch_up(
        &self,
        since: Cursor,
        filter: EnumSet<EventKind>,
    ) -> WalletResult<Vec<EmittedEvent>> {
        self.db.with(|conn| {
            let rows: Vec<(i64, String)> = conn
                .prepare("SELECT cursor, event_json FROM events WHERE cursor > ?1 ORDER BY cursor")
                .map_err(storage_err)?
                .query_map(params![since.0], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(storage_err)?
                .collect::<rusqlite::Result<_>>()
                .map_err(storage_err)?;
            let mut out = Vec::new();
            for (cursor, event_json) in rows {
                let emitted = EmittedEvent {
                    cursor: Cursor(cursor as u64),
                    event: from_json(&event_json)?,
                };
                // Apply the kind filter in Rust so the semantics match `WalletEvent::matches` exactly.
                if emitted.event.matches(filter) {
                    out.push(emitted);
                }
            }
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TransactionSummary, WalletEvent};

    fn coin(id: &str, amount: u64, created: Option<u32>, spent: Option<u32>) -> CoinRecord {
        CoinRecord {
            coin_id: id.into(),
            puzzle_hash: Puzzlehash("ph".into()),
            amount: Amount(amount),
            created_height: created,
            spent_height: spent,
        }
    }

    fn identity(id: u32) -> IdentityRef {
        IdentityRef::new(WalletId(id))
    }

    #[tokio::test]
    async fn a_new_unspent_coin_is_created_and_counts_toward_balance() {
        let store = SqliteWalletStore::open_in_memory().unwrap();
        let id = identity(1);
        let change = store
            .apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None))
            .unwrap();
        assert_eq!(change, CoinChange::Created);
        assert_eq!(store.balance(&id).await.unwrap().confirmed, Amount(100));
        assert_eq!(store.coins(&id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn re_delivering_an_identical_coin_is_unchanged() {
        let store = SqliteWalletStore::open_in_memory().unwrap();
        let id = identity(1);
        store
            .apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None))
            .unwrap();
        let change = store
            .apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None))
            .unwrap();
        assert_eq!(change, CoinChange::Unchanged);
    }

    #[tokio::test]
    async fn spending_a_known_coin_is_spent_and_drops_from_balance() {
        let store = SqliteWalletStore::open_in_memory().unwrap();
        let id = identity(1);
        store
            .apply_coin_state(id.wallet_id, coin("a", 100, Some(5), None))
            .unwrap();
        let change = store
            .apply_coin_state(id.wallet_id, coin("a", 100, Some(5), Some(9)))
            .unwrap();
        assert_eq!(change, CoinChange::Spent);
        assert_eq!(store.balance(&id).await.unwrap().confirmed, Amount(0));
        assert!(store.coins(&id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_non_spend_field_change_is_updated() {
        let store = SqliteWalletStore::open_in_memory().unwrap();
        let id = identity(1);
        store
            .apply_coin_state(id.wallet_id, coin("a", 100, None, None))
            .unwrap();
        let change = store
            .apply_coin_state(id.wallet_id, coin("a", 100, Some(7), None))
            .unwrap();
        assert_eq!(change, CoinChange::Updated);
    }

    #[tokio::test]
    async fn a_full_u64_amount_survives_the_text_encoding() {
        let store = SqliteWalletStore::open_in_memory().unwrap();
        let id = identity(1);
        store
            .apply_coin_state(id.wallet_id, coin("big", u64::MAX, Some(1), None))
            .unwrap();
        assert_eq!(
            store.balance(&id).await.unwrap().confirmed,
            Amount(u64::MAX)
        );
    }

    #[tokio::test]
    async fn rollback_forgets_coins_created_after_the_fork_and_unspends_the_rest() {
        let store = SqliteWalletStore::open_in_memory().unwrap();
        let id = identity(1);
        store
            .apply_coin_state(id.wallet_id, coin("keep", 10, Some(3), None))
            .unwrap();
        store
            .apply_coin_state(id.wallet_id, coin("drop", 20, Some(8), None))
            .unwrap();
        store
            .apply_coin_state(id.wallet_id, coin("respent", 100, Some(2), Some(9)))
            .unwrap();
        store.set_peak(id.wallet_id, 9).unwrap();

        let mut affected = store.rollback_to(id.wallet_id, 5).unwrap();
        affected.sort();
        assert_eq!(affected, vec!["drop".to_string(), "respent".to_string()]);
        // "keep" (10) stays; "respent" (100) is spendable again; "drop" is gone.
        assert_eq!(store.balance(&id).await.unwrap().confirmed, Amount(110));
        assert_eq!(store.sync_status(&id).await.unwrap().peak_height, 5);
    }

    #[tokio::test]
    async fn set_peak_never_moves_backwards() {
        let store = SqliteWalletStore::open_in_memory().unwrap();
        let id = identity(1);
        store.set_peak(id.wallet_id, 10).unwrap();
        store.set_peak(id.wallet_id, 4).unwrap();
        assert_eq!(store.peak_height(id.wallet_id).unwrap(), 10);
        assert_eq!(store.sync_status(&id).await.unwrap().peak_height, 10);
    }

    #[tokio::test]
    async fn sync_status_reflects_lifecycle_and_target() {
        let store = SqliteWalletStore::open_in_memory().unwrap();
        let id = identity(1);
        store
            .set_sync_status(id.wallet_id, SyncLifecycle::Syncing, 200)
            .unwrap();
        let status = store.sync_status(&id).await.unwrap();
        assert_eq!(status.state, SyncLifecycle::Syncing);
        assert_eq!(status.target_height, 200);
    }

    #[tokio::test]
    async fn cat_nft_did_and_history_round_trip() {
        let store = SqliteWalletStore::open_in_memory().unwrap();
        let id = identity(1);
        store
            .upsert_cat(
                id.wallet_id,
                CatRecord {
                    asset_id: AssetId("tail".into()),
                    balance: Amount(50),
                    name: Some("DBX".into()),
                },
            )
            .unwrap();
        store
            .upsert_nft(
                id.wallet_id,
                NftRecord {
                    launcher_id: "nft".into(),
                    data_uri: Some("ipfs://x".into()),
                },
            )
            .unwrap();
        store
            .upsert_did(
                id.wallet_id,
                DidRecord {
                    launcher_id: "did".into(),
                    name: None,
                },
            )
            .unwrap();
        store
            .record_transaction(
                id.wallet_id,
                TransactionRecord {
                    tx_id: "t".into(),
                    confirmed_height: Some(11),
                    summary: TransactionSummary {
                        outputs: vec![],
                        fee: Amount(1),
                    },
                },
            )
            .unwrap();

        assert_eq!(store.cats(&id).await.unwrap()[0].balance, Amount(50));
        assert_eq!(store.nfts(&id).await.unwrap().len(), 1);
        assert_eq!(store.dids(&id).await.unwrap().len(), 1);
        assert_eq!(store.history(&id).await.unwrap()[0].summary.fee, Amount(1));
    }

    #[tokio::test]
    async fn state_is_isolated_per_wallet() {
        let store = SqliteWalletStore::open_in_memory().unwrap();
        store
            .apply_coin_state(WalletId(1), coin("a", 100, Some(5), None))
            .unwrap();
        assert_eq!(
            store.balance(&identity(2)).await.unwrap().confirmed,
            Amount(0)
        );
        assert_eq!(
            store.balance(&identity(1)).await.unwrap().confirmed,
            Amount(100)
        );
    }

    #[test]
    fn migrating_is_idempotent_and_records_the_version() {
        let db = Db::open_in_memory().unwrap();
        // A second migrate pass over the same connection is a no-op (no error, version unchanged).
        db.with(|conn| {
            migrate(conn)?;
            let version: i64 = conn
                .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
                .map_err(storage_err)?;
            assert_eq!(version, MIGRATIONS.len() as i64);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn migration_recovers_from_a_crash_between_ddl_and_version_write() {
        // Regression (H1/F4): a crash AFTER a migration's DDL committed but BEFORE its version was
        // recorded must not brick the DB. Simulate that exact window — apply migration 1's DDL and
        // commit it, but leave the recorded version at 0 — then run the reopen path (`migrate`) and
        // assert it recovers idempotently instead of failing with "table coins already exists".
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
            [],
        )
        .unwrap();
        conn.execute_batch(MIGRATIONS[0]).unwrap();
        // No version row written: the reopen resolves current_version = 0 and re-runs migration 1.

        migrate(&conn).expect("reopen must recover idempotently from the crash window");

        let version: i64 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64);
    }

    #[test]
    fn a_future_schema_version_is_rejected() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)", [])
            .unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (999)", [])
            .unwrap();
        let err = migrate(&conn).unwrap_err();
        assert_eq!(err.code, WalletErrorCode::Storage);
    }

    fn tip(height: u32) -> WalletEvent {
        WalletEvent::NewTip {
            height,
            header_hash: format!("{height:064x}"),
        }
    }

    #[tokio::test]
    async fn delta_log_backfills_strictly_after_the_cursor_filtered() {
        let log = SqliteDeltaLog::open_in_memory().unwrap();
        log.append(&EmittedEvent {
            cursor: Cursor(1),
            event: tip(1),
        })
        .unwrap();
        log.append(&EmittedEvent {
            cursor: Cursor(2),
            event: tip(2),
        })
        .unwrap();

        let missed = log.catch_up(Cursor(1), EnumSet::all()).await.unwrap();
        assert_eq!(missed.len(), 1);
        assert_eq!(missed[0].cursor, Cursor(2));

        let none = log
            .catch_up(Cursor::default(), EnumSet::empty())
            .await
            .unwrap();
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn appending_the_same_cursor_twice_is_idempotent() {
        let log = SqliteDeltaLog::open_in_memory().unwrap();
        let e = EmittedEvent {
            cursor: Cursor(1),
            event: tip(1),
        };
        log.append(&e).unwrap();
        log.append(&e).unwrap();
        let all = log
            .catch_up(Cursor::default(), EnumSet::all())
            .await
            .unwrap();
        assert_eq!(all.len(), 1);
    }
}
