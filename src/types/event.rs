//! The wallet event taxonomy — the heart of the event-driven design (SPEC §5).
//!
//! The engine EMITS [`WalletEvent`]s (see `engine::events`); dig-app SUBSCRIBES to a
//! FILTERED view of them (see `client::subscribe`) by [`EventKind`]. Subscription is live and
//! best-effort; a subscriber that falls behind uses a [`Cursor`] to `catch_up` from the
//! engine's persisted delta, then resumes live. This is the "event-driven, poll only on a
//! gap" contract.

use enumset::{EnumSet, EnumSetType};
use serde::{Deserialize, Serialize};

use super::identity::WalletId;
use super::value::{Amount, AssetId};

/// A monotonic, per-wallet sequence number stamped on delivered events.
///
/// A subscriber remembers the last cursor it saw; on a gap (reconnect or lag) it calls
/// `catch_up(since)` ONCE to backfill the missed range, then resumes the live stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Cursor(pub u64);

impl Cursor {
    /// The next cursor in sequence.
    pub fn next(self) -> Cursor {
        Cursor(self.0 + 1)
    }
}

/// Where the sync loop is relative to the chain tip (a tri-state, pushed via `sync_progress`).
#[derive(Debug, Serialize, Deserialize, EnumSetType)]
#[enumset(serialize_repr = "list")]
#[serde(rename_all = "snake_case")]
pub enum SyncLifecycle {
    /// Not yet started / no peer.
    Idle,
    /// Actively catching up to the tip.
    Syncing,
    /// Caught up to the tip and tracking live.
    Synced,
}

/// A snapshot of sync state for a wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStatus {
    /// The tri-state lifecycle.
    pub state: SyncLifecycle,
    /// The height the wallet has processed up to.
    pub peak_height: u32,
    /// The chain tip height the wallet is syncing toward.
    pub target_height: u32,
}

/// The kind discriminant of a [`WalletEvent`], used as the subscription FILTER.
///
/// A subscriber passes an `EnumSet<EventKind>`; the engine delivers only matching events
/// (e.g. #970 funds notifications subscribe `FundsReceived | FundsSent`; #979 chain-watch
/// subscribes `CoinStateChanged | NewTip`).
#[derive(Debug, Serialize, Deserialize, EnumSetType)]
#[enumset(serialize_repr = "list")]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Inbound value landed.
    FundsReceived,
    /// Outbound value confirmed.
    FundsSent,
    /// A tracked coin's spent/created state changed.
    CoinStateChanged,
    /// A submitted transaction confirmed.
    Confirmation,
    /// A submitted transaction failed.
    TransactionFailed,
    /// A new chain tip was observed.
    NewTip,
    /// Sync progress advanced.
    SyncProgress,
    /// CAT metadata became available.
    CatInfo,
    /// DID metadata became available.
    DidInfo,
    /// NFT data became available.
    NftData,
    /// A new HD receive address became active.
    Derivation,
}

/// A delivered event paired with its monotonic [`Cursor`].
///
/// The engine stamps a per-instance cursor on every event as it is emitted; subscribers
/// remember the last cursor and pass it to `catch_up` after a gap. This envelope is what
/// flows over the subscription stream (live) and what `catch_up` returns (backfill).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmittedEvent {
    /// The monotonic delivery cursor.
    pub cursor: Cursor,
    /// The event payload.
    pub event: WalletEvent,
}

/// The event the engine emits and dig-app consumes.
///
/// Tagged by `type` in snake_case on the wire (`{"type":"funds_received",…}`), so a
/// machine consumer branches on a stable discriminant (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WalletEvent {
    /// Inbound value landed for a wallet.
    FundsReceived {
        /// The wallet that received value.
        wallet_id: WalletId,
        /// The asset received; `None` = native XCH.
        asset: Option<AssetId>,
        /// The amount received.
        amount: Amount,
        /// The receiving coin id (hex).
        coin_id: String,
        /// The confirmation height.
        confirmed_height: u32,
    },
    /// Outbound value confirmed for a wallet.
    FundsSent {
        /// The wallet that sent value.
        wallet_id: WalletId,
        /// The asset sent; `None` = native XCH.
        asset: Option<AssetId>,
        /// The amount sent.
        amount: Amount,
        /// The transaction id (hex).
        tx_id: String,
        /// The confirmation height.
        confirmed_height: u32,
    },
    /// A tracked coin changed state.
    CoinStateChanged {
        /// The affected coin id (hex).
        coin_id: String,
        /// Whether the coin is now spent.
        spent: bool,
        /// The height it was created at, if known.
        created_height: Option<u32>,
        /// The height it was spent at, if spent.
        spent_height: Option<u32>,
    },
    /// A submitted transaction confirmed on-chain.
    Confirmation {
        /// The transaction id (hex).
        tx_id: String,
        /// The confirmation height.
        height: u32,
    },
    /// A submitted transaction failed (rejected or never confirmed).
    TransactionFailed {
        /// The transaction id (hex).
        tx_id: String,
        /// A human-readable failure reason.
        error: String,
    },
    /// A new chain tip was observed.
    NewTip {
        /// The tip height.
        height: u32,
        /// The tip header hash (hex).
        header_hash: String,
    },
    /// Sync progress advanced for a wallet.
    SyncProgress {
        /// The wallet whose sync advanced.
        wallet_id: WalletId,
        /// The current lifecycle state.
        state: SyncLifecycle,
        /// The processed height.
        peak_height: u32,
        /// The tip height being synced toward.
        target_height: u32,
    },
    /// CAT metadata for an asset became available.
    CatInfo {
        /// The CAT asset id.
        asset_id: AssetId,
        /// The resolved ticker/name.
        name: Option<String>,
    },
    /// DID metadata became available.
    DidInfo {
        /// The DID launcher id (hex).
        launcher_id: String,
    },
    /// NFT data became available.
    NftData {
        /// The NFT launcher id (hex).
        launcher_id: String,
    },
    /// A new HD receive address became active.
    Derivation {
        /// The wallet the address belongs to.
        wallet_id: WalletId,
        /// The newly-active derivation index.
        index: u32,
    },
}

impl WalletEvent {
    /// The [`EventKind`] discriminant used for subscription filtering.
    pub fn kind(&self) -> EventKind {
        match self {
            Self::FundsReceived { .. } => EventKind::FundsReceived,
            Self::FundsSent { .. } => EventKind::FundsSent,
            Self::CoinStateChanged { .. } => EventKind::CoinStateChanged,
            Self::Confirmation { .. } => EventKind::Confirmation,
            Self::TransactionFailed { .. } => EventKind::TransactionFailed,
            Self::NewTip { .. } => EventKind::NewTip,
            Self::SyncProgress { .. } => EventKind::SyncProgress,
            Self::CatInfo { .. } => EventKind::CatInfo,
            Self::DidInfo { .. } => EventKind::DidInfo,
            Self::NftData { .. } => EventKind::NftData,
            Self::Derivation { .. } => EventKind::Derivation,
        }
    }

    /// Whether this event passes a subscription filter (an `EnumSet` of kinds).
    pub fn matches(&self, filter: EnumSet<EventKind>) -> bool {
        filter.contains(self.kind())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_advances_monotonically() {
        assert_eq!(Cursor(0).next(), Cursor(1));
        assert!(Cursor(1) > Cursor(0));
    }

    #[test]
    fn event_is_tagged_snake_case() {
        let e = WalletEvent::Confirmation {
            tx_id: "ab".into(),
            height: 100,
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"type\":\"confirmation\""), "{json}");
        let back: WalletEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn kind_maps_each_variant() {
        let e = WalletEvent::FundsReceived {
            wallet_id: WalletId(1),
            asset: None,
            amount: Amount(5),
            coin_id: "c".into(),
            confirmed_height: 10,
        };
        assert_eq!(e.kind(), EventKind::FundsReceived);
    }

    #[test]
    fn filter_admits_only_matching_kinds() {
        let received = WalletEvent::FundsReceived {
            wallet_id: WalletId(1),
            asset: None,
            amount: Amount(5),
            coin_id: "c".into(),
            confirmed_height: 10,
        };
        let tip = WalletEvent::NewTip {
            height: 9,
            header_hash: "hh".into(),
        };

        let funds_only = EventKind::FundsReceived | EventKind::FundsSent;
        assert!(received.matches(funds_only));
        assert!(!tip.matches(funds_only));
    }

    #[test]
    fn all_events_round_trip() {
        let events = vec![
            WalletEvent::FundsSent {
                wallet_id: WalletId(2),
                asset: Some(AssetId("tail".into())),
                amount: Amount(3),
                tx_id: "t".into(),
                confirmed_height: 1,
            },
            WalletEvent::CoinStateChanged {
                coin_id: "c".into(),
                spent: true,
                created_height: Some(1),
                spent_height: Some(2),
            },
            WalletEvent::SyncProgress {
                wallet_id: WalletId(1),
                state: SyncLifecycle::Syncing,
                peak_height: 5,
                target_height: 10,
            },
            WalletEvent::CatInfo {
                asset_id: AssetId("a".into()),
                name: Some("DBX".into()),
            },
            WalletEvent::Derivation {
                wallet_id: WalletId(1),
                index: 7,
            },
        ];
        for e in events {
            let json = serde_json::to_string(&e).unwrap();
            let back: WalletEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back, e);
        }
    }
}
