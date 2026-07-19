//! `engine::events` — THE EMITTER (SPEC §5).
//!
//! The engine publishes [`WalletEvent`]s here as its state advances (funds in/out, coin
//! state, sync progress). Delivery is a cheap, cloneable fan-out over a Tokio broadcast
//! channel; publishing with no subscribers is a no-op (best-effort semantics). Every event
//! is stamped with a monotonic [`Cursor`] so a lagging subscriber can `catch_up` (SPEC §5).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use enumset::EnumSet;
use tokio::sync::broadcast;

use crate::types::{
    CatchUp, Cursor, EmittedEvent, EventKind, WalletError, WalletEvent, WalletResult,
};

/// A durable sink an [`EventSink`] dual-writes every published event into, so the delta log survives
/// a process restart and can backfill beyond the in-memory ring (#1118).
///
/// The persistent SQLite backing (`super::persist::SqliteDeltaLog`) implements this AND [`CatchUp`],
/// so wiring it into an [`EventSink`] gives durable emission while a consumer reads it back through
/// the same `&dyn CatchUp` seam — no call-site change.
pub trait PersistentEventLog: Send + Sync {
    /// Durably record one emitted event. Idempotent on its cursor.
    fn append(&self, emitted: &EmittedEvent) -> WalletResult<()>;
}

/// How many recently-emitted events the in-memory delta log retains for catch-up backfill.
///
/// A subscriber that lags or reconnects backfills the missed range from this window. It is sized
/// generously above a typical broadcast buffer so a subscriber that briefly falls behind can always
/// recover; a gap older than this window is unrecoverable in-memory (the persistent SQLite-backed
/// catch-up, #1118, removes that bound by swapping the backing store behind the same [`CatchUp`]
/// trait).
pub const DEFAULT_HISTORY_CAPACITY: usize = 4096;

/// The engine-side event emitter: a broadcast sender, the monotonic cursor counter, and a bounded
/// in-memory delta log for catch-up backfill.
///
/// Cheap to clone (`Arc`-backed) so every engine subsystem can hold one and publish.
#[derive(Clone)]
pub struct EventSink {
    sender: broadcast::Sender<EmittedEvent>,
    next_cursor: Arc<AtomicU64>,
    /// The recently-emitted events retained for `catch_up` backfill (bounded ring, oldest evicted).
    history: Arc<Mutex<VecDeque<EmittedEvent>>>,
    history_capacity: usize,
    /// An optional durable delta log every published event is ALSO written to (#1118). When set,
    /// the on-disk log outlives the process and the bounded in-memory ring.
    persistent: Option<Arc<dyn PersistentEventLog>>,
}

impl EventSink {
    /// Create an emitter whose broadcast buffer holds up to `capacity` in-flight events per
    /// subscriber before the slowest subscriber starts observing lag. The catch-up delta log is
    /// sized to [`DEFAULT_HISTORY_CAPACITY`] (never below the broadcast `capacity`).
    pub fn new(capacity: usize) -> Self {
        Self::with_history_capacity(capacity, DEFAULT_HISTORY_CAPACITY.max(capacity))
    }

    /// Create an emitter with an explicit broadcast `capacity` and delta-log `history_capacity`
    /// (the number of recent events retained for catch-up backfill).
    pub fn with_history_capacity(capacity: usize, history_capacity: usize) -> Self {
        Self::build(capacity, history_capacity, None)
    }

    /// Create an emitter that ALSO dual-writes every published event to a durable `persistent` log,
    /// so catch-up survives a restart + reaches beyond the in-memory window (#1118). The in-memory
    /// ring is retained too (fast, live-stream catch-up); the durable log is the unbounded backstop.
    pub fn with_persistent_log(
        capacity: usize,
        history_capacity: usize,
        persistent: Arc<dyn PersistentEventLog>,
    ) -> Self {
        Self::build(capacity, history_capacity, Some(persistent))
    }

    /// Shared constructor for the three public builders above.
    fn build(
        capacity: usize,
        history_capacity: usize,
        persistent: Option<Arc<dyn PersistentEventLog>>,
    ) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            // Real cursors start at 1 so `Cursor::default()` (0) is the "seen nothing" sentinel: a
            // fresh subscriber's `catch_up(Cursor(0))` (strictly-greater) backfills the whole window.
            next_cursor: Arc::new(AtomicU64::new(1)),
            history: Arc::new(Mutex::new(VecDeque::with_capacity(history_capacity))),
            history_capacity,
            persistent,
        }
    }

    /// Stamp `event` with the next cursor, record it in the delta log, and fan it out. Returns the
    /// assigned cursor.
    ///
    /// Best-effort fan-out: if there are no live subscribers the event is simply dropped from the
    /// broadcast (the cursor is still consumed, preserving monotonicity), but it is ALWAYS appended
    /// to the delta log so a later subscriber can `catch_up` to it.
    pub fn publish(&self, event: WalletEvent) -> Cursor {
        let cursor = Cursor(self.next_cursor.fetch_add(1, Ordering::SeqCst));
        let emitted = EmittedEvent { cursor, event };
        self.record(emitted.clone());
        // A send error means "no receivers"; that is expected and not a failure.
        let _ = self.sender.send(emitted);
        cursor
    }

    /// Append an emitted event to the bounded in-memory delta log (evicting the oldest at capacity)
    /// and, when a durable log is wired, to that too.
    ///
    /// The durable write is best-effort: `publish` returns a `Cursor` infallibly (SPEC §5), so a
    /// persistence failure cannot abort emission — the event still lives in the in-memory ring and
    /// the live fan-out. The durable log is the beyond-the-window backstop, not the source of truth
    /// for a live subscriber.
    fn record(&self, emitted: EmittedEvent) {
        if let Some(persistent) = &self.persistent {
            let _ = persistent.append(&emitted);
        }
        let mut history = self.history.lock().expect("event delta log mutex poisoned");
        if history.len() == self.history_capacity {
            history.pop_front();
        }
        history.push_back(emitted);
    }

    /// Open a new live subscription receiver. The client seam wraps this into a filtered stream.
    pub fn subscribe(&self) -> broadcast::Receiver<EmittedEvent> {
        self.sender.subscribe()
    }

    /// A cheap handle to the catch-up delta log — the [`CatchUp`] backfill source a lagging
    /// subscriber calls once, sharing this sink's retained event window.
    pub fn catch_up_log(&self) -> DeltaLog {
        DeltaLog {
            history: Arc::clone(&self.history),
        }
    }

    /// The number of live subscribers (useful for tests + backpressure heuristics).
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

/// The in-memory [`CatchUp`] backfill source over an [`EventSink`]'s retained delta log.
///
/// A subscriber that observes a lag/gap calls [`catch_up`](CatchUp::catch_up) ONCE with its last
/// seen [`Cursor`] to fetch the missed range (filtered by the same [`EnumSet<EventKind>`] as its
/// live stream), then resumes live. Cheap to clone; shares the sink's ring behind an `Arc`.
///
/// # The #1118 swap seam
/// This is the Wave-0 in-memory backing (poll-only-on-gap, bounded window). The persistent
/// SQLite-backed catch-up (#1118) implements the SAME [`CatchUp`] trait with `Error = WalletError`,
/// so a consumer holding `&dyn CatchUp<Error = WalletError>` swaps to it with no call-site change —
/// gaining unbounded retention across restarts.
#[derive(Clone)]
pub struct DeltaLog {
    history: Arc<Mutex<VecDeque<EmittedEvent>>>,
}

#[async_trait]
impl CatchUp for DeltaLog {
    type Error = WalletError;

    /// Every retained [`EmittedEvent`] with a cursor STRICTLY GREATER than `since`, in cursor order,
    /// narrowed to `filter` (the same rule the live stream applies, so live and catch-up deliver an
    /// identical filtered view).
    ///
    /// The in-memory window is bounded: events older than the retained range are unrecoverable here
    /// (a fully persistent range is #1118). Within the window the range is complete and ordered.
    async fn catch_up(
        &self,
        since: Cursor,
        filter: EnumSet<EventKind>,
    ) -> Result<Vec<EmittedEvent>, WalletError> {
        let history = self.history.lock().expect("event delta log mutex poisoned");
        Ok(history
            .iter()
            .filter(|emitted| emitted.cursor > since)
            .filter(|emitted| emitted.event.matches(filter))
            .cloned()
            .collect())
    }
}

/// [`EventSink`] IS the engine's `dig-events-protocol` emitter — the trait the protocol crate
/// fixes so a second engine implementation stays interchangeable (#1072).
impl dig_events_protocol::EventEmitter for EventSink {
    fn publish(&self, event: WalletEvent) -> Cursor {
        EventSink::publish(self, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WalletId;

    fn tip(height: u32) -> WalletEvent {
        WalletEvent::NewTip {
            height,
            header_hash: format!("{height:064x}"),
        }
    }

    #[tokio::test]
    async fn publish_stamps_monotonic_cursors() {
        let sink = EventSink::new(16);
        // Cursors are 1-based (0 is the "seen nothing" sentinel — see EventSink::with_history_capacity).
        assert_eq!(sink.publish(tip(1)), Cursor(1));
        assert_eq!(sink.publish(tip(2)), Cursor(2));
        assert_eq!(sink.publish(tip(3)), Cursor(3));
    }

    #[tokio::test]
    async fn subscriber_receives_published_events_in_order() {
        let sink = EventSink::new(16);
        let mut rx = sink.subscribe();
        sink.publish(tip(10));
        sink.publish(tip(11));

        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();
        assert_eq!(first.cursor, Cursor(1));
        assert_eq!(second.cursor, Cursor(2));
        assert_eq!(first.event, tip(10));
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_a_noop() {
        let sink = EventSink::new(4);
        // No panic, cursor still advances.
        assert_eq!(sink.subscriber_count(), 0);
        let c = sink.publish(WalletEvent::Derivation {
            wallet_id: WalletId(1),
            index: 0,
        });
        assert_eq!(c, Cursor(1));
    }

    #[tokio::test]
    async fn fan_out_reaches_every_subscriber() {
        let sink = EventSink::new(16);
        let mut a = sink.subscribe();
        let mut b = sink.subscribe();
        assert_eq!(sink.subscriber_count(), 2);
        sink.publish(tip(5));
        assert_eq!(a.recv().await.unwrap().event, tip(5));
        assert_eq!(b.recv().await.unwrap().event, tip(5));
    }

    // --- The in-memory delta log / CatchUp backfill (SPEC §5.3) ---

    #[tokio::test]
    async fn catch_up_backfills_events_strictly_after_the_cursor() {
        let sink = EventSink::new(16);
        sink.publish(tip(1)); // cursor 1
        sink.publish(tip(2)); // cursor 2
        sink.publish(tip(3)); // cursor 3

        let log = sink.catch_up_log();
        let missed = log.catch_up(Cursor(1), EnumSet::all()).await.unwrap();
        // Strictly greater than cursor 1 → cursors 2 and 3, in order.
        assert_eq!(missed.len(), 2);
        assert_eq!(missed[0].cursor, Cursor(2));
        assert_eq!(missed[1].cursor, Cursor(3));
    }

    #[tokio::test]
    async fn catch_up_from_default_cursor_backfills_the_whole_window() {
        // The delta log is populated on publish regardless of subscribers, so a subscriber that
        // connects LATER backfills EVERY event from the "seen nothing" sentinel (Cursor::default).
        let sink = EventSink::new(4);
        assert_eq!(sink.subscriber_count(), 0);
        sink.publish(tip(7)); // cursor 1
        sink.publish(tip(8)); // cursor 2

        let all = sink
            .catch_up_log()
            .catch_up(Cursor::default(), EnumSet::all())
            .await
            .unwrap();
        assert_eq!(all.len(), 2, "both events are strictly after the sentinel");
        assert_eq!(all[0].cursor, Cursor(1));
        assert_eq!(all[1].cursor, Cursor(2));
    }

    #[tokio::test]
    async fn catch_up_applies_the_kind_filter() {
        let sink = EventSink::new(16);
        sink.publish(WalletEvent::FundsReceived {
            wallet_id: WalletId(1),
            asset: None,
            amount: crate::types::Amount(1),
            coin_id: "c".into(),
            confirmed_height: 1,
        }); // cursor 1
        sink.publish(tip(9)); // cursor 2
        sink.publish(tip(10)); // cursor 3

        // An empty filter yields nothing, whatever the range.
        let nothing = sink
            .catch_up_log()
            .catch_up(Cursor::default(), EnumSet::empty())
            .await
            .unwrap();
        assert!(nothing.is_empty());

        // Backfill the whole window filtered to NewTip only — the FundsReceived at cursor 1 is dropped.
        let tips = sink
            .catch_up_log()
            .catch_up(Cursor::default(), EventKind::NewTip.into())
            .await
            .unwrap();
        assert_eq!(tips.len(), 2);
        assert_eq!(tips[0].cursor, Cursor(2));
        assert_eq!(tips[1].cursor, Cursor(3));
    }

    #[tokio::test]
    async fn delta_log_evicts_the_oldest_beyond_capacity() {
        // A tiny history window drops the oldest events; catch-up from the sentinel returns only
        // what is still retained (the in-memory bound; #1118 makes this unbounded).
        let sink = EventSink::with_history_capacity(4, 2);
        sink.publish(tip(1)); // cursor 1 (evicted)
        sink.publish(tip(2)); // cursor 2 (evicted)
        sink.publish(tip(3)); // cursor 3 (retained)
        sink.publish(tip(4)); // cursor 4 (retained)

        let retained = sink
            .catch_up_log()
            .catch_up(Cursor::default(), EnumSet::all())
            .await
            .unwrap();
        // Only the last two survive the ring; ordering preserved.
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].cursor, Cursor(3));
        assert_eq!(retained[1].cursor, Cursor(4));
    }
}
