//! `engine::events` — THE EMITTER (SPEC §5).
//!
//! The engine publishes [`WalletEvent`]s here as its state advances (funds in/out, coin
//! state, sync progress). Delivery is a cheap, cloneable fan-out over a Tokio broadcast
//! channel; publishing with no subscribers is a no-op (best-effort semantics). Every event
//! is stamped with a monotonic [`Cursor`] so a lagging subscriber can `catch_up` (SPEC §5).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::broadcast;

use crate::types::{Cursor, EmittedEvent, WalletEvent};

/// The engine-side event emitter: a broadcast sender plus the monotonic cursor counter.
///
/// Cheap to clone (`Arc`-backed) so every engine subsystem can hold one and publish.
#[derive(Clone)]
pub struct EventSink {
    sender: broadcast::Sender<EmittedEvent>,
    next_cursor: Arc<AtomicU64>,
}

impl EventSink {
    /// Create an emitter whose broadcast buffer holds up to `capacity` in-flight events per
    /// subscriber before the slowest subscriber starts observing lag.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            next_cursor: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Stamp `event` with the next cursor and fan it out. Returns the assigned cursor.
    ///
    /// Best-effort: if there are no live subscribers the event is simply dropped (the cursor
    /// is still consumed, preserving monotonicity for `catch_up`).
    pub fn publish(&self, event: WalletEvent) -> Cursor {
        let cursor = Cursor(self.next_cursor.fetch_add(1, Ordering::SeqCst));
        // A send error means "no receivers"; that is expected and not a failure.
        let _ = self.sender.send(EmittedEvent { cursor, event });
        cursor
    }

    /// Open a new live subscription receiver. The client seam wraps this into a filtered stream.
    pub fn subscribe(&self) -> broadcast::Receiver<EmittedEvent> {
        self.sender.subscribe()
    }

    /// The number of live subscribers (useful for tests + backpressure heuristics).
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
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
        assert_eq!(sink.publish(tip(1)), Cursor(0));
        assert_eq!(sink.publish(tip(2)), Cursor(1));
        assert_eq!(sink.publish(tip(3)), Cursor(2));
    }

    #[tokio::test]
    async fn subscriber_receives_published_events_in_order() {
        let sink = EventSink::new(16);
        let mut rx = sink.subscribe();
        sink.publish(tip(10));
        sink.publish(tip(11));

        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();
        assert_eq!(first.cursor, Cursor(0));
        assert_eq!(second.cursor, Cursor(1));
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
        assert_eq!(c, Cursor(0));
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
}
