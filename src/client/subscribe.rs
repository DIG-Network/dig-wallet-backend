//! `client::subscribe` — the event SUBSCRIBER side (SPEC §5).
//!
//! dig-app subscribes to a FILTERED view of the engine's events and drives its UI from the
//! stream ("event-driven, poll only on a gap"). When a subscriber falls behind (broadcast lag)
//! or reconnects, it calls [`CatchUp::catch_up`] ONCE with its last [`Cursor`] to backfill the
//! missed range from the engine's persisted delta, then resumes the live stream.

use async_trait::async_trait;
use enumset::EnumSet;

use crate::types::{Cursor, EmittedEvent, EventKind, WalletResult};

/// Keep only the events whose kind is in `filter`, preserving order.
///
/// The pure core of subscription filtering — used both to filter a live stream and to filter a
/// `catch_up` backfill so both paths apply identical semantics.
pub fn filter_events(
    events: impl IntoIterator<Item = EmittedEvent>,
    filter: EnumSet<EventKind>,
) -> Vec<EmittedEvent> {
    events
        .into_iter()
        .filter(|e| e.event.matches(filter))
        .collect()
}

/// The backfill contract: fetch the events after `since` (exclusive) from the engine's
/// persisted delta, filtered to `filter`. Called once after a lag/reconnect gap.
#[async_trait]
pub trait CatchUp: Send + Sync {
    /// Return the filtered events with a cursor strictly greater than `since`, in order.
    async fn catch_up(
        &self,
        since: Cursor,
        filter: EnumSet<EventKind>,
    ) -> WalletResult<Vec<EmittedEvent>>;
}

/// A live subscription wrapper over the engine's broadcast receiver, applying the kind filter.
///
/// Available on the client side (in-process bridge). Over IPC the same filtered stream is delivered
/// as server-push; the filter semantics are identical (they share [`filter_events`]).
#[cfg(feature = "engine")]
pub struct Subscription {
    receiver: tokio::sync::broadcast::Receiver<EmittedEvent>,
    filter: EnumSet<EventKind>,
}

#[cfg(feature = "engine")]
impl Subscription {
    /// Wrap a broadcast receiver with a kind filter.
    pub fn new(
        receiver: tokio::sync::broadcast::Receiver<EmittedEvent>,
        filter: EnumSet<EventKind>,
    ) -> Self {
        Self { receiver, filter }
    }

    /// Await the next matching event.
    ///
    /// Returns `Ok(Some(event))` for a matching event, `Ok(None)` when the sender is closed, and
    /// `Err(cursor_hint)` on lag — the caller then `catch_up`s from its last seen cursor. Events
    /// that do not match the filter are skipped transparently.
    pub async fn next(&mut self) -> Result<Option<EmittedEvent>, LagSignal> {
        loop {
            match self.receiver.recv().await {
                Ok(event) if event.event.matches(self.filter) => return Ok(Some(event)),
                Ok(_) => continue, // filtered out
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(None),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    return Err(LagSignal);
                }
            }
        }
    }
}

/// Signals that the subscriber lagged and must `catch_up` from its last cursor.
#[cfg(feature = "engine")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LagSignal;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{WalletEvent, WalletId};

    fn tip(cursor: u64, height: u32) -> EmittedEvent {
        EmittedEvent {
            cursor: Cursor(cursor),
            event: WalletEvent::NewTip {
                height,
                header_hash: "hh".into(),
            },
        }
    }

    fn received(cursor: u64) -> EmittedEvent {
        EmittedEvent {
            cursor: Cursor(cursor),
            event: WalletEvent::FundsReceived {
                wallet_id: WalletId(1),
                asset: None,
                amount: crate::types::Amount(1),
                coin_id: "c".into(),
                confirmed_height: 1,
            },
        }
    }

    #[test]
    fn filter_keeps_only_matching_kinds_in_order() {
        let events = vec![tip(0, 1), received(1), tip(2, 2)];
        let only_tips = filter_events(events.clone(), EventKind::NewTip.into());
        assert_eq!(only_tips.len(), 2);
        assert_eq!(only_tips[0].cursor, Cursor(0));
        assert_eq!(only_tips[1].cursor, Cursor(2));

        let only_funds = filter_events(events, EventKind::FundsReceived.into());
        assert_eq!(only_funds.len(), 1);
        assert_eq!(only_funds[0].cursor, Cursor(1));
    }

    #[test]
    fn empty_filter_keeps_nothing() {
        let kept = filter_events(vec![tip(0, 1)], EnumSet::empty());
        assert!(kept.is_empty());
    }

    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn live_subscription_skips_filtered_events() {
        let sink = crate::engine::EventSink::new(16);
        let mut sub = Subscription::new(sink.subscribe(), EventKind::NewTip.into());
        sink.publish(WalletEvent::FundsReceived {
            wallet_id: WalletId(1),
            asset: None,
            amount: crate::types::Amount(1),
            coin_id: "c".into(),
            confirmed_height: 1,
        });
        sink.publish(WalletEvent::NewTip {
            height: 9,
            header_hash: "hh".into(),
        });

        let next = sub.next().await.unwrap().unwrap();
        assert_eq!(
            next.event,
            WalletEvent::NewTip {
                height: 9,
                header_hash: "hh".into()
            }
        );
    }

    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn closed_sender_yields_none() {
        let sink = crate::engine::EventSink::new(4);
        let mut sub = Subscription::new(sink.subscribe(), EnumSet::all());
        drop(sink);
        assert_eq!(sub.next().await.unwrap(), None);
    }
}
