//! End-to-end event-system integration test (SPEC §5) — the exact flow dig-app (#1008) drives.
//!
//! Proves the whole contract wired together across the engine + client seams: the engine EMITS,
//! a client SUBSCRIBES to a filtered live stream, a slow subscriber observes a LAG signal, then
//! CATCHES UP from its last cursor and resumes — with ordering and the kind filter preserved.

#![cfg(all(feature = "engine", feature = "client"))]

use enumset::EnumSet;

use dig_wallet_backend::client::subscribe::{LagSignal, Subscription};
use dig_wallet_backend::engine::EventSink;
use dig_wallet_backend::types::{Amount, CatchUp, Cursor, EventKind, WalletEvent, WalletId};

fn funds_received(coin: &str) -> WalletEvent {
    WalletEvent::FundsReceived {
        wallet_id: WalletId(1),
        asset: None,
        amount: Amount(100),
        coin_id: coin.into(),
        confirmed_height: 10,
    }
}

fn tip(height: u32) -> WalletEvent {
    WalletEvent::NewTip {
        height,
        header_hash: format!("{height:064x}"),
    }
}

/// A live subscriber receives only the kinds it subscribed to, in emission order.
#[tokio::test]
async fn live_stream_delivers_only_subscribed_kinds_in_order() {
    let sink = EventSink::new(32);
    let mut sub = Subscription::new(sink.subscribe(), EventKind::NewTip.into());

    sink.publish(funds_received("a")); // filtered out
    sink.publish(tip(1));
    sink.publish(funds_received("b")); // filtered out
    sink.publish(tip(2));

    let first = sub.next().await.unwrap().unwrap();
    let second = sub.next().await.unwrap().unwrap();
    assert_eq!(first.event, tip(1));
    assert_eq!(second.event, tip(2));
    assert!(first.cursor < second.cursor, "cursors preserve order");
}

/// The full poll-only-on-gap flow: a subscriber that lags gets a [`LagSignal`], backfills the exact
/// missed range from its last cursor via [`CatchUp`], and the backfill honours the same filter and
/// preserves ordering — then the subscriber can resume live.
#[tokio::test]
async fn lagged_subscriber_catches_up_from_its_last_cursor() {
    // A tiny broadcast buffer forces the receiver to lag as soon as we outpace it.
    let sink = EventSink::with_history_capacity(2, 1024);
    let mut sub = Subscription::new(sink.subscribe(), EnumSet::all());

    // Consume the first event live so we have a real "last seen" cursor.
    let first_cursor = sink.publish(tip(1));
    let seen = sub.next().await.unwrap().unwrap();
    assert_eq!(seen.cursor, first_cursor);

    // Now flood past the buffer without consuming — the receiver falls behind.
    for height in 2..=10 {
        sink.publish(tip(height));
    }

    // The next live read reports the gap.
    assert_eq!(sub.next().await, Err(LagSignal));

    // Backfill everything strictly after the last cursor we actually saw.
    let missed = sink
        .catch_up_log()
        .catch_up(seen.cursor, EnumSet::all())
        .await
        .unwrap();

    // Cursors 2..=10 (nine events), contiguous and in order — nothing lost, nothing duplicated.
    assert_eq!(missed.len(), 9);
    for (offset, emitted) in missed.iter().enumerate() {
        assert_eq!(emitted.cursor, Cursor(first_cursor.0 + 1 + offset as u64));
        assert_eq!(emitted.event, tip(2 + offset as u32));
    }
}

/// Catch-up applies the subscriber's kind filter, so live + backfill deliver an identical view.
#[tokio::test]
async fn catch_up_backfill_honours_the_subscription_filter() {
    let sink = EventSink::new(4);
    let filter: EnumSet<EventKind> = EventKind::FundsReceived.into();

    sink.publish(tip(1)); // filtered out
    sink.publish(funds_received("a")); // kept
    sink.publish(tip(2)); // filtered out
    sink.publish(funds_received("b")); // kept

    let backfill = sink
        .catch_up_log()
        .catch_up(Cursor::default(), filter)
        .await
        .unwrap();

    assert_eq!(backfill.len(), 2);
    assert_eq!(backfill[0].event, funds_received("a"));
    assert_eq!(backfill[1].event, funds_received("b"));
}
