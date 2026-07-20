//! `engine::offer_state` — the private pending-offer map for the two-call offer flows (SPEC §3d).
//!
//! Making and taking an offer are each TWO engine calls with a client-side signature in between
//! (build → sign → assemble/finalize). The intermediate an in-progress build carries forward is a
//! non-serializable chia-wallet-sdk allocator object — a live [`SpendContext`] plus, for a make,
//! the requested-payment metadata, or, for a take, the parsed [`Offer`]. Serializing it across the
//! seam is impossible (and would leak SDK types over IPC), so instead the engine parks it HERE,
//! keyed by an opaque [`OfferBuildId`], and only that id crosses the wire.
//!
//! # Why this never holds a key (SPEC §1.4)
//! A parked build is unsigned coin-spend construction state only. The signature is produced
//! client-side and returned by value in the second call; nothing secret is ever stored here.
//!
//! # Lifetime + leak safety
//! An abandoned build (the client never sends the second call) would otherwise pin a `SpendContext`
//! forever. Every access first sweeps entries older than [`PENDING_TTL`], so a forgotten build is
//! reclaimed and the map cannot grow without bound.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dig_offers::{AssetInfo, Offer, RequestedPayments, SpendContext};

use crate::types::OfferBuildId;

/// How long an in-progress offer build is retained before it is swept as abandoned.
///
/// Generous enough for an interactive client to review + sign between the two calls, short enough
/// that a forgotten build does not pin memory for long.
pub const PENDING_TTL: Duration = Duration::from_secs(300);

/// The intermediate an in-progress build carries from its first call to its second, held with the
/// SAME [`SpendContext`] both phases must share (a requested-NFT/CAT leg carries an
/// allocator-relative pointer that only survives in that one context).
enum PendingKind {
    /// A make awaiting assembly: the requested-payment metadata `make_assemble` needs. Boxed so
    /// this large payload does not bloat the enum for every variant (clippy `large_enum_variant`).
    Make(Box<MakeState>),
    /// A take awaiting finalization: the maker's parsed offer `take_combine` consumes. Boxed for
    /// the same size-balancing reason.
    Take { offer: Box<Offer> },
}

/// The requested-side metadata a parked make carries forward to `make_assemble`.
struct MakeState {
    requested_payments: RequestedPayments,
    requested_asset_info: AssetInfo,
}

/// One parked build: its shared spend context, its phase-specific intermediate, and when it was
/// created (for TTL sweeping).
struct PendingOffer {
    ctx: SpendContext,
    kind: PendingKind,
    created_at: Instant,
}

/// The make intermediate handed back to the builder to finish a make.
pub(crate) struct MakeIntermediate {
    pub ctx: SpendContext,
    pub requested_payments: RequestedPayments,
    pub requested_asset_info: AssetInfo,
}

/// The take intermediate handed back to the builder to finish a take.
///
/// Unlike a make, finalizing a take ([`dig_offers::take_combine`]) needs only the parsed offer, not
/// the shared context — so the parked [`SpendContext`] is simply dropped when the entry is removed.
pub(crate) struct TakeIntermediate {
    pub offer: Offer,
}

/// A thread-safe map of in-progress offer builds, keyed by an opaque [`OfferBuildId`].
///
/// Cheap to hold behind the offer builder. The map stores only unsigned construction state; a
/// second call removes and consumes its entry (a build is single-use).
#[derive(Default)]
pub struct PendingOffers {
    entries: Mutex<HashMap<OfferBuildId, PendingOffer>>,
    counter: AtomicU64,
}

impl PendingOffers {
    /// An empty pending map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Park a make awaiting assembly, returning its handle.
    pub(crate) fn insert_make(
        &self,
        ctx: SpendContext,
        requested_payments: RequestedPayments,
        requested_asset_info: AssetInfo,
    ) -> OfferBuildId {
        self.insert(
            ctx,
            PendingKind::Make(Box::new(MakeState {
                requested_payments,
                requested_asset_info,
            })),
        )
    }

    /// Park a take awaiting finalization, returning its handle.
    pub(crate) fn insert_take(&self, ctx: SpendContext, offer: Offer) -> OfferBuildId {
        self.insert(
            ctx,
            PendingKind::Take {
                offer: Box::new(offer),
            },
        )
    }

    /// Remove + return a parked make. `None` if the id is unknown, expired, or is a take.
    pub(crate) fn take_make(&self, id: &OfferBuildId) -> Option<MakeIntermediate> {
        match self.remove(id)? {
            PendingOffer {
                ctx,
                kind: PendingKind::Make(make),
                ..
            } => Some(MakeIntermediate {
                ctx,
                requested_payments: make.requested_payments,
                requested_asset_info: make.requested_asset_info,
            }),
            _ => None,
        }
    }

    /// Remove + return a parked take. `None` if the id is unknown, expired, or is a make.
    pub(crate) fn take_take(&self, id: &OfferBuildId) -> Option<TakeIntermediate> {
        match self.remove(id)? {
            PendingOffer {
                kind: PendingKind::Take { offer },
                ..
            } => Some(TakeIntermediate { offer: *offer }),
            _ => None,
        }
    }

    /// The number of currently-parked builds (after sweeping) — for tests + diagnostics.
    pub fn len(&self) -> usize {
        let mut entries = self.entries.lock().expect("pending-offer mutex poisoned");
        sweep_expired(&mut entries);
        entries.len()
    }

    /// Whether no builds are parked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert an entry under a freshly-minted opaque id, sweeping expired entries first.
    fn insert(&self, ctx: SpendContext, kind: PendingKind) -> OfferBuildId {
        let id = OfferBuildId(format!(
            "offer-build-{}",
            self.counter.fetch_add(1, Ordering::Relaxed)
        ));
        let mut entries = self.entries.lock().expect("pending-offer mutex poisoned");
        sweep_expired(&mut entries);
        entries.insert(
            id.clone(),
            PendingOffer {
                ctx,
                kind,
                created_at: Instant::now(),
            },
        );
        id
    }

    /// Remove an entry by id, sweeping expired entries first (so an expired target returns `None`).
    fn remove(&self, id: &OfferBuildId) -> Option<PendingOffer> {
        let mut entries = self.entries.lock().expect("pending-offer mutex poisoned");
        sweep_expired(&mut entries);
        entries.remove(id)
    }
}

/// Drop every parked build older than [`PENDING_TTL`] — abandoned-build reclamation.
fn sweep_expired(entries: &mut HashMap<OfferBuildId, PendingOffer>) {
    let now = Instant::now();
    entries.retain(|_, offer| now.duration_since(offer.created_at) < PENDING_TTL);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_make_can_be_parked_and_reclaimed_once() {
        let pending = PendingOffers::new();
        let id = pending.insert_make(
            SpendContext::new(),
            RequestedPayments::new(),
            AssetInfo::new(),
        );
        assert_eq!(pending.len(), 1);
        assert!(pending.take_make(&id).is_some(), "first take succeeds");
        assert!(pending.take_make(&id).is_none(), "a build is single-use");
        assert!(pending.is_empty());
    }

    #[test]
    fn a_make_id_cannot_be_finalized_as_a_take() {
        let pending = PendingOffers::new();
        let id = pending.insert_make(
            SpendContext::new(),
            RequestedPayments::new(),
            AssetInfo::new(),
        );
        assert!(
            pending.take_take(&id).is_none(),
            "wrong-kind id is rejected"
        );
        // The mismatched call consumed nothing recoverable — the entry is removed either way.
        assert!(pending.take_make(&id).is_none());
    }

    #[test]
    fn an_unknown_id_is_none() {
        let pending = PendingOffers::new();
        assert!(pending.take_make(&OfferBuildId("nope".into())).is_none());
    }

    #[test]
    fn expired_builds_are_swept() {
        let pending = PendingOffers::new();
        let id = pending.insert_make(
            SpendContext::new(),
            RequestedPayments::new(),
            AssetInfo::new(),
        );
        // Force-age the entry past the TTL, then confirm access reclaims it.
        {
            let mut entries = pending.entries.lock().unwrap();
            let offer = entries.get_mut(&id).unwrap();
            offer.created_at = Instant::now() - (PENDING_TTL + Duration::from_secs(1));
        }
        assert!(pending.take_make(&id).is_none(), "expired build is gone");
        assert!(pending.is_empty());
    }
}
