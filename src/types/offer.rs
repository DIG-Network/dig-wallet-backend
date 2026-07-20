//! Offer request/response types — the wire contract for the offers surface (SPEC §3d, #1122).
//!
//! These are the serde objects that cross the seam IPC boundary for making, taking, cancelling,
//! combining, and summarizing Chia offers. Pure data (public material only) — like every other
//! `types` object they carry NO secret key, and, critically, NO chia-wallet-sdk allocator type
//! (`Offer`/`RequestedPayments`/`AssetInfo`/`SpendContext`) ever appears here.
//!
//! # Why an opaque build id crosses the seam, not an SDK object
//! Making and taking are TWO calls with a client-side signature in between, and the intermediate
//! state each phase carries forward (a live `SpendContext` plus the requested-payment metadata for
//! a make, or the parsed `Offer` for a take) is a non-serializable SDK allocator object. Rather
//! than serialize it, the engine holds it in a private pending map (`engine::offer_state`) keyed by
//! an opaque [`OfferBuildId`]; only the id — a plain string — crosses the wire. The first call
//! returns a [`PendingOfferBuild`] (the id + the unsigned spend to sign); the second call passes
//! the id back with the signed bundle to finish the operation engine-side.

use serde::{Deserialize, Serialize};

use super::identity::IdentityRef;
use super::spend::{SignedBundle, UnsignedSpend};
use super::value::Address;
use super::{Amount, AssetId};

/// An opaque, engine-generated handle to an in-progress offer build.
///
/// Returned by the first call of a two-call flow ([`MakeOfferRequest`]/[`TakeOfferRequest`]) and
/// passed back to the second ([`AssembleOfferRequest`]/[`FinalizeTakeRequest`]). It names an entry
/// in the engine's private pending-offer map; the client treats it as an opaque token.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OfferBuildId(pub String);

/// The fungible assets an offer OFFERS (what leaves the maker's wallet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferedAssets {
    /// Native XCH offered, in mojos. Zero = no XCH leg.
    pub xch: Amount,
    /// CAT legs offered: `(asset id, amount)` pairs.
    pub cats: Vec<(AssetId, Amount)>,
}

/// The fungible assets an offer REQUESTS (what the taker must pay to the maker), plus where the
/// maker is paid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedAssets {
    /// Native XCH requested, in mojos. Zero = no XCH leg.
    pub xch: Amount,
    /// CAT legs requested: `(asset id, amount)` pairs.
    pub cats: Vec<(AssetId, Amount)>,
    /// Where the requested assets are paid to (the maker's receive address).
    pub payee: Address,
}

/// Call 1 of a make: build the maker's unsigned side of a new offer.
///
/// Returns a [`PendingOfferBuild`] — an [`OfferBuildId`] and the [`UnsignedSpend`] the maker signs.
/// The signed bundle is then handed back via [`AssembleOfferRequest`] to produce the `offer1…`
/// string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakeOfferRequest {
    /// The maker identity (public material).
    pub identity: IdentityRef,
    /// What the offer gives up.
    pub offered: OfferedAssets,
    /// What the offer asks for, and where it is paid.
    pub requested: RequestedAssets,
    /// The network fee the maker pays, in mojos.
    pub fee: Amount,
}

/// Call 2 of a make: assemble a signed maker bundle into a broadcastable-by-a-taker `offer1…`
/// string. Runs entirely engine-side (no key), using the pending state named by `build_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssembleOfferRequest {
    /// The handle returned by the matching [`MakeOfferRequest`].
    pub build_id: OfferBuildId,
    /// The maker's signed spend bundle (the [`UnsignedSpend`] from call 1, signed client-side).
    pub signed: SignedBundle,
}

/// Call 1 of a take: build the taker's unsigned side of accepting an existing offer.
///
/// Returns a [`PendingOfferBuild`]; the taker signs the [`UnsignedSpend`] and hands the signature
/// back via [`FinalizeTakeRequest`] to produce the atomic settlement bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakeOfferRequest {
    /// The taker identity (public material).
    pub identity: IdentityRef,
    /// The `offer1…` string being accepted.
    pub offer: String,
    /// The network fee the taker pays, in mojos.
    pub fee: Amount,
}

/// Call 2 of a take: combine the maker's offer with the taker's signed spends into the atomic
/// settlement [`SignedBundle`]. The result is broadcastable but is NEVER auto-pushed — the caller
/// broadcasts it explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeTakeRequest {
    /// The handle returned by the matching [`TakeOfferRequest`].
    pub build_id: OfferBuildId,
    /// The taker's signed spend bundle (the [`UnsignedSpend`] from call 1, signed client-side).
    pub signed: SignedBundle,
}

/// A single-call request to build the maker's reclaim spend for an outstanding offer.
///
/// Returns an [`UnsignedSpend`] the maker signs + broadcasts through the ordinary spend path
/// (same shape as a send) to invalidate the offer and reclaim the offered coins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelOfferRequest {
    /// The maker identity (public material) — must control the offered coins.
    pub identity: IdentityRef,
    /// The `offer1…` string to cancel.
    pub offer: String,
    /// The network fee the maker pays to cancel, in mojos.
    pub fee: Amount,
}

/// A pure request to combine several one-sided offers into one bundled offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CombineOffersRequest {
    /// The `offer1…` strings to merge (at least two).
    pub offers: Vec<String>,
}

/// A pure request to inspect an offer without building anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummarizeOfferRequest {
    /// The `offer1…` string to summarize.
    pub offer: String,
}

/// The result of a two-call flow's FIRST call: the handle + the unsigned spend to sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOfferBuild {
    /// The handle to pass to the matching second call.
    pub build_id: OfferBuildId,
    /// The unsigned spend the client must sign.
    pub unsigned: UnsignedSpend,
}

/// A finished offer string (`offer1…`, the canonical bech32-ish offer encoding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferString {
    /// The encoded offer.
    pub offer: String,
}

/// One asset line in an [`OfferSummary`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SummaryAsset {
    /// A native-XCH amount, in mojos.
    Xch {
        /// The XCH amount.
        amount: Amount,
    },
    /// A CAT amount of a given asset id.
    Cat {
        /// The CAT asset id (TAIL hash, hex).
        asset_id: AssetId,
        /// The CAT amount.
        amount: Amount,
    },
    /// An NFT, by launcher id.
    Nft {
        /// The NFT launcher id (hex).
        launcher_id: String,
    },
}

/// A decoded, human- and machine-readable view of an offer's two sides plus its economics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferSummary {
    /// What the offer gives up.
    pub offered: Vec<SummaryAsset>,
    /// What the offer asks for.
    pub requested: Vec<SummaryAsset>,
    /// The net cost a taker funds to accept (the arbitrage).
    pub arbitrage: Vec<SummaryAsset>,
    /// Royalty legs: `(launcher id hex, basis points)`.
    pub royalties: Vec<(String, u16)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WalletId;

    fn make_request() -> MakeOfferRequest {
        MakeOfferRequest {
            identity: IdentityRef::new(WalletId(1)),
            offered: OfferedAssets {
                xch: Amount(0),
                cats: vec![(AssetId("dbx".into()), Amount(1_000))],
            },
            requested: RequestedAssets {
                xch: Amount(50_000),
                cats: vec![],
                payee: Address("xch1payee".into()),
            },
            fee: Amount(0),
        }
    }

    #[test]
    fn make_offer_request_round_trips() {
        let req = make_request();
        let json = serde_json::to_string(&req).unwrap();
        let back: MakeOfferRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn take_and_finalize_round_trip() {
        let take = TakeOfferRequest {
            identity: IdentityRef::new(WalletId(2)),
            offer: "offer1abc".into(),
            fee: Amount(10),
        };
        let json = serde_json::to_string(&take).unwrap();
        assert_eq!(take, serde_json::from_str(&json).unwrap());

        let finalize = FinalizeTakeRequest {
            build_id: OfferBuildId("build-7".into()),
            signed: SignedBundle {
                bundle: chia::protocol::SpendBundle::new(vec![], chia::bls::Signature::default()),
            },
        };
        let json = serde_json::to_string(&finalize).unwrap();
        assert_eq!(finalize, serde_json::from_str(&json).unwrap());
    }

    #[test]
    fn summary_asset_is_tagged() {
        let summary = OfferSummary {
            offered: vec![SummaryAsset::Cat {
                asset_id: AssetId("dbx".into()),
                amount: Amount(1_000),
            }],
            requested: vec![SummaryAsset::Xch {
                amount: Amount(50_000),
            }],
            arbitrage: vec![],
            royalties: vec![("launcher".into(), 300)],
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"kind\":\"cat\""), "tagged enum: {json}");
        let back: OfferSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn pending_offer_build_round_trips() {
        let pending = PendingOfferBuild {
            build_id: OfferBuildId("b1".into()),
            unsigned: UnsignedSpend {
                coin_spends: vec![],
                required_signatures: vec![],
                summary: crate::types::TransactionSummary {
                    outputs: vec![],
                    fee: Amount(0),
                },
            },
        };
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(pending, serde_json::from_str(&json).unwrap());
    }
}
