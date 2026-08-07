//! `engine::build_offer` — unsigned Chia-offer construction (SPEC §3d, #1122).
//!
//! The offers surface — make, take, cancel, combine, summarize — built the DIG way: the engine
//! constructs UNSIGNED spends through the canonical [`dig-offers`](https://crates.io/crates/dig-offers)
//! expert crate and returns them for client review + signing. It NEVER signs and NEVER hand-rolls
//! offer/settlement CLVM (§4.1) — the make-must-not-settle (no-self-fund) rule and take's
//! settlement-announcement assertions live INSIDE dig-offers and are preserved by composing it.
//!
//! # The engine-side stateful two-call flow (make + take)
//! Making and taking each split into build → (client signs) → assemble/finalize, and the two
//! phases MUST share ONE [`SpendContext`]. Because that context (and the requested-payment metadata
//! / parsed offer it carries) is a non-serializable SDK allocator object, it never crosses the
//! seam: [`dig_offers::make_assemble`] and [`dig_offers::take_combine`] use NO secret key — they
//! transform an ALREADY-SIGNED bundle plus public data — so assembly runs entirely engine-side. The
//! intermediate is parked in [`super::offer_state::PendingOffers`] between the two calls, keyed by
//! an opaque [`OfferBuildId`]; only that id and the [`UnsignedSpend`] cross the wire.
//!
//! # Scope
//! XCH↔CAT offers. NFT offer legs are deferred (they need spendable-NFT resolution through the
//! input provider); `$DIG` is a CAT, so the CAT legs cover the #1122 value flow.

use std::sync::Arc;

use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin};
use chia_wallet_sdk::driver::Cat;
use chia_wallet_sdk::utils::Address as Bech32Address;
use indexmap::IndexMap;

use dig_offers::{
    cancel_build, combine as combine_offers, decode as decode_offer_bundle, make_assemble,
    make_build, offer_id as offer_id_of, summarize as summarize_offer, take_build, take_combine,
    OfferAsset, OfferCost, OfferedSide, RequestedSide, SpendContext, TakerFunds,
};

use crate::types::{
    Address, AssembleOfferRequest, AssetId, CancelOfferRequest, CombineOffersRequest,
    FinalizeTakeRequest, IdentityRef, MakeOfferRequest, Network, OfferString, OfferSummary,
    OfferedAssets, PendingOfferBuild, RequestedAssets, SignedBundle, SpendOutput,
    SummarizeOfferRequest, SummaryAsset, TakeOfferRequest, TransactionSummary, UnsignedSpend,
    WalletError, WalletErrorCode, WalletResult,
};

use super::build::{
    ensure_signed_offline, select_or_fail, spend_failed, SdkSpendBuilder, SpendInputs,
};
use super::offer_state::{MakeIntermediate, PendingOffers, TakeIntermediate};

/// Builds unsigned offer spends and assembles signed ones — the engine-side offers surface.
///
/// Wraps an [`SdkSpendBuilder`] (reusing its key-free required-signature extraction and network
/// aggregate-signature domain) and owns the [`PendingOffers`] map the two-call flows park state in.
pub struct OfferBuilder {
    builder: SdkSpendBuilder,
    pending: PendingOffers,
}

impl OfferBuilder {
    /// Create an offer builder over a public [`SpendInputs`] provider, for `network`, bounding any
    /// XCH fee/fund selection at `coin_cap`.
    pub fn new(inputs: Arc<dyn SpendInputs>, network: Network, coin_cap: usize) -> Self {
        Self {
            builder: SdkSpendBuilder::new(inputs, network, coin_cap),
            pending: PendingOffers::new(),
        }
    }

    /// The parked-build map, exposed for diagnostics + tests.
    pub fn pending(&self) -> &PendingOffers {
        &self.pending
    }

    /// The input provider the builder reads public coin/key material from.
    fn inputs(&self) -> &Arc<dyn SpendInputs> {
        &self.builder.inputs
    }

    // --- make: build → (client signs) → assemble ------------------------------------------------

    /// Call 1 of a make: build the maker's unsigned side of a new offer and park it for assembly.
    ///
    /// The requested side is an assertion, never a settle action (dig-offers' no-self-fund rule),
    /// so the maker only ever spends the OFFERED assets here — never funding both sides.
    pub fn build_make(&self, request: MakeOfferRequest) -> WalletResult<PendingOfferBuild> {
        let MakeOfferRequest {
            identity,
            offered,
            requested,
            fee,
        } = request;
        let fee = fee.mojos();

        let offered_side = self.resolve_offered_side(&identity, &offered, fee)?;
        let requested_side = resolve_requested_side(&requested)?;

        let mut ctx = SpendContext::new();
        let unsigned_make =
            make_build(&mut ctx, offered_side, requested_side, fee).map_err(map_offer_error)?;

        let unsigned = self.finish_unsigned(
            unsigned_make.coin_spends.clone(),
            make_summary(&offered, &requested, fee),
        )?;
        let build_id = self.pending.insert_make(
            ctx,
            unsigned_make.requested_payments,
            unsigned_make.requested_asset_info,
        );
        Ok(PendingOfferBuild { build_id, unsigned })
    }

    /// Call 2 of a make: assemble the maker's signed bundle into an `offer1…` string, entirely
    /// engine-side (no key), consuming the parked build named by `build_id`.
    pub fn assemble_make(&self, request: AssembleOfferRequest) -> WalletResult<OfferString> {
        let AssembleOfferRequest { build_id, signed } = request;
        let MakeIntermediate {
            mut ctx,
            requested_payments,
            requested_asset_info,
        } = self
            .pending
            .take_make(&build_id)
            .ok_or_else(unknown_build)?;

        let offer = make_assemble(
            &mut ctx,
            signed.bundle,
            requested_payments,
            requested_asset_info,
        )
        .map_err(map_offer_error)?;
        finish_offer_string(offer)
    }

    // --- take: build → (client signs) → finalize ------------------------------------------------

    /// Call 1 of a take: build the taker's unsigned side of accepting `offer`, and park the parsed
    /// offer for finalization.
    pub fn build_take(&self, request: TakeOfferRequest) -> WalletResult<PendingOfferBuild> {
        let TakeOfferRequest {
            identity,
            offer,
            fee,
        } = request;
        let fee = fee.mojos();

        // The taker funds the arbitrage (what the offer requests). Size fund selection from it.
        let cost = summarize_offer(&offer).map_err(map_offer_error)?.arbitrage;
        let funds = self.resolve_taker_funds(&identity, &cost, fee)?;

        let mut ctx = SpendContext::new();
        let unsigned_take = take_build(&mut ctx, &offer, funds, fee).map_err(map_offer_error)?;

        let summary = taker_summary(&unsigned_take.offer, fee)?;
        let unsigned = self.finish_unsigned(unsigned_take.coin_spends.clone(), summary)?;
        let build_id = self.pending.insert_take(ctx, unsigned_take.offer);
        Ok(PendingOfferBuild { build_id, unsigned })
    }

    /// Call 2 of a take: combine the maker's offer with the taker's signed spends into the atomic
    /// settlement bundle. Broadcastable, but NEVER auto-pushed — the caller broadcasts it.
    pub fn finalize_take(&self, request: FinalizeTakeRequest) -> WalletResult<SignedBundle> {
        let FinalizeTakeRequest { build_id, signed } = request;
        let TakeIntermediate { offer } = self
            .pending
            .take_take(&build_id)
            .ok_or_else(unknown_build)?;
        let bundle = take_combine(offer, signed.bundle);
        Ok(SignedBundle { bundle })
    }

    // --- cancel (single build call) -------------------------------------------------------------

    /// Build the maker's unsigned reclaim spend for an outstanding offer. The result is signed +
    /// broadcast through the ordinary spend path (same shape as a send).
    pub fn build_cancel(&self, request: CancelOfferRequest) -> WalletResult<UnsignedSpend> {
        let CancelOfferRequest {
            identity,
            offer,
            fee,
        } = request;
        let fee = fee.mojos();

        let reclaim_puzzle_hash = self.inputs().change_puzzle_hash(&identity)?;
        let owner_keys = self.owner_keys_for_offer(&offer)?;

        let mut ctx = SpendContext::new();
        let unsigned_cancel = cancel_build(&mut ctx, &offer, reclaim_puzzle_hash, &owner_keys, fee)
            .map_err(map_offer_error)?;

        // A cancel reclaims the offered coins to the maker (no external recipient); the review
        // summary carries only the fee.
        self.finish_unsigned(
            unsigned_cancel.coin_spends,
            TransactionSummary {
                outputs: vec![],
                received: vec![],
                fee: crate::types::Amount(fee),
            },
        )
    }

    // --- pure operations ------------------------------------------------------------------------

    /// Combine several one-sided offers into one bundled offer (pure; no wallet state).
    pub fn combine(&self, request: CombineOffersRequest) -> WalletResult<OfferString> {
        let CombineOffersRequest { offers } = request;
        let refs: Vec<&str> = offers.iter().map(String::as_str).collect();
        let offer = combine_offers(&refs).map_err(map_offer_error)?;
        finish_offer_string(offer)
    }

    /// Summarize an offer's two sides + economics (pure; no wallet state).
    pub fn summarize(&self, request: SummarizeOfferRequest) -> WalletResult<OfferSummary> {
        let SummarizeOfferRequest { offer } = request;
        let summary = summarize_offer(&offer).map_err(map_offer_error)?;
        Ok(OfferSummary {
            offer_id: compute_offer_id(&offer)?,
            offered: summary.offered.iter().map(map_offer_asset).collect(),
            requested: summary.requested.iter().map(map_offer_asset).collect(),
            arbitrage: cost_to_assets(&summary.arbitrage),
            royalties: summary
                .royalties
                .iter()
                .map(|(launcher_id, basis_points)| (hex::encode(launcher_id), *basis_points))
                .collect(),
        })
    }

    // --- shared helpers -------------------------------------------------------------------------

    /// Wrap built coin spends into a reviewable [`UnsignedSpend`]: extract the required signatures
    /// through the SAME key-free extractor every other builder uses, and assert it is a real
    /// signed-offline spend before it can leave the engine.
    fn finish_unsigned(
        &self,
        coin_spends: Vec<chia_protocol::CoinSpend>,
        summary: TransactionSummary,
    ) -> WalletResult<UnsignedSpend> {
        let required_signatures = self.builder.required_signatures(&coin_spends)?;
        ensure_signed_offline(&coin_spends, &required_signatures)?;
        Ok(UnsignedSpend {
            coin_spends,
            required_signatures,
            summary,
        })
    }

    /// Resolve the maker's OFFERED side: the spendable XCH (when XCH is offered or a fee is paid)
    /// and CAT coins of each offered asset, the keys authorizing them, the offered amounts, and the
    /// change address. dig-offers selects the exact coins it needs from these.
    fn resolve_offered_side<'a>(
        &self,
        identity: &IdentityRef,
        offered: &OfferedAssets,
        fee: u64,
    ) -> WalletResult<OfferedSide<'a>> {
        let offer_xch = offered.xch.mojos();
        if offer_xch == 0 && offered.cats.is_empty() {
            return Err(WalletError::invalid_input(
                "an offer must offer at least one asset",
            ));
        }

        let xch_coins = if offer_xch > 0 || fee > 0 {
            self.inputs().spendable_xch(identity)?
        } else {
            Vec::new()
        };

        let mut cat_coins: Vec<Cat> = Vec::new();
        let mut offer_cats: Vec<(Bytes32, u64)> = Vec::new();
        for (asset_id, amount) in &offered.cats {
            let amount = amount.mojos();
            if amount == 0 {
                return Err(WalletError::invalid_input(
                    "an offered CAT amount must be non-zero",
                ));
            }
            let asset = parse_asset_id(asset_id)?;
            cat_coins.extend(self.inputs().spendable_cat(identity, asset_id)?);
            offer_cats.push((asset, amount));
        }

        let owner_keys = self.owner_keys_for(&xch_coins, &cat_coins)?;
        Ok(OfferedSide {
            change_puzzle_hash: self.inputs().change_puzzle_hash(identity)?,
            owner_keys,
            xch_coins,
            cat_coins,
            nfts: Vec::new(),
            offer_xch,
            offer_cats,
            _pd: std::marker::PhantomData,
        })
    }

    /// Resolve the taker's FUNDING side: XCH covering the requested XCH + fee, and CAT coins
    /// covering each requested CAT leg, with the keys authorizing them.
    fn resolve_taker_funds<'a>(
        &self,
        identity: &IdentityRef,
        cost: &OfferCost,
        fee: u64,
    ) -> WalletResult<TakerFunds<'a>> {
        // Taker fund selection shares engine::selection::select_for_spend (via select_or_fail) with
        // ordinary XCH/CAT sends, so an over-cap taker selection reports NeedsConsolidation exactly
        // as a send does — no bespoke greedy path that would diverge from that contract.
        let cap = self.builder.coin_cap;

        let xch_target = cost.xch.saturating_add(fee);
        let xch_coins = if xch_target > 0 {
            select_or_fail(
                &self.inputs().spendable_xch(identity)?,
                xch_target,
                cap,
                "XCH (take)",
            )?
        } else {
            Vec::new()
        };

        let mut cat_coins: Vec<Cat> = Vec::new();
        for (asset, need) in &cost.cats {
            let asset_id = AssetId(hex::encode(asset));
            let available = self.inputs().spendable_cat(identity, &asset_id)?;
            cat_coins.extend(select_cats(&available, *asset, *need, cap)?);
        }

        let owner_keys = self.owner_keys_for(&xch_coins, &cat_coins)?;
        Ok(TakerFunds {
            change_puzzle_hash: self.inputs().change_puzzle_hash(identity)?,
            owner_keys,
            xch_coins,
            cat_coins,
            nfts: Vec::new(),
            _pd: std::marker::PhantomData,
        })
    }

    /// Build the `owner_keys` map dig-offers authorizes coins with: each XCH coin's puzzle hash and
    /// each CAT coin's inner (p2) puzzle hash → the synthetic public key the wallet holds for it.
    /// Fail-closed when the wallet holds no key for a coin it is asked to spend.
    fn owner_keys_for(
        &self,
        xch_coins: &[Coin],
        cat_coins: &[Cat],
    ) -> WalletResult<IndexMap<Bytes32, PublicKey>> {
        let mut owner_keys = IndexMap::new();
        for coin in xch_coins {
            self.insert_key(&mut owner_keys, coin.puzzle_hash)?;
        }
        for cat in cat_coins {
            self.insert_key(&mut owner_keys, cat.info.p2_puzzle_hash)?;
        }
        Ok(owner_keys)
    }

    /// Build the `owner_keys` map for the offered coins committed inside an existing offer, by
    /// decoding the offer bundle and resolving a key for each coin's puzzle hash the wallet holds.
    ///
    /// Used by cancel: the offered coins are no longer "spendable" state (they are committed to the
    /// offer), but the wallet still holds the synthetic key for their standard-layer puzzle hash.
    ///
    /// Fail-closed on an UNOWNED offer: if the wallet holds NO key for ANY of the offer's committed
    /// coins, it cannot be the offer's maker, so cancel is refused with a clear error rather than
    /// silently returning an empty key map (which would yield a non-signable, un-broadcastable
    /// unsigned spend — a footgun the caller can't distinguish from a real cancel).
    fn owner_keys_for_offer(&self, offer: &str) -> WalletResult<IndexMap<Bytes32, PublicKey>> {
        let bundle = decode_offer_bundle(offer).map_err(map_offer_error)?;
        let mut owner_keys = IndexMap::new();
        for coin_spend in &bundle.coin_spends {
            let puzzle_hash = coin_spend.coin.puzzle_hash;
            if let Some(key) = self.inputs().synthetic_key(puzzle_hash) {
                owner_keys.insert(puzzle_hash, key);
            }
        }
        if owner_keys.is_empty() {
            return Err(spend_failed(
                "cannot cancel this offer: the wallet holds no standard-layer key for any of its \
                 offered coins (not the offer's maker, or a CAT/NFT offer whose coins must be \
                 reclaimed through their native layer)",
            ));
        }
        Ok(owner_keys)
    }

    /// Insert the wallet's key for `puzzle_hash` into `owner_keys`, or fail closed if absent.
    fn insert_key(
        &self,
        owner_keys: &mut IndexMap<Bytes32, PublicKey>,
        puzzle_hash: Bytes32,
    ) -> WalletResult<()> {
        if owner_keys.contains_key(&puzzle_hash) {
            return Ok(());
        }
        let key = self
            .inputs()
            .synthetic_key(puzzle_hash)
            .ok_or_else(|| spend_failed("no public key for an offered coin's puzzle hash"))?;
        owner_keys.insert(puzzle_hash, key);
        Ok(())
    }
}

/// Wrap a finished `offer1…` string with its stable ecosystem id for the wire response.
fn finish_offer_string(offer: String) -> WalletResult<OfferString> {
    let offer_id = compute_offer_id(&offer)?;
    Ok(OfferString { offer, offer_id })
}

/// The offer's stable, ecosystem-wide id (`sha256` of the uncompressed bundle) as lowercase hex.
fn compute_offer_id(offer: &str) -> WalletResult<String> {
    offer_id_of(offer).map(hex::encode).map_err(map_offer_error)
}

/// Resolve the requested side (what the taker pays) from its wire form.
fn resolve_requested_side(requested: &RequestedAssets) -> WalletResult<RequestedSide> {
    let xch = requested.xch.mojos();
    let mut cats: Vec<(Bytes32, u64)> = Vec::new();
    for (asset_id, amount) in &requested.cats {
        let amount = amount.mojos();
        if amount == 0 {
            return Err(WalletError::invalid_input(
                "a requested CAT amount must be non-zero",
            ));
        }
        cats.push((parse_asset_id(asset_id)?, amount));
    }
    if xch == 0 && cats.is_empty() {
        return Err(WalletError::invalid_input(
            "an offer must request at least one asset",
        ));
    }
    Ok(RequestedSide {
        payee_puzzle_hash: decode_address(&requested.payee)?,
        xch,
        cats,
        nfts: Vec::new(),
    })
}

/// The review summary for a make: the OFFERED assets that LEAVE the maker's wallet (committed to the
/// settlement puzzle, an empty-address sink), plus the fee, plus — DISTINCTLY — the REQUESTED assets
/// the maker RECEIVES in return, so the confirm shows the trade both ways (#2241).
///
/// The offered legs carry an empty address (their destination is the fixed settlement puzzle, not a
/// chosen recipient — #1511 PR-B) and are gated by the signer against the coin spends. The received
/// legs carry the maker's own receive address (the offer's `payee`) and are surfaced INFORMATIONALLY
/// in [`TransactionSummary::received`]: they are not re-derivable from the coin spends (a make binds
/// the requested payment as a non-invertible settlement-announcement hash) and so are NOT part of the
/// signer's egress gate. Their FULFILLMENT is consensus-enforced by the offer mechanism itself — the
/// maker's offered coins are unspendable unless a settlement coin announces exactly this requested
/// payment — so the received legs are a faithful "you will receive" hint, and the maker still
/// independently verifies + consents to the offered legs (what actually leaves) via the signer.
fn make_summary(
    offered: &OfferedAssets,
    requested: &RequestedAssets,
    fee: u64,
) -> TransactionSummary {
    let mut outputs = Vec::new();
    if offered.xch.mojos() > 0 {
        outputs.push(SpendOutput {
            address: Address(String::new()),
            amount: offered.xch,
            asset_id: None,
        });
    }
    for (asset_id, amount) in &offered.cats {
        outputs.push(SpendOutput {
            address: Address(String::new()),
            amount: *amount,
            asset_id: Some(asset_id.clone()),
        });
    }

    // The requested payments the maker receives, each to the maker's own receive address (`payee`).
    let mut received = Vec::new();
    if requested.xch.mojos() > 0 {
        received.push(SpendOutput {
            address: requested.payee.clone(),
            amount: requested.xch,
            asset_id: None,
        });
    }
    for (asset_id, amount) in &requested.cats {
        received.push(SpendOutput {
            address: requested.payee.clone(),
            amount: *amount,
            asset_id: Some(asset_id.clone()),
        });
    }

    TransactionSummary {
        outputs,
        received,
        fee: crate::types::Amount(fee),
    }
}

/// The review summary for a take: the requested payments the taker PAYS, each to its REAL payee
/// address, plus the fee.
///
/// Unlike the offered side of a make — where the maker's assets are committed to the settlement
/// puzzle (an empty-address `protocol_sink`) — a take funds the maker's requested payments as ordinary
/// coins created DIRECTLY to the payee puzzle hashes the offer specifies. The taker must review WHO is
/// paid, so the recipients carry their real `xch1…` addresses; the client signer independently
/// re-derives the same recipients from the coin spends and gates on this summary (#1511 PR-B). The
/// assets the taker RECEIVES return to its own change address and are not listed (they do not leave
/// the wallet).
fn taker_summary(
    offer: &chia_wallet_sdk::driver::Offer,
    fee: u64,
) -> WalletResult<TransactionSummary> {
    let payments = offer.requested_payments();
    let mut outputs = Vec::new();
    for notarized in &payments.xch {
        for payment in &notarized.payments {
            outputs.push(requested_payment_output(
                payment.puzzle_hash,
                payment.amount,
                None,
            )?);
        }
    }
    for (asset_id, notarized_payments) in &payments.cats {
        for notarized in notarized_payments {
            for payment in &notarized.payments {
                outputs.push(requested_payment_output(
                    payment.puzzle_hash,
                    payment.amount,
                    Some(*asset_id),
                )?);
            }
        }
    }
    Ok(TransactionSummary {
        outputs,
        // A take's received leg (the maker's offered assets returning to the taker's change address)
        // is out of scope for #2241, which surfaces only the MAKE's received leg.
        received: vec![],
        fee: crate::types::Amount(fee),
    })
}

/// One requested-payment recipient, its payee puzzle hash rendered as an `xch1…` address (the same
/// display form the client verifier re-derives, so the signer's summary gate compares byte-for-byte).
fn requested_payment_output(
    payee: Bytes32,
    amount: u64,
    asset_id: Option<Bytes32>,
) -> WalletResult<SpendOutput> {
    Ok(SpendOutput {
        address: Address(
            Bech32Address::new(payee, "xch".into())
                .encode()
                .map_err(|e| spend_failed(format!("cannot encode payee address: {e:?}")))?,
        ),
        amount: crate::types::Amount(amount),
        asset_id: asset_id.map(|asset| AssetId(hex::encode(asset))),
    })
}

/// Translate a dig-offers [`OfferAsset`] into the wire [`SummaryAsset`].
fn map_offer_asset(asset: &OfferAsset) -> SummaryAsset {
    match asset {
        OfferAsset::Xch(amount) => SummaryAsset::Xch {
            amount: crate::types::Amount(*amount),
        },
        OfferAsset::Cat { asset_id, amount } => SummaryAsset::Cat {
            asset_id: AssetId(hex::encode(asset_id)),
            amount: crate::types::Amount(*amount),
        },
        OfferAsset::Nft { launcher_id } => SummaryAsset::Nft {
            launcher_id: hex::encode(launcher_id),
        },
    }
}

/// Translate a dig-offers [`OfferCost`] (arbitrage) into wire [`SummaryAsset`]s.
fn cost_to_assets(cost: &OfferCost) -> Vec<SummaryAsset> {
    let mut assets = Vec::new();
    if cost.xch > 0 {
        assets.push(SummaryAsset::Xch {
            amount: crate::types::Amount(cost.xch),
        });
    }
    for (asset, amount) in &cost.cats {
        assets.push(SummaryAsset::Cat {
            asset_id: AssetId(hex::encode(asset)),
            amount: crate::types::Amount(*amount),
        });
    }
    assets
}

/// Select CAT coins of `asset` covering `need`, sharing the capped high-value-first selection
/// (and its NeedsConsolidation/InsufficientFunds distinction) that XCH/CAT sends use.
///
/// The shared [`select_or_fail`] operates on plain [`Coin`]s, so selection runs over the CATs'
/// underlying coins; the chosen coin ids are then mapped back to their [`Cat`]s (with lineage
/// proofs) for dig-offers to spend.
fn select_cats(coins: &[Cat], asset: Bytes32, need: u64, cap: usize) -> WalletResult<Vec<Cat>> {
    let of_asset: Vec<Cat> = coins
        .iter()
        .filter(|cat| cat.info.asset_id == asset)
        .copied()
        .collect();
    let underlying: Vec<Coin> = of_asset.iter().map(|cat| cat.coin).collect();
    let selected = select_or_fail(&underlying, need, cap, &format!("CAT {asset} (take)"))?;

    let chosen_ids: std::collections::HashSet<Bytes32> =
        selected.iter().map(Coin::coin_id).collect();
    Ok(of_asset
        .into_iter()
        .filter(|cat| chosen_ids.contains(&cat.coin.coin_id()))
        .collect())
}

/// Parse a 32-byte CAT asset id (TAIL hash) from its lowercase-hex wire form.
fn parse_asset_id(asset_id: &AssetId) -> WalletResult<Bytes32> {
    let bytes = hex::decode(&asset_id.0)
        .map_err(|e| WalletError::invalid_input(format!("bad asset id {}: {e}", asset_id.0)))?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        WalletError::invalid_input(format!("asset id {} is not 32 bytes", asset_id.0))
    })?;
    Ok(Bytes32::new(array))
}

/// Decode a bech32m address to its puzzle hash, fail-closed on a malformed address.
fn decode_address(address: &Address) -> WalletResult<Bytes32> {
    Bech32Address::decode(&address.0)
        .map(|decoded| decoded.puzzle_hash)
        .map_err(|e| WalletError::invalid_input(format!("bad address {}: {e:?}", address.0)))
}

/// The error for a build-id that is unknown, expired, or of the wrong flow (make vs take).
fn unknown_build() -> WalletError {
    WalletError::new(
        WalletErrorCode::InvalidInput,
        "unknown or expired offer build id (the build may have timed out — rebuild it)",
    )
}

/// Translate a dig-offers error into the wallet-backend error catalogue.
fn map_offer_error(error: dig_offers::Error) -> WalletError {
    use dig_offers::Error;
    match error {
        Error::InvalidInput(message) => {
            let lowered = message.to_ascii_lowercase();
            if lowered.contains("insufficient") {
                WalletError::new(WalletErrorCode::InsufficientFunds, message)
            } else {
                WalletError::invalid_input(message)
            }
        }
        Error::Decode(message) => WalletError::invalid_input(format!("malformed offer: {message}")),
        Error::Incompatible(message) => WalletError::invalid_input(message),
        Error::Driver(e) => spend_failed(format!("offer driver: {e:?}")),
        Error::Signer(e) => spend_failed(format!("offer signature extraction: {e:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Amount, WalletId};
    use chia_protocol::CoinSpend;
    use chia_sdk_test::{sign_transaction, BlsPairWithCoin, Simulator};
    use chia_wallet_sdk::driver::{SpendContext as SdkCtx, StandardLayer};
    use chia_wallet_sdk::types::Conditions;

    /// A test input provider serving a fixed set of the SIMULATOR's real coins + their keys, so a
    /// built spend evaluates against coins that actually exist on the simulated chain.
    struct TestInputs {
        xch: Vec<Coin>,
        cats: Vec<Cat>,
        keys: Vec<(Bytes32, PublicKey)>,
        change: Bytes32,
    }

    impl SpendInputs for TestInputs {
        fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<Coin>> {
            Ok(self.xch.clone())
        }
        fn spendable_cat(&self, _: &IdentityRef, asset_id: &AssetId) -> WalletResult<Vec<Cat>> {
            let want = parse_asset_id(asset_id).ok();
            Ok(self
                .cats
                .iter()
                .filter(|cat| want.map_or(true, |a| cat.info.asset_id == a))
                .copied()
                .collect())
        }
        fn synthetic_key(&self, puzzle_hash: Bytes32) -> Option<PublicKey> {
            self.keys
                .iter()
                .find(|(ph, _)| *ph == puzzle_hash)
                .map(|(_, key)| *key)
        }
        fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<Bytes32> {
            Ok(self.change)
        }
    }

    fn identity() -> IdentityRef {
        IdentityRef::new(WalletId(1))
    }

    /// An offer builder over a wallet holding `xch` + `cats` at `owner`'s key, on the simulator net.
    fn builder_for(owner: &BlsPairWithCoin, xch: Vec<Coin>, cats: Vec<Cat>) -> OfferBuilder {
        OfferBuilder::new(
            Arc::new(TestInputs {
                xch,
                cats,
                keys: vec![(owner.puzzle_hash, owner.pk)],
                change: owner.puzzle_hash,
            }),
            Network::Simulator,
            500,
        )
    }

    /// Issue `amount` of a fresh CAT to `owner`, settling it on the simulator, and return the
    /// spendable [`Cat`] (with lineage proof) + its asset id. Funded by a throwaway coin so the
    /// owner's own coin stays unspent.
    fn issue_cat_to(sim: &mut Simulator, owner: &BlsPairWithCoin, amount: u64) -> (Cat, Bytes32) {
        let mut ctx = SdkCtx::new();
        let funding = sim.new_coin(owner.puzzle_hash, amount);
        let hint = ctx.hint(owner.puzzle_hash).unwrap();
        let (issue, cats) = Cat::single_issuance(
            &mut ctx,
            funding.coin_id(),
            None,
            amount,
            Conditions::new().create_coin(owner.puzzle_hash, amount, hint),
        )
        .unwrap();
        StandardLayer::new(owner.pk)
            .spend(&mut ctx, funding, issue)
            .unwrap();
        let asset_id = cats[0].info.asset_id;
        sim.spend_coins(ctx.take(), std::slice::from_ref(&owner.sk))
            .unwrap();
        (cats[0], asset_id)
    }

    /// The TEST-ONLY caller-side signer: sign `coin_spends` with `sk` (the role the identity
    /// boundary hands the client) and package the broadcast-ready [`SignedBundle`].
    fn client_sign(coin_spends: &[CoinSpend], owner: &BlsPairWithCoin) -> SignedBundle {
        let signature = sign_transaction(coin_spends, std::slice::from_ref(&owner.sk)).unwrap();
        SignedBundle {
            bundle: chia_protocol::SpendBundle::new(coin_spends.to_vec(), signature),
        }
    }

    fn xch_address(puzzle_hash: Bytes32) -> Address {
        Address(
            Bech32Address::new(puzzle_hash, "xch".into())
                .encode()
                .unwrap(),
        )
    }

    /// The full round trip for OFFER-CAT / GET-XCH: maker offers a CAT and requests XCH; the taker
    /// funds the XCH. Asserts the atomic settlement bundle is accepted by the simulator, and that
    /// the maker never self-funds (the maker holds NO XCH — only the offered CAT).
    #[test]
    fn round_trip_offer_cat_for_xch_settles() {
        let mut sim = Simulator::new();
        let maker = sim.bls(0); // maker.coin is a zero coin; maker holds only the CAT
        let (maker_cat, asset) = issue_cat_to(&mut sim, &maker, 1_000);
        let taker = sim.bls(60_000); // taker funds the requested XCH

        // maker: offer 1_000 CAT, request 50_000 XCH — maker has NO spendable XCH (no self-fund).
        let maker_builder = builder_for(&maker, vec![], vec![maker_cat]);
        let pending = maker_builder
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode(asset)), Amount(1_000))],
                },
                requested: RequestedAssets {
                    xch: Amount(50_000),
                    cats: vec![],
                    payee: xch_address(maker.puzzle_hash),
                },
                fee: Amount(0),
            })
            .expect("make builds without any XCH → no self-fund");
        let signed = client_sign(&pending.unsigned.coin_spends, &maker);
        let offer = maker_builder
            .assemble_make(AssembleOfferRequest {
                build_id: pending.build_id,
                signed,
            })
            .unwrap();
        assert!(offer.offer.starts_with("offer1"), "assembled offer string");

        // taker: accept, funding the 50_000 XCH.
        let taker_builder = builder_for(&taker, vec![taker.coin], vec![]);
        let take_pending = taker_builder
            .build_take(TakeOfferRequest {
                identity: identity(),
                offer: offer.offer,
                fee: Amount(0),
            })
            .unwrap();
        let taker_signed = client_sign(&take_pending.unsigned.coin_spends, &taker);
        let settlement = taker_builder
            .finalize_take(FinalizeTakeRequest {
                build_id: take_pending.build_id,
                signed: taker_signed,
            })
            .unwrap();

        sim.new_transaction(settlement.bundle)
            .expect("the atomic settlement bundle must be accepted");
    }

    /// The full round trip for OFFER-XCH / GET-CAT: maker offers XCH and requests a CAT the taker
    /// holds. Proves both directions settle.
    #[test]
    fn round_trip_offer_xch_for_cat_settles() {
        let mut sim = Simulator::new();
        let maker = sim.bls(50_000);
        let taker = sim.bls(0);
        let (taker_cat, asset) = issue_cat_to(&mut sim, &taker, 1_000);

        let maker_builder = builder_for(&maker, vec![maker.coin], vec![]);
        let pending = maker_builder
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(50_000),
                    cats: vec![],
                },
                requested: RequestedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode(asset)), Amount(1_000))],
                    payee: xch_address(maker.puzzle_hash),
                },
                fee: Amount(0),
            })
            .unwrap();
        let signed = client_sign(&pending.unsigned.coin_spends, &maker);
        let offer = maker_builder
            .assemble_make(AssembleOfferRequest {
                build_id: pending.build_id,
                signed,
            })
            .unwrap();

        let taker_builder = builder_for(&taker, vec![taker.coin], vec![taker_cat]);
        let take_pending = taker_builder
            .build_take(TakeOfferRequest {
                identity: identity(),
                offer: offer.offer,
                fee: Amount(0),
            })
            .unwrap();
        let taker_signed = client_sign(&take_pending.unsigned.coin_spends, &taker);
        let settlement = taker_builder
            .finalize_take(FinalizeTakeRequest {
                build_id: take_pending.build_id,
                signed: taker_signed,
            })
            .unwrap();

        sim.new_transaction(settlement.bundle)
            .expect("reverse-direction settlement must be accepted");
    }

    /// Cancelling an outstanding offer reclaims the offered coin to the maker (settles on-chain).
    #[test]
    fn cancel_reclaims_the_offered_coin() {
        let mut sim = Simulator::new();
        let maker = sim.bls(50_000);
        let taker = sim.bls(0);
        let (_taker_cat, asset) = issue_cat_to(&mut sim, &taker, 1_000);

        let maker_builder = builder_for(&maker, vec![maker.coin], vec![]);
        let pending = maker_builder
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(50_000),
                    cats: vec![],
                },
                requested: RequestedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode(asset)), Amount(1_000))],
                    payee: xch_address(maker.puzzle_hash),
                },
                fee: Amount(0),
            })
            .unwrap();
        let signed = client_sign(&pending.unsigned.coin_spends, &maker);
        let offer = maker_builder
            .assemble_make(AssembleOfferRequest {
                build_id: pending.build_id,
                signed,
            })
            .unwrap();

        let cancel = maker_builder
            .build_cancel(CancelOfferRequest {
                identity: identity(),
                offer: offer.offer,
                fee: Amount(0),
            })
            .unwrap();
        let cancel_signed = client_sign(&cancel.coin_spends, &maker);
        sim.new_transaction(cancel_signed.bundle)
            .expect("the maker's reclaim must settle");
    }

    // --- unit tests: fail-closed edges ----------------------------------------------------------

    /// Cancelling an offer the wallet does NOT own fails closed with a clear error, rather than
    /// silently producing an empty/non-signable unsigned spend (the #1122 custody-adjacent finding).
    #[test]
    fn cancel_of_an_unowned_offer_is_rejected() {
        let mut sim = Simulator::new();
        let maker = sim.bls(50_000);
        let stranger = sim.bls(50_000);
        let cat_owner = sim.bls(0);
        let (_cat, asset) = issue_cat_to(&mut sim, &cat_owner, 1_000);

        // The maker builds + assembles a real XCH-for-CAT offer.
        let maker_builder = builder_for(&maker, vec![maker.coin], vec![]);
        let pending = maker_builder
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(50_000),
                    cats: vec![],
                },
                requested: RequestedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode(asset)), Amount(1_000))],
                    payee: xch_address(maker.puzzle_hash),
                },
                fee: Amount(0),
            })
            .unwrap();
        let signed = client_sign(&pending.unsigned.coin_spends, &maker);
        let offer = maker_builder
            .assemble_make(AssembleOfferRequest {
                build_id: pending.build_id,
                signed,
            })
            .unwrap();

        // A DIFFERENT wallet (no key for the maker's offered coin) must NOT be able to cancel it.
        let stranger_builder = builder_for(&stranger, vec![stranger.coin], vec![]);
        let err = stranger_builder
            .build_cancel(CancelOfferRequest {
                identity: identity(),
                offer: offer.offer,
                fee: Amount(0),
            })
            .unwrap_err();
        assert_eq!(
            err.code,
            WalletErrorCode::SpendValidationFailed,
            "an unowned cancel must fail closed, not return a non-signable spend"
        );
    }

    /// The CAT-offer cancel path (previously untested): a CAT-offered coin must be reclaimed through
    /// its native layer, which this standard-layer cancel does not build — so it fails closed rather
    /// than emitting an unsignable spend from an empty owner-key map.
    #[test]
    fn cancel_of_a_cat_offer_is_rejected() {
        let mut sim = Simulator::new();
        let maker = sim.bls(0);
        let (maker_cat, asset) = issue_cat_to(&mut sim, &maker, 1_000);

        // maker offers a CAT, requesting XCH (no self-fund — the maker holds only the CAT).
        let maker_builder = builder_for(&maker, vec![], vec![maker_cat]);
        let pending = maker_builder
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode(asset)), Amount(1_000))],
                },
                requested: RequestedAssets {
                    xch: Amount(50_000),
                    cats: vec![],
                    payee: xch_address(maker.puzzle_hash),
                },
                fee: Amount(0),
            })
            .unwrap();
        let signed = client_sign(&pending.unsigned.coin_spends, &maker);
        let offer = maker_builder
            .assemble_make(AssembleOfferRequest {
                build_id: pending.build_id,
                signed,
            })
            .unwrap();

        let err = maker_builder
            .build_cancel(CancelOfferRequest {
                identity: identity(),
                offer: offer.offer,
                fee: Amount(0),
            })
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// #2241: a MAKE's reviewed summary surfaces the REQUESTED payment as a distinct `received` leg
    /// (to the maker's receive address), so the maker sees the trade both ways at the confirm — while
    /// the OFFERED assets remain empty-address egress legs in `outputs`. Anchored to a real make
    /// bundle built through dig-offers, not a hand-rolled summary.
    #[test]
    fn a_make_summary_surfaces_the_requested_payment_as_a_received_leg() {
        let mut sim = Simulator::new();
        let maker = sim.bls(0);
        let (maker_cat, asset) = issue_cat_to(&mut sim, &maker, 1_000);
        let payee = xch_address(maker.puzzle_hash);

        let pending = builder_for(&maker, vec![], vec![maker_cat])
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode(asset)), Amount(1_000))],
                },
                requested: RequestedAssets {
                    xch: Amount(50_000),
                    cats: vec![],
                    payee: payee.clone(),
                },
                fee: Amount(0),
            })
            .unwrap();

        let summary = pending.unsigned.summary;
        // The offered CAT leaves the wallet as an empty-address settlement egress.
        assert_eq!(summary.outputs.len(), 1);
        assert!(summary.outputs[0].address.0.is_empty());
        assert_eq!(
            summary.outputs[0].asset_id,
            Some(AssetId(hex::encode(asset)))
        );
        // The requested 50_000 XCH is surfaced DISTINCTLY as a received leg to the maker's address.
        assert_eq!(summary.received.len(), 1);
        assert_eq!(summary.received[0].amount, Amount(50_000));
        assert_eq!(summary.received[0].asset_id, None);
        assert_eq!(summary.received[0].address, payee);
    }

    /// A make/summarize response carries the offer's stable ecosystem id (#1318 task 4).
    #[test]
    fn offer_string_and_summary_carry_the_offer_id() {
        let mut sim = Simulator::new();
        let maker = sim.bls(50_000);
        let cat_owner = sim.bls(0);
        let (_cat, asset) = issue_cat_to(&mut sim, &cat_owner, 1_000);

        let maker_builder = builder_for(&maker, vec![maker.coin], vec![]);
        let pending = maker_builder
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(50_000),
                    cats: vec![],
                },
                requested: RequestedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode(asset)), Amount(1_000))],
                    payee: xch_address(maker.puzzle_hash),
                },
                fee: Amount(0),
            })
            .unwrap();
        let signed = client_sign(&pending.unsigned.coin_spends, &maker);
        let offer = maker_builder
            .assemble_make(AssembleOfferRequest {
                build_id: pending.build_id,
                signed,
            })
            .unwrap();

        // 32-byte sha256 → 64 hex chars, and it matches summarize's id for the same offer.
        assert_eq!(offer.offer_id.len(), 64, "offer_id is a 32-byte hex hash");
        let summary = maker_builder
            .summarize(SummarizeOfferRequest {
                offer: offer.offer.clone(),
            })
            .unwrap();
        assert_eq!(summary.offer_id, offer.offer_id, "id is stable per offer");
    }

    /// A taker whose funds are too fragmented to cover the requested amount within the coin cap
    /// reports the consolidation shortfall the shared selection produces — the same behaviour a
    /// plain XCH send has (#1318 task 3: taker selection unified through `select_for_spend`).
    #[test]
    fn over_cap_taker_selection_reports_needs_consolidation() {
        let mut sim = Simulator::new();
        let maker = sim.bls(0);
        let (maker_cat, asset) = issue_cat_to(&mut sim, &maker, 1_000);
        let taker = sim.bls(0);

        // maker offers a CAT, requesting 3 XCH.
        let maker_builder = builder_for(&maker, vec![], vec![maker_cat]);
        let pending = maker_builder
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode(asset)), Amount(1_000))],
                },
                requested: RequestedAssets {
                    xch: Amount(3),
                    cats: vec![],
                    payee: xch_address(maker.puzzle_hash),
                },
                fee: Amount(0),
            })
            .unwrap();
        let signed = client_sign(&pending.unsigned.coin_spends, &maker);
        let offer = maker_builder
            .assemble_make(AssembleOfferRequest {
                build_id: pending.build_id,
                signed,
            })
            .unwrap();

        // The taker holds 3 XCH total but split across 3 one-mojo coins, under a coin cap of 2:
        // enough value, too fragmented to reach 3 within the cap → NeedsConsolidation (surfaced as
        // InsufficientFunds with a "consolidation" message, exactly as a send reports it).
        let taker_coins: Vec<Coin> = (0..3).map(|_| sim.new_coin(taker.puzzle_hash, 1)).collect();
        let taker_builder = OfferBuilder::new(
            Arc::new(TestInputs {
                xch: taker_coins,
                cats: vec![],
                keys: vec![(taker.puzzle_hash, taker.pk)],
                change: taker.puzzle_hash,
            }),
            Network::Simulator,
            2,
        );
        let err = taker_builder
            .build_take(TakeOfferRequest {
                identity: identity(),
                offer: offer.offer,
                fee: Amount(0),
            })
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InsufficientFunds);
        assert!(
            err.message.contains("consolidation"),
            "over-cap taker selection reports consolidation, not a plain shortfall: {}",
            err.message
        );
    }

    #[test]
    fn make_with_nothing_offered_is_rejected() {
        let maker = Simulator::new().bls(0);
        let err = builder_for(&maker, vec![], vec![])
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(0),
                    cats: vec![],
                },
                requested: RequestedAssets {
                    xch: Amount(1),
                    cats: vec![],
                    payee: xch_address(maker.puzzle_hash),
                },
                fee: Amount(0),
            })
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[test]
    fn make_with_nothing_requested_is_rejected() {
        let mut sim = Simulator::new();
        let maker = sim.bls(0);
        let (cat, asset) = issue_cat_to(&mut sim, &maker, 1_000);
        let err = builder_for(&maker, vec![], vec![cat])
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode(asset)), Amount(1_000))],
                },
                requested: RequestedAssets {
                    xch: Amount(0),
                    cats: vec![],
                    payee: xch_address(maker.puzzle_hash),
                },
                fee: Amount(0),
            })
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[test]
    fn make_offering_a_zero_cat_amount_is_rejected() {
        let maker = Simulator::new().bls(0);
        let err = builder_for(&maker, vec![], vec![])
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode([0xabu8; 32])), Amount(0))],
                },
                requested: RequestedAssets {
                    xch: Amount(1),
                    cats: vec![],
                    payee: xch_address(maker.puzzle_hash),
                },
                fee: Amount(0),
            })
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[test]
    fn take_a_malformed_offer_is_rejected() {
        let taker = Simulator::new().bls(10_000);
        let err = builder_for(&taker, vec![taker.coin], vec![])
            .build_take(TakeOfferRequest {
                identity: identity(),
                offer: "not-an-offer".into(),
                fee: Amount(0),
            })
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[test]
    fn summarize_a_malformed_offer_is_rejected() {
        let maker = Simulator::new().bls(0);
        let err = builder_for(&maker, vec![], vec![])
            .summarize(SummarizeOfferRequest {
                offer: "   ".into(),
            })
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[test]
    fn combine_fewer_than_two_offers_is_rejected() {
        let maker = Simulator::new().bls(0);
        let err = builder_for(&maker, vec![], vec![])
            .combine(CombineOffersRequest {
                offers: vec!["offer1abc".into()],
            })
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[test]
    fn assemble_with_an_unknown_build_id_is_rejected() {
        let maker = Simulator::new().bls(0);
        let err = builder_for(&maker, vec![], vec![])
            .assemble_make(AssembleOfferRequest {
                build_id: crate::types::OfferBuildId("nope".into()),
                signed: SignedBundle {
                    bundle: chia_protocol::SpendBundle::new(vec![], chia_bls::Signature::default()),
                },
            })
            .unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    /// A make parks exactly one pending build; assembling it consumes the entry.
    #[test]
    fn a_make_parks_then_consumes_one_pending_build() {
        let mut sim = Simulator::new();
        let maker = sim.bls(0);
        let (cat, asset) = issue_cat_to(&mut sim, &maker, 1_000);
        let builder = builder_for(&maker, vec![], vec![cat]);
        let pending = builder
            .build_make(MakeOfferRequest {
                identity: identity(),
                offered: OfferedAssets {
                    xch: Amount(0),
                    cats: vec![(AssetId(hex::encode(asset)), Amount(1_000))],
                },
                requested: RequestedAssets {
                    xch: Amount(50_000),
                    cats: vec![],
                    payee: xch_address(maker.puzzle_hash),
                },
                fee: Amount(0),
            })
            .unwrap();
        assert_eq!(builder.pending().len(), 1);
        let signed = client_sign(&pending.unsigned.coin_spends, &maker);
        builder
            .assemble_make(AssembleOfferRequest {
                build_id: pending.build_id,
                signed,
            })
            .unwrap();
        assert!(builder.pending().is_empty(), "assembly consumes the build");
    }
}
