//! `engine::singleton` — hydrating NFTs, DIDs and CATs out of a parent coin spend (SPEC §7, #42).
//!
//! A peer reports coins; it does not report what they *are*. A CAT coin's puzzle hash is opaque, and
//! an NFT or DID is a singleton whose identity lives in its parent's puzzle reveal. So the engine's
//! `nfts()` / `dids()` / `cats()` reads can only populate once something walks the PARENT SPEND and
//! reconstructs the asset from it.
//!
//! # Composition, not a port
//!
//! The parsing itself is not re-derived here. `chia-wallet-sdk` already owns the canonical
//! reconstruction — [`Nft::parse_child`], [`Did::parse_child`], [`Cat::parse_children`] — including
//! the subtleties (running the transfer program and metadata updater for an NFT, the revocation layer
//! for a CAT, the odd-amount singleton child for a DID). Re-implementing that logic would be a rival
//! implementation of consensus-adjacent parsing, which is the one place a second version is most
//! expensive to be wrong in (Appendix B). This module is the composition layer: it finds the candidate
//! children, asks each canonical driver, and maps what comes back onto the engine's own record types.
//!
//! # Tolerance is the design, not a shortcut
//!
//! A wallet syncs from a chain that contains everything. Most spends are not singletons at all, and
//! some that look like one will fail to parse — a truncated lineage, an unfamiliar inner layer, a
//! custom metadata updater. Every per-family parse failure is therefore SKIPPED and counted, never
//! propagated: one unparseable coin must not stop a sync. The single error this can return is a spend
//! that does not run at all, because that means the caller handed over something that is not a spend.
//!
//! # Key isolation
//!
//! Everything here is public chain data — coins, puzzles, launcher ids. No key material is read,
//! derived, or held (SPEC §1.4, #908).

use chia_protocol::{Coin, CoinSpend};
use chia_puzzle_types::nft::NftMetadata;
use chia_wallet_sdk::driver::{Cat, HashedPtr, Nft, Puzzle};
use chia_wallet_sdk::types::Condition;
use clvm_traits::{FromClvm, ToClvm};
use clvmr::{Allocator, NodePtr};

use crate::types::{
    Amount, AssetId, CatRecord, DidRecord, NftRecord, WalletError, WalletErrorCode, WalletResult,
};

/// The assets reconstructed from one parent spend, partitioned by family.
///
/// A single spend can yield several families at once — a mint that also pays CAT change is ordinary —
/// so this is a partition rather than a one-of.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HydratedSingletons {
    /// DIDs whose next state this spend created.
    pub dids: Vec<DidRecord>,
    /// NFTs whose next state this spend created.
    pub nfts: Vec<NftRecord>,
    /// CAT balances this spend created, aggregated per asset id.
    pub cats: Vec<CatRecord>,
    /// How many candidate children were recognised as a singleton family but failed to parse.
    ///
    /// Surfaced rather than swallowed: a sync that silently hydrates nothing and a sync that has
    /// nothing to hydrate look identical from the outside, and only this number tells them apart.
    pub skipped: usize,
}

impl HydratedSingletons {
    /// Whether this spend yielded no assets at all (the common case for an ordinary payment).
    pub fn is_empty(&self) -> bool {
        self.dids.is_empty() && self.nfts.is_empty() && self.cats.is_empty()
    }
}

/// Reconstruct every NFT, DID and CAT that `parent` creates.
///
/// Returns an error only when the spend does not run — a puzzle/solution pair that cannot be
/// evaluated is not a spend, and reporting an empty hydration for it would be a lie. Every other
/// failure is counted in [`HydratedSingletons::skipped`].
pub fn reconstruct_from_parent_spend(parent: &CoinSpend) -> WalletResult<HydratedSingletons> {
    let mut allocator = Allocator::new();
    let puzzle_ptr = parent
        .puzzle_reveal
        .to_clvm(&mut allocator)
        .map_err(|e| unparseable(format!("puzzle reveal: {e:?}")))?;
    let solution = parent
        .solution
        .to_clvm(&mut allocator)
        .map_err(|e| unparseable(format!("solution: {e:?}")))?;
    let puzzle = Puzzle::parse(&allocator, puzzle_ptr);

    let mut out = HydratedSingletons::default();
    hydrate_nft(&mut allocator, parent, puzzle, solution, &mut out);
    hydrate_dids(&mut allocator, parent, &mut out)?;
    hydrate_cats(&mut allocator, parent, puzzle, solution, &mut out);
    Ok(out)
}

/// Ask the canonical NFT driver for the child this spend created.
///
/// `Nft::parse_child` derives the child coin itself, so no candidate enumeration is needed. A `None`
/// means "not an NFT" and is not a skip; an `Err` means "looked like an NFT and would not parse" and
/// is.
fn hydrate_nft(
    allocator: &mut Allocator,
    parent: &CoinSpend,
    puzzle: Puzzle,
    solution: NodePtr,
    out: &mut HydratedSingletons,
) {
    match Nft::parse_child(allocator, parent.coin, puzzle, solution) {
        Ok(Some(nft)) => out.nfts.push(NftRecord {
            launcher_id: hex::encode(nft.info.launcher_id),
            data_uri: first_data_uri(allocator, nft.info.metadata),
        }),
        Ok(None) => {}
        Err(_) => out.skipped += 1,
    }
}

/// Ask the canonical DID crate about each odd-amount child this spend creates.
///
/// Routed through `dig-did` — the ecosystem's DID expert crate (#40) — rather than the raw sdk
/// driver, so this crate holds no second opinion about what a DID is. `dig-did` is called directly
/// instead of via [`super::did::hydrate_did`] because hydration here needs to tell its error
/// variants apart: "not a DID" and "no successor coin" are ordinary facts about an ordinary spend,
/// while a genuine parse failure is a skip worth counting. The facade flattens that distinction,
/// which is right for a caller asking about one known DID and wrong for a scanner.
///
/// Unlike the NFT path, DID hydration is told WHICH child to reconstruct, so the candidates have to
/// be enumerated first. A singleton always carries an odd amount, which is what narrows the
/// created-coin set to the ones worth asking about.
fn hydrate_dids(
    allocator: &mut Allocator,
    parent: &CoinSpend,
    out: &mut HydratedSingletons,
) -> WalletResult<()> {
    for child in odd_children(allocator, parent)? {
        match dig_did::hydrate_did_from_parent_spend(
            parent.coin,
            &parent.puzzle_reveal,
            &parent.solution,
            child,
        ) {
            Ok(did) => out.dids.push(DidRecord {
                launcher_id: hex::encode(did.info.launcher_id),
                name: None,
            }),
            // Not a DID at all, or a DID spend that created no successor: both are ordinary facts
            // about an ordinary spend, not failures, so neither counts as a skip.
            Err(dig_did::DidError::NotDid | dig_did::DidError::MissingLineage) => {}
            Err(_) => out.skipped += 1,
        }
    }
    Ok(())
}

/// Ask the canonical CAT driver for the children this spend created, aggregating per asset id.
///
/// Several CAT children of one spend commonly share an asset id (a payment plus its change), and the
/// engine's [`CatRecord`] is a per-asset BALANCE rather than a per-coin row, so they are summed.
fn hydrate_cats(
    allocator: &mut Allocator,
    parent: &CoinSpend,
    puzzle: Puzzle,
    solution: NodePtr,
    out: &mut HydratedSingletons,
) {
    let children = match Cat::parse_children(allocator, parent.coin, puzzle, solution) {
        Ok(Some(children)) => children,
        Ok(None) => return,
        Err(_) => {
            out.skipped += 1;
            return;
        }
    };

    for cat in children {
        let asset_id = AssetId(hex::encode(cat.info.asset_id));
        match out.cats.iter_mut().find(|c| c.asset_id == asset_id) {
            Some(existing) => existing.balance = Amount(existing.balance.mojos() + cat.coin.amount),
            None => out.cats.push(CatRecord {
                asset_id,
                balance: Amount(cat.coin.amount),
                name: None,
            }),
        }
    }
}

/// The odd-amount coins this spend creates — the singleton-child candidates.
///
/// Runs the spend once and reads its `CREATE_COIN` conditions. An even-amount child cannot be a
/// singleton, so filtering here keeps the driver from being asked about ordinary payments.
fn odd_children(allocator: &mut Allocator, parent: &CoinSpend) -> WalletResult<Vec<Coin>> {
    let puzzle = parent
        .puzzle_reveal
        .to_clvm(allocator)
        .map_err(|e| unparseable(format!("puzzle reveal: {e:?}")))?;
    let solution = parent
        .solution
        .to_clvm(allocator)
        .map_err(|e| unparseable(format!("solution: {e:?}")))?;
    let output = clvmr::run_program(
        allocator,
        &clvmr::ChiaDialect::new(0),
        puzzle,
        solution,
        u64::MAX,
    )
    .map_err(|e| unparseable(format!("spend did not run: {e:?}")))?
    .1;
    let conditions: Vec<Condition> = FromClvm::from_clvm(allocator, output)
        .map_err(|e| unparseable(format!("conditions: {e:?}")))?;

    let parent_id = parent.coin.coin_id();
    Ok(conditions
        .into_iter()
        .filter_map(Condition::into_create_coin)
        .filter(|create| create.amount % 2 == 1)
        .map(|create| Coin::new(parent_id, create.puzzle_hash, create.amount))
        .collect())
}

/// The first data URI in an NFT's metadata, when the metadata is the standard shape.
///
/// A custom metadata updater may store something else entirely; that is legal and simply yields
/// `None` rather than an error, because an unreadable metadata blob does not make the NFT itself
/// unknown — its launcher id is still the identity that matters.
fn first_data_uri(allocator: &Allocator, metadata: HashedPtr) -> Option<String> {
    NftMetadata::from_clvm(allocator, metadata.ptr())
        .ok()?
        .data_uris
        .into_iter()
        .next()
}

/// Shorthand for a spend that could not be evaluated at all.
fn unparseable(message: impl Into<String>) -> WalletError {
    WalletError::new(WalletErrorCode::SpendValidationFailed, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::PublicKey;
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::driver::SpendContext;
    use chia_wallet_sdk::types::Conditions;

    /// The BLS12-381 G1 generator: a valid, non-infinity public key with no secret counterpart.
    fn owner_pk() -> PublicKey {
        const G1_GENERATOR: [u8; 48] = [
            0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9,
            0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f,
            0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a,
            0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
        ];
        PublicKey::from_bytes(&G1_GENERATOR).expect("the G1 generator is a valid public key")
    }

    fn owner_ph() -> chia_protocol::Bytes32 {
        chia_protocol::Bytes32::from(StandardArgs::curry_tree_hash(owner_pk()).to_bytes())
    }

    /// The spend in `spends` that created `child` — the PARENT this module reconstructs from.
    ///
    /// Selected by matching the child's `parent_coin_info` rather than by taking a fixed index,
    /// because an index would silently point at the wrong spend the moment a builder reorders its
    /// output, and the test would then prove something about a different spend.
    fn parent_of(spends: &[CoinSpend], child: chia_protocol::Coin) -> CoinSpend {
        spends
            .iter()
            .find(|spend| spend.coin.coin_id() == child.parent_coin_info)
            .expect("the child's parent must be among the spends that created it")
            .clone()
    }

    /// A REAL DID launch, built by the canonical `dig-did` builder.
    fn did_launch() -> (Vec<CoinSpend>, dig_did::Did) {
        let mut ctx = SpendContext::new();
        let launch = dig_did::create_simple_did(
            &mut ctx,
            Coin::new(chia_protocol::Bytes32::new([0x22; 32]), owner_ph(), 1),
            dig_did::Owner::Standard(owner_pk()),
        )
        .expect("the canonical DID launch builder");
        let did = launch.child.expect("a launch yields the settled DID");
        (launch.coin_spends, did)
    }

    /// A REAL NFT mint, built by the canonical `dig-nft` builder.
    fn nft_mint() -> (Vec<CoinSpend>, dig_nft::Nft) {
        let mut ctx = SpendContext::new();
        let metadata = ctx
            .alloc(&chia_puzzle_types::nft::NftMetadata::default())
            .expect("the default NFT metadata allocates");
        let metadata = ctx.serialize(&metadata).expect("metadata serializes");
        let mint = dig_nft::mint(
            &mut ctx,
            &dig_nft::Owner::Standard(owner_pk()),
            Coin::new(chia_protocol::Bytes32::new([0x44; 32]), owner_ph(), 1),
            &dig_nft::MintSpec::new(metadata, owner_ph()),
        )
        .expect("the canonical NFT mint builder");
        let nft = *mint.children.first().expect("a mint yields one NFT");
        (mint.coin_spends, nft)
    }

    /// An ordinary standard-layer payment — the CONTROL.
    ///
    /// Without it, a hydrator that returned every coin it saw as a DID would pass the two positive
    /// tests below: each has exactly one singleton to find, so neither can tell "recognised the
    /// singleton" from "called everything a singleton".
    fn ordinary_payment() -> CoinSpend {
        let mut ctx = SpendContext::new();
        let funding = Coin::new(chia_protocol::Bytes32::new([0x66; 32]), owner_ph(), 1_000);
        chia_wallet_sdk::driver::StandardLayer::new(owner_pk())
            .spend(
                &mut ctx,
                funding,
                Conditions::new().create_coin(
                    chia_protocol::Bytes32::new([0x77; 32]),
                    900,
                    chia_puzzle_types::Memos::None,
                ),
            )
            .expect("the standard layer spends the funding coin");
        ctx.take().pop().expect("one coin spend")
    }

    #[test]
    fn a_real_did_launch_hydrates_the_did_it_created() {
        let (spends, did) = did_launch();
        let hydrated = reconstruct_from_parent_spend(&parent_of(&spends, did.coin))
            .expect("a real DID parent spend runs");

        assert_eq!(
            hydrated
                .dids
                .iter()
                .map(|d| d.launcher_id.as_str())
                .collect::<Vec<_>>(),
            vec![hex::encode(did.info.launcher_id).as_str()],
            "the hydrated DID must be the one the builder actually created"
        );
        assert_eq!(hydrated.skipped, 0);
    }

    #[test]
    fn a_real_nft_mint_hydrates_the_nft_it_created() {
        let (spends, nft) = nft_mint();
        let hydrated = reconstruct_from_parent_spend(&parent_of(&spends, nft.coin))
            .expect("a real NFT parent spend runs");

        assert_eq!(
            hydrated
                .nfts
                .iter()
                .map(|n| n.launcher_id.as_str())
                .collect::<Vec<_>>(),
            vec![hex::encode(nft.info.launcher_id).as_str()],
            "the hydrated NFT must be the one the builder actually created"
        );
    }

    /// The control: an ordinary payment is not a singleton of any family.
    #[test]
    fn an_ordinary_payment_hydrates_nothing_and_skips_nothing() {
        let hydrated =
            reconstruct_from_parent_spend(&ordinary_payment()).expect("an ordinary spend runs");

        assert!(
            hydrated.is_empty(),
            "an ordinary payment must not be reported as an NFT, DID or CAT: {hydrated:?}"
        );
        assert_eq!(
            hydrated.skipped, 0,
            "a spend that is simply not a singleton is not a SKIP — skipped counts recognised-but-unparseable"
        );
    }

    /// A DID launch must not also be reported as an NFT, and vice versa. Two positive tests run in
    /// isolation cannot see a hydrator that files every singleton under every family.
    #[test]
    fn each_family_claims_only_its_own_singleton() {
        let (did_spends, did) = did_launch();
        let did_hydrated =
            reconstruct_from_parent_spend(&parent_of(&did_spends, did.coin)).unwrap();
        assert!(did_hydrated.nfts.is_empty(), "a DID is not an NFT");
        assert!(did_hydrated.cats.is_empty(), "a DID is not a CAT");

        let (nft_spends, nft) = nft_mint();
        let nft_hydrated =
            reconstruct_from_parent_spend(&parent_of(&nft_spends, nft.coin)).unwrap();
        assert!(nft_hydrated.dids.is_empty(), "an NFT is not a DID");
        assert!(nft_hydrated.cats.is_empty(), "an NFT is not a CAT");
    }

    /// A spend whose puzzle cannot be EVALUATED is the ONE error this returns — the caller handed
    /// over something that is not a spend, and reporting an empty hydration for it would be a lie.
    ///
    /// The fixture is deliberately malformed CLVM (`0xff` opens a cons pair and then ends), not the
    /// nil program: nil is a perfectly legal puzzle that RUNS and yields no conditions, so an empty
    /// hydration for it is the correct answer rather than a failure. Using nil here would have
    /// asserted an error the code is right not to raise.
    #[test]
    fn a_spend_that_does_not_run_is_an_error_not_an_empty_result() {
        let malformed = chia_protocol::Program::new(vec![0xff].into());
        let broken = CoinSpend::new(
            Coin::new(chia_protocol::Bytes32::new([0x88; 32]), owner_ph(), 1),
            malformed.clone(),
            malformed,
        );
        assert!(
            reconstruct_from_parent_spend(&broken).is_err(),
            "a puzzle that cannot produce conditions must surface as an error"
        );
    }
}
