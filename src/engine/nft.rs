//! `engine::nft` — the wallet's NFT surface, composed from the canonical `dig-nft` crate (#41).
//!
//! # Why this is a facade and not a port
//!
//! #41 was written as "port the builders from `sage/mint.rs`". That is no longer the right shape:
//! `dig-nft` now exists as the ecosystem's CHIP-0025 expert crate and owns mint, bulk mint,
//! transfer, metadata update, owner assignment and royalty settlement. Porting 449 lines of mint
//! logic into this crate would create a rival implementation of the intricate part — launcher
//! wiring, metadata encoding, the owner-DID attribution conditions — and rivals of
//! consensus-adjacent builders are the most expensive kind to let drift (Appendix B).
//!
//! So the port becomes an adoption. This module supplies what a facade must: the crate's types
//! re-exported so consumers need no direct `dig-nft` dependency, and the wallet's own catalogued
//! error taxonomy (SPEC §2) in place of `dig-nft`'s.
//!
//! # The owner-DID condition is a real obligation, not a detail
//!
//! When a mint attributes an NFT to an owner DID, `dig-nft` returns conditions that DID's own spend
//! MUST emit in the SAME bundle. They are carried through on [`NftOperation::did_conditions`]
//! rather than dropped, because a bundle missing them does not mint an unattributed NFT — it fails.
//!
//! # Custody
//!
//! Every operation builds an UNSIGNED spend. No key is read, derived, or held (SPEC §1.4, #908).

use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_wallet_sdk::driver::SpendContext;

use crate::types::{WalletError, WalletErrorCode, WalletResult};

/// The NFT types a consumer needs, re-exported so nothing takes a direct `dig-nft` dependency.
pub use dig_nft::{
    decode_nft_id, encode_nft_id, DidRef, MetadataUpdate, MintSpec, Nft, NftInfo, UriKind,
};

/// An unsigned NFT operation: the spends to broadcast, the NFTs they produce, and any conditions an
/// owner DID must emit alongside them.
#[derive(Debug, Clone)]
pub struct NftOperation {
    /// The unsigned coin spends, in spend order.
    pub coin_spends: Vec<CoinSpend>,
    /// The resulting NFTs, in the order their specs were given.
    pub children: Vec<Nft>,
    /// Conditions the attributed owner DID's own spend must emit in the SAME bundle.
    ///
    /// Empty when the operation involves no DID. When non-empty it is REQUIRED: a bundle that omits
    /// these does not produce an unattributed NFT, it fails to produce one at all.
    pub did_conditions: chia_wallet_sdk::types::Conditions,
}

impl From<dig_nft::NftSpend> for NftOperation {
    fn from(spend: dig_nft::NftSpend) -> Self {
        Self {
            coin_spends: spend.coin_spends,
            children: spend.children,
            did_conditions: spend.did_conditions,
        }
    }
}

/// Mint one NFT from `funding_coin`.
pub fn mint_nft(
    funding_coin: Coin,
    owner_key: PublicKey,
    spec: &MintSpec,
) -> WalletResult<NftOperation> {
    let mut ctx = SpendContext::new();
    dig_nft::mint(
        &mut ctx,
        &dig_nft::Owner::Standard(owner_key),
        funding_coin,
        spec,
    )
    .map(NftOperation::from)
    .map_err(|e| nft_failed("mint", e))
}

/// Mint several NFTs from ONE funding coin, in a single operation.
///
/// This is not a loop over [`mint_nft`]: the whole point of a bulk mint is that the NFTs share one
/// funding coin and one set of parent conditions, which a sequence of independent mints could not
/// produce. An empty spec list is rejected by `dig-nft` rather than silently yielding nothing.
pub fn bulk_mint_nfts(
    funding_coin: Coin,
    owner_key: PublicKey,
    specs: &[MintSpec],
) -> WalletResult<NftOperation> {
    let mut ctx = SpendContext::new();
    dig_nft::bulk_mint(
        &mut ctx,
        &dig_nft::Owner::Standard(owner_key),
        funding_coin,
        specs,
    )
    .map(NftOperation::from)
    .map_err(|e| nft_failed("bulk mint", e))
}

/// Transfer an NFT to `new_owner_puzzle_hash`.
pub fn transfer_nft(
    nft: Nft,
    owner_key: PublicKey,
    new_owner_puzzle_hash: Bytes32,
) -> WalletResult<NftOperation> {
    let mut ctx = SpendContext::new();
    dig_nft::transfer(
        &mut ctx,
        &dig_nft::Owner::Standard(owner_key),
        nft,
        new_owner_puzzle_hash,
    )
    .map(NftOperation::from)
    .map_err(|e| nft_failed("transfer", e))
}

/// Transfer an NFT and update its metadata in the same spend.
pub fn transfer_nft_with_metadata(
    nft: Nft,
    owner_key: PublicKey,
    new_owner_puzzle_hash: Bytes32,
    metadata_update: &MetadataUpdate,
) -> WalletResult<NftOperation> {
    let mut ctx = SpendContext::new();
    dig_nft::transfer_with_metadata(
        &mut ctx,
        &dig_nft::Owner::Standard(owner_key),
        nft,
        new_owner_puzzle_hash,
        metadata_update,
    )
    .map(NftOperation::from)
    .map_err(|e| nft_failed("transfer with metadata", e))
}

/// Update an NFT's metadata, leaving ownership where it is.
///
/// The default metadata updater only PREPENDS URIs; it cannot rewrite or remove one. That is a
/// property of the on-chain puzzle, not of this function, and it is why an "update" here can only
/// ever add.
pub fn update_nft_metadata(
    nft: Nft,
    owner_key: PublicKey,
    metadata_update: &MetadataUpdate,
) -> WalletResult<NftOperation> {
    let mut ctx = SpendContext::new();
    dig_nft::update_metadata(
        &mut ctx,
        &dig_nft::Owner::Standard(owner_key),
        nft,
        metadata_update,
    )
    .map(NftOperation::from)
    .map_err(|e| nft_failed("metadata update", e))
}

/// Map a `dig-nft` failure into the wallet's catalogued error taxonomy (SPEC §2).
fn nft_failed(operation: &str, error: dig_nft::Error) -> WalletError {
    WalletError::new(
        WalletErrorCode::SpendValidationFailed,
        format!("NFT {operation} failed: {error}"),
    )
}
