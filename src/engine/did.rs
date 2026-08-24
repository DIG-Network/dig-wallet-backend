//! `engine::did` — the wallet's DID surface, composed from the canonical `dig-did` crate (#40).
//!
//! # This module deliberately contains almost no DID logic
//!
//! `dig-did` is the ecosystem's DID expert crate: it owns the launch spend, the parent-spend
//! hydration, the lineage proof, and `did:chia:` resolution. Every one of those is
//! consensus-adjacent parsing or spend construction, and a second implementation of either would be
//! a rival that drifts (Appendix B). So this module is a COMPOSITION layer with two jobs:
//!
//! 1. **Be the facade.** Consumers depend on `dig-wallet-backend`, never on `dig-did` directly, so
//!    the DID types and operations they need are re-exported from here. That keeps the DID crate an
//!    implementation detail this crate can move without breaking five consumers.
//! 2. **Speak the wallet's error language.** `dig-did` returns [`dig_did::DidError`]; the wallet
//!    seam's contract is [`crate::types::WalletError`] with a catalogued code (SPEC §2), so each
//!    entry point translates.
//!
//! # Custody
//!
//! Every operation here builds an UNSIGNED spend and reports what must sign it. No key is read,
//! derived, or held; the engine never signs (SPEC §1.4, identity boundary #908). The signature the
//! caller must obtain comes from the client seam's signer, as it does for every other builder.

use chia_bls::PublicKey;
use chia_protocol::{Coin, CoinSpend, Program};
use chia_wallet_sdk::driver::SpendContext;

use crate::types::{Address, Network, WalletError, WalletErrorCode, WalletResult};

/// The DID types a consumer needs in order to use this surface, re-exported so nothing has to take
/// a direct `dig-did` dependency (the facade rule, Appendix B).
pub use dig_did::{
    did_string_from_launcher_id, launcher_id_from_did_string, AncestryProof, ChainSource, Did,
    DidInfo, DidTip, LineageModel, Owner, DID_CHIA_PREFIX, MAX_LINEAGE_DEPTH,
};

/// An unsigned DID operation: the spends to broadcast, and the DID they will produce.
///
/// `child` is `None` for a terminal operation (a melt), which is why it is an [`Option`] rather than
/// a plain DID — a caller that assumes a successor always exists would be wrong exactly when the DID
/// is being destroyed.
#[derive(Debug, Clone)]
pub struct DidOperation {
    /// The unsigned coin spends, in spend order.
    pub coin_spends: Vec<CoinSpend>,
    /// The DID as it will exist once these spends confirm, or `None` for a terminal operation.
    pub child: Option<Did>,
}

impl From<dig_did::DidSpend> for DidOperation {
    fn from(spend: dig_did::DidSpend) -> Self {
        Self {
            coin_spends: spend.coin_spends,
            child: spend.child,
        }
    }
}

/// Launch a new DID from `funding_coin`, owned by `owner_key`.
///
/// The funding coin becomes the DID in full and its amount MUST be odd — an even amount produces no
/// singleton at all, so the coin would simply be spent and the DID would not exist. `dig-did`
/// enforces this; it is repeated here because a caller reading only this signature would not
/// otherwise know that the amount is load-bearing rather than incidental.
pub fn launch_did(funding_coin: Coin, owner_key: PublicKey) -> WalletResult<DidOperation> {
    let mut ctx = SpendContext::new();
    dig_did::create_simple_did(&mut ctx, funding_coin, Owner::Standard(owner_key))
        .map(DidOperation::from)
        .map_err(|e| did_failed("launch", e))
}

/// Transfer a DID to `new_owner_puzzle_hash`.
///
/// Composed rather than delegated because `dig-did` exposes the general
/// [`dig_did::spend_did_with_conditions`] and not a transfer verb: a DID transfer IS a DID spend
/// that recreates the singleton under a new inner puzzle hash. The composition lives here so a
/// caller does not have to know that, but the spend construction itself is still entirely
/// `dig-did`'s.
pub fn transfer_did(
    did: Did,
    owner_key: PublicKey,
    new_owner_puzzle_hash: chia_protocol::Bytes32,
) -> WalletResult<DidOperation> {
    use chia_wallet_sdk::types::Conditions;

    let mut ctx = SpendContext::new();
    let conditions = Conditions::new().create_coin(
        new_owner_puzzle_hash,
        did.coin.amount,
        chia_puzzle_types::Memos::None,
    );
    let child = dig_did::spend_did_with_conditions(&mut ctx, did, Owner::Standard(owner_key), conditions)
        .map_err(|e| did_failed("transfer", e))?;
    Ok(DidOperation {
        coin_spends: ctx.take(),
        child: Some(child),
    })
}

/// Hydrate the DID a parent spend created.
///
/// This is how a DID becomes known from chain data alone: a peer reports the child coin, and the
/// parent's puzzle reveal is what says the coin is a DID and which one. Fails closed — it never
/// fabricates a lineage proof or an owner hint.
pub fn hydrate_did(
    parent_coin: Coin,
    parent_puzzle_reveal: &Program,
    parent_solution: &Program,
    child_coin: Coin,
) -> WalletResult<Did> {
    dig_did::hydrate_did_from_parent_spend(
        parent_coin,
        parent_puzzle_reveal,
        parent_solution,
        child_coin,
    )
    .map_err(|e| did_failed("hydrate", e))
}

/// Prove that `coin_id` descends from `did`, walking the chain through `source`.
///
/// The proof is what lets a wallet say a store or NFT is genuinely anchored to an identity rather
/// than merely claiming to be. It is bounded by [`MAX_LINEAGE_DEPTH`], because an unbounded ancestry
/// walk against a hostile source is an unbounded amount of work.
pub fn prove_did_lineage<S: ChainSource>(
    source: &S,
    coin_id: chia_protocol::Bytes32,
    did: &Did,
) -> WalletResult<AncestryProof> {
    dig_did::prove_lineage(coin_id, did, source).map_err(|e| did_failed("lineage proof", e))
}

/// Resolve a `did:chia:` string to the XCH address its current owner controls.
///
/// Walks the DID's lineage to its tip first, so the answer reflects the DID as it is NOW rather than
/// as it was when it was launched — a DID that has been transferred resolves to its new owner.
///
/// `None` means the DID could not be resolved to an owner address, and it is returned rather than
/// raised because "this DID has no resolvable owner right now" is an ANSWER, not a failure. Collapsing
/// it into an error would make an unresolvable DID indistinguishable from a chain read that broke.
pub fn resolve_did_xch_address<S: ChainSource>(
    source: &S,
    did_string: &str,
    network: Network,
) -> WalletResult<Option<Address>> {
    let resolved =
        dig_did::resolve_xch_address_from_did_string(did_string, address_prefix(network), source)
            .map_err(|e| did_failed("resolve", e))?;
    resolved
        .map(|address| {
            address
                .encode()
                .map(Address)
                .map_err(|e| {
                    WalletError::new(
                        WalletErrorCode::SpendValidationFailed,
                        format!("DID resolve produced an unencodable address: {e}"),
                    )
                })
        })
        .transpose()
}

/// The bech32m human-readable prefix for a network.
///
/// The prefix is part of the address, not decoration: an address encoded under the wrong prefix is a
/// different address, and a wallet that showed one would be inviting a send into nowhere. It is
/// therefore derived from the network rather than passed in by a caller who might guess.
fn address_prefix(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "xch",
        Network::Testnet | Network::Simulator => "txch",
    }
}

/// Map a `dig-did` failure into the wallet's catalogued error taxonomy (SPEC §2).
///
/// `operation` is carried into the message because every variant below can arise from several verbs,
/// and "which DID operation failed" is the first thing a reader needs.
fn did_failed(operation: &str, error: dig_did::DidError) -> WalletError {
    WalletError::new(
        WalletErrorCode::SpendValidationFailed,
        format!("DID {operation} failed: {error}"),
    )
}
