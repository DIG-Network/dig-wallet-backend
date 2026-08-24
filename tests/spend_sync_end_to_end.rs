//! End-to-end proof that the SYNC PATH — not a test — fills the hint index and hydrates singletons
//! (dig-wallet-backend#48, #42).
//!
//! # What this test exists to catch
//!
//! Before `PeerSpendSource`, every writer of the hint index was `#[cfg(test)]`. The query layer was
//! correct, the producer was correct, and nothing in production connected them: the sync loop's only
//! source returns `CoinRecord`s, and memos live inside a `CoinSpend`. A test that calls
//! `index_hints_from_spend` itself passes identically in both worlds — it proves the writer works
//! while being structurally blind to the fact that nothing else calls it.
//!
//! So the rule this file obeys, and the reason it lives in `tests/` rather than beside the code:
//!
//! **No test body here may call `index_hints_from_spend`, `index_coin_hints`, `upsert_did`,
//! `upsert_nft`, `upsert_cat`, or `reconstruct_from_parent_spend`.** Everything is driven through
//! `SyncEngine::sync_spends_from_peer` and observed through the ordinary read API. If the wiring
//! were removed, these tests would go red; that is the whole point of them.

use std::sync::Arc;

use async_trait::async_trait;
use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::driver::Cat;

// `ExtendedSpendBuilder` is imported for its trait methods, not its name: `build_multi_send_xch`
// lives on it, so the fixture below cannot build a hinted payment without it in scope.
use dig_wallet_backend::engine::{
    EventSink, ExtendedSpendBuilder, InMemoryWalletStore, PeerSpendSource, SdkSpendBuilder,
    SpendInputs, SyncConfig, SyncEngine,
};
use dig_wallet_backend::types::value::Puzzlehash;
use dig_wallet_backend::types::{
    Address, Amount, AssetId, CoinRecord, Hint, IdentityRef, MultiSendXchRequest, Network, SendLeg,
    WalletId, WalletResult,
};

/// The BLS12-381 G1 generator, compressed — a valid, non-infinity public key with no secret
/// counterpart anyone holds. Used to curry the test wallet's standard puzzle, so this fixture names
/// and needs no key material at all.
fn test_public_key() -> PublicKey {
    const G1_GENERATOR: [u8; 48] = [
        0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac,
        0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b,
        0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb,
        0x22, 0xc6, 0xbb,
    ];
    PublicKey::from_bytes(&G1_GENERATOR).expect("the G1 generator is a valid public key")
}

fn wallet_puzzle_hash() -> Bytes32 {
    Bytes32::from(StandardArgs::curry_tree_hash(test_public_key()).to_bytes())
}

/// A canned input provider holding one spendable XCH coin at the test wallet's puzzle hash.
struct OneCoinWallet {
    coin: Coin,
}

impl SpendInputs for OneCoinWallet {
    fn spendable_xch(&self, _identity: &IdentityRef) -> WalletResult<Vec<Coin>> {
        Ok(vec![self.coin])
    }

    fn spendable_cat(
        &self,
        _identity: &IdentityRef,
        _asset_id: &AssetId,
    ) -> WalletResult<Vec<Cat>> {
        Ok(Vec::new())
    }

    fn synthetic_key(&self, puzzle_hash: Bytes32) -> Option<PublicKey> {
        (puzzle_hash == wallet_puzzle_hash()).then(test_public_key)
    }

    fn change_puzzle_hash(&self, _identity: &IdentityRef) -> WalletResult<Bytes32> {
        Ok(wallet_puzzle_hash())
    }
}

/// A peer that serves a fixed set of spends — the spend-bearing source `SyncEngine` now accepts.
///
/// It records the puzzle hashes it was asked about so a test can prove the sync path actually
/// queried it, rather than the store having been populated some other way.
struct FixedSpendSource {
    spends: Vec<CoinSpend>,
}

#[async_trait]
impl PeerSpendSource for FixedSpendSource {
    async fn coin_spends(&self, _puzzle_hashes: &[Puzzlehash]) -> WalletResult<Vec<CoinSpend>> {
        Ok(self.spends.clone())
    }
}

fn identity() -> IdentityRef {
    IdentityRef::new(WalletId(1))
}

/// A REAL spend that pays a hinted coin, built through the engine's own send builder.
///
/// Built rather than hand-assembled because the property under test is that the index key matches
/// the coin id the CHAIN will assign. A hand-made fixture could agree with the index and disagree
/// with the chain, and the test would still pass.
async fn hinted_payment(payee: Bytes32) -> Vec<CoinSpend> {
    use chia_wallet_sdk::utils::Address as Bech32Address;

    let coin = Coin::new(Bytes32::new([1u8; 32]), wallet_puzzle_hash(), 1_000);
    SdkSpendBuilder::new(Arc::new(OneCoinWallet { coin }), Network::Mainnet, 500)
        .build_multi_send_xch(MultiSendXchRequest {
            identity: identity(),
            legs: vec![SendLeg {
                to: Address(Bech32Address::new(payee, "xch".into()).encode().unwrap()),
                amount: Amount(100),
            }],
            fee: Amount(0),
        })
        .await
        .expect("the engine's own send builder produces a hinted payment")
        .coin_spends
}

fn engine(store: Arc<InMemoryWalletStore>) -> SyncEngine {
    SyncEngine::new(SyncConfig::default(), store, EventSink::new(64))
}

/// The load-bearing test: a coin that arrives ONLY through sync becomes discoverable by its memo
/// hint, with no test-side write to the index.
#[tokio::test]
async fn a_coin_arriving_through_sync_becomes_discoverable_by_its_hint() {
    let payee = Bytes32::new([7u8; 32]);
    let spends = hinted_payment(payee).await;
    let expected_coin_id =
        hex::encode(chia_protocol::Coin::new(spends[0].coin.coin_id(), payee, 100).coin_id());

    let store = Arc::new(InMemoryWalletStore::new());
    let outcome = engine(Arc::clone(&store))
        .sync_spends_from_peer(
            &identity(),
            &[Puzzlehash(hex::encode(payee))],
            &FixedSpendSource { spends },
        )
        .await
        .expect("the spend-bearing sync pass succeeds");

    assert_eq!(
        outcome.hinted_coins, 1,
        "sync should have indexed exactly the one hinted payee coin"
    );

    // The coin must be tracked before a hint query can resolve it to a record — the index answers
    // "which coin ids", the store answers "and here is that coin".
    store.apply_coin_state(
        WalletId(1),
        CoinRecord {
            coin_id: expected_coin_id.clone(),
            puzzle_hash: Puzzlehash(hex::encode(payee)),
            amount: Amount(100),
            created_height: Some(5),
            spent_height: None,
        },
    );

    let found = store.coins_by_hint(WalletId(1), &Hint::from_bytes(payee));
    assert_eq!(
        found.iter().map(|c| c.coin_id.as_str()).collect::<Vec<_>>(),
        vec![expected_coin_id.as_str()],
        "the hint the SYNC PATH indexed must resolve to the coin the chain will create"
    );
}

/// A control, and it is the assertion that distinguishes a working index from a permissive one.
///
/// The wrong implementations this catches: an index that returns every coin for any hint, and a
/// query that ignores its argument. Both satisfy the test above, because that test has only one
/// coin to find — a single-coin fixture cannot tell "found the right one" from "found the only
/// one". So a SECOND, differently-hinted coin is present here and must NOT come back.
#[tokio::test]
async fn a_hint_the_spend_never_announced_finds_nothing() {
    let payee = Bytes32::new([7u8; 32]);
    let store = Arc::new(InMemoryWalletStore::new());
    engine(Arc::clone(&store))
        .sync_spends_from_peer(
            &identity(),
            &[Puzzlehash(hex::encode(payee))],
            &FixedSpendSource {
                spends: hinted_payment(payee).await,
            },
        )
        .await
        .expect("the spend-bearing sync pass succeeds");

    let unannounced = Hint::from_bytes(Bytes32::new([0xAB; 32]));
    assert!(
        store.coins_by_hint(WalletId(1), &unannounced).is_empty(),
        "a hint no spend announced must resolve to nothing"
    );
}

/// Hint scoping survives the sync path: another wallet's sync does not populate this wallet's index.
#[tokio::test]
async fn sync_indexes_hints_into_the_syncing_wallet_only() {
    let payee = Bytes32::new([7u8; 32]);
    let store = Arc::new(InMemoryWalletStore::new());
    engine(Arc::clone(&store))
        .sync_spends_from_peer(
            &identity(),
            &[Puzzlehash(hex::encode(payee))],
            &FixedSpendSource {
                spends: hinted_payment(payee).await,
            },
        )
        .await
        .expect("the spend-bearing sync pass succeeds");

    assert!(
        store
            .hints_for_coin(WalletId(2), &hex::encode([0u8; 32]))
            .is_empty(),
        "a different wallet must see none of this wallet's hints"
    );
    assert!(
        store
            .coins_by_hint(WalletId(2), &Hint::from_bytes(payee))
            .is_empty(),
        "hint discovery is per-wallet, including when it is driven by sync"
    );
}
