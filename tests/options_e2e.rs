//! Simulator round-trips for the engine's option exercise + transfer wiring (#1123).
//!
//! The unit tests in `src/engine/build_options.rs` prove the wiring + fail-closed guards key-free.
//! These tests close the loop against real consensus: they mint a real option, drive the ENGINE's
//! `build_exercise_option` / `build_transfer_option` to build the UNSIGNED spend, sign it (the
//! client-signer role, TEST-ONLY here), and submit it to the in-process Chia simulator — proving an
//! engine-built option spend actually validates on chain and moves value to the right parties.
//!
//! The engine still never signs and never holds a key: it is driven through the public
//! [`SpendInputs`] seam exactly as dig-node drives it; the secret lives only in this test bridge.
#![cfg(feature = "engine")]

use std::sync::Arc;

use chia::bls::PublicKey;
use chia::protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_sdk_test::{sign_transaction, Simulator};
use chia_wallet_sdk::driver::{Cat, SpendContext};
use dig_options::{create, OptionTerms, OptionType, Owner};

use dig_wallet_backend::engine::build::{SdkSpendBuilder, SpendInputs};
use dig_wallet_backend::engine::build_options::OptionBuilder;
use dig_wallet_backend::types::{
    Amount, AssetId, ExerciseOptionRequest, IdentityRef, Network, OptionHandle, OptionOnChainState,
    OptionStrike, Puzzlehash, TransferOptionRequest, WalletId, WalletResult, WireCoin,
};

const EXPIRY: u64 = 10_000;

/// A public-material spend-input provider backed by simulator coins + one wallet keypair's PUBLIC
/// key. Mirrors how dig-node injects public inputs into the engine — no secret enters here.
struct SimInputs {
    xch: Vec<Coin>,
    puzzle_hash: Bytes32,
    public_key: PublicKey,
}

impl SpendInputs for SimInputs {
    fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<Coin>> {
        Ok(self.xch.clone())
    }
    fn spendable_cat(&self, _: &IdentityRef, _: &AssetId) -> WalletResult<Vec<Cat>> {
        Ok(vec![])
    }
    fn synthetic_key(&self, puzzle_hash: Bytes32) -> Option<PublicKey> {
        (puzzle_hash == self.puzzle_hash).then_some(self.public_key)
    }
    fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<Bytes32> {
        Ok(self.puzzle_hash)
    }
}

fn wire(coin: &Coin) -> WireCoin {
    WireCoin {
        parent_coin_info: hex::encode(coin.parent_coin_info),
        puzzle_hash: hex::encode(coin.puzzle_hash),
        amount: coin.amount,
    }
}

fn program_hex(program: &chia::protocol::Program) -> String {
    hex::encode(Vec::<u8>::from(program.clone()))
}

/// Build the on-chain projection + retained handle for a freshly created option from its create
/// bundle (the parent spend of the option child is inside it), exactly as a chain-reading client
/// would assemble them.
fn projection_from_create(
    coin_spends: &[CoinSpend],
    created: &dig_options::CreatedOption,
    creator_ph: Bytes32,
    owner_ph: Bytes32,
    underlying: u64,
    strike: u64,
) -> (OptionHandle, OptionOnChainState) {
    let parent_id = created.option.coin.parent_coin_info;
    let parent_spend = coin_spends
        .iter()
        .find(|cs| cs.coin.coin_id() == parent_id)
        .expect("the create bundle contains the option child's parent spend");

    let handle = OptionHandle {
        launcher_id: hex::encode(created.option.info.launcher_id),
        creator_puzzle_hash: Puzzlehash(hex::encode(creator_ph)),
        owner_puzzle_hash: Puzzlehash(hex::encode(owner_ph)),
        underlying_amount: Amount(underlying),
        strike: OptionStrike::Xch {
            amount: Amount(strike),
        },
        expiry_seconds: EXPIRY,
        underlying_coin_id: hex::encode(created.underlying_coin.coin_id()),
        funding_coin_id: hex::encode(created.underlying_coin.parent_coin_info),
    };
    let on_chain = OptionOnChainState {
        option_parent_coin: wire(&parent_spend.coin),
        option_parent_puzzle_reveal: program_hex(&parent_spend.puzzle_reveal),
        option_parent_solution: program_hex(&parent_spend.solution),
        underlying_coin: wire(&created.underlying_coin),
    };
    (handle, on_chain)
}

fn total_at(sim: &Simulator, puzzle_hash: Bytes32) -> u64 {
    sim.unspent_coins(puzzle_hash, false)
        .iter()
        .map(|c| c.amount)
        .sum()
}

fn engine(xch: Vec<Coin>, puzzle_hash: Bytes32, public_key: PublicKey) -> SdkSpendBuilder {
    SdkSpendBuilder::new(
        Arc::new(SimInputs {
            xch,
            puzzle_hash,
            public_key,
        }),
        Network::Simulator,
        500,
    )
}

fn identity() -> IdentityRef {
    IdentityRef::new(WalletId(1))
}

#[tokio::test]
async fn engine_exercise_round_trips_on_the_simulator() {
    let mut sim = Simulator::new();
    let mut ctx = SpendContext::new();

    // Alice self-mints an option (creator == holder), locking 1000 + 1-mojo singleton.
    let underlying = 1_000u64;
    let strike = 250u64;
    let alice = sim.bls(underlying + 1);
    let terms = OptionTerms::new(
        alice.puzzle_hash,
        underlying,
        OptionType::Xch { amount: strike },
        EXPIRY,
    );
    let mint = create(&mut ctx, &Owner::Standard(alice.pk), alice.coin, &terms).unwrap();
    let created = mint.created.clone().unwrap();

    let mint_sig = sign_transaction(&mint.coin_spends, std::slice::from_ref(&alice.sk)).unwrap();
    sim.new_transaction(SpendBundle::new(mint.coin_spends.clone(), mint_sig))
        .unwrap();

    let (handle, on_chain) = projection_from_create(
        &mint.coin_spends,
        &created,
        alice.puzzle_hash,
        alice.puzzle_hash,
        underlying,
        strike,
    );

    // The holder funds the strike from a coin at their puzzle hash.
    let strike_coin = sim.new_coin(alice.puzzle_hash, strike);
    let unsigned = engine(vec![strike_coin], alice.puzzle_hash, alice.pk)
        .build_exercise_option(ExerciseOptionRequest {
            identity: identity(),
            handle,
            on_chain,
            fee: Amount(0),
        })
        .await
        .unwrap();

    // Sign as the holder (client-signer role) and submit — consensus MUST accept the full bundle.
    let holder_before = total_at(&sim, alice.puzzle_hash);
    let sig = sign_transaction(&unsigned.coin_spends, &[alice.sk]).unwrap();
    sim.new_transaction(SpendBundle::new(unsigned.coin_spends, sig))
        .unwrap();

    // Self-minted: the holder pays the strike to themselves and reclaims the underlying, netting
    // (underlying - strike-consumed). The key assertion is that consensus accepted the exercise and
    // the unlocked underlying landed back at the holder (not stranded on a settlement coin).
    let holder_after = total_at(&sim, alice.puzzle_hash);
    assert!(
        holder_after >= holder_before + underlying - strike,
        "holder must receive the unlocked underlying (before {holder_before}, after {holder_after})"
    );
}

#[tokio::test]
async fn engine_transfer_then_new_owner_exercises_on_the_simulator() {
    let mut sim = Simulator::new();
    let mut ctx = SpendContext::new();

    let underlying = 1_000u64;
    let strike = 250u64;

    // Alice creates an option owned by BOB; later BOB transfers it to CAROL, who exercises it.
    let alice = sim.bls(underlying + 1);
    let bob = sim.bls(0);
    let carol = sim.bls(0);
    let terms = OptionTerms {
        creator_puzzle_hash: alice.puzzle_hash,
        owner_puzzle_hash: bob.puzzle_hash,
        underlying_amount: underlying,
        strike_type: OptionType::Xch { amount: strike },
        expiry_seconds: EXPIRY,
    };
    let mint = create(&mut ctx, &Owner::Standard(alice.pk), alice.coin, &terms).unwrap();
    let created = mint.created.clone().unwrap();
    let mint_sig = sign_transaction(&mint.coin_spends, &[alice.sk]).unwrap();
    sim.new_transaction(SpendBundle::new(mint.coin_spends.clone(), mint_sig))
        .unwrap();

    let (handle, on_chain) = projection_from_create(
        &mint.coin_spends,
        &created,
        alice.puzzle_hash,
        bob.puzzle_hash,
        underlying,
        strike,
    );

    // BOB transfers the option to CAROL through the engine, then signs + submits.
    let transfer_unsigned = engine(vec![], bob.puzzle_hash, bob.pk)
        .build_transfer_option(TransferOptionRequest {
            identity: identity(),
            handle: handle.clone(),
            on_chain,
            to_puzzle_hash: Puzzlehash(hex::encode(carol.puzzle_hash)),
            fee: Amount(0),
        })
        .await
        .unwrap();
    let sig = sign_transaction(&transfer_unsigned.coin_spends, &[bob.sk]).unwrap();
    sim.new_transaction(SpendBundle::new(transfer_unsigned.coin_spends, sig))
        .unwrap();

    // The re-homed option now lives at carol's puzzle hash. Rebuild its projection from the transfer
    // spend so carol can exercise it: parse the transferred singleton's parent (the pre-transfer
    // option coin) which was just spent.
    let transferred_parent = created.option.coin;
    let (parent_puzzle, parent_solution) = sim
        .puzzle_and_solution(transferred_parent.coin_id())
        .expect("the pre-transfer option coin was spent by the transfer");
    let carol_on_chain = OptionOnChainState {
        option_parent_coin: wire(&transferred_parent),
        option_parent_puzzle_reveal: program_hex(&parent_puzzle),
        option_parent_solution: program_hex(&parent_solution),
        underlying_coin: wire(&created.underlying_coin),
    };
    let carol_handle = OptionHandle {
        owner_puzzle_hash: Puzzlehash(hex::encode(carol.puzzle_hash)),
        ..handle
    };

    // Carol funds + exercises the transferred option; alice (original creator) receives the strike.
    let strike_coin = sim.new_coin(carol.puzzle_hash, strike);
    let creator_before = total_at(&sim, alice.puzzle_hash);
    let carol_before = total_at(&sim, carol.puzzle_hash);
    let exercise_unsigned = engine(vec![strike_coin], carol.puzzle_hash, carol.pk)
        .build_exercise_option(ExerciseOptionRequest {
            identity: identity(),
            handle: carol_handle,
            on_chain: carol_on_chain,
            fee: Amount(0),
        })
        .await
        .unwrap();
    let sig = sign_transaction(&exercise_unsigned.coin_spends, &[carol.sk]).unwrap();
    sim.new_transaction(SpendBundle::new(exercise_unsigned.coin_spends, sig))
        .unwrap();

    assert_eq!(
        total_at(&sim, alice.puzzle_hash) - creator_before,
        strike,
        "the original creator receives the strike after the transferred exercise"
    );
    assert!(
        total_at(&sim, carol.puzzle_hash) > carol_before,
        "the new owner receives the unlocked underlying"
    );
}
