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

use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_sdk_test::{sign_transaction, Simulator};
use chia_wallet_sdk::driver::{Cat, SpendContext, StandardLayer};
use chia_wallet_sdk::types::Conditions;
use dig_options::{create, OptionTerms, OptionType, Owner};

use dig_wallet_backend::client::verify::analyze;
use dig_wallet_backend::engine::build::{SdkSpendBuilder, SpendInputs};
use dig_wallet_backend::engine::build_options::OptionBuilder;
use dig_wallet_backend::types::{
    Amount, AssetId, ExerciseOptionRequest, IdentityRef, Network, OptionHandle, OptionOnChainState,
    OptionStrike, Puzzlehash, TransferOptionRequest, WalletErrorCode, WalletId, WalletResult,
    WireCoin,
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

fn program_hex(program: &chia_protocol::Program) -> String {
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

// ---- #1511 PR-C Case-A signature-source guards: melt/exercise refused, transfer allowlisted. ----
//
// The consensus PROOF these guards rely on is SDK `option_contract.rs::test_incomplete_exercise`
// (the mode-23 `SEND_MESSAGE` ⟺ singleton `MeltSingleton` are inseparable on chain: message-without-
// melt AND melt-without-message both consensus-REJECT) + `test_transfer_option` (a plain re-home
// transfer succeeds). Consensus therefore already makes "any singleton spend unlocks the underlying"
// impossible; the ONLY residual risk is the WALLET being tricked into SIGNING the melting/message-
// bearing leg. These tests exercise that risk through the real `client::verify::analyze` seam the
// signer gates on: an `Err` there is the signer refusing (producing ZERO signatures).

/// Mint a self-owned (creator == owner) option in `ctx`, funded by `funding`, and drain the mint
/// spends from `ctx` so a subsequent `ctx.take()` yields ONLY the option action under test. The
/// returned `created.option` is spendable directly through the SDK driver (`analyze` never checks
/// lineage validity, only the decoded value flow + condition allowlist).
fn create_self_option(
    ctx: &mut SpendContext,
    pk: PublicKey,
    funding: Coin,
    puzzle_hash: Bytes32,
) -> dig_options::CreatedOption {
    let terms = OptionTerms::new(puzzle_hash, 1_000, OptionType::Xch { amount: 250 }, EXPIRY);
    let mint = create(ctx, &Owner::Standard(pk), funding, &terms).unwrap();
    let created = mint.created.clone().unwrap();
    let _ = ctx.take(); // discard the mint spends; keep only the action-under-test
    created
}

/// RED (Finding 1): an option EXERCISE that MELTS the singleton + emits the mode-23 `SEND_MESSAGE`,
/// with the `P2OneOfMany` underlying leg OMITTED from the bundle (the strip-the-leg attack), must be
/// refused at the signature source — the non-re-home refusal, NOT the leg-presence check. Before the
/// Finding-1 fix the melt/else-branch fell through and `analyze` returned `Ok`, letting the wallet
/// sign the leg that unlocks the underlying.
#[test]
fn exercise_stripped_underlying_leg_is_refused() {
    let mut sim = Simulator::new();
    let mut ctx = SpendContext::new();
    let alice = sim.bls(1_001);
    let created = create_self_option(&mut ctx, alice.pk, alice.coin, alice.puzzle_hash);

    // Spend the option singleton ALONE (melt + mode-23 exercise message); no underlying leg present.
    let inner = StandardLayer::new(alice.pk);
    created
        .option
        .exercise(&mut ctx, &inner, Conditions::new())
        .unwrap();
    let spends = ctx.take();

    let err = analyze(&spends).expect_err("a melting option-singleton spend must be refused");
    assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
}

/// Regression (defense in depth): the SAME exercise WITH the `P2OneOfMany` underlying leg present —
/// the full engine-built exercise bundle — stays refused. Both the Finding-1 melt-branch refusal and
/// the pre-existing `P2OneOfManyLayer` refusal cover it; either firing yields the fail-closed verdict.
#[tokio::test]
async fn exercise_with_underlying_leg_is_refused() {
    let mut sim = Simulator::new();
    let mut ctx = SpendContext::new();
    let (underlying, strike) = (1_000u64, 250u64);
    let alice = sim.bls(underlying + 1);
    let terms = OptionTerms::new(
        alice.puzzle_hash,
        underlying,
        OptionType::Xch { amount: strike },
        EXPIRY,
    );
    let mint = create(&mut ctx, &Owner::Standard(alice.pk), alice.coin, &terms).unwrap();
    let created = mint.created.clone().unwrap();
    let (handle, on_chain) = projection_from_create(
        &mint.coin_spends,
        &created,
        alice.puzzle_hash,
        alice.puzzle_hash,
        underlying,
        strike,
    );

    let strike_coin = sim.new_coin(alice.puzzle_hash, strike);
    let unsigned = engine(vec![strike_coin], alice.puzzle_hash, alice.pk)
        .build_exercise_option(ExerciseOptionRequest {
            identity: identity(),
            handle,
            on_chain,
            fee: Amount(0),
        })
        .await
        .expect("the engine still builds a valid exercise bundle");

    let err = analyze(&unsigned.coin_spends).expect_err("an exercise bundle must be refused");
    assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
}

/// RED (guard b): a re-homing TRANSFER whose delegated puzzle ALSO carries the mode-23 exercise
/// `SEND_MESSAGE` must be refused by the transfer allowlist. Before the allowlist the transfer branch
/// only looked at `CREATE_COIN`s and ignored the message, so `analyze` returned `Ok` — a transfer
/// signature that also authorizes the underlying-unlocking message.
#[test]
fn transfer_delegated_puzzle_carrying_exercise_message_is_refused() {
    let mut sim = Simulator::new();
    let mut ctx = SpendContext::new();
    let alice = sim.bls(1_001);
    let created = create_self_option(&mut ctx, alice.pk, alice.coin, alice.puzzle_hash);

    let inner = StandardLayer::new(alice.pk);
    let destination = Bytes32::new([0x9a; 32]);
    let data = ctx.alloc(&created.option.info.underlying_coin_id).unwrap();
    let smuggled = Conditions::new().send_message(
        23,
        created.option.info.underlying_delegated_puzzle_hash.into(),
        vec![data],
    );
    let _rehomed = created
        .option
        .transfer(&mut ctx, &inner, destination, smuggled)
        .unwrap();
    let spends = ctx.take();

    let err =
        analyze(&spends).expect_err("a transfer carrying the exercise message must be refused");
    assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
}

/// GREEN control: a clean re-home transfer (no message, no melt) still analyzes cleanly, signs, and
/// SETTLES on the simulator — proving the two guards do not over-refuse the one signable option
/// action. Mirrors SDK `test_transfer_option`.
#[tokio::test]
async fn plain_transfer_still_signs() {
    let mut sim = Simulator::new();
    let mut ctx = SpendContext::new();
    let (underlying, strike) = (1_000u64, 250u64);
    let alice = sim.bls(underlying + 1);
    let bob = sim.bls(0);
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

    let unsigned = engine(vec![], alice.puzzle_hash, alice.pk)
        .build_transfer_option(TransferOptionRequest {
            identity: identity(),
            handle,
            on_chain,
            to_puzzle_hash: Puzzlehash(hex::encode(bob.puzzle_hash)),
            fee: Amount(0),
        })
        .await
        .unwrap();

    // The transfer allowlist must NOT over-refuse a clean re-home.
    analyze(&unsigned.coin_spends).expect("a clean option transfer analyzes cleanly");
    let sig = sign_transaction(&unsigned.coin_spends, &[alice.sk]).unwrap();
    sim.new_transaction(SpendBundle::new(unsigned.coin_spends, sig))
        .expect("a clean option transfer must settle on the simulator");
}

/// #2249 (headline): the offer settlement-binding pass is enforced PER-EGRESS regardless of option
/// mode. A bundle that carries a legitimate option TRANSFER (which flips `option_mode` on merely by
/// spending an option-layer coin) PLUS an UNRELATED standard coin dumping value into a settlement
/// sink with NO offer-binding announcement must be REFUSED — the standard coin's un-bound egress is
/// a give-it-away-for-nothing leg, and the mere presence of an option coin does NOT exempt it.
///
/// This pins the property that #2241 established (the whole-bundle `if !option_mode { skip }` was
/// replaced by an unconditional bundle-level pass): an attacker cannot include any option-layer coin
/// to disable MR-6 binding on a standard coin. The only leg that legitimately carries no
/// offer-binding (the consensus-forced option exercise strike) never reaches this pass — exercise is
/// refused fail-closed at the signature source — so no exemption is needed here.
#[tokio::test]
async fn unbound_settlement_sink_beside_an_option_transfer_is_refused_2249() {
    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::puzzles::SETTLEMENT_PAYMENT_HASH;

    let mut sim = Simulator::new();
    let mut ctx = SpendContext::new();
    let (underlying, strike) = (1_000u64, 250u64);
    let alice = sim.bls(underlying + 1);
    let bob = sim.bls(0);
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

    // A real, clean option transfer — flips `option_mode` on for the whole bundle.
    let unsigned = engine(vec![], alice.puzzle_hash, alice.pk)
        .build_transfer_option(TransferOptionRequest {
            identity: identity(),
            handle,
            on_chain,
            to_puzzle_hash: Puzzlehash(hex::encode(bob.puzzle_hash)),
            fee: Amount(0),
        })
        .await
        .unwrap();
    let mut spends = unsigned.coin_spends;

    // Splice in an UNRELATED standard coin that dumps its whole value into the settlement puzzle with
    // NO announcement — the give-it-away-for-nothing egress an attacker would smuggle beside the
    // option coin to exploit any `option_mode` binding skip.
    let sink_coin = sim.new_coin(alice.puzzle_hash, 50_000);
    StandardLayer::new(alice.pk)
        .spend(
            &mut ctx,
            sink_coin,
            Conditions::new().create_coin(
                Bytes32::new(SETTLEMENT_PAYMENT_HASH),
                50_000,
                Memos::None,
            ),
        )
        .unwrap();
    spends.extend(ctx.take());

    let err = analyze(&spends)
        .expect_err("an unbound settlement sink beside an option transfer must be refused");
    assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
}

// ---- #2285: dedicated teeth for the untested `analyze` custody refusal branches. ----
//
// Each test constructs the MINIMAL spend that reaches one refusal guard and asserts the SPECIFIC
// error (message substring), so a future edit that removes/weakens the guard turns the test RED. All
// are additive TEST-ONLY coverage — no production code changes.

/// #2285 (branch 1, ref #2245): an option EXERCISE's locked-underlying leg — a bare `P2OneOfManyLayer`
/// (1-of-2 exercise/clawback) coin — is refused fail-closed as "not signable", REGARDLESS of whether
/// the option singleton is present in the bundle (defeating the strip-the-leg attack). Constructs the
/// `P2OneOfManyLayer` puzzle directly, pins the coin's committed hash to it (so the #1518 puzzle-reveal
/// bind passes), and spends it alone — reaching the dedicated `P2OneOfManyLayer` refusal in the
/// dispatch (distinct from the melt/non-re-home refusal the exercise-bundle tests cover).
#[test]
fn a_bare_p2_one_of_many_underlying_leg_is_refused_2285() {
    use chia_wallet_sdk::driver::{Layer, P2OneOfManyLayer};
    use clvm_utils::tree_hash;
    use clvmr::serde::node_to_bytes;

    let mut ctx = SpendContext::new();
    let layer = P2OneOfManyLayer::new(Bytes32::new([0x5a; 32]));
    let puzzle_ptr = layer.construct_puzzle(&mut ctx).unwrap();
    let puzzle_reveal = node_to_bytes(&ctx, puzzle_ptr).unwrap();
    // The coin must commit to exactly the revealed puzzle's hash (the #1518 bind), else `analyze`
    // refuses on the substituted-puzzle guard instead of the branch under test.
    let committed = Bytes32::new(tree_hash(&ctx, puzzle_ptr).to_bytes());
    let coin = Coin::new(Bytes32::new([0x11; 32]), committed, 1);
    let spend = CoinSpend::new(coin, puzzle_reveal.into(), vec![0x80].into());

    let err = analyze(&[spend]).expect_err("a bare P2OneOfMany underlying leg must be refused");
    assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    assert!(
        err.message.contains("option exercise is not signable"),
        "got: {}",
        err.message
    );
}

/// #2285 (branch 3): an option-singleton spend whose INNER p2 puzzle is not a standard layer is refused
/// — a transfer is signable only because it touches the inner STANDARD layer to re-home; a foreign
/// inner puzzle's authorized flow cannot be verified. Spends the singleton via `OptionContract::spend`
/// with an identity inner puzzle (`1`) that emits an odd re-home `CREATE_COIN` (so it decodes down the
/// transfer path), reaching the inner-not-standard refusal.
#[test]
fn option_singleton_with_a_non_standard_inner_is_refused_2285() {
    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::driver::Spend;
    use clvm_utils::tree_hash;

    let mut sim = Simulator::new();
    let mut ctx = SpendContext::new();
    let alice = sim.bls(1_001);
    let created = create_self_option(&mut ctx, alice.pk, alice.coin, alice.puzzle_hash);

    // Re-home the option's p2 onto an identity puzzle (`1`, which returns its solution) so the coin's
    // committed puzzle hash wraps the NON-standard inner — the #1518 puzzle-reveal bind then passes and
    // `analyze` reaches the inner-not-a-standard-layer refusal (not the substituted-puzzle guard).
    let inner_puzzle = ctx.alloc(&1).unwrap();
    let inner_hash = Bytes32::new(tree_hash(&ctx, inner_puzzle).to_bytes());
    let option = created.option.child(inner_hash, 1);
    let inner_solution = ctx
        .alloc(&Conditions::new().create_coin(Bytes32::new([0x77; 32]), 1, Memos::None))
        .unwrap();
    let _ = option
        .spend(&mut ctx, Spend::new(inner_puzzle, inner_solution))
        .unwrap();
    let spends = ctx.take();

    let err = analyze(&spends).expect_err("a non-standard option inner puzzle must be refused");
    assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    assert!(
        err.message
            .contains("option singleton inner puzzle is not a standard layer"),
        "got: {}",
        err.message
    );
}

/// #2285 (branch 4): an option TRANSFER whose delegated puzzle emits MORE THAN ONE `CREATE_COIN` — an
/// undisclosed extra egress riding the re-home — is refused. Builds a clean re-home transfer, then
/// splices in a SECOND (even-amount, non-sink) `CREATE_COIN` through the extra conditions; the
/// single-re-home count guard fires.
#[test]
fn option_transfer_with_a_second_create_coin_is_refused_2285() {
    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::driver::StandardLayer;

    let mut sim = Simulator::new();
    let mut ctx = SpendContext::new();
    let alice = sim.bls(1_001);
    let created = create_self_option(&mut ctx, alice.pk, alice.coin, alice.puzzle_hash);

    let inner = StandardLayer::new(alice.pk);
    let extra = Conditions::new().create_coin(Bytes32::new([0x88; 32]), 2, Memos::None);
    let _ = created
        .option
        .transfer(&mut ctx, &inner, Bytes32::new([0x77; 32]), extra)
        .unwrap();
    let spends = ctx.take();

    let err = analyze(&spends).expect_err("a second CREATE_COIN on a transfer must be refused");
    assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    assert!(
        err.message.contains("more than one CREATE_COIN"),
        "got: {}",
        err.message
    );
}

/// #2285 (branch 5, MR-12): an option TRANSFER that re-homes the singleton to a canonical STRUCTURAL
/// puzzle hash (here the settlement-payments hash) — an unauthorized re-home laundered as a protocol
/// sink — is refused. A legitimate transfer re-homes to the new owner's chosen p2 the human reviews,
/// never to a structural hash.
#[test]
fn option_transfer_to_a_structural_sink_hash_is_refused_2285() {
    use chia_wallet_sdk::driver::StandardLayer;
    use chia_wallet_sdk::puzzles::SETTLEMENT_PAYMENT_HASH;

    let mut sim = Simulator::new();
    let mut ctx = SpendContext::new();
    let alice = sim.bls(1_001);
    let created = create_self_option(&mut ctx, alice.pk, alice.coin, alice.puzzle_hash);

    let inner = StandardLayer::new(alice.pk);
    let _ = created
        .option
        .transfer(
            &mut ctx,
            &inner,
            Bytes32::new(SETTLEMENT_PAYMENT_HASH),
            Conditions::new(),
        )
        .unwrap();
    let spends = ctx.take();

    let err = analyze(&spends).expect_err("a re-home to a structural hash must be refused");
    assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    assert!(
        err.message.contains("structural puzzle hash"),
        "got: {}",
        err.message
    );
}

/// #2285 (branch 6): in OPTION mode conservation is `in − out` (the implicit fee); an option spend
/// whose outputs EXCEED its inputs would mint value, so `checked_sub` returning `None` is refused. The
/// 1-mojo option singleton is re-homed with an odd `CREATE_COIN` of amount 3 (> the 1-mojo input),
/// minting 2 mojos — reaching the mint refusal in the `analyze` conservation epilogue.
#[test]
fn option_spend_that_mints_value_is_refused_2285() {
    use chia_puzzle_types::Memos;
    use chia_wallet_sdk::driver::StandardLayer;

    let mut sim = Simulator::new();
    let mut ctx = SpendContext::new();
    let alice = sim.bls(1_001);
    let created = create_self_option(&mut ctx, alice.pk, alice.coin, alice.puzzle_hash);

    let inner = StandardLayer::new(alice.pk);
    let _ = created
        .option
        .spend_with(
            &mut ctx,
            &inner,
            Conditions::new().create_coin(Bytes32::new([0x77; 32]), 3, Memos::None),
        )
        .unwrap();
    let spends = ctx.take();

    let err = analyze(&spends).expect_err("an option spend minting value must be refused");
    assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    assert!(
        err.message.contains("option spend mints value"),
        "got: {}",
        err.message
    );
}
