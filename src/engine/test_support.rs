//! Shared test fixtures for the engine spend builders.
//!
//! One wallet key, one puzzle hash, one input provider — used by BOTH `build` and
//! `build_extended` so the two suites cannot drift into disagreeing about what a wallet coin is.
//! Test-only (`#[cfg(test)]`), and deliberately key-FREE: the "wallet key" is the BLS12-381 G1
//! generator, so no secret material is named anywhere under `src/engine` (SPEC §1.4).

use std::sync::Arc;

use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::standard::StandardArgs;
use chia_wallet_sdk::driver::{Cat, SpendContext};
use chia_wallet_sdk::types::Conditions;
use chia_wallet_sdk::utils::Address as Bech32Address;

use super::build::{SdkSpendBuilder, SpendInputs};
use crate::types::{
    Address, Amount, AssetId, IdentityRef, Network, SendCatRequest, WalletId, WalletResult,
};

/// The BLS12-381 G1 generator, compressed — a valid, non-infinity public key. Used to curry
/// a standard puzzle in tests WITHOUT any secret material (the key-isolation invariant
/// forbids naming a secret type anywhere under `src/engine`). Deriving it from the generator
/// keeps the value self-explanatory and avoids a bare literal being read as a key.
pub fn test_public_key() -> PublicKey {
    let mut generator = [0u8; 48];
    generator[0] = 0x97;
    generator[1] = 0xf1;
    generator[2] = 0xd3;
    generator[3] = 0xa7;
    generator[4] = 0x31;
    generator[5] = 0x97;
    generator[6] = 0xd7;
    generator[7] = 0x94;
    generator[8] = 0x26;
    generator[9] = 0x95;
    generator[10] = 0x63;
    generator[11] = 0x8c;
    generator[12] = 0x4f;
    generator[13] = 0xa9;
    generator[14] = 0xac;
    generator[15] = 0x0f;
    generator[16] = 0xc3;
    generator[17] = 0x68;
    generator[18] = 0x8c;
    generator[19] = 0x4f;
    generator[20] = 0x97;
    generator[21] = 0x74;
    generator[22] = 0xb9;
    generator[23] = 0x05;
    generator[24] = 0xa1;
    generator[25] = 0x4e;
    generator[26] = 0x3a;
    generator[27] = 0x3f;
    generator[28] = 0x17;
    generator[29] = 0x1b;
    generator[30] = 0xac;
    generator[31] = 0x58;
    generator[32] = 0x6c;
    generator[33] = 0x55;
    generator[34] = 0xe8;
    generator[35] = 0x3f;
    generator[36] = 0xf9;
    generator[37] = 0x7a;
    generator[38] = 0x1a;
    generator[39] = 0xef;
    generator[40] = 0xfb;
    generator[41] = 0x3a;
    generator[42] = 0xf0;
    generator[43] = 0x0a;
    generator[44] = 0xdb;
    generator[45] = 0x22;
    generator[46] = 0xc6;
    generator[47] = 0xbb;
    PublicKey::from_bytes(&generator).expect("valid G1 generator")
}

/// The standard-layer puzzle hash the test key controls.
pub fn wallet_puzzle_hash() -> Bytes32 {
    Bytes32::from(StandardArgs::curry_tree_hash(test_public_key()).to_bytes())
}

/// A coin at the wallet's puzzle hash, distinguished by `seed` and holding `amount`.
pub fn wallet_coin(amount: u64, seed: u8) -> Coin {
    Coin::new(Bytes32::new([seed; 32]), wallet_puzzle_hash(), amount)
}

/// Issue a real CAT owned by the test wallet key and return its spendable coin.
///
/// Uses chia-wallet-sdk's genesis-by-coin-id issuance in a throwaway context to mint a valid
/// [`Cat`] (with lineage proof + inner p2 puzzle hash = the wallet key) that the CAT-send
/// builder can spend — no simulator, no secret material.
pub fn issued_cat(amount: u64) -> Cat {
    let mut ctx = SpendContext::new();
    let genesis = wallet_coin(amount, 42);
    let hint = ctx.hint(wallet_puzzle_hash()).unwrap();
    let create = Conditions::new().create_coin(wallet_puzzle_hash(), amount, hint);
    let (_, cats) =
        Cat::single_issuance(&mut ctx, genesis.coin_id(), None, amount, create).unwrap();
    cats[0]
}

/// A test input provider: canned XCH + CAT coins at the wallet key, and that one synthetic key.
pub struct TestInputs {
    pub xch: Vec<Coin>,
    pub cats: Vec<Cat>,
}

impl TestInputs {
    /// An input provider with no coins — for tests that only exercise the network domain.
    pub fn empty() -> Self {
        TestInputs {
            xch: vec![],
            cats: vec![],
        }
    }
}

impl SpendInputs for TestInputs {
    fn spendable_xch(&self, _: &IdentityRef) -> WalletResult<Vec<Coin>> {
        Ok(self.xch.clone())
    }
    fn spendable_cat(&self, _: &IdentityRef, _: &AssetId) -> WalletResult<Vec<Cat>> {
        Ok(self.cats.clone())
    }
    fn synthetic_key(&self, puzzle_hash: Bytes32) -> Option<PublicKey> {
        (puzzle_hash == wallet_puzzle_hash()).then(test_public_key)
    }
    fn change_puzzle_hash(&self, _: &IdentityRef) -> WalletResult<Bytes32> {
        Ok(wallet_puzzle_hash())
    }
}

pub fn builder(xch: Vec<Coin>) -> SdkSpendBuilder {
    builder_with_cats(xch, vec![])
}

pub fn builder_with_cats(xch: Vec<Coin>, cats: Vec<Cat>) -> SdkSpendBuilder {
    SdkSpendBuilder::new(Arc::new(TestInputs { xch, cats }), Network::Mainnet, 500)
}

pub fn cat_request(asset: &str, amount: u64, fee: u64) -> SendCatRequest {
    SendCatRequest {
        identity: IdentityRef::new(WalletId(1)),
        asset_id: AssetId(asset.into()),
        to: recipient(),
        amount: Amount(amount),
        fee: Amount(fee),
    }
}

/// A valid mainnet address (a real xch1… bech32m) for the recipient.
pub fn recipient() -> Address {
    let ph = Bytes32::new([7u8; 32]);
    Address(Bech32Address::new(ph, "xch".into()).encode().unwrap())
}
