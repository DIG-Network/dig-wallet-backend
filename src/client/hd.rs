//! `client::hd` — the master-HD → profile key derivation (#997), behind the client seam.
//!
//! The wallet has a single master HD key (a BIP-39 seed) from which every profile's keys
//! derive deterministically. `IdentityRef.profile_ix` selects a profile via the hardened path
//!
//! ```text
//! m / 44' / 8444' / {profile_ix}'
//! ```
//!
//! (BIP-32/44 hardened, Chia's SLIP-44 coin type 8444 — the #997 model). Each profile's
//! receive/signing keys are unhardened children of that profile account node.
//!
//! # Key isolation + custody
//! Everything here lives behind the `client` feature (the only place secret material compiles in,
//! SPEC §1.4). The master seed is held in a [`Zeroizing`] buffer so it is wiped on drop; no
//! `Debug`, `Serialize`, or `Clone` that would expose the secret is derived on [`MasterKey`].
//!
//! # At-rest storage is dig-keystore's job (#1024)
//! This module does NOT persist or encrypt the seed — that is `dig-keystore`'s responsibility.
//! The [`MasterKeySource`] trait is the seam boundary: #1024 implements it over
//! `dig_keystore::Keystore<L1WalletBls>` (unlock → `expose_secret` → the master seed). Defining
//! the trait here lets the signer be built + tested against a key source without hand-rolling a
//! keystore.

use chia::bls::{master_to_wallet_unhardened, DerivableKey, PublicKey, SecretKey};
use chia::puzzles::DeriveSynthetic;
use zeroize::Zeroizing;

use crate::types::{WalletError, WalletResult};

/// BIP-44 purpose index for the DIG profile derivation path (#997: `m/44'/8444'/…`).
const PURPOSE: u32 = 44;

/// Chia's registered SLIP-44 coin type — the second hardened level of the #997 path.
const CHIA_COIN_TYPE: u32 = 8444;

/// How many unhardened receive-address keys are derived under a profile when matching the
/// public keys a spend requires (the address gap limit). A required signature whose key is not
/// found within this window cannot be signed (fail-closed).
pub const DEFAULT_ADDRESS_GAP: u32 = 100;

/// The wallet's master HD key material — the root every profile key derives from.
///
/// Holds the BIP-39 seed bytes in a [`Zeroizing`] buffer (wiped on drop). Deliberately does NOT
/// implement `Debug`, `Serialize`, or `Clone`: the secret never leaves this value except as
/// derived keys the signer uses in-place.
pub struct MasterKey {
    seed: Zeroizing<Vec<u8>>,
}

impl MasterKey {
    /// Wrap raw master-seed bytes (the value `dig-keystore` unlocks). The bytes are moved into a
    /// zeroizing buffer; the caller's copy should itself be zeroizing.
    pub fn from_seed_bytes(seed: impl Into<Vec<u8>>) -> Self {
        Self {
            seed: Zeroizing::new(seed.into()),
        }
    }

    /// The EIP-2333 master signing key (`SecretKey::from_seed`). Transient — used to derive.
    fn master(&self) -> SecretKey {
        SecretKey::from_seed(&self.seed)
    }

    /// Derive the account node for `profile_ix`: `m/44'/8444'/{profile_ix}'` (all hardened).
    ///
    /// Hardened at every level so a leaked child/public key cannot be used to reconstruct a
    /// sibling profile's keys.
    pub fn profile_account_key(&self, profile_ix: u32) -> SecretKey {
        self.master()
            .derive_hardened(PURPOSE)
            .derive_hardened(CHIA_COIN_TYPE)
            .derive_hardened(profile_ix)
    }

    /// The public key of a profile's account node — public material safe to hand the engine.
    pub fn profile_public_key(&self, profile_ix: u32) -> PublicKey {
        self.profile_account_key(profile_ix).public_key()
    }

    /// Derive a profile's receive/signing key at `address_ix` (unhardened child of the account
    /// node), so the matching public keys can be advertised for tracking without exposing the
    /// account secret.
    pub fn address_key(&self, profile_ix: u32, address_ix: u32) -> SecretKey {
        self.profile_account_key(profile_ix)
            .derive_unhardened(address_ix)
    }

    /// The public key of a profile's receive address at `address_ix`.
    pub fn address_public_key(&self, profile_ix: u32, address_ix: u32) -> PublicKey {
        self.address_key(profile_ix, address_ix).public_key()
    }

    /// Derive the CANONICAL Chia wallet SIGNING (money) key at wallet index `index`:
    /// `master_to_wallet_unhardened(master, index).derive_synthetic()` — the unhardened wallet child
    /// `m/12381/8444/2/index`, made synthetic against the canonical `DEFAULT_HIDDEN_PUZZLE_HASH`.
    ///
    /// This is the ONE derivation that controls real funds: the SYNTHETIC public key is what curries
    /// the standard transaction puzzle, so its puzzle-tree-hash is the wallet's on-chain XCH address.
    /// It is byte-identical to dig-account's `WalletKey` (`master_to_wallet_unhardened(seed, ix)
    /// .derive_synthetic()`), the pre-cutover dig-app `WalletKey`, and every standard Chia wallet
    /// (incl. Sage) — so a spend the money-signer authorizes lands at the SAME address every other
    /// wallet reading the same seed sees. This is DISTINCT from the legacy profile path
    /// [`address_key`](MasterKey::address_key) (`m/44'/8444'/…`), which is a different, never-funded
    /// key set; wiring a consumer's money spends over that legacy path fund-LOCKS coins at the
    /// canonical address (see the cross-round-trip golden in tests).
    ///
    /// Derived transiently per call so no long-lived copy of the money key is held.
    pub fn wallet_signing_key(&self, index: u32) -> SecretKey {
        master_to_wallet_unhardened(&self.master(), index).derive_synthetic()
    }

    /// The SYNTHETIC public key of the canonical wallet money key at `index` — the key that curries
    /// the standard puzzle (and therefore identifies the wallet's on-chain address). Public material.
    pub fn wallet_public_key(&self, index: u32) -> PublicKey {
        self.wallet_signing_key(index).public_key()
    }

    /// The dig-identity secret key at the canonical hardened path `m/12381'/8444'/9'/0'`
    /// (dig-identity SPEC §6a.1). This is a SINGLE per-wallet key — DISTINCT from the Chia wallet
    /// keys ([`address_key`](MasterKey::address_key), coin index `2`): it secures no coins, only the
    /// identity. Its G1 public key is the 48-byte value published to slot `0x0010`.
    ///
    /// Kept module-private: the raw scalar never escapes this crate. Callers reach it only through
    /// [`identity_public_key_bytes`](MasterKey::identity_public_key_bytes) (public material) or
    /// [`identity_dh`](MasterKey::identity_dh) (the DECAP, which returns the shared secret, never the
    /// scalar). Derived transiently per call so no long-lived copy of the key is held.
    fn identity_secret_key(&self) -> SecretKey {
        let master = dig_identity::master_secret_key_from_seed(&self.seed);
        dig_identity::derive_identity_sk(&master)
    }

    /// The 48-byte compressed BLS12-381 **G1** identity public key (the value published to slot
    /// `0x0010`). Public material — safe to advertise. This is the key a sender seals a dig-message
    /// to, and the key this holder DECAPs against in [`identity_dh`](MasterKey::identity_dh).
    pub fn identity_public_key_bytes(&self) -> [u8; 48] {
        dig_identity::public_key_bytes(&self.identity_secret_key())
    }

    /// The recipient DECAP of a dig-message seal: the G1-ECDH `dh(identity_sk, peer_g1) =
    /// identity_sk · peer_g1`, returning the 48-byte compressed shared G1 point for the KEM/KDF
    /// (dig-identity SPEC §6a.2). This is a DH operation, NOT a signature — the ONE identity key does
    /// both, on path-disjoint, group-separated primitives (sign = G2, DH = G1).
    ///
    /// # Custody
    /// `peer_g1` is subgroup- and non-identity-checked BEFORE the scalar multiplication (inside
    /// [`dig_identity::g1_dh`]), so a malformed / off-curve / small-subgroup / identity peer point is
    /// rejected fail-closed and can never be used to recover bits of the identity scalar (invalid-curve
    /// / small-subgroup key-recovery defense). Only the intended shared secret is ever returned; the
    /// raw scalar is not exposed.
    pub fn identity_dh(&self, peer_g1: &[u8; 48]) -> WalletResult<[u8; 48]> {
        dig_identity::g1_dh(&self.identity_secret_key(), peer_g1).ok_or_else(|| {
            WalletError::invalid_input(
                "peer G1 point failed the subgroup / non-identity check (decap refused)",
            )
        })
    }
}

/// The seam that yields the unlocked [`MasterKey`] from at-rest storage.
///
/// The client seam does NOT implement at-rest encryption — persistence + decryption is
/// `dig-keystore`'s job (#1024, DIGLW1 / AES-256-GCM / Argon2id). This trait is the boundary
/// #1024 implements over `dig_keystore::Keystore<L1WalletBls>`: unlock the keystore, expose the
/// master seed, and hand back a [`MasterKey`]. Implementations MUST fail-closed on a locked,
/// absent, or corrupt store.
pub trait MasterKeySource: Send + Sync {
    /// Produce the unlocked master key, or a fail-closed error.
    fn master_key(&self) -> WalletResult<MasterKey>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia::bls::{sign as bls_sign, verify as bls_verify};
    use chia::puzzles::standard::StandardArgs;
    use chia_wallet_sdk::utils::Address as Bech32Address;
    use sha2::{Digest, Sha256};

    /// A deterministic 32-byte test seed derived by hashing a label — NOT an integer-literal
    /// key (avoids the CodeQL "hard-coded cryptographic value" finding).
    fn seed_from_label(label: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"dig-wallet-backend/client/hd/test/");
        hasher.update(label.as_bytes());
        hasher.finalize().to_vec()
    }

    #[test]
    fn derivation_is_deterministic_for_same_seed_and_profile() {
        let a = MasterKey::from_seed_bytes(seed_from_label("determinism"));
        let b = MasterKey::from_seed_bytes(seed_from_label("determinism"));
        assert_eq!(
            a.profile_public_key(0).to_bytes(),
            b.profile_public_key(0).to_bytes(),
        );
        assert_eq!(
            a.address_public_key(3, 7).to_bytes(),
            b.address_public_key(3, 7).to_bytes(),
        );
    }

    #[test]
    fn distinct_profiles_yield_distinct_keys() {
        let key = MasterKey::from_seed_bytes(seed_from_label("profiles"));
        let p0 = key.profile_public_key(0).to_bytes();
        let p1 = key.profile_public_key(1).to_bytes();
        assert_ne!(p0, p1, "profile 0 and 1 must derive different keys");
    }

    #[test]
    fn distinct_address_indices_yield_distinct_keys() {
        let key = MasterKey::from_seed_bytes(seed_from_label("addresses"));
        let a0 = key.address_public_key(0, 0).to_bytes();
        let a1 = key.address_public_key(0, 1).to_bytes();
        assert_ne!(a0, a1);
    }

    #[test]
    fn different_seeds_yield_different_keys() {
        let a = MasterKey::from_seed_bytes(seed_from_label("seed-a"));
        let b = MasterKey::from_seed_bytes(seed_from_label("seed-b"));
        assert_ne!(
            a.profile_public_key(0).to_bytes(),
            b.profile_public_key(0).to_bytes(),
        );
    }

    /// Golden vector pinning the #997 path `m/44'/8444'/0'` for a fixed seed. If the derivation
    /// path or algorithm ever changes, this breaks — the whole point (published addresses must
    /// stay reproducible forever). The seed is hashed from a label, not a literal key.
    #[test]
    fn profile_zero_matches_golden_vector() {
        let key = MasterKey::from_seed_bytes(seed_from_label("golden"));
        let hex = hex::encode(key.profile_public_key(0).to_bytes());
        assert_eq!(hex, GOLDEN_PROFILE_0_PUBKEY);
    }

    /// A derived key actually signs + verifies (the account node is a usable BLS key).
    #[test]
    fn derived_key_signs_and_verifies() {
        let key = MasterKey::from_seed_bytes(seed_from_label("sign"));
        let sk = key.address_key(0, 0);
        let pk = sk.public_key();
        let msg = seed_from_label("payload");
        let sig = bls_sign(&sk, &msg);
        assert!(bls_verify(&sig, &pk, &msg));
    }

    // Pinned from the first green run of `profile_zero_matches_golden_vector` — see that test.
    const GOLDEN_PROFILE_0_PUBKEY: &str =
        "8414b105c32eaac1095ad7f54ab41353c252d4567e5859b6cd69303ebcbc4f0ccf75917a70e1e1cbeddb838adbc2ee05";

    // --- Canonical wallet (money) key — CROSS round-trip golden against dig-account -------------
    //
    // The all-`0x42` seed's canonical synthetic wallet key at index 0. These constants are
    // COPIED VERBATIM from dig-account's frozen `WalletKey` golden (crates/40-application/
    // dig-account/src/keys/wallet_key.rs — pk 884cc9a2… / ph e05ec4f5… / addr xch1up0vfat…), the
    // ecosystem's canonical money-key contract. If `wallet_signing_key` ever drifts from that
    // derivation the coins the money-signer controls diverge from where funds actually live (a
    // fund-lock), so this cross-crate vector is the guard.
    const SEED_0X42: [u8; 32] = [0x42; 32];
    const DIG_ACCOUNT_GOLDEN_SYNTHETIC_PK: &str =
        "884cc9a2b28a0aefe62ab1ccc6c5e638e48224d1a18a015260b40587e07c9132e929c3c3c1135494cd11cc70b36d7c34";
    const DIG_ACCOUNT_GOLDEN_PUZZLE_HASH: &str =
        "e05ec4f5685b878461988e9f26d3cb88556942d3c716c176d72eeeddfd9994a3";
    const DIG_ACCOUNT_GOLDEN_ADDRESS: &str =
        "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";

    /// CROSS ROUND-TRIP GOLDEN: the SAME seed produces the SAME synthetic money key + puzzle hash +
    /// address as dig-account's `WalletKey`. This is the release-first contract PR1 exists to hold —
    /// a consumer wiring `WalletOps → LocalSigner` over `wallet_signing_key` controls exactly the
    /// address dig-account (and Sage, and dig-app) computes for the same seed. A mismatch = fund-lock.
    #[test]
    fn wallet_signing_key_matches_dig_account_golden() {
        let key = MasterKey::from_seed_bytes(SEED_0X42);
        let pk = key.wallet_public_key(0);
        assert_eq!(
            hex::encode(pk.to_bytes()),
            DIG_ACCOUNT_GOLDEN_SYNTHETIC_PK,
            "canonical synthetic wallet pubkey drifted from dig-account's WalletKey golden (fund-lock)"
        );
        let puzzle_hash = StandardArgs::curry_tree_hash(pk);
        assert_eq!(
            hex::encode(puzzle_hash.to_bytes()),
            DIG_ACCOUNT_GOLDEN_PUZZLE_HASH,
        );
        let address = Bech32Address::new(puzzle_hash.into(), "xch".to_string())
            .encode()
            .unwrap();
        assert_eq!(address, DIG_ACCOUNT_GOLDEN_ADDRESS);
    }

    /// Non-vacuity: the LEGACY profile path (`m/44'/8444'/0'/0`) — the pre-fix money path — does NOT
    /// match the canonical golden. This is exactly the drift the fix removes: signing a consumer's
    /// money spends over the legacy set locks funds at the canonical address.
    #[test]
    fn legacy_profile_key_does_not_match_the_canonical_golden() {
        let key = MasterKey::from_seed_bytes(SEED_0X42);
        assert_ne!(
            hex::encode(key.address_public_key(0, 0).to_bytes()),
            DIG_ACCOUNT_GOLDEN_SYNTHETIC_PK,
            "legacy profile path must be distinct from the canonical money key (that IS the drift)"
        );
    }

    /// Non-vacuity: dropping `.derive_synthetic()` (the exact pre-fix bug shape) breaks the golden.
    #[test]
    fn dropping_synthetic_breaks_the_canonical_golden() {
        let master = SecretKey::from_seed(&SEED_0X42);
        let non_synthetic = master_to_wallet_unhardened(&master, 0).public_key();
        assert_ne!(
            hex::encode(non_synthetic.to_bytes()),
            DIG_ACCOUNT_GOLDEN_SYNTHETIC_PK,
        );
    }

    /// Distinct wallet indices derive distinct canonical money keys.
    #[test]
    fn distinct_wallet_indices_yield_distinct_canonical_keys() {
        let key = MasterKey::from_seed_bytes(seed_from_label("canon-idx"));
        assert_ne!(
            key.wallet_public_key(0).to_bytes(),
            key.wallet_public_key(1).to_bytes(),
        );
    }

    /// The canonical wallet key actually signs + verifies (it is a usable BLS key).
    #[test]
    fn canonical_wallet_key_signs_and_verifies() {
        let key = MasterKey::from_seed_bytes(seed_from_label("canon-sign"));
        let sk = key.wallet_signing_key(0);
        assert_eq!(sk.public_key(), key.wallet_public_key(0));
        let msg = seed_from_label("canon-payload");
        let sig = bls_sign(&sk, &msg);
        assert!(bls_verify(&sig, &sk.public_key(), &msg));
    }

    // --- G1-ECDH decap (dig-message recipient open) -------------------------------------------

    /// The compressed G1 identity element (point at infinity): 0xc0 flag byte, all coordinate bytes
    /// zero. A DH against it must be refused (§6a.3 non-identity check).
    fn g1_infinity() -> [u8; 48] {
        let mut bytes = [0u8; 48];
        bytes[0] = 0xc0;
        bytes
    }

    /// The identity public key is a valid, non-identity G1 subgroup point (the slot-0x0010 value).
    #[test]
    fn identity_public_key_is_a_valid_g1_point() {
        let key = MasterKey::from_seed_bytes(seed_from_label("id-pub"));
        assert!(dig_identity::g1_subgroup_check(
            &key.identity_public_key_bytes()
        ));
    }

    /// The DECAP round-trip: `dh(our_sk, peer_pub) == dh(peer_sk, our_pub)` — the defining ECDH
    /// symmetry, and exactly dig-identity's `g1_dh` KAT. This is what lets a recipient OPEN what a
    /// sender sealed.
    #[test]
    fn decap_round_trip_is_symmetric() {
        let ours = MasterKey::from_seed_bytes(seed_from_label("rt-ours"));
        let peer = MasterKey::from_seed_bytes(seed_from_label("rt-peer"));

        let we_open = ours.identity_dh(&peer.identity_public_key_bytes()).unwrap();
        let they_open = peer.identity_dh(&ours.identity_public_key_bytes()).unwrap();

        assert_eq!(we_open, they_open, "G1-ECDH must be symmetric");
        // The shared secret is a real point, not a degenerate/identity result.
        assert_ne!(we_open, g1_infinity());
    }

    /// Self-decap (sender == recipient) is valid: a holder DHing against its OWN identity key
    /// produces a well-formed shared secret (dh(sk, sk·G) = sk²·G).
    #[test]
    fn self_decap_is_valid() {
        let key = MasterKey::from_seed_bytes(seed_from_label("self"));
        let shared = key.identity_dh(&key.identity_public_key_bytes()).unwrap();
        assert!(dig_identity::g1_subgroup_check(&shared));
    }

    /// The subgroup / non-identity check REJECTS the identity point BEFORE any scalar mult — a
    /// fail-closed error, no key material touched.
    #[test]
    fn decap_rejects_the_identity_point() {
        let key = MasterKey::from_seed_bytes(seed_from_label("reject-inf"));
        assert_eq!(
            key.identity_dh(&g1_infinity()).unwrap_err().code,
            crate::types::WalletErrorCode::InvalidInput,
        );
    }

    /// A malformed / off-curve peer point is rejected fail-closed (invalid-curve attack defense).
    #[test]
    fn decap_rejects_a_malformed_point() {
        let key = MasterKey::from_seed_bytes(seed_from_label("reject-junk"));
        assert!(key.identity_dh(&[0xff; 48]).is_err());
    }

    /// Distinct peers yield distinct shared secrets (the DH actually depends on the peer point — no
    /// constant/degenerate output).
    #[test]
    fn distinct_peers_yield_distinct_shared_secrets() {
        let ours = MasterKey::from_seed_bytes(seed_from_label("dist-ours"));
        let peer_a = MasterKey::from_seed_bytes(seed_from_label("dist-a"));
        let peer_b = MasterKey::from_seed_bytes(seed_from_label("dist-b"));
        let a = ours
            .identity_dh(&peer_a.identity_public_key_bytes())
            .unwrap();
        let b = ours
            .identity_dh(&peer_b.identity_public_key_bytes())
            .unwrap();
        assert_ne!(a, b);
    }

    /// Key isolation: the DECAP output is the SHARED SECRET only — it is not the identity public key
    /// and not a copy of any advertised public material, so the scalar cannot be read back from it.
    #[test]
    fn decap_output_is_not_public_material() {
        let ours = MasterKey::from_seed_bytes(seed_from_label("iso-ours"));
        let peer = MasterKey::from_seed_bytes(seed_from_label("iso-peer"));
        let shared = ours.identity_dh(&peer.identity_public_key_bytes()).unwrap();
        assert_ne!(shared, ours.identity_public_key_bytes());
        assert_ne!(shared, peer.identity_public_key_bytes());
    }

    /// The identity key is DISTINCT from the wallet coin keys (different derivation path) — a
    /// leaked/rotated wallet address key can't reconstruct the identity key and vice-versa.
    #[test]
    fn identity_key_is_distinct_from_wallet_keys() {
        let key = MasterKey::from_seed_bytes(seed_from_label("distinct"));
        assert_ne!(
            key.identity_public_key_bytes().to_vec(),
            key.profile_public_key(0).to_bytes().to_vec(),
        );
        assert_ne!(
            key.identity_public_key_bytes().to_vec(),
            key.address_public_key(0, 0).to_bytes().to_vec(),
        );
    }
}
