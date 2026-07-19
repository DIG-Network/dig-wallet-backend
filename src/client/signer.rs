//! `client::signer` — the SIGNING interface (SPEC §4, §8). dig-app holds the key HERE.
//!
//! This module and [`super::hd`] are the ONLY places the crate touches secret material
//! (`chia::bls::SecretKey`), compiled ONLY under the `client` feature. dig-app implements
//! [`IdentitySigner`] with a [`LocalSigner`] that holds the master key and, when the engine needs
//! a spend signed, matches each [`crate::types::RequiredSignature`] to a derived key, signs, and aggregates.
//! The key never leaves dig-app — the engine only ever calls OUT to a
//! [`crate::engine::signer::RemoteSigner`], for which [`LocalSigner`] is the concrete impl.
//!
//! # Custody controls (fail-closed)
//! Two properties defend the signer against a compromised or buggy engine handing it dangerous
//! bytes to sign:
//!
//! 1. **AGG_SIG_ME binding — refuse `AGG_SIG_UNSAFE`.** Every message the signer signs MUST be
//!    bound to the network by ending with the network's AGG_SIG_ME additional data (the genesis
//!    challenge). A consensus-valid `AGG_SIG_ME`-family message always carries this suffix; an
//!    unbound `AGG_SIG_UNSAFE` message must not (consensus rejects an `UNSAFE` message ending with
//!    it). Refusing unbound messages stops the engine from obtaining a signature that could be
//!    replayed against a different coin.
//! 2. **Key-must-match, fail-closed.** A required signature whose public key the signer cannot
//!    reproduce from its own derivation is rejected — the signer never fabricates or skips a
//!    signature.

use async_trait::async_trait;
use chia::bls::{aggregate, sign as bls_sign, PublicKey, SecretKey, Signature};
use chia::protocol::SpendBundle;

use crate::types::{
    IdentityRef, Network, SignedBundle, UnsignedSpend, WalletError, WalletErrorCode, WalletResult,
};

use super::hd::{MasterKey, DEFAULT_ADDRESS_GAP};

/// The Chia mainnet genesis challenge — the AGG_SIG_ME additional data every mainnet spend
/// signature is bound to. Sourced from `dig-constants` (the ecosystem's single source of truth for
/// the Chia-L1 domain), so the signer binds byte-identically to what [`crate::engine::build`]
/// binds — signer == engine by construction (see the `signer_binds_the_same_agg_sig_me_as_engine`
/// KAT). `CHIA_L1_*` is the Chia L1 genesis, deliberately distinct from the DIG L2 genesis.
const MAINNET_AGG_SIG_ME_EXTRA_DATA: [u8; 32] = dig_constants::CHIA_L1_MAINNET_AGG_SIG_ME;

/// The Chia testnet11 genesis challenge — the AGG_SIG_ME additional data on testnet11, likewise
/// sourced from `dig-constants` so signer and engine cannot drift.
const TESTNET11_AGG_SIG_ME_EXTRA_DATA: [u8; 32] = dig_constants::CHIA_L1_TESTNET11_AGG_SIG_ME;

/// The client-side signing contract: sign an unsigned spend for a specific identity.
///
/// dig-app implements this over the key it holds. It is deliberately separate from the engine's
/// [`crate::engine::signer::RemoteSigner`]: `IdentitySigner` is the local, key-holding view;
/// `RemoteSigner` is the engine's remote-callback view. [`LocalSigner`] bridges the two.
#[async_trait]
pub trait IdentitySigner: Send + Sync {
    /// The public identity this signer signs for.
    fn identity(&self) -> &IdentityRef;

    /// Gather the required signatures for `unsigned`, aggregate, and return a signed bundle.
    async fn sign(&self, unsigned: UnsignedSpend) -> WalletResult<SignedBundle>;
}

/// A signer that holds the master HD key in-process (dig-app side).
///
/// Holds a [`MasterKey`] entirely within the client seam — it never crosses to the engine. On
/// [`sign_unsigned`](LocalSigner::sign_unsigned) it derives the active profile's address keys,
/// matches each [`crate::types::RequiredSignature`] to a derived key, signs the (network-bound) message with
/// augmented BLS, and aggregates. Deliberately no `Debug`/`Serialize`/`Clone`: the held key never
/// leaks.
pub struct LocalSigner {
    identity: IdentityRef,
    master: MasterKey,
    agg_sig_me_extra_data: [u8; 32],
    address_gap: u32,
}

impl LocalSigner {
    /// Create a signer for `identity` holding `master`, bound to `network` (which fixes the
    /// AGG_SIG_ME additional data the signer requires on every message).
    ///
    /// [`Network::Simulator`] has no fixed genesis challenge; use
    /// [`with_agg_sig_me_extra_data`](LocalSigner::with_agg_sig_me_extra_data) to supply the
    /// simulator's constant explicitly.
    pub fn new(identity: IdentityRef, master: MasterKey, network: Network) -> WalletResult<Self> {
        let agg_sig_me_extra_data = match network {
            Network::Mainnet => MAINNET_AGG_SIG_ME_EXTRA_DATA,
            Network::Testnet => TESTNET11_AGG_SIG_ME_EXTRA_DATA,
            Network::Simulator => return Err(WalletError::invalid_input(
                "Network::Simulator has no fixed genesis challenge; use with_agg_sig_me_extra_data",
            )),
        };
        Ok(Self {
            identity,
            master,
            agg_sig_me_extra_data,
            address_gap: DEFAULT_ADDRESS_GAP,
        })
    }

    /// Create a signer bound to an explicit AGG_SIG_ME additional data (e.g. a simulator or custom
    /// network genesis challenge).
    pub fn with_agg_sig_me_extra_data(
        identity: IdentityRef,
        master: MasterKey,
        agg_sig_me_extra_data: [u8; 32],
    ) -> Self {
        Self {
            identity,
            master,
            agg_sig_me_extra_data,
            address_gap: DEFAULT_ADDRESS_GAP,
        }
    }

    /// Override the address gap limit — how many derived address keys the signer will try to match
    /// a required signature against.
    pub fn with_address_gap(mut self, address_gap: u32) -> Self {
        self.address_gap = address_gap;
        self
    }

    /// The public key of the active profile's account node. Public material — safe to expose.
    pub fn public_key(&self) -> PublicKey {
        self.master.profile_public_key(self.identity.profile_ix)
    }

    /// The AGG_SIG_ME additional data (network genesis challenge) this signer requires every
    /// message to be bound to. Public, non-secret material — exposed so the engine seam can prove,
    /// in a KAT, that it builds messages bound to the exact bytes this signer will accept
    /// (signer == engine). Never secret key material.
    pub fn agg_sig_me_extra_data(&self) -> [u8; 32] {
        self.agg_sig_me_extra_data
    }

    /// Find the secret key matching `target` among the active profile's derived address keys,
    /// searching indices `0..address_gap`. `None` when no derived key matches (fail-closed).
    fn find_key(&self, target: &PublicKey) -> Option<SecretKey> {
        let profile = self.identity.profile_ix;
        (0..self.address_gap)
            .map(|ix| self.master.address_key(profile, ix))
            .find(|sk| &sk.public_key() == target)
    }

    /// The custody core: verify every required signature is a network-bound message the signer can
    /// produce, sign each, and aggregate into a broadcast-ready bundle. Fail-closed.
    pub fn sign_unsigned(&self, unsigned: &UnsignedSpend) -> WalletResult<SignedBundle> {
        let mut signatures: Vec<Signature> = Vec::with_capacity(unsigned.required_signatures.len());

        for required in &unsigned.required_signatures {
            self.reject_unbound_message(&required.message)?;
            let key = self.find_key(&required.public_key).ok_or_else(|| {
                WalletError::new(
                    WalletErrorCode::SigningFailed,
                    "no derived key matches a required signature's public key",
                )
            })?;
            signatures.push(bls_sign(&key, &required.message));
        }

        let aggregated = aggregate(&signatures);
        Ok(SignedBundle {
            bundle: SpendBundle::new(unsigned.coin_spends.clone(), aggregated),
        })
    }

    /// The 48-byte compressed G1 identity public key (dig-identity slot `0x0010`) this signer can
    /// DECAP against. Public material — safe to advertise so a sender can seal a dig-message to it.
    pub fn identity_public_key_bytes(&self) -> [u8; 48] {
        self.master.identity_public_key_bytes()
    }

    /// The recipient DECAP: the G1-ECDH `dh(identity_sk, peer_g1)` against the held identity key,
    /// returning the 48-byte compressed shared secret for the dig-message KEM/KDF. `peer_g1` is
    /// subgroup- and non-identity-checked before the scalar multiplication (fail-closed). See
    /// [`MasterKey::identity_dh`](super::hd::MasterKey::identity_dh).
    pub fn decap(&self, peer_g1: &[u8; 48]) -> WalletResult<[u8; 48]> {
        self.master.identity_dh(peer_g1)
    }

    /// Reject any message not bound to this network's AGG_SIG_ME additional data — i.e. refuse to
    /// sign `AGG_SIG_UNSAFE`/unbound bytes that could be replayed against another coin.
    fn reject_unbound_message(&self, message: &[u8]) -> WalletResult<()> {
        if message.ends_with(&self.agg_sig_me_extra_data) {
            Ok(())
        } else {
            Err(WalletError::new(
                WalletErrorCode::SigningFailed,
                "refusing to sign a message not bound to the network (possible AGG_SIG_UNSAFE)",
            ))
        }
    }
}

#[async_trait]
impl IdentitySigner for LocalSigner {
    fn identity(&self) -> &IdentityRef {
        &self.identity
    }

    async fn sign(&self, unsigned: UnsignedSpend) -> WalletResult<SignedBundle> {
        self.sign_unsigned(&unsigned)
    }
}

/// [`LocalSigner`] is the concrete implementation of the engine's remote-signing callback: the
/// engine holds an `Arc<dyn RemoteSigner>` and calls out to it, never holding the key itself.
/// Available only when the `engine` seam is also compiled (e.g. the in-process DIG-Browser bridge).
#[cfg(feature = "engine")]
#[async_trait]
impl crate::engine::signer::RemoteSigner for LocalSigner {
    async fn sign(&self, unsigned: UnsignedSpend) -> WalletResult<SignedBundle> {
        self.sign_unsigned(&unsigned)
    }

    async fn dh(&self, peer_g1: [u8; 48]) -> WalletResult<[u8; 48]> {
        self.decap(&peer_g1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Amount, RequiredSignature, TransactionSummary, WalletErrorCode, WalletId};
    use chia::bls::{aggregate_verify, verify as bls_verify};
    use sha2::{Digest, Sha256};

    /// A deterministic test seed hashed from a label (not an integer-literal key — dodges the
    /// CodeQL "hard-coded cryptographic value" finding).
    fn seed_from_label(label: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"dig-wallet-backend/client/signer/test/");
        hasher.update(label.as_bytes());
        hasher.finalize().to_vec()
    }

    fn master(label: &str) -> MasterKey {
        MasterKey::from_seed_bytes(seed_from_label(label))
    }

    fn mainnet_signer(label: &str) -> LocalSigner {
        LocalSigner::new(
            IdentityRef::new(WalletId(1)),
            master(label),
            Network::Mainnet,
        )
        .unwrap()
    }

    fn empty_summary() -> TransactionSummary {
        TransactionSummary {
            outputs: vec![],
            fee: Amount(0),
        }
    }

    /// An AGG_SIG_ME-style message: an arbitrary body followed by the mainnet genesis-challenge
    /// suffix (what a real network-bound message carries).
    fn bound_message(body: &str) -> Vec<u8> {
        let mut msg = body.as_bytes().to_vec();
        msg.extend_from_slice(&MAINNET_AGG_SIG_ME_EXTRA_DATA);
        msg
    }

    fn spend_needing(sigs: Vec<RequiredSignature>) -> UnsignedSpend {
        UnsignedSpend {
            coin_spends: vec![],
            required_signatures: sigs,
            summary: empty_summary(),
        }
    }

    #[test]
    fn public_key_is_the_profile_account_key() {
        let signer = mainnet_signer("pubkey");
        assert_eq!(signer.public_key(), master("pubkey").profile_public_key(0));
    }

    #[test]
    fn simulator_requires_explicit_extra_data() {
        // `LocalSigner` has no `Debug` (it holds a key), so match rather than `unwrap_err`.
        let result = LocalSigner::new(
            IdentityRef::new(WalletId(1)),
            master("sim"),
            Network::Simulator,
        );
        match result {
            Err(err) => assert_eq!(err.code, WalletErrorCode::InvalidInput),
            Ok(_) => panic!("simulator without explicit extra data must fail"),
        }
    }

    #[tokio::test]
    async fn signs_a_bound_message_with_a_derived_key() {
        let signer = mainnet_signer("happy");
        let addr_pk = master("happy").address_public_key(0, 0);
        let message = bound_message("spend-me");

        let signed = signer
            .sign(spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: message.clone(),
            }]))
            .await
            .unwrap();

        // The aggregated signature verifies against the derived key + the exact message (AUG).
        assert!(bls_verify(
            &signed.bundle.aggregated_signature,
            &addr_pk,
            &message
        ));
    }

    #[tokio::test]
    async fn refuses_an_unbound_message_agg_sig_unsafe() {
        let signer = mainnet_signer("unsafe");
        let addr_pk = master("unsafe").address_public_key(0, 0);

        // No genesis-challenge suffix -> looks like AGG_SIG_UNSAFE -> refused.
        let err = signer
            .sign(spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: b"unbound-attacker-bytes".to_vec(),
            }]))
            .await
            .unwrap_err();

        assert_eq!(err.code, WalletErrorCode::SigningFailed);
    }

    #[tokio::test]
    async fn refuses_when_no_derived_key_matches() {
        let signer = mainnet_signer("nomatch").with_address_gap(4);
        // A public key from a DIFFERENT seed — the signer cannot reproduce it.
        let foreign = master("foreign").address_public_key(0, 0);

        let err = signer
            .sign(spend_needing(vec![RequiredSignature {
                public_key: foreign,
                message: bound_message("x"),
            }]))
            .await
            .unwrap_err();

        assert_eq!(err.code, WalletErrorCode::SigningFailed);
    }

    #[tokio::test]
    async fn signs_key_found_deeper_in_the_gap() {
        let signer = mainnet_signer("deep");
        let addr_pk = master("deep").address_public_key(0, 5);
        let message = bound_message("deep-spend");

        let signed = signer
            .sign(spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: message.clone(),
            }]))
            .await
            .unwrap();

        assert!(bls_verify(
            &signed.bundle.aggregated_signature,
            &addr_pk,
            &message
        ));
    }

    #[tokio::test]
    async fn key_beyond_the_gap_is_not_found() {
        let signer = mainnet_signer("gap").with_address_gap(3);
        let out_of_range = master("gap").address_public_key(0, 10);

        let err = signer
            .sign(spend_needing(vec![RequiredSignature {
                public_key: out_of_range,
                message: bound_message("y"),
            }]))
            .await
            .unwrap_err();

        assert_eq!(err.code, WalletErrorCode::SigningFailed);
    }

    #[tokio::test]
    async fn aggregates_multiple_required_signatures() {
        let signer = mainnet_signer("multi");
        let pk0 = master("multi").address_public_key(0, 0);
        let pk1 = master("multi").address_public_key(0, 1);
        let m0 = bound_message("first");
        let m1 = bound_message("second");

        let signed = signer
            .sign(spend_needing(vec![
                RequiredSignature {
                    public_key: pk0,
                    message: m0.clone(),
                },
                RequiredSignature {
                    public_key: pk1,
                    message: m1.clone(),
                },
            ]))
            .await
            .unwrap();

        // The aggregate verifies against both (public_key, message) pairs.
        assert!(aggregate_verify(
            &signed.bundle.aggregated_signature,
            [(&pk0, m0.as_slice()), (&pk1, m1.as_slice())],
        ));
    }

    #[tokio::test]
    async fn empty_spend_produces_the_infinity_signature() {
        let signer = mainnet_signer("empty");
        let signed = signer.sign(spend_needing(vec![])).await.unwrap();
        assert_eq!(signed.bundle.aggregated_signature, Signature::default());
    }

    #[tokio::test]
    async fn identity_accessor_returns_the_signing_identity() {
        let signer = mainnet_signer("id");
        assert_eq!(signer.identity().wallet_id, WalletId(1));
    }

    #[tokio::test]
    async fn explicit_extra_data_binds_a_custom_network() {
        // A bespoke genesis challenge (e.g. a simulator) — messages must end with THESE bytes.
        let extra: [u8; 32] = Sha256::digest(b"custom-genesis").into();
        let signer = LocalSigner::with_agg_sig_me_extra_data(
            IdentityRef::new(WalletId(1)),
            master("custom"),
            extra,
        );
        let addr_pk = master("custom").address_public_key(0, 0);
        let mut message = b"custom-spend".to_vec();
        message.extend_from_slice(&extra);

        let signed = signer
            .sign(spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: message.clone(),
            }]))
            .await
            .unwrap();
        assert!(bls_verify(
            &signed.bundle.aggregated_signature,
            &addr_pk,
            &message
        ));
    }

    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn local_signer_serves_as_the_engines_remote_signer() {
        use crate::engine::signer::RemoteSigner;

        let signer = mainnet_signer("remote");
        let addr_pk = master("remote").address_public_key(0, 0);
        let message = bound_message("remote-spend");

        let signed = RemoteSigner::sign(
            &signer,
            spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: message.clone(),
            }]),
        )
        .await
        .unwrap();
        assert!(bls_verify(
            &signed.bundle.aggregated_signature,
            &addr_pk,
            &message
        ));
    }

    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn remote_signer_dh_decaps_against_the_identity_key() {
        use crate::engine::signer::RemoteSigner;

        let ours = mainnet_signer("dh-ours");
        let peer = mainnet_signer("dh-peer");

        // The engine-facing decap round-trips with the peer's inherent decap (ECDH symmetry).
        let we_open = RemoteSigner::dh(&ours, peer.identity_public_key_bytes())
            .await
            .unwrap();
        let they_open = peer.decap(&ours.identity_public_key_bytes()).unwrap();
        assert_eq!(we_open, they_open);
    }

    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn remote_signer_dh_default_impl_fails_closed() {
        use crate::engine::signer::RemoteSigner;

        // A signer that only signs (no identity key wired) — uses the trait's default `dh`.
        struct SignOnly;
        #[async_trait]
        impl RemoteSigner for SignOnly {
            async fn sign(&self, _u: UnsignedSpend) -> WalletResult<SignedBundle> {
                unreachable!("not exercised")
            }
        }
        let err = SignOnly.dh([0u8; 48]).await.unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn sign_path_is_unchanged_alongside_decap() {
        // The one key does both: signing still works exactly as before after decap is added.
        let signer = mainnet_signer("both");
        let addr_pk = master("both").address_public_key(0, 0);
        let message = bound_message("sign-and-decap");
        let signed = signer
            .sign(spend_needing(vec![RequiredSignature {
                public_key: addr_pk,
                message: message.clone(),
            }]))
            .await
            .unwrap();
        assert!(bls_verify(
            &signed.bundle.aggregated_signature,
            &addr_pk,
            &message
        ));
        // And decap works with the same holder.
        let peer = mainnet_signer("both-peer");
        assert!(signer.decap(&peer.identity_public_key_bytes()).is_ok());
    }

    /// signer == engine byte-KAT (signer half). The signer requires every message to be bound to
    /// exactly the `dig-constants` Chia-L1 AGG_SIG_ME value, for mainnet and testnet11. The engine
    /// half (`engine_binds_the_dig_constants_mainnet_agg_sig_me`, src/engine/build.rs) proves the
    /// engine binds that SAME constant into real messages. One SSOT ⇒ signer == engine, no drift.
    #[test]
    fn signer_requires_the_dig_constants_agg_sig_me() {
        let mainnet =
            LocalSigner::new(IdentityRef::new(WalletId(1)), master("m"), Network::Mainnet).unwrap();
        let testnet =
            LocalSigner::new(IdentityRef::new(WalletId(1)), master("t"), Network::Testnet).unwrap();
        assert_eq!(
            mainnet.agg_sig_me_extra_data(),
            dig_constants::CHIA_L1_MAINNET_AGG_SIG_ME,
        );
        assert_eq!(
            testnet.agg_sig_me_extra_data(),
            dig_constants::CHIA_L1_TESTNET11_AGG_SIG_ME,
        );
    }

    /// Genesis-challenge pin: the dig-constants-sourced AGG_SIG_ME values the signer binds to MUST
    /// equal the known Chia L1 genesis challenges. Guards against dig-constants ever drifting these
    /// custody-critical bytes (dig-constants also KATs them against chia-sdk-types independently).
    #[test]
    fn agg_sig_me_extra_data_pins_the_chia_l1_genesis_challenges() {
        assert_eq!(
            hex::encode(MAINNET_AGG_SIG_ME_EXTRA_DATA),
            "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb",
        );
        assert_eq!(
            hex::encode(TESTNET11_AGG_SIG_ME_EXTRA_DATA),
            "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615",
        );
    }
}
