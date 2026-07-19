//! `client::identity` — the identity PROVIDER + domain-separated identity signing (SPEC §4, §8).
//!
//! dig-app supplies the engine the public material it needs to operate as an identity: the
//! [`IdentityRef`] and the set of derived public keys the engine should track. Public material
//! goes out; the secret stays behind this seam. [`HdIdentity`] is the concrete provider, backed by
//! the #997 master-HD → profile derivation (via [`super::hd`]).
//!
//! # Identity signatures are domain-separated (custody)
//! Beyond spend signing (see [`super::signer`]), an identity sometimes signs an application-level
//! message (e.g. an auth challenge). Those signatures are ALWAYS domain-separated: the signer
//! prefixes a `DIGNET-<domain>-v1` framing before the payload and NEVER signs raw, caller-supplied
//! bytes directly. The framing guarantees an identity signature can never collide with an
//! AGG_SIG_ME spend signature (which instead ends with the network genesis challenge, see
//! [`super::signer`]) — a signature obtained for one purpose cannot be replayed as the other.

use chia::bls::{sign as bls_sign, PublicKey, Signature};

use crate::types::{IdentityRef, WalletError, WalletResult};

use super::hd::{MasterKey, DEFAULT_ADDRESS_GAP};

/// Supplies the engine an identity's PUBLIC material.
pub trait IdentityProvider: Send + Sync {
    /// The identity currently selected in dig-app.
    fn active_identity(&self) -> &IdentityRef;

    /// The public keys the engine should subscribe/track for the active identity (the derived
    /// address set). Public material only.
    fn tracked_public_keys(&self) -> WalletResult<Vec<PublicKey>>;
}

/// The #997 HD-backed identity: holds the master key, exposes public material to the engine, and
/// produces domain-separated identity signatures. The secret never leaves this value.
///
/// Deliberately no `Debug`/`Serialize`/`Clone`: the held [`MasterKey`] must not leak.
pub struct HdIdentity {
    identity: IdentityRef,
    master: MasterKey,
    address_gap: u32,
}

impl HdIdentity {
    /// Build an identity over `master` for `identity` (its `profile_ix` selects the derivation).
    pub fn new(identity: IdentityRef, master: MasterKey) -> Self {
        Self {
            identity,
            master,
            address_gap: DEFAULT_ADDRESS_GAP,
        }
    }

    /// Override how many derived address public keys [`tracked_public_keys`] advertises.
    ///
    /// [`tracked_public_keys`]: IdentityProvider::tracked_public_keys
    pub fn with_address_gap(mut self, address_gap: u32) -> Self {
        self.address_gap = address_gap;
        self
    }

    /// The public key of the active profile's account node.
    pub fn profile_public_key(&self) -> PublicKey {
        self.master.profile_public_key(self.identity.profile_ix)
    }

    /// The 48-byte compressed G1 identity public key (dig-identity slot `0x0010`) — the value a
    /// sender seals a dig-message to. Public material; safe to advertise.
    pub fn identity_public_key_bytes(&self) -> [u8; 48] {
        self.master.identity_public_key_bytes()
    }

    /// The recipient DECAP of a dig-message seal: the G1-ECDH `dh(identity_sk, peer_g1)` against the
    /// held identity key, returning the 48-byte compressed shared secret for the KEM/KDF. `peer_g1`
    /// is subgroup- and non-identity-checked before the scalar multiplication (fail-closed). This is
    /// the DH the recipient uses to OPEN a message; it is NOT a signature (see
    /// [`sign_identity_message`](HdIdentity::sign_identity_message)) — the one identity key does both
    /// on group-separated primitives. See [`MasterKey::identity_dh`](super::hd::MasterKey::identity_dh).
    pub fn decap(&self, peer_g1: &[u8; 48]) -> WalletResult<[u8; 48]> {
        self.master.identity_dh(peer_g1)
    }

    /// Sign an application-level message under `domain`, domain-separated so the signature can
    /// never be confused with (or replayed as) a spend signature. Fails closed on an empty or
    /// non-ASCII-alphanumeric-or-dash `domain`.
    pub fn sign_identity_message(&self, domain: &str, payload: &[u8]) -> WalletResult<Signature> {
        let framed = domain_framed_message(domain, payload)?;
        let key = self.master.profile_account_key(self.identity.profile_ix);
        Ok(bls_sign(&key, &framed))
    }
}

impl IdentityProvider for HdIdentity {
    fn active_identity(&self) -> &IdentityRef {
        &self.identity
    }

    fn tracked_public_keys(&self) -> WalletResult<Vec<PublicKey>> {
        let profile = self.identity.profile_ix;
        Ok((0..self.address_gap)
            .map(|ix| self.master.address_public_key(profile, ix))
            .collect())
    }
}

/// Build the domain-separated byte string an identity signature is computed over:
/// `DIGNET-<domain>-v1` followed by a `0x00` separator and the payload. The separator makes the
/// framing unambiguous, and the `DIGNET-` prefix guarantees the bytes cannot coincide with a spend
/// message. Rejects a `domain` that is empty or contains anything but ASCII letters, digits, and
/// `-` (so the framing can't be smuggled or spoofed).
fn domain_framed_message(domain: &str, payload: &[u8]) -> WalletResult<Vec<u8>> {
    let is_valid = !domain.is_empty()
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !is_valid {
        return Err(WalletError::invalid_input(
            "identity signing domain must be non-empty ASCII alphanumeric/dash",
        ));
    }
    let mut framed = format!("DIGNET-{domain}-v1").into_bytes();
    framed.push(0x00);
    framed.extend_from_slice(payload);
    Ok(framed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{WalletErrorCode, WalletId};
    use chia::bls::verify as bls_verify;
    use sha2::{Digest, Sha256};

    fn seed_from_label(label: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"dig-wallet-backend/client/identity/test/");
        hasher.update(label.as_bytes());
        hasher.finalize().to_vec()
    }

    fn identity(label: &str, profile_ix: u32) -> HdIdentity {
        let master = MasterKey::from_seed_bytes(seed_from_label(label));
        HdIdentity::new(
            IdentityRef::new(WalletId(1)).with_profile(profile_ix),
            master,
        )
    }

    #[test]
    fn active_identity_is_reported() {
        let id = identity("active", 2);
        assert_eq!(id.active_identity().profile_ix, 2);
    }

    #[test]
    fn tracked_public_keys_count_matches_the_gap() {
        let id = identity("tracked", 0).with_address_gap(5);
        assert_eq!(id.tracked_public_keys().unwrap().len(), 5);
    }

    #[test]
    fn tracked_public_keys_are_the_derived_address_keys() {
        let id = identity("derived", 0).with_address_gap(3);
        let master = MasterKey::from_seed_bytes(seed_from_label("derived"));
        let keys = id.tracked_public_keys().unwrap();
        assert_eq!(keys[0], master.address_public_key(0, 0));
        assert_eq!(keys[2], master.address_public_key(0, 2));
    }

    #[test]
    fn identity_signature_verifies_against_the_domain_framed_message() {
        let id = identity("sign", 0);
        let payload = b"auth-challenge-nonce";
        let sig = id.sign_identity_message("auth", payload).unwrap();

        let framed = domain_framed_message("auth", payload).unwrap();
        assert!(bls_verify(&sig, &id.profile_public_key(), &framed));
    }

    #[test]
    fn identity_signature_is_not_valid_over_the_raw_payload() {
        // The whole point of domain separation: the signature does NOT verify over the bare
        // payload, so it can't be lifted into a different (unframed) context.
        let id = identity("sep", 0);
        let payload = b"raw";
        let sig = id.sign_identity_message("auth", payload).unwrap();
        assert!(!bls_verify(&sig, &id.profile_public_key(), payload));
    }

    #[test]
    fn different_domains_yield_different_signatures() {
        let id = identity("domains", 0);
        let payload = b"same-payload";
        let a = id.sign_identity_message("auth", payload).unwrap();
        let b = id.sign_identity_message("login", payload).unwrap();
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn decap_round_trips_between_two_identities() {
        let ours = identity("dh-a", 0);
        let peer = identity("dh-b", 0);
        let we_open = ours.decap(&peer.identity_public_key_bytes()).unwrap();
        let they_open = peer.decap(&ours.identity_public_key_bytes()).unwrap();
        assert_eq!(we_open, they_open);
    }

    #[test]
    fn decap_rejects_a_bad_peer_point() {
        let id = identity("dh-bad", 0);
        assert_eq!(
            id.decap(&[0xff; 48]).unwrap_err().code,
            WalletErrorCode::InvalidInput,
        );
    }

    #[test]
    fn identity_public_key_is_48_bytes_and_distinct_from_spend_key() {
        let id = identity("dh-pub", 0);
        assert_eq!(id.identity_public_key_bytes().len(), 48);
        assert_ne!(
            id.identity_public_key_bytes().to_vec(),
            id.profile_public_key().to_bytes().to_vec(),
        );
    }

    #[test]
    fn empty_domain_is_rejected() {
        let id = identity("empty", 0);
        let err = id.sign_identity_message("", b"x").unwrap_err();
        assert_eq!(err.code, WalletErrorCode::InvalidInput);
    }

    #[test]
    fn malformed_domain_is_rejected() {
        let id = identity("bad", 0);
        assert_eq!(
            id.sign_identity_message("bad domain!", b"x")
                .unwrap_err()
                .code,
            WalletErrorCode::InvalidInput,
        );
    }
}
