//! `engine::signer` — the CALLBACK boundary the engine invokes to get a spend signed.
//!
//! This is the crux of the key-isolation invariant (SPEC §1d): the engine holds an
//! `Arc<dyn RemoteSigner>` and CALLS it to turn an [`UnsignedSpend`] into a [`SignedBundle`].
//! It NEVER holds a key. In dig-node-service the concrete implementation is an IPC proxy that
//! marshals the unsigned spend out to dig-app (which holds the key and signs) and returns the
//! signed bundle. The trait's signature admits only public/post-sign types — no secret ever
//! crosses this boundary INTO the engine.

use async_trait::async_trait;

use crate::types::{SignedBundle, UnsignedSpend, WalletError, WalletResult};

/// The signing + DECAP callback the engine calls out to. Implemented on the client side (dig-app).
///
/// # Key isolation
/// The engine only ever holds a `dyn RemoteSigner`; the private key lives entirely behind
/// this trait, in the implementor. No secret material crosses this boundary: for [`sign`], an
/// [`UnsignedSpend`] goes out and a [`SignedBundle`] comes back; for [`dh`], a public 48-byte G1
/// peer point goes out and the shared secret comes back — the identity scalar never leaves.
///
/// [`sign`]: RemoteSigner::sign
/// [`dh`]: RemoteSigner::dh
#[async_trait]
pub trait RemoteSigner: Send + Sync {
    /// Sign `unsigned` and return a broadcast-ready bundle.
    ///
    /// Implementations review, gather the required signatures for each
    /// [`crate::types::RequiredSignature`], aggregate them, and return the [`SignedBundle`].
    async fn sign(&self, unsigned: UnsignedSpend) -> WalletResult<SignedBundle>;

    /// The recipient DECAP of a dig-message seal: perform the G1-ECDH `dh(identity_sk, peer_g1)`
    /// with the held identity key and return the 48-byte compressed shared G1 point for the KEM/KDF.
    ///
    /// This is a DH operation, NOT a signature — the identity key does both, on group-separated
    /// primitives (sign = BLS G2, DH = G1). Implementations MUST subgroup- and non-identity-check
    /// `peer_g1` BEFORE the scalar multiplication (invalid-curve / small-subgroup key-recovery
    /// defense) and return only the shared secret, never the scalar.
    ///
    /// The default implementation fail-closes: a signer that does not hold an identity key (or an
    /// engine-side proxy that has not wired decap) refuses rather than silently misbehaving. Key
    /// holders (e.g. [`crate::client::signer::LocalSigner`]) override it.
    async fn dh(&self, _peer_g1: [u8; 48]) -> WalletResult<[u8; 48]> {
        Err(WalletError::invalid_input(
            "this signer does not support G1-ECDH decap",
        ))
    }
}
