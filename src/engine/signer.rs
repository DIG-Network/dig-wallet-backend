//! `engine::signer` — the CALLBACK boundary the engine invokes to get a spend signed.
//!
//! This is the crux of the key-isolation invariant (SPEC §1d): the engine holds an
//! `Arc<dyn RemoteSigner>` and CALLS it to turn an [`UnsignedSpend`] into a [`SignedBundle`].
//! It NEVER holds a key. In dig-node-service the concrete implementation is an IPC proxy that
//! marshals the unsigned spend out to dig-app (which holds the key and signs) and returns the
//! signed bundle. The trait's signature admits only public/post-sign types — no secret ever
//! crosses this boundary INTO the engine.

use async_trait::async_trait;

use crate::types::{SignedBundle, UnsignedSpend, WalletResult};

/// The signing callback the engine calls out to. Implemented on the client side (dig-app).
///
/// # Key isolation
/// The engine only ever holds a `dyn RemoteSigner`; the private key lives entirely behind
/// this trait, in the implementor. Neither the argument nor the return type carries secret
/// material — [`UnsignedSpend`] goes out, [`SignedBundle`] comes back.
#[async_trait]
pub trait RemoteSigner: Send + Sync {
    /// Sign `unsigned` and return a broadcast-ready bundle.
    ///
    /// Implementations review, gather the required signatures for each
    /// [`crate::types::RequiredSignature`], aggregate them, and return the [`SignedBundle`].
    async fn sign(&self, unsigned: UnsignedSpend) -> WalletResult<SignedBundle>;
}
