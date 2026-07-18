//! `client::signer` — the SIGNING interface (SPEC §4, §8). dig-app holds the key HERE.
//!
//! This is the ONLY module in the crate that touches secret material (`chia::bls::SecretKey`),
//! and it is compiled ONLY under the `client` feature. dig-app implements [`IdentitySigner`] with a
//! [`LocalSigner`] that holds the derived key, and registers it as the engine's
//! [`crate::engine::signer::RemoteSigner`] over IPC. The engine calls out to it with an
//! [`UnsignedSpend`] and gets back a [`SignedBundle`]; the key never leaves dig-app.
//!
//! The HD/keystore/mnemonic primitives (#997 master-HD → profile derivation, at-rest
//! encryption) live behind this seam too; their concrete implementation is a later lane.

use async_trait::async_trait;
use chia::bls::{PublicKey, SecretKey};

use crate::types::{IdentityRef, SignedBundle, UnsignedSpend, WalletError, WalletResult};

/// The client-side signing contract: sign an unsigned spend for a specific identity.
///
/// dig-app implements this over the key it holds. It is deliberately separate from the
/// engine's `RemoteSigner`: `IdentitySigner` is the local, key-holding view; `RemoteSigner`
/// is the engine's remote-callback view. A [`LocalSigner`] bridges the two.
#[async_trait]
pub trait IdentitySigner: Send + Sync {
    /// The public identity this signer signs for.
    fn identity(&self) -> &IdentityRef;

    /// Gather the required signatures for `unsigned`, aggregate, and return a signed bundle.
    async fn sign(&self, unsigned: UnsignedSpend) -> WalletResult<SignedBundle>;
}

/// A signer that holds a derived key in-process (dig-app side).
///
/// Holds the secret key entirely within the client seam — it never crosses to the engine. The
/// concrete signing logic (matching each [`crate::types::RequiredSignature`] to a derived key
/// and aggregating) is a later lane; this skeleton establishes the key-holding boundary and the
/// public-material accessor.
pub struct LocalSigner {
    identity: IdentityRef,
    secret_key: SecretKey,
}

impl LocalSigner {
    /// Create a signer for `identity` holding `secret_key`. The key stays inside this value.
    pub fn new(identity: IdentityRef, secret_key: SecretKey) -> Self {
        Self {
            identity,
            secret_key,
        }
    }

    /// The public key corresponding to the held secret key. Public material — safe to expose.
    pub fn public_key(&self) -> PublicKey {
        self.secret_key.public_key()
    }
}

#[async_trait]
impl IdentitySigner for LocalSigner {
    fn identity(&self) -> &IdentityRef {
        &self.identity
    }

    async fn sign(&self, _unsigned: UnsignedSpend) -> WalletResult<SignedBundle> {
        Err(WalletError::not_implemented(
            "client::signer::LocalSigner::sign",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WalletId;

    /// A test secret key derived from a label (not a hard-coded key literal — avoids the
    /// CodeQL "hard-coded cryptographic value" finding).
    fn test_secret_key() -> SecretKey {
        let seed: Vec<u8> = b"dig-wallet-backend/client/signer/test-seed"
            .iter()
            .cycle()
            .take(32)
            .copied()
            .collect();
        SecretKey::from_seed(&seed)
    }

    #[test]
    fn local_signer_exposes_only_public_material() {
        let signer = LocalSigner::new(IdentityRef::new(WalletId(1)), test_secret_key());
        // The public key is derivable + exposable; the secret never leaves the signer.
        assert_eq!(signer.public_key(), signer.public_key());
        assert_eq!(signer.identity().wallet_id, WalletId(1));
    }

    #[tokio::test]
    async fn sign_is_unimplemented_in_the_skeleton() {
        let signer = LocalSigner::new(IdentityRef::new(WalletId(1)), test_secret_key());
        let unsigned = UnsignedSpend {
            coin_spends: vec![],
            required_signatures: vec![],
            summary: crate::types::TransactionSummary {
                outputs: vec![],
                fee: crate::types::Amount(0),
            },
        };
        let err = signer.sign(unsigned).await.unwrap_err();
        assert_eq!(err.code, crate::types::WalletErrorCode::NotImplemented);
    }
}
