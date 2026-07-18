//! `client::identity` — the identity PROVIDER (SPEC §4).
//!
//! dig-app supplies the engine the public material it needs to operate as an identity: the
//! [`IdentityRef`] and the set of public keys / derivations the engine should track. Public
//! goes out; the secret stays behind [`super::signer`]. The concrete provider (backed by the
//! #997 master-HD → profile derivation) is a later lane.

use chia::bls::PublicKey;

use crate::types::{IdentityRef, WalletResult};

/// Supplies the engine an identity's PUBLIC material.
pub trait IdentityProvider: Send + Sync {
    /// The identity currently selected in dig-app.
    fn active_identity(&self) -> &IdentityRef;

    /// The public keys the engine should subscribe/track for the active identity (the derived
    /// address set). Public material only.
    fn tracked_public_keys(&self) -> WalletResult<Vec<PublicKey>>;
}
