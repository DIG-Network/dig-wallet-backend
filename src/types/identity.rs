//! Identity references — the PUBLIC material that parameterizes the engine.
//!
//! The engine is identity-*parameterized*, never identity-*owning*: dig-app tells the
//! engine "operate as identity X" by handing it an [`IdentityRef`], which carries only
//! public material (a master-key fingerprint, an optional DID, a profile index). No
//! secret key, mnemonic, or seed appears here — those live behind the client seam's signer
//! (SPEC §1d, the key-isolation invariant).
//!
//! [`WalletId`] itself is the canonical `dig-events-protocol` newtype (re-exported via
//! `crate::types`, see `mod.rs`) — the same identifier the engine stamps on emitted events.

use serde::{Deserialize, Serialize};

use super::WalletId;

/// A Chia Decentralized Identifier (the DID singleton's launcher id), in `did:chia:` bech32m
/// text form. Stored as text so the client seam can display it without decoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(pub String);

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The public identity handle dig-app hands the engine to say "operate as this identity".
///
/// This is the ONLY identity object that crosses INTO the engine, and it is public-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRef {
    /// The master-key fingerprint identifying this wallet.
    pub wallet_id: WalletId,
    /// The DID this identity is bound to, when it has one.
    pub did: Option<Did>,
    /// The profile index (a #997 master-HD → profile derivation slot). `0` = the root profile.
    pub profile_ix: u32,
}

impl IdentityRef {
    /// Construct a root-profile identity reference (no DID).
    pub fn new(wallet_id: WalletId) -> Self {
        Self {
            wallet_id,
            did: None,
            profile_ix: 0,
        }
    }

    /// Return a copy scoped to a specific profile index.
    pub fn with_profile(mut self, profile_ix: u32) -> Self {
        self.profile_ix = profile_ix;
        self
    }

    /// Return a copy bound to a DID.
    pub fn with_did(mut self, did: Did) -> Self {
        self.did = Some(did);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_sets_profile_and_did() {
        let id = IdentityRef::new(WalletId(42))
            .with_profile(3)
            .with_did(Did("did:chia:1abc".into()));
        assert_eq!(id.wallet_id, WalletId(42));
        assert_eq!(id.profile_ix, 3);
        assert_eq!(id.did, Some(Did("did:chia:1abc".into())));
    }

    #[test]
    fn defaults_to_root_profile_no_did() {
        let id = IdentityRef::new(WalletId(1));
        assert_eq!(id.profile_ix, 0);
        assert!(id.did.is_none());
    }

    #[test]
    fn round_trips_through_json() {
        let id = IdentityRef::new(WalletId(7)).with_profile(1);
        let json = serde_json::to_string(&id).unwrap();
        let back: IdentityRef = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn display_forms_are_readable() {
        assert_eq!(WalletId(9).to_string(), "9");
        assert_eq!(Did("did:chia:x".into()).to_string(), "did:chia:x");
    }
}
