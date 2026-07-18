//! Spend objects — the unsigned request that leaves the engine and the signed bundle
//! that comes back.
//!
//! These are the two objects that cross the signing seam (SPEC §1d): the engine BUILDS an
//! [`UnsignedSpend`] and hands it OUT to dig-app for review + signing; dig-app returns a
//! [`SignedBundle`] which the engine broadcasts. Neither object contains a secret key —
//! the signature is produced client-side and only the resulting public signature comes back.

use chia::bls::PublicKey;
use chia::protocol::{CoinSpend, SpendBundle};
use serde::{Deserialize, Serialize};

use super::value::TransactionSummary;

/// One signature the spend requires: the public key that must sign, and the exact message
/// bytes it must sign over. dig-app matches the public key to a derived secret key it holds
/// and signs `message`. Storing the public key (not the secret) keeps the request key-free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredSignature {
    /// The public key whose corresponding secret must produce the signature.
    pub public_key: PublicKey,
    /// The exact bytes to be signed (AGG_SIG message, hex on the wire).
    #[serde(with = "hex_bytes")]
    pub message: Vec<u8>,
}

/// An unsigned spend the engine built: the coin spends, the signatures it needs, and a
/// human-facing summary for the client review surface. This is what the engine hands to
/// dig-app's signer — it carries NO secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedSpend {
    /// The coin spends composing the transaction (chia-wallet-sdk driver output).
    pub coin_spends: Vec<CoinSpend>,
    /// Every signature that must be gathered before this can broadcast.
    pub required_signatures: Vec<RequiredSignature>,
    /// The net effect, for the review/confirm UI.
    pub summary: TransactionSummary,
}

/// A fully-signed spend bundle, ready for broadcast. Produced client-side (dig-app aggregates
/// the signatures) and returned to the engine's broadcaster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBundle {
    /// The aggregated, broadcast-ready bundle.
    pub bundle: SpendBundle,
}

/// Serialize a byte vector as lowercase hex on the wire (readable, JS-safe).
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::value::Amount;

    #[test]
    fn required_signature_round_trips_with_hex_message() {
        let sig = RequiredSignature {
            public_key: PublicKey::default(),
            message: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json = serde_json::to_string(&sig).unwrap();
        assert!(
            json.contains("deadbeef"),
            "message must be hex-encoded: {json}"
        );
        let back: RequiredSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sig);
    }

    #[test]
    fn unsigned_spend_round_trips() {
        let unsigned = UnsignedSpend {
            coin_spends: vec![],
            required_signatures: vec![],
            summary: TransactionSummary {
                outputs: vec![],
                fee: Amount(0),
            },
        };
        let json = serde_json::to_string(&unsigned).unwrap();
        let back: UnsignedSpend = serde_json::from_str(&json).unwrap();
        assert_eq!(back, unsigned);
    }

    #[test]
    fn signed_bundle_round_trips() {
        let signed = SignedBundle {
            bundle: SpendBundle::new(vec![], chia::bls::Signature::default()),
        };
        let json = serde_json::to_string(&signed).unwrap();
        let back: SignedBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signed);
    }

    #[test]
    fn bad_hex_message_is_rejected() {
        let json = r#"{"public_key":"","message":"zz"}"#;
        assert!(serde_json::from_str::<RequiredSignature>(json).is_err());
    }
}
