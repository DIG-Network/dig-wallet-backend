//! Value + record types: the wire shapes for balances, coins, and assets.
//!
//! These are pure, I/O-free data. `Amount` carries the JS-safe-integer serialization
//! contract; the record types mirror what the engine's state store indexes and returns.

use serde::{Deserialize, Serialize};

/// The largest integer a IEEE-754 double (a JavaScript `number`) represents exactly:
/// 2^53 − 1. Amounts at or below this serialize as a JSON number; larger ones serialize
/// as a decimal string so a JS/TS consumer never silently loses precision (SPEC §2).
pub const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// A quantity in the smallest unit (mojos for XCH, base units for a CAT).
///
/// Serialized as a JSON number when it fits in a JS-safe integer, otherwise as a decimal
/// string. Deserialization accepts either form, so the type is symmetric across the IPC
/// boundary regardless of magnitude.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Amount(pub u64);

impl Amount {
    /// The raw value in the smallest unit.
    pub fn mojos(self) -> u64 {
        self.0
    }
}

impl Serialize for Amount {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0 <= MAX_JS_SAFE_INTEGER {
            serializer.serialize_u64(self.0)
        } else {
            serializer.serialize_str(&self.0.to_string())
        }
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Accept either a JSON number or a decimal string (the two forms `Amount` emits).
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum NumberOrString {
            Number(u64),
            Text(String),
        }
        match NumberOrString::deserialize(deserializer)? {
            NumberOrString::Number(n) => Ok(Amount(n)),
            NumberOrString::Text(s) => s.parse().map(Amount).map_err(serde::de::Error::custom),
        }
    }
}

/// The Chia network an engine instance operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    /// The production Chia mainnet.
    Mainnet,
    /// A test network.
    Testnet,
    /// A local simulator (chia-wallet-sdk test peer).
    Simulator,
}

/// A bech32m-encoded payment address (e.g. `xch1…`), stored as text for display.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub String);

/// A 32-byte puzzle hash in lowercase hex (no `0x`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Puzzlehash(pub String);

/// A CAT asset id (tail hash) in lowercase hex; `None` conceptually denotes native XCH.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId(pub String);

/// A tracked coin as the state store records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinRecord {
    /// The coin id (hex).
    pub coin_id: String,
    /// The coin's puzzle hash.
    pub puzzle_hash: Puzzlehash,
    /// The coin's value.
    pub amount: Amount,
    /// The block height the coin was created at, if confirmed.
    pub created_height: Option<u32>,
    /// The block height the coin was spent at, if spent.
    pub spent_height: Option<u32>,
}

/// A CAT balance line (an asset the wallet holds units of).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatRecord {
    /// The CAT asset id (tail hash).
    pub asset_id: AssetId,
    /// The spendable balance of this asset.
    pub balance: Amount,
    /// A human-facing ticker/name when known (enriched client-side, #972).
    pub name: Option<String>,
}

/// An NFT the wallet controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftRecord {
    /// The NFT launcher id (hex).
    pub launcher_id: String,
    /// The current data URI, when resolved.
    pub data_uri: Option<String>,
}

/// A DID the wallet controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidRecord {
    /// The DID launcher id (hex).
    pub launcher_id: String,
    /// A user-assigned label, when set.
    pub name: Option<String>,
}

/// A wallet's aggregate balance for the native asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Balance {
    /// Value spendable now (confirmed, unspent).
    pub confirmed: Amount,
    /// Value confirmed plus inbound-pending minus outbound-pending.
    pub spendable: Amount,
}

/// A concise, human-oriented summary of a spend's net effect — carried on an
/// [`crate::types::UnsignedSpend`] and rendered by the client review surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionSummary {
    /// The net outputs to non-change recipients.
    pub outputs: Vec<SpendOutput>,
    /// The fee paid to the farmer.
    pub fee: Amount,
}

/// One recipient line within a [`TransactionSummary`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendOutput {
    /// The destination address.
    pub address: Address,
    /// The amount sent to it.
    pub amount: Amount,
    /// The asset sent; `None` = native XCH.
    pub asset_id: Option<AssetId>,
}

/// A settled transaction as it appears in history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionRecord {
    /// The transaction id (hex).
    pub tx_id: String,
    /// The block height it confirmed at, if confirmed.
    pub confirmed_height: Option<u32>,
    /// Its summarized effect.
    pub summary: TransactionSummary,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_amount_serializes_as_number() {
        assert_eq!(serde_json::to_string(&Amount(1000)).unwrap(), "1000");
        assert_eq!(
            serde_json::to_string(&Amount(MAX_JS_SAFE_INTEGER)).unwrap(),
            "9007199254740991"
        );
    }

    #[test]
    fn large_amount_serializes_as_string() {
        let big = Amount(MAX_JS_SAFE_INTEGER + 1);
        assert_eq!(serde_json::to_string(&big).unwrap(), "\"9007199254740992\"");
    }

    #[test]
    fn amount_deserializes_from_either_form() {
        let from_num: Amount = serde_json::from_str("42").unwrap();
        assert_eq!(from_num, Amount(42));
        let from_str: Amount = serde_json::from_str("\"9007199254740992\"").unwrap();
        assert_eq!(from_str, Amount(9_007_199_254_740_992));
    }

    #[test]
    fn amount_round_trips_across_the_threshold() {
        for v in [
            0u64,
            1,
            MAX_JS_SAFE_INTEGER,
            MAX_JS_SAFE_INTEGER + 1,
            u64::MAX,
        ] {
            let json = serde_json::to_string(&Amount(v)).unwrap();
            let back: Amount = serde_json::from_str(&json).unwrap();
            assert_eq!(back, Amount(v), "round-trip failed for {v}");
        }
    }

    #[test]
    fn amount_bad_string_is_an_error() {
        assert!(serde_json::from_str::<Amount>("\"not-a-number\"").is_err());
    }

    #[test]
    fn mojos_accessor_returns_raw() {
        assert_eq!(Amount(555).mojos(), 555);
    }

    #[test]
    fn records_round_trip() {
        let summary = TransactionSummary {
            outputs: vec![SpendOutput {
                address: Address("xch1abc".into()),
                amount: Amount(10),
                asset_id: None,
            }],
            fee: Amount(1),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: TransactionSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }
}
