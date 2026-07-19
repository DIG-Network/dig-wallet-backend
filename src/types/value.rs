//! Value + record types: the wire shapes for balances, coins, and assets.
//!
//! These are pure, I/O-free data. `Amount` and `AssetId` are the canonical
//! `dig-events-protocol` newtypes (re-exported from `crate::types`, see `mod.rs`); the record
//! types here mirror what the engine's state store indexes and returns.

use serde::{Deserialize, Serialize};

use super::{Amount, AssetId};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// Value spendable now (confirmed, unspent).
    pub confirmed: Amount,
    /// Value confirmed plus inbound-pending minus outbound-pending.
    pub spendable: Amount,
}

impl Default for Balance {
    /// `dig-events-protocol`'s `Amount` has no `Default` (SPEC #1112 canonical form), so this is
    /// spelled out explicitly rather than derived — both fields zero.
    fn default() -> Self {
        Self {
            confirmed: Amount(0),
            spendable: Amount(0),
        }
    }
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

    // `Amount`/`AssetId` themselves are now owned + tested by `dig-events-protocol`
    // (always-string wire form); this suite covers only the record types defined here.

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
