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
///
/// `#[non_exhaustive]` (#2242): a decode-output type — new fields (like `received`, #2241) are
/// added additively as the review surface grows, so external matches/literals must use `..`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TransactionSummary {
    /// The net outputs to non-change recipients — value LEAVING the wallet (a plain send's
    /// recipients, or an offer make's offered assets committed to the settlement puzzle).
    pub outputs: Vec<SpendOutput>,
    /// Value the spend causes the wallet to RECEIVE, surfaced so a two-sided action (an offer
    /// MAKE) shows the trade both ways at the confirm. This is DISTINCT from [`outputs`] (never
    /// conflated with value leaving): a make's `received` legs are the requested payments the maker
    /// gets, each to the maker's own receive address. Empty for a plain one-way send.
    ///
    /// Additive (`#[serde(default)]`) so older wire payloads without the field still deserialize.
    #[serde(default)]
    pub received: Vec<SpendOutput>,
    /// The fee paid to the farmer.
    pub fee: Amount,
    /// The lowercase-hex coin id of every singleton the spend permanently DESTROYS — a profile's DID
    /// or dig-store ended by a terminal melt (dig_ecosystem#3068).
    ///
    /// Destruction is the one effect no [`outputs`](Self::outputs) line can express: a melt creates
    /// no coin and moves the fee by the singleton's lone mojo. Naming it here is what lets the
    /// confirm screen show it and the signing gate compare it, so a melt cannot ride an ordinary
    /// send disguised as a fee one mojo larger.
    ///
    /// Additive (`#[serde(default)]`) so older wire payloads without the field still deserialize —
    /// an absent field means "this spend destroys nothing", which the gate then holds it to.
    #[serde(default)]
    pub melted_singletons: Vec<String>,
    /// One canonical description per NFT lifecycle action the spend performs — `"transfer nft1…"`
    /// / `"mint nft1…"` (dig_ecosystem#3077).
    ///
    /// An NFT action is nearly free in mojos: a transfer moves the singleton's lone mojo to itself
    /// and nets ~0 XCH. So, exactly like a melt, it is expressible in neither
    /// [`outputs`](Self::outputs) nor [`fee`](Self::fee), and a person shown only those would
    /// confirm a dust movement while an NFT changed hands. Naming the action here is what lets the
    /// confirm screen say what is happening and the signing gate refuse a bundle whose NFT action
    /// the reviewed summary never mentioned.
    ///
    /// Additive (`#[serde(default)]`) so older wire payloads still deserialize — an absent field
    /// means "this spend touches no NFT", which the gate then holds it to.
    #[serde(default)]
    pub nft_operations: Vec<String>,
}

impl TransactionSummary {
    /// Build a one-way-send summary (no `received` leg) — the common case, and the only
    /// constructor an external crate needs since `#[non_exhaustive]` (#2242) forbids a bare
    /// struct literal outside this crate. A two-sided summary (an offer MAKE's `received` leg)
    /// is still built in-crate, where the literal form remains available.
    pub fn new(outputs: Vec<SpendOutput>, fee: Amount) -> Self {
        Self {
            outputs,
            received: Vec::new(),
            fee,
            melted_singletons: Vec::new(),
            nft_operations: Vec::new(),
        }
    }
}

/// One recipient line within a [`TransactionSummary`].
///
/// `#[non_exhaustive]` (#2242): a decode-output line type — grows additively alongside
/// `TransactionSummary`, so external matches/literals must use `..`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SpendOutput {
    /// The destination address.
    pub address: Address,
    /// The amount sent to it.
    pub amount: Amount,
    /// The asset sent; `None` = native XCH.
    pub asset_id: Option<AssetId>,
}

impl SpendOutput {
    /// Whether this output is a settlement/protocol SINK rather than a recipient payment.
    ///
    /// Convention (the single source of truth for it): an EMPTY address marks an output that flows
    /// into the offer/settlement protocol machinery (a settlement-layer coin, a change-to-self sink)
    /// rather than to a named recipient. Sinks are compared by amount + asset only — never by
    /// address — because they have no meaningful destination string. WHY it matters: the signer's
    /// egress gate ([`assert_reviewed_summary_matches`]) relies on this distinction to multiset-match
    /// the reviewed summary against what will actually be signed; a bare `address.0.is_empty()` check
    /// scattered across the emit/read-back seams could silently disagree, so both seams route through
    /// this one named predicate.
    pub fn is_protocol_sink(&self) -> bool {
        self.address.0.is_empty()
    }
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
            melted_singletons: Vec::new(),
            nft_operations: Vec::new(),
            received: vec![],
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

    /// #2282: an EMPTY address marks a protocol sink; a non-empty one is a recipient.
    #[test]
    fn is_protocol_sink_tracks_the_empty_address_convention() {
        let sink = SpendOutput {
            address: Address(String::new()),
            amount: Amount(5),
            asset_id: None,
        };
        let recipient = SpendOutput {
            address: Address("xch1abc".into()),
            amount: Amount(5),
            asset_id: None,
        };
        assert!(sink.is_protocol_sink());
        assert!(!recipient.is_protocol_sink());
    }
}
