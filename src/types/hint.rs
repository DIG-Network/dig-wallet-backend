//! Coin **hints** — the memo values a coin is discoverable by (SPEC §2).
//!
//! A Chia coin announces zero or more memos on creation. A *traditional* wallet treats only the
//! FIRST memo as a hint and indexes coins by that alone. DIG DataLayer store launcher coins carry
//! **two** meaningful memos (dig-merkle `hint.rs` / SPEC §9):
//!
//! - **memo1** — the global `DATASTORE_LAUNCHER_HINT`, shared by every store launcher.
//! - **memo2** — the per-owner hint, `sha256(DIGSTORE_OWNER_HINT_DOMAIN ‖ owner_puzzle_hash)`.
//!
//! Indexing only memo1 makes every store in the network look identical; indexing only memo2 loses
//! "is this a store launcher at all". So this crate indexes **both, in whatever position they
//! appear**, and answers the three questions a caller can ask: by either hint alone, and by the
//! two together (see [`crate::engine::hints::HintIndex`]).

use serde::{Deserialize, Serialize};

/// A single coin hint — the lower-cased hex of a 32-byte memo value.
///
/// Position-free by construction: a hint carries no notion of being "the first memo", which is
/// precisely the assumption a traditional single-memo index bakes in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hint(pub String);

impl Hint {
    /// A hint from any hex-ish string, normalised to lower case and without a `0x` prefix so two
    /// spellings of the same memo index to the same key.
    pub fn new(hex: impl AsRef<str>) -> Self {
        let raw = hex.as_ref();
        let body = raw
            .strip_prefix("0x")
            .or_else(|| raw.strip_prefix("0X"))
            .unwrap_or(raw);
        Self(body.to_ascii_lowercase())
    }

    /// A hint from raw memo bytes.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(bytes))
    }

    /// The normalised hex body.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_normalises_case_and_prefix_to_one_key() {
        assert_eq!(Hint::new("0xAB12"), Hint::new("ab12"));
        assert_eq!(Hint::new("0XAB12"), Hint::new("ab12"));
    }

    #[test]
    fn hint_from_bytes_is_lower_hex() {
        assert_eq!(Hint::from_bytes([0xab, 0x12]).as_str(), "ab12");
    }

    #[test]
    fn hint_round_trips_through_serde() {
        let hint = Hint::new("beef");
        let back: Hint = serde_json::from_str(&serde_json::to_string(&hint).unwrap()).unwrap();
        assert_eq!(hint, back);
    }
}
