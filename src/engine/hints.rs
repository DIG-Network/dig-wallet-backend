//! `engine::hints` — the dual-memo coin hint index (SPEC §3).
//!
//! A traditional Chia wallet indexes a coin by its FIRST memo only. That is not enough for DIG:
//! a DataLayer store launcher carries a global launcher hint AND a per-owner hint, and the useful
//! query is usually the CONJUNCTION — "store launchers owned by *this* owner". A first-memo index
//! cannot answer it, and a union index answers it wrongly, returning every launcher in the
//! network.
//!
//! So [`HintIndex`] records every hint a coin was announced under, position-free, and answers all
//! three questions #45 names:
//!
//! | question | method |
//! |---|---|
//! | by memo1 alone | [`HintIndex::coins_by_hint`] |
//! | by memo2 alone | [`HintIndex::coins_by_hint`] |
//! | by memo1 **and** memo2 together | [`HintIndex::coins_by_all_hints`] |
//!
//! The index holds PUBLIC discovery material only — coin ids and memo hex. No key, no secret
//! (the key-isolation invariant, SPEC §1.4).

use std::collections::{BTreeSet, HashMap};

use crate::types::Hint;

/// A position-free, many-to-many index of coin id to the hints the coin was announced under.
///
/// Both directions are kept, so a coin can be withdrawn on a reorg rollback without scanning
/// every hint bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HintIndex {
    /// hint -> the coin ids announced under it.
    by_hint: HashMap<Hint, BTreeSet<String>>,
    /// coin id -> every hint that coin was announced under.
    by_coin: HashMap<String, BTreeSet<Hint>>,
}

impl HintIndex {
    /// An empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `coin_id` was announced under `hints`.
    ///
    /// Every hint is indexed whatever its memo position, and indexing is additive: re-observing a
    /// coin with a further hint widens its entry rather than replacing it.
    pub fn index(&mut self, coin_id: impl Into<String>, hints: impl IntoIterator<Item = Hint>) {
        let coin_id = coin_id.into();
        let entry = self.by_coin.entry(coin_id.clone()).or_default();
        for hint in hints {
            entry.insert(hint.clone());
            self.by_hint
                .entry(hint)
                .or_default()
                .insert(coin_id.clone());
        }
    }

    /// The coin ids announced under `hint`, in deterministic order.
    pub fn coins_by_hint(&self, hint: &Hint) -> Vec<String> {
        self.by_hint
            .get(hint)
            .map(|coins| coins.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The coin ids announced under **every** hint in `hints` — the conjunctive query.
    ///
    /// An empty `hints` matches nothing rather than everything: an unconstrained discovery query
    /// is a caller mistake, and answering it with the whole index would hand back the full coin
    /// set to a caller that constrained on none of it.
    pub fn coins_by_all_hints(&self, hints: &[Hint]) -> Vec<String> {
        let Some((first, rest)) = hints.split_first() else {
            return Vec::new();
        };
        let Some(seed) = self.by_hint.get(first) else {
            return Vec::new();
        };
        let mut matched: BTreeSet<String> = seed.clone();
        for hint in rest {
            let Some(bucket) = self.by_hint.get(hint) else {
                return Vec::new();
            };
            matched.retain(|coin| bucket.contains(coin));
        }
        matched.into_iter().collect()
    }

    /// The coin ids announced under **any** hint in `hints` — the disjunctive query.
    pub fn coins_by_any_hint(&self, hints: &[Hint]) -> Vec<String> {
        let mut matched = BTreeSet::new();
        for hint in hints {
            if let Some(bucket) = self.by_hint.get(hint) {
                matched.extend(bucket.iter().cloned());
            }
        }
        matched.into_iter().collect()
    }

    /// Every hint `coin_id` was announced under, in deterministic order.
    pub fn hints_for(&self, coin_id: &str) -> Vec<Hint> {
        self.by_coin
            .get(coin_id)
            .map(|hints| hints.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Withdraw `coin_id` from the index entirely (a reorg forgot the coin).
    ///
    /// Emptied hint buckets are dropped, so a rolled-back coin leaves no trace a later query
    /// could match on.
    pub fn forget(&mut self, coin_id: &str) {
        let Some(hints) = self.by_coin.remove(coin_id) else {
            return;
        };
        for hint in hints {
            if let Some(bucket) = self.by_hint.get_mut(&hint) {
                bucket.remove(coin_id);
                if bucket.is_empty() {
                    self.by_hint.remove(&hint);
                }
            }
        }
    }

    /// The number of distinct coins in the index.
    pub fn len(&self) -> usize {
        self.by_coin.len()
    }

    /// Whether the index holds no coins.
    pub fn is_empty(&self) -> bool {
        self.by_coin.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memo1() -> Hint {
        Hint::new("11".repeat(32))
    }
    fn memo2() -> Hint {
        Hint::new("22".repeat(32))
    }
    fn other() -> Hint {
        Hint::new("99".repeat(32))
    }

    /// The fixture that separates a correct dual-memo index from the plausible wrong ones.
    ///
    /// - `both` carries memo1 FIRST and memo2 SECOND — the store-launcher shape.
    /// - `first_only` carries memo1 first and an unrelated second memo.
    /// - `second_only` carries an unrelated FIRST memo and memo2 second — the coin a traditional
    ///   first-memo-only index is structurally blind to.
    fn populated() -> HintIndex {
        let mut index = HintIndex::new();
        index.index("both", [memo1(), memo2()]);
        index.index("first_only", [memo1(), other()]);
        index.index("second_only", [other(), memo2()]);
        index
    }

    #[test]
    fn memo1_query_finds_every_coin_carrying_it() {
        assert_eq!(
            populated().coins_by_hint(&memo1()),
            vec!["both", "first_only"]
        );
    }

    /// Load-bearing against a first-memo-only index: `second_only` announces memo2 in SECOND
    /// position, so an index that only ever reads memo[0] returns `["both"]` here and fails.
    #[test]
    fn memo2_query_finds_a_coin_that_carries_it_in_second_position() {
        assert_eq!(
            populated().coins_by_hint(&memo2()),
            vec!["both", "second_only"]
        );
    }

    /// Load-bearing against a UNION implementation of the combined query, which would return all
    /// three coins. Only `both` carries memo1 AND memo2.
    #[test]
    fn combined_query_is_the_intersection_not_the_union() {
        assert_eq!(
            populated().coins_by_all_hints(&[memo1(), memo2()]),
            vec!["both"]
        );
    }

    #[test]
    fn any_hint_query_is_the_union() {
        assert_eq!(
            populated().coins_by_any_hint(&[memo1(), memo2()]),
            vec!["both", "first_only", "second_only"]
        );
    }

    #[test]
    fn combined_query_with_an_unknown_hint_matches_nothing() {
        assert!(populated()
            .coins_by_all_hints(&[memo1(), Hint::new("ff".repeat(32))])
            .is_empty());
    }

    /// An unconstrained conjunctive query must not degenerate into "return everything".
    #[test]
    fn combined_query_with_no_hints_matches_nothing() {
        assert!(populated().coins_by_all_hints(&[]).is_empty());
    }

    #[test]
    fn hints_for_reports_both_memos_of_a_dual_hinted_coin() {
        assert_eq!(populated().hints_for("both"), vec![memo1(), memo2()]);
    }

    #[test]
    fn indexing_again_widens_rather_than_replaces() {
        let mut index = HintIndex::new();
        index.index("c", [memo1()]);
        index.index("c", [memo2()]);
        assert_eq!(index.hints_for("c"), vec![memo1(), memo2()]);
        assert_eq!(index.coins_by_all_hints(&[memo1(), memo2()]), vec!["c"]);
    }

    #[test]
    fn forget_withdraws_a_coin_from_every_bucket() {
        let mut index = populated();
        index.forget("both");
        assert_eq!(index.coins_by_hint(&memo1()), vec!["first_only"]);
        assert_eq!(index.coins_by_hint(&memo2()), vec!["second_only"]);
        assert!(index.coins_by_all_hints(&[memo1(), memo2()]).is_empty());
        assert!(index.hints_for("both").is_empty());
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn forget_drops_an_emptied_bucket_entirely() {
        let mut index = HintIndex::new();
        index.index("only", [memo1()]);
        index.forget("only");
        assert!(index.is_empty());
        assert!(index.coins_by_hint(&memo1()).is_empty());
    }

    #[test]
    fn forgetting_an_unknown_coin_is_a_no_op() {
        let mut index = populated();
        index.forget("nope");
        assert_eq!(index.len(), 3);
    }
}
