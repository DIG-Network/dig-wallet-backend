//! `engine::selection` — capped, high-value-first XCH/CAT coin selection (SPEC §3).
//!
//! Selection is the first half of building a spend: given the coins a wallet holds and a
//! target amount, pick the exact input coins the [`super::build::SpendBuilder`] will spend.
//! It is pure — no network, no signing, no secret material — and deterministic (coins are
//! ordered largest-first, ties broken by coin id), so the same wallet state always selects
//! the same inputs.
//!
//! # The three outcomes (never conflated)
//! A selection resolves to exactly one [`SelectionOutcome`]:
//! - [`SelectionOutcome::Selected`] — coins covering the target were found within the coin
//!   cap; spend precisely these. Carries the change (`total − target`) so the builder emits
//!   the change output.
//! - [`SelectionOutcome::NeedsConsolidation`] — the wallet holds enough total value, but the
//!   largest `cap` coins cannot reach the target. A spend drawing more than `cap` inputs would
//!   exceed the block/mempool cost ceiling, so the wallet must first merge coins (see
//!   [`select_for_consolidation`]) and retry. This is NOT insufficient funds — consolidation
//!   cannot create value, but it can reach a target that fragmentation had put out of reach.
//! - [`SelectionOutcome::InsufficientFunds`] — the wallet's total spendable value is below the
//!   target; no consolidation could ever cover it.
//!
//! Distinguishing `NeedsConsolidation` from `InsufficientFunds` is the ecosystem-wide contract
//! (mirrors dig-store's `digstore-chain::selection`): a caller must be able to tell "merge and
//! retry" apart from "you simply don't have the money".

use chia::protocol::Coin;

use crate::types::{WalletError, WalletErrorCode, WalletResult};

/// The default maximum number of input coins a single spend may consume.
///
/// A spend bundle drawing too many coins exceeds Chia's block/mempool cost ceiling and is
/// rejected, so selection is bounded: the largest `cap` coins are considered, and a wallet
/// that cannot reach a target within the cap must consolidate first. Consumers that track a
/// different cap (e.g. [`super::sync::SyncConfig::coin_cap`]) pass their own value.
pub const DEFAULT_COIN_CAP: usize = 500;

/// The result of a capped, high-value-first selection over a wallet's coins.
///
/// The three variants are deliberately distinct so a caller never conflates "merge and retry"
/// ([`Self::NeedsConsolidation`]) with a genuine shortfall ([`Self::InsufficientFunds`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionOutcome {
    /// Coins reaching the target were found within the cap; spend exactly these.
    Selected {
        /// The selected coins, high-value-first (each an input coin, identity preserved so the
        /// builder can spend it under its owning key).
        coins: Vec<Coin>,
        /// Total mojos / CAT base units of the selected coins.
        total: u64,
        /// Excess over the target (`total − target`) — the change output amount.
        change: u64,
    },
    /// Enough total value exists, but reaching the target needs more than `cap` coins.
    /// Consolidate and retry.
    NeedsConsolidation {
        /// The number of unspent coins the wallet holds.
        available_coin_count: u32,
        /// The sum of all unspent coins (always `>= required`).
        available_total: u64,
        /// The target that could not be reached within the cap.
        required: u64,
        /// The coin-count cap in force.
        cap: usize,
    },
    /// The wallet's total value is below the target — genuinely insufficient funds.
    InsufficientFunds {
        /// The sum of all unspent coins (always `< required`).
        available_total: u64,
        /// The target amount that could not be covered.
        required: u64,
    },
}

/// Select coins covering `target`, high-value-first, considering at most `cap` coins.
///
/// Deterministic: coins are ordered by descending amount, ties broken by ascending coin id, so
/// identical wallet state always yields the identical selection. Pure — no network, no signing.
///
/// A `target` of zero selects no coins (the caller — a real spend always has `amount + fee > 0`
/// — is responsible for rejecting an empty spend).
pub fn select_for_spend(coins: &[Coin], target: u64, cap: usize) -> SelectionOutcome {
    let available_total: u64 = coins.iter().map(|c| c.amount).sum();
    let available_coin_count = coins.len() as u32;

    if available_total < target {
        return SelectionOutcome::InsufficientFunds {
            available_total,
            required: target,
        };
    }

    let ordered = ordered_high_value_first(coins);

    // Only the largest `cap` coins are spendable in one bundle. If even those cannot reach the
    // target, the wallet holds the value but too fragmented — it must consolidate first.
    let capped_total: u64 = ordered.iter().take(cap).map(|c| c.amount).sum();
    if capped_total < target {
        return SelectionOutcome::NeedsConsolidation {
            available_coin_count,
            available_total,
            required: target,
            cap,
        };
    }

    // Take the minimal high-value-first prefix that reaches the target (guaranteed within `cap`,
    // since the largest `cap` coins already cover it).
    let mut selected = Vec::new();
    let mut total = 0u64;
    for coin in ordered {
        if total >= target {
            break;
        }
        total += coin.amount;
        selected.push(coin);
    }
    SelectionOutcome::Selected {
        coins: selected,
        total,
        change: total - target,
    }
}

/// Select up to `cap` coins to merge into one during consolidation, highest-value-first.
///
/// Requires at least two coins (merging one coin is a no-op). The returned coins feed the
/// consolidation spend the builder constructs. Pure — no network, no signing.
pub fn select_for_consolidation(coins: &[Coin], cap: usize) -> WalletResult<Vec<Coin>> {
    if coins.len() < 2 {
        return Err(WalletError::new(
            WalletErrorCode::InvalidInput,
            "consolidation requires at least two coins",
        ));
    }
    let mut ordered = ordered_high_value_first(coins);
    ordered.truncate(cap.max(2));
    Ok(ordered)
}

/// Order coins by descending amount, ties broken by ascending coin id (deterministic).
fn ordered_high_value_first(coins: &[Coin]) -> Vec<Coin> {
    let mut ordered = coins.to_vec();
    ordered.sort_by(|a, b| {
        b.amount
            .cmp(&a.amount)
            .then_with(|| a.coin_id().cmp(&b.coin_id()))
    });
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia::protocol::Bytes32;

    /// A coin with a distinct id per `seed` and the given `amount`.
    fn coin(amount: u64, seed: u8) -> Coin {
        Coin::new(
            Bytes32::new([seed; 32]),
            Bytes32::new([seed.wrapping_add(100); 32]),
            amount,
        )
    }

    fn amounts(coins: &[Coin]) -> Vec<u64> {
        coins.iter().map(|c| c.amount).collect()
    }

    #[test]
    fn default_cap_is_500() {
        assert_eq!(DEFAULT_COIN_CAP, 500);
    }

    #[test]
    fn selects_high_value_first_with_change() {
        let coins = [coin(100, 1), coin(300, 2), coin(200, 3)];
        match select_for_spend(&coins, 400, DEFAULT_COIN_CAP) {
            SelectionOutcome::Selected {
                coins,
                total,
                change,
            } => {
                // 300 then 200 reaches 400; the 100 coin is untouched.
                assert_eq!(amounts(&coins), vec![300, 200]);
                assert_eq!(total, 500);
                assert_eq!(change, 100);
            }
            other => panic!("expected Selected, got {other:?}"),
        }
    }

    #[test]
    fn exact_target_yields_zero_change() {
        let coins = [coin(300, 1), coin(200, 2)];
        match select_for_spend(&coins, 500, DEFAULT_COIN_CAP) {
            SelectionOutcome::Selected { total, change, .. } => {
                assert_eq!(total, 500);
                assert_eq!(change, 0);
            }
            other => panic!("expected Selected, got {other:?}"),
        }
    }

    #[test]
    fn stops_at_the_minimal_prefix() {
        // 500 alone covers 400; the second coin must NOT be selected.
        let coins = [coin(500, 1), coin(400, 2)];
        match select_for_spend(&coins, 400, DEFAULT_COIN_CAP) {
            SelectionOutcome::Selected { coins, change, .. } => {
                assert_eq!(amounts(&coins), vec![500]);
                assert_eq!(change, 100);
            }
            other => panic!("expected Selected, got {other:?}"),
        }
    }

    #[test]
    fn selection_is_deterministic_across_input_order() {
        let a = [coin(100, 1), coin(300, 2), coin(200, 3)];
        let b = [coin(200, 3), coin(100, 1), coin(300, 2)];
        assert_eq!(
            select_for_spend(&a, 400, DEFAULT_COIN_CAP),
            select_for_spend(&b, 400, DEFAULT_COIN_CAP),
        );
    }

    #[test]
    fn equal_amounts_tie_break_by_coin_id() {
        // Two coins of equal value: the one with the smaller coin id is chosen first.
        let coins = [coin(50, 9), coin(50, 1)];
        let SelectionOutcome::Selected { coins: picked, .. } =
            select_for_spend(&coins, 50, DEFAULT_COIN_CAP)
        else {
            panic!("expected Selected");
        };
        assert_eq!(picked.len(), 1);
        let expected = if coin(50, 1).coin_id() < coin(50, 9).coin_id() {
            coin(50, 1)
        } else {
            coin(50, 9)
        };
        assert_eq!(picked[0].coin_id(), expected.coin_id());
    }

    #[test]
    fn at_cap_boundary_is_selected() {
        // 50 coins of 1, cap 50, target 50 → all 50 reach it exactly, within the cap.
        let coins: Vec<Coin> = (0..50).map(|i| coin(1, i as u8)).collect();
        match select_for_spend(&coins, 50, 50) {
            SelectionOutcome::Selected { total, change, .. } => {
                assert_eq!(total, 50);
                assert_eq!(change, 0);
            }
            other => panic!("expected Selected at the cap boundary, got {other:?}"),
        }
    }

    #[test]
    fn one_over_cap_needs_consolidation() {
        // 51 coins of 1, cap 50, target 51 → total 51 is enough but the largest 50 sum to 50.
        let coins: Vec<Coin> = (0..51).map(|i| coin(1, i as u8)).collect();
        match select_for_spend(&coins, 51, 50) {
            SelectionOutcome::NeedsConsolidation {
                available_coin_count,
                available_total,
                required,
                cap,
            } => {
                assert_eq!(available_coin_count, 51);
                assert_eq!(available_total, 51);
                assert_eq!(required, 51);
                assert_eq!(cap, 50);
            }
            other => panic!("expected NeedsConsolidation, got {other:?}"),
        }
    }

    #[test]
    fn genuine_shortfall_is_insufficient_not_consolidation() {
        let coins: Vec<Coin> = (0..51).map(|i| coin(1, i as u8)).collect();
        match select_for_spend(&coins, 100, 50) {
            SelectionOutcome::InsufficientFunds {
                available_total,
                required,
            } => {
                assert_eq!(available_total, 51);
                assert_eq!(required, 100);
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    #[test]
    fn empty_wallet_is_insufficient() {
        match select_for_spend(&[], 10, DEFAULT_COIN_CAP) {
            SelectionOutcome::InsufficientFunds {
                available_total,
                required,
            } => {
                assert_eq!(available_total, 0);
                assert_eq!(required, 10);
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    #[test]
    fn zero_target_selects_nothing() {
        match select_for_spend(&[coin(10, 1)], 0, DEFAULT_COIN_CAP) {
            SelectionOutcome::Selected { coins, change, .. } => {
                assert!(coins.is_empty());
                assert_eq!(change, 0);
            }
            other => panic!("expected an empty Selected, got {other:?}"),
        }
    }

    #[test]
    fn selected_coins_are_inputs() {
        let inputs = [coin(500, 7), coin(400, 8)];
        let SelectionOutcome::Selected { coins, .. } =
            select_for_spend(&inputs, 600, DEFAULT_COIN_CAP)
        else {
            panic!("expected Selected");
        };
        let input_ids: std::collections::HashSet<Bytes32> =
            inputs.iter().map(|c| c.coin_id()).collect();
        for c in &coins {
            assert!(
                input_ids.contains(&c.coin_id()),
                "selected coin is an input"
            );
        }
    }

    #[test]
    fn consolidation_picks_largest_capped() {
        let coins = [coin(5, 1), coin(1, 2), coin(4, 3), coin(2, 4), coin(3, 5)];
        let picked = select_for_consolidation(&coins, 3).unwrap();
        assert_eq!(amounts(&picked), vec![5, 4, 3]);
    }

    #[test]
    fn consolidation_requires_two_coins() {
        assert_eq!(
            select_for_consolidation(&[coin(10, 1)], 50)
                .unwrap_err()
                .code,
            WalletErrorCode::InvalidInput
        );
        assert_eq!(
            select_for_consolidation(&[], 50).unwrap_err().code,
            WalletErrorCode::InvalidInput
        );
    }

    #[test]
    fn consolidation_never_truncates_below_two() {
        // A cap of 1 would merge nothing; consolidation keeps at least two coins.
        let coins = [coin(5, 1), coin(4, 2), coin(3, 3)];
        assert_eq!(select_for_consolidation(&coins, 1).unwrap().len(), 2);
    }
}
