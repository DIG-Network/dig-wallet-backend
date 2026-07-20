//! Tipping request/response types — the seam contract for $DIG tips (SPEC §3c, dig_ecosystem#377).
//!
//! These are the pure, serializable value types both seams speak to build a tip — a single CAT
//! payment (typically $DIG) to a recipient — that the engine constructs by composing the canonical
//! [`dig-tips`](https://crates.io/crates/dig-tips) crate (never by re-implementing CAT CLVM, §4.1).
//! Like every type in this layer they carry only PUBLIC material: parties are named by puzzle
//! hashes, keys never appear.
//!
//! # The honest auto-tip (§6.0 $DIG North Star)
//! [`AutoTipRequest`] drives the default-on, capped, one-click-off auto-tip. The decision is made
//! FIRST (against the caps in [`AutoTipPolicy`] + today's [`TipLedger`]); the spend is built ONLY
//! when the decision is [`TipDecision::Tip`], so a capped/declined tip can never be constructed.
//! Moving $DIG must never gate consuming content — a tip is always declinable and one-flag-off.

use serde::{Deserialize, Serialize};

use super::identity::IdentityRef;
use super::value::Puzzlehash;
use super::{Amount, AssetId, UnsignedSpend};

/// A request to TIP `amount` base units of `asset_id` to `recipient`, drawn from `identity`'s CATs.
///
/// A tip is a single CAT payment; surplus returns to the identity's change puzzle hash. This is the
/// low-level, always-attempt path (an explicit user tip) — the guarded auto-tip is
/// [`AutoTipRequest`], which decides against the caps before building.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipRequest {
    /// The tipping identity — its spendable CATs fund the tip (public material).
    pub identity: IdentityRef,
    /// The CAT asset id being tipped (e.g. the $DIG asset id).
    pub asset_id: AssetId,
    /// The tip recipient's inner (p2) puzzle hash.
    pub recipient: Puzzlehash,
    /// The tip amount, in the CAT's base units.
    pub amount: Amount,
}

/// How the auto-tip fires: automatically on a qualifying event, or only with explicit approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipMode {
    /// Tip automatically when a qualifying event occurs (still capped + declinable).
    Auto,
    /// Never tip without an explicit per-tip approval from the user.
    Manual,
}

/// The honest, capped, declinable auto-tip configuration (the serializable mirror of
/// `dig_tips::AutoTipPolicy`).
///
/// Every field is user-visible so a settings UI can render + persist it: the one-click-off is
/// `enabled = false`, and the two daily caps are hard ceilings the auto-tip can never exceed —
/// keeping the default-on money movement honest (§6.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoTipPolicy {
    /// The master switch. `false` is the one-click-off — no tip is decided while disabled.
    pub enabled: bool,
    /// Whether tips fire automatically or require explicit approval.
    pub mode: TipMode,
    /// The CAT asset id being tipped (e.g. the $DIG asset id).
    pub asset_id: AssetId,
    /// The tip recipient's inner (p2) puzzle hash (typically the DIG treasury).
    pub recipient: Puzzlehash,
    /// The amount each tip sends, in base units.
    pub tip_amount: Amount,
    /// The minimum primary-send amount that triggers an auto-tip (base units).
    pub threshold: Amount,
    /// The hard cap on the NUMBER of tips per UTC day.
    pub max_tips_per_day: u32,
    /// The hard cap on the total tipped AMOUNT per UTC day (base units).
    pub max_amount_per_day: Amount,
}

/// Today's running tip counters (owned + persisted by the caller, reset at the UTC day boundary).
///
/// The mirror of `dig_tips::LedgerSnapshot` — the caps are evaluated against these so a running
/// total can never be bypassed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipLedger {
    /// How many tips have already fired today.
    pub tips_today: u32,
    /// The total amount already tipped today (base units).
    pub amount_today: Amount,
}

impl Default for TipLedger {
    /// A fresh day: no tips fired, nothing tipped yet.
    fn default() -> Self {
        Self {
            tips_today: 0,
            amount_today: Amount(0),
        }
    }
}

/// A request to auto-tip alongside a primary send of `primary_send_amount`, gated by `policy` +
/// `ledger`. The spend is built only if the decision is [`TipDecision::Tip`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoTipRequest {
    /// The tipping identity — its spendable CATs fund the tip (public material).
    pub identity: IdentityRef,
    /// The auto-tip policy (recipient, amount, caps, on/off).
    pub policy: AutoTipPolicy,
    /// The amount of the primary send this tip rides alongside (base units).
    pub primary_send_amount: Amount,
    /// Today's running tip counters, for the cap evaluation.
    pub ledger: TipLedger,
}

/// Why a tip was deferred by a daily cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapReason {
    /// The per-day tip COUNT cap is reached.
    Frequency,
    /// The per-day AMOUNT cap would be exceeded.
    Amount,
}

/// The outcome of an auto-tip decision (the serializable mirror of `dig_tips::TipDecision`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum TipDecision {
    /// Tip `amount` base units to the policy's recipient.
    Tip {
        /// The amount to tip, in base units.
        amount: Amount,
    },
    /// The auto-tip is switched off.
    SkipDisabled,
    /// The triggering send was below the policy threshold.
    SkipBelowThreshold,
    /// A manual-mode tip was not (yet) approved.
    SkipManualNotApproved,
    /// A daily cap prevents the tip.
    SkipCapReached {
        /// Which cap was hit.
        reason: CapReason,
    },
}

/// The result of an [`AutoTipRequest`]: the decision the caps produced, and the unsigned tip spend
/// IFF the decision was [`TipDecision::Tip`] (otherwise `None` — nothing was built).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoTipOutcome {
    /// What the caps decided.
    pub decision: TipDecision,
    /// The unsigned tip spend, present only when `decision` is [`TipDecision::Tip`].
    pub unsigned: Option<UnsignedSpend>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WalletId;

    fn sample_policy() -> AutoTipPolicy {
        AutoTipPolicy {
            enabled: true,
            mode: TipMode::Auto,
            asset_id: AssetId("ab".repeat(32)),
            recipient: Puzzlehash("cd".repeat(32)),
            tip_amount: Amount(1_000),
            threshold: Amount(0),
            max_tips_per_day: 50,
            max_amount_per_day: Amount(50_000),
        }
    }

    #[test]
    fn tip_request_round_trips() {
        let req = TipRequest {
            identity: IdentityRef::new(WalletId(1)),
            asset_id: AssetId("ef".repeat(32)),
            recipient: Puzzlehash("12".repeat(32)),
            amount: Amount(1_000),
        };
        let back: TipRequest = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn auto_tip_request_round_trips() {
        let req = AutoTipRequest {
            identity: IdentityRef::new(WalletId(2)),
            policy: sample_policy(),
            primary_send_amount: Amount(100_000),
            ledger: TipLedger::default(),
        };
        let back: AutoTipRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn tip_mode_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&TipMode::Auto).unwrap(), "\"auto\"");
        assert_eq!(
            serde_json::to_string(&TipMode::Manual).unwrap(),
            "\"manual\""
        );
    }

    #[test]
    fn tip_decision_is_tagged() {
        let json = serde_json::to_string(&TipDecision::Tip { amount: Amount(7) }).unwrap();
        assert!(
            json.contains("\"decision\":\"tip\""),
            "unexpected form: {json}"
        );
        let capped = serde_json::to_string(&TipDecision::SkipCapReached {
            reason: CapReason::Amount,
        })
        .unwrap();
        assert!(capped.contains("skip_cap_reached"), "unexpected: {capped}");
    }

    #[test]
    fn auto_tip_outcome_round_trips_with_and_without_a_spend() {
        let skipped = AutoTipOutcome {
            decision: TipDecision::SkipDisabled,
            unsigned: None,
        };
        let back: AutoTipOutcome =
            serde_json::from_str(&serde_json::to_string(&skipped).unwrap()).unwrap();
        assert_eq!(skipped, back);
    }
}
