//! `client::review` — spend REVIEW / DECODE for the native-confirm UI (SPEC §4).
//!
//! Before dig-app signs, it shows the user exactly what a spend does. This module turns an
//! [`UnsignedSpend`]'s summary into human-readable lines ("Send 1.5 XCH to xch1… · fee 0.0001
//! XCH") so the user reviews rather than trusts blindly. Decoding is deterministic and
//! side-effect free.

use crate::types::{Amount, UnsignedSpend};

/// Mojos per one XCH (12 decimal places).
const MOJOS_PER_XCH: u64 = 1_000_000_000_000;

/// A human-readable rendering of an unsigned spend for the confirm dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanReadableSummary {
    /// One line per recipient output.
    pub lines: Vec<String>,
    /// The fee, rendered.
    pub fee_line: String,
    /// The number of coin spends the transaction contains.
    pub coin_spend_count: usize,
    /// The number of signatures the user's key must produce.
    pub required_signature_count: usize,
}

/// Render `amount` as a decimal XCH string (or the raw base amount for a CAT, when `is_xch`
/// is false). Trailing zeros are trimmed for readability; `0` renders as `0`.
fn render_amount(amount: Amount, is_xch: bool) -> String {
    if !is_xch {
        return amount.mojos().to_string();
    }
    let mojos = amount.mojos();
    let whole = mojos / MOJOS_PER_XCH;
    let frac = mojos % MOJOS_PER_XCH;
    if frac == 0 {
        return whole.to_string();
    }
    let frac_str = format!("{frac:012}");
    let trimmed = frac_str.trim_end_matches('0');
    format!("{whole}.{trimmed}")
}

/// Decode an unsigned spend into a human-readable summary for review.
pub fn decode(unsigned: &UnsignedSpend) -> HumanReadableSummary {
    let lines = unsigned
        .summary
        .outputs
        .iter()
        .map(|out| {
            let is_xch = out.asset_id.is_none();
            let unit = match &out.asset_id {
                None => "XCH".to_string(),
                Some(asset) => format!("CAT {}", asset.0),
            };
            format!(
                "Send {} {} to {}",
                render_amount(out.amount, is_xch),
                unit,
                out.address.0
            )
        })
        .collect();

    HumanReadableSummary {
        lines,
        fee_line: format!("Fee {} XCH", render_amount(unsigned.summary.fee, true)),
        coin_spend_count: unsigned.coin_spends.len(),
        required_signature_count: unsigned.required_signatures.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, AssetId, SpendOutput, TransactionSummary};

    fn unsigned(outputs: Vec<SpendOutput>, fee: Amount) -> UnsignedSpend {
        UnsignedSpend {
            coin_spends: vec![],
            required_signatures: vec![],
            summary: TransactionSummary { outputs, fee },
        }
    }

    #[test]
    fn renders_whole_and_fractional_xch() {
        assert_eq!(render_amount(Amount(MOJOS_PER_XCH), true), "1");
        assert_eq!(
            render_amount(Amount(MOJOS_PER_XCH + MOJOS_PER_XCH / 2), true),
            "1.5"
        );
        assert_eq!(render_amount(Amount(0), true), "0");
        assert_eq!(render_amount(Amount(1), true), "0.000000000001");
    }

    #[test]
    fn renders_cat_base_units_raw() {
        assert_eq!(render_amount(Amount(1000), false), "1000");
    }

    #[test]
    fn decode_produces_a_line_per_output() {
        let spend = unsigned(
            vec![
                SpendOutput {
                    address: Address("xch1alice".into()),
                    amount: Amount(MOJOS_PER_XCH),
                    asset_id: None,
                },
                SpendOutput {
                    address: Address("xch1bob".into()),
                    amount: Amount(50),
                    asset_id: Some(AssetId("tail123".into())),
                },
            ],
            Amount(MOJOS_PER_XCH / 10000),
        );
        let summary = decode(&spend);
        assert_eq!(summary.lines.len(), 2);
        assert_eq!(summary.lines[0], "Send 1 XCH to xch1alice");
        assert_eq!(summary.lines[1], "Send 50 CAT tail123 to xch1bob");
        assert_eq!(summary.fee_line, "Fee 0.0001 XCH");
        assert_eq!(summary.coin_spend_count, 0);
        assert_eq!(summary.required_signature_count, 0);
    }

    #[test]
    fn decode_of_empty_spend_has_no_lines() {
        let summary = decode(&unsigned(vec![], Amount(0)));
        assert!(summary.lines.is_empty());
        assert_eq!(summary.fee_line, "Fee 0 XCH");
    }
}
