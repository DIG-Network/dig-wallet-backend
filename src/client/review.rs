//! `client::review` — spend REVIEW / DECODE for the native-confirm UI (SPEC §4).
//!
//! Before dig-app signs, it shows the user exactly what a spend does. This module turns an
//! [`UnsignedSpend`]'s summary into human-readable lines ("Send 1.5 XCH to xch1… · fee 0.0001
//! XCH") so the user reviews rather than trusts blindly. Decoding is deterministic and
//! side-effect free.

use crate::types::{Amount, TransactionSummary, UnsignedSpend};

/// Mojos per one XCH (12 decimal places).
const MOJOS_PER_XCH: u64 = 1_000_000_000_000;

/// A human-readable rendering of an unsigned spend for the confirm dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanReadableSummary {
    /// One line per recipient output — value LEAVING the wallet.
    pub lines: Vec<String>,
    /// One line per RECEIVED output — value the spend causes the wallet to receive (an offer MAKE's
    /// requested payments). Distinct from [`lines`] so the confirm shows the trade both ways without
    /// conflating what leaves with what arrives; empty for a plain one-way send (#2241).
    ///
    /// # Engine-declared, NOT verified
    /// Unlike [`lines`] (the egress the signer cryptographically gates on), these lines are the
    /// engine's DECLARED upside: a make binds its requested payment as a non-invertible
    /// settlement-announcement hash, so the received value is not re-derivable from the coin spends
    /// and cannot be independently verified. Each line is prefixed with an explicit "(unverified)"
    /// marker so a maker never attributes egress-grade assurance to the receive side. Full
    /// crypto-verification of the requested payment is a separate follow-up.
    pub receive_lines: Vec<String>,
    /// The fee, rendered.
    pub fee_line: String,
    /// The number of coin spends the transaction contains.
    pub coin_spend_count: usize,
    /// The number of signatures the user's key must produce.
    pub required_signature_count: usize,
    /// Whether the rendered lines were INDEPENDENTLY re-derived from the coin spends
    /// ([`super::verify::derive_summary`], or the key-aware
    /// [`super::signer::LocalSigner::decode_verified`]). When `false` the spend could not be
    /// independently decoded — the lines fall back to the engine's (untrusted) claim and the confirm
    /// UI MUST surface this as unverifiable; [`super::signer::LocalSigner::sign_unsigned`] will refuse
    /// to sign it.
    pub verified: bool,
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

/// Decode an unsigned spend into a human-readable summary for DISPLAY-ONLY review — MAY be unverified.
///
/// The rendered value flow is re-derived straight from the coin spends
/// ([`super::verify::derive_summary`], #1058) so the confirm dialog shows what the transaction
/// ACTUALLY does — the same authoritative summary the signer gates on — never the engine's
/// (potentially lying) claim. If the spend cannot be independently decoded the engine summary is
/// shown as a last resort with [`HumanReadableSummary::verified`] `= false`.
///
/// # Never use this ahead of signing
/// This lenient mode can silently degrade from "what the bundle DOES" to "what the (untrusted)
/// builder CLAIMS it does". It is safe ONLY for a display surface that renders + honours the
/// `verified` flag. Any path that precedes signing / a pre-sign consent prompt MUST use
/// [`super::signer::LocalSigner::decode_verified`] instead, which has NO fallback AND applies the
/// signer's key-aware ownership split, so it fails closed (#2209). The naming makes the unsafe choice
/// the loud one: a caller that reaches for `decode` is opting into a possibly-unverified,
/// key-free screen.
///
/// # Key-free — do not trust its recipient/change split
/// `decode` renders the KEY-FREE [`super::verify::derive_summary`], whose recipient/change split is a
/// memo heuristic with no ownership check. An un-hinted output to a NON-owned address is bucketed as
/// "change" and dropped from the rendered lines — so this view can hide a real egress. Only the
/// key-aware [`super::signer::LocalSigner::decode_verified`] (which the signer authorizes against)
/// surfaces every non-owned output. This lenient decode is for a display surface only.
pub fn decode(unsigned: &UnsignedSpend) -> HumanReadableSummary {
    match super::verify::derive_summary(&unsigned.coin_spends) {
        Ok(summary) => render(unsigned, &summary, true),
        // Fall back to the engine's (untrusted) claim, flagged unverified. The signer refuses to
        // sign such a spend regardless (`verify_before_signing` re-runs `analyze` fail-closed).
        Err(_) => render(unsigned, &unsigned.summary, false),
    }
}

/// Render a re-derived [`TransactionSummary`] into the human-readable confirm lines. `verified`
/// records whether `summary` came from an independent re-derivation
/// ([`super::signer::LocalSigner::decode_verified`] and the happy path of [`decode`] pass `true`;
/// [`decode`] passes `false` for its engine-claim fallback).
///
/// `pub(crate)` so the key-aware consent decode on [`super::signer::LocalSigner`] renders through the
/// SAME formatter as the lenient display decode — one rendering of confirm lines, no drift.
pub(crate) fn render(
    unsigned: &UnsignedSpend,
    summary: &TransactionSummary,
    verified: bool,
) -> HumanReadableSummary {
    let lines = summary
        .outputs
        .iter()
        .map(|out| render_output_line("Send", out))
        .collect();

    // The received legs are rendered from the engine-declared `unsigned.summary`, NOT from the
    // (possibly re-derived) `summary` argument: a make's requested payment is bound as a
    // non-invertible settlement-announcement hash, so it is not independently re-derivable and the
    // key-free / key-aware re-derivation leaves `received` empty. Sourcing it from the reviewed
    // spend's own summary makes the receive lines identical on both the display decode and the
    // consent decode (#2241). The "(unverified)" verb marks these as engine-declared — the received
    // value is bound as a non-invertible announcement hash, so it is NOT independently re-derivable
    // like the gated "Send" egress; a maker must not read egress-grade assurance into the upside.
    let receive_lines = unsigned
        .summary
        .received
        .iter()
        .map(|out| render_output_line("Receive (unverified)", out))
        .collect();

    HumanReadableSummary {
        lines,
        receive_lines,
        fee_line: format!("Fee {} XCH", render_amount(summary.fee, true)),
        coin_spend_count: unsigned.coin_spends.len(),
        required_signature_count: unsigned.required_signatures.len(),
        verified,
    }
}

/// Render one output as a `"<verb> <amount> <unit> to <address>"` line (e.g. `Send`/`Receive`).
fn render_output_line(verb: &str, out: &crate::types::SpendOutput) -> String {
    let is_xch = out.asset_id.is_none();
    let unit = match &out.asset_id {
        None => "XCH".to_string(),
        Some(asset) => format!("CAT {}", asset.0),
    };
    format!(
        "{} {} {} to {}",
        verb,
        render_amount(out.amount, is_xch),
        unit,
        out.address.0
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, AssetId, SpendOutput};

    fn unsigned(outputs: Vec<SpendOutput>, fee: Amount) -> UnsignedSpend {
        UnsignedSpend {
            coin_spends: vec![],
            required_signatures: vec![],
            summary: TransactionSummary {
                outputs,
                received: vec![],
                fee,
            },
        }
    }

    /// #2241: a summary carrying a `received` leg renders a distinct "Receive …" line, separate from
    /// the "Send …" recipient lines, so an offer make shows the trade both ways at the confirm.
    #[test]
    fn decode_renders_received_legs_as_distinct_receive_lines() {
        let mut spend = unsigned(
            vec![SpendOutput {
                address: Address(String::new()),
                amount: Amount(1000),
                asset_id: Some(AssetId("dig".into())),
            }],
            Amount(0),
        );
        spend.summary.received = vec![SpendOutput {
            address: Address("xch1maker".into()),
            amount: Amount(MOJOS_PER_XCH),
            asset_id: None,
        }];
        let summary = decode(&spend);
        assert_eq!(summary.lines.len(), 1);
        // The receive leg is engine-declared, so it renders with an explicit "(unverified)" marker,
        // distinct from the cryptographically-gated "Send" lines (#2241).
        assert_eq!(
            summary.receive_lines,
            vec!["Receive (unverified) 1 XCH to xch1maker"]
        );
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
        // No coin spends to independently decode → the engine summary is a fallback, flagged
        // unverified so the confirm UI warns and the signer refuses.
        assert!(!summary.verified);
    }

    #[test]
    fn decode_of_empty_spend_has_no_lines() {
        let summary = decode(&unsigned(vec![], Amount(0)));
        assert!(summary.lines.is_empty());
        assert_eq!(summary.fee_line, "Fee 0 XCH");
        assert!(
            !summary.verified,
            "an undecodable spend is not independently verified"
        );
    }

    /// A real, decodable spend is rendered from the re-derived (authoritative) summary and flagged
    /// verified.
    ///
    /// The no-fallback CONSENT decode is now key-aware and lives on
    /// [`super::super::signer::LocalSigner::decode_verified`] (a free function structurally cannot
    /// apply the ownership split); its coverage — including the divergence from this key-free view on
    /// an un-hinted non-owned output — lives in the signer tests (#2209).
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn decode_of_a_real_spend_is_verified() {
        use crate::engine::build::{SdkSpendBuilder, SpendBuilder, SpendInputs};
        use crate::types::{IdentityRef, Network, SendXchRequest, WalletId};
        use chia_protocol::{Bytes32, Coin};
        use chia_puzzle_types::standard::StandardArgs;
        use chia_wallet_sdk::utils::Address as Bech32Address;
        use std::sync::Arc;

        fn pk() -> chia_bls::PublicKey {
            let mut g = [0u8; 48];
            for (i, b) in [
                0x97u8, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f,
                0xa9, 0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a,
                0x3f, 0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb,
                0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
            ]
            .into_iter()
            .enumerate()
            {
                g[i] = b;
            }
            chia_bls::PublicKey::from_bytes(&g).unwrap()
        }
        fn ph() -> Bytes32 {
            Bytes32::from(StandardArgs::curry_tree_hash(pk()).to_bytes())
        }
        struct One;
        impl SpendInputs for One {
            fn spendable_xch(&self, _: &IdentityRef) -> crate::types::WalletResult<Vec<Coin>> {
                Ok(vec![Coin::new(Bytes32::new([3u8; 32]), ph(), 1000)])
            }
            fn spendable_cat(
                &self,
                _: &IdentityRef,
                _: &crate::types::AssetId,
            ) -> crate::types::WalletResult<Vec<chia_wallet_sdk::driver::Cat>> {
                Ok(vec![])
            }
            fn synthetic_key(&self, p: Bytes32) -> Option<chia_bls::PublicKey> {
                (p == ph()).then(pk)
            }
            fn change_puzzle_hash(&self, _: &IdentityRef) -> crate::types::WalletResult<Bytes32> {
                Ok(ph())
            }
        }
        let to = Address(
            Bech32Address::new(Bytes32::new([7u8; 32]), "xch".into())
                .encode()
                .unwrap(),
        );
        let unsigned = SdkSpendBuilder::new(Arc::new(One), Network::Mainnet, 500)
            .build_send_xch(SendXchRequest {
                identity: IdentityRef::new(WalletId(1)),
                to,
                amount: Amount(600),
                fee: Amount(10),
            })
            .await
            .unwrap();
        let summary = decode(&unsigned);
        assert!(summary.verified);
        assert_eq!(summary.lines.len(), 1);
    }
}
