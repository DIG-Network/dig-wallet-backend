//! `client::review` — spend REVIEW / DECODE for the native-confirm UI (SPEC §4).
//!
//! Before dig-app signs, it shows the user exactly what a spend does. This module turns an
//! [`UnsignedSpend`]'s summary into human-readable lines ("Send 1.5 XCH to xch1… · fee 0.0001
//! XCH") so the user reviews rather than trusts blindly. Decoding is deterministic and
//! side-effect free.

use crate::types::{Amount, TransactionSummary, UnsignedSpend, WalletResult};

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
    /// Whether the rendered lines were INDEPENDENTLY re-derived from the coin spends
    /// ([`super::verify::derive_summary`]). When `false` the spend could not be independently decoded
    /// — the lines fall back to the engine's (untrusted) claim and the confirm UI MUST surface this
    /// as unverifiable; [`super::signer::LocalSigner::sign_unsigned`] will refuse to sign it.
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
/// [`decode_verified`] instead, which has NO fallback and fails closed (#2209). The naming makes the
/// unsafe choice the loud one: a caller that reaches for `decode` is opting into a possibly-unverified
/// screen.
pub fn decode(unsigned: &UnsignedSpend) -> HumanReadableSummary {
    match super::verify::derive_summary(&unsigned.coin_spends) {
        Ok(summary) => render(unsigned, &summary, true),
        // Fall back to the engine's (untrusted) claim, flagged unverified. The signer refuses to
        // sign such a spend regardless (`verify_before_signing` re-runs `analyze` fail-closed).
        Err(_) => render(unsigned, &unsigned.summary, false),
    }
}

/// Decode an unsigned spend for a pre-sign CONSENT prompt — NO fallback, fails closed (#2209).
///
/// Unlike [`decode`], this mode has no unverified branch: if the value flow cannot be independently
/// re-derived from the coin spends ([`super::verify::derive_summary`]) it returns `Err`, and NEVER
/// renders the engine's (untrusted) claim. Use it on any path that leads to signing, so the screen a
/// user consents to is always the one the interpreter proved — never the one the builder asserted.
///
/// # The single-interpreter invariant
/// Exactly ONE component interprets what a spend means: [`super::verify::analyze`] (via
/// [`super::verify::derive_summary`]). The signer gates on it ([`super::signer::LocalSigner::
/// verify_before_signing`]) and the consent prompt renders from it here — so the screen the user
/// approves and the bytes the signer authorizes derive from the SAME source, by construction. The
/// lenient [`decode`] fallback quietly swaps that interpreter for the builder's claim at the worst
/// moment; `decode_verified` refuses to. The returned summary is always `verified`.
pub fn decode_verified(unsigned: &UnsignedSpend) -> WalletResult<HumanReadableSummary> {
    let summary = super::verify::derive_summary(&unsigned.coin_spends)?;
    Ok(render(unsigned, &summary, true))
}

/// Render a re-derived (or, for the lenient path, fallback) [`TransactionSummary`] into the
/// human-readable confirm lines. `verified` records whether `summary` came from the independent
/// re-derivation ([`decode_verified`] always passes `true`; [`decode`] passes `false` for its
/// engine-claim fallback).
fn render(
    unsigned: &UnsignedSpend,
    summary: &TransactionSummary,
    verified: bool,
) -> HumanReadableSummary {
    let lines = summary
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
        fee_line: format!("Fee {} XCH", render_amount(summary.fee, true)),
        coin_spend_count: unsigned.coin_spends.len(),
        required_signature_count: unsigned.required_signatures.len(),
        verified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, AssetId, SpendOutput};

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

    /// The no-fallback [`decode_verified`] REFUSES exactly where the lenient [`decode`] silently
    /// degrades to the engine's (untrusted) claim (`verified: false`).
    ///
    /// The bundle is a REAL coin spend whose re-derivation genuinely fails — a non-standard puzzle
    /// (the identity program `1`, solution `()`) the chia-wallet-sdk drivers cannot account for, run
    /// through the same [`super::verify::analyze`] wire the signer gates on. It is not a mock rigged
    /// to report failure: `analyze` runs the actual puzzle and rejects it fail-closed.
    #[test]
    fn decode_verified_refuses_where_lenient_decode_is_unverified() {
        use crate::types::WalletErrorCode;
        use chia_protocol::{Bytes32, Coin, CoinSpend};

        // A coin spend the drivers cannot decode: the identity puzzle `1` is neither a standard
        // layer, a CAT, an option, nor a settlement puzzle, so `analyze` refuses it.
        let coin = Coin::new(Bytes32::new([1u8; 32]), Bytes32::new([2u8; 32]), 100);
        let bad_spend = CoinSpend::new(coin, vec![0x01].into(), vec![0x80].into());
        let unsigned = UnsignedSpend {
            coin_spends: vec![bad_spend],
            required_signatures: vec![],
            summary: TransactionSummary {
                outputs: vec![SpendOutput {
                    address: Address("xch1attacker".into()),
                    amount: Amount(MOJOS_PER_XCH),
                    asset_id: None,
                }],
                fee: Amount(0),
            },
        };

        // The lenient decoder degrades to the engine's untrusted claim, flagged unverified.
        let lenient = decode(&unsigned);
        assert!(
            !lenient.verified,
            "the lenient decoder falls back to the engine claim, flagged unverified"
        );
        assert_eq!(
            lenient.lines,
            vec!["Send 1 XCH to xch1attacker".to_string()]
        );

        // The no-fallback decoder REFUSES — it never renders the untrusted engine claim.
        let err = decode_verified(&unsigned)
            .expect_err("decode_verified must fail when re-derivation fails, never fall back");
        assert_eq!(err.code, WalletErrorCode::SpendValidationFailed);
    }

    /// A real, decodable spend is rendered from the re-derived (authoritative) summary and flagged
    /// verified.
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

        // The no-fallback consent decoder SUCCEEDS on a genuinely decodable spend and matches the
        // lenient render byte-for-byte (same interpreter, same output).
        let verified = decode_verified(&unsigned).expect("a decodable spend verifies");
        assert!(verified.verified);
        assert_eq!(verified, summary);
    }
}
