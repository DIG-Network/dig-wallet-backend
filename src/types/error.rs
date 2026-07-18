//! The wallet-backend error type and its stable, machine-facing error-code catalogue.
//!
//! Every error carries a stable `WalletErrorCode` (SPEC §2). The codes are a machine
//! contract (§6.2): consumers branch on the code, never on the human message, so the
//! prose can improve without breaking a scripted caller.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A stable, catalogued identifier for a class of wallet-backend failure.
///
/// Codes are append-only: a released code's meaning never changes and a code is never
/// reused for a different failure. New failure classes get a new code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WalletErrorCode {
    /// A value could not be parsed or violated an encoding invariant (bad address,
    /// out-of-range amount, malformed hex).
    InvalidInput,
    /// The requested identity/wallet is not known to the engine.
    UnknownIdentity,
    /// Coin selection could not satisfy the requested spend (insufficient spendable value).
    InsufficientFunds,
    /// A spend failed pre-broadcast validation (fail-closed: SPEC §3).
    SpendValidationFailed,
    /// The signing seam (dig-app) rejected or failed to produce a signature.
    SigningFailed,
    /// The chain/peer transport failed (dial, sync, or broadcast).
    Transport,
    /// The local wallet state store failed (read/write/migration).
    Storage,
    /// An event subscriber fell too far behind and lost events; catch up via a cursor.
    SubscriberLagged,
    /// A requested capability is defined by the contract but not yet implemented in this build.
    NotImplemented,
}

impl WalletErrorCode {
    /// The stable string form used on the wire and in logs (`invalid_input`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::UnknownIdentity => "unknown_identity",
            Self::InsufficientFunds => "insufficient_funds",
            Self::SpendValidationFailed => "spend_validation_failed",
            Self::SigningFailed => "signing_failed",
            Self::Transport => "transport",
            Self::Storage => "storage",
            Self::SubscriberLagged => "subscriber_lagged",
            Self::NotImplemented => "not_implemented",
        }
    }
}

/// The wallet-backend error type shared across both seams.
///
/// Pairs a stable [`WalletErrorCode`] with a human-readable context message.
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[error("{code:?}: {message}")]
pub struct WalletError {
    /// The stable, machine-branchable classification.
    pub code: WalletErrorCode,
    /// Human-readable context; may change between releases (not a contract).
    pub message: String,
}

impl WalletError {
    /// Construct an error from a code and a context message.
    pub fn new(code: WalletErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Shorthand for an [`WalletErrorCode::InvalidInput`] error.
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(WalletErrorCode::InvalidInput, message)
    }

    /// Shorthand for a [`WalletErrorCode::NotImplemented`] error — used by seam-skeleton
    /// bodies that later lanes fill in.
    pub fn not_implemented(what: impl Into<String>) -> Self {
        Self::new(WalletErrorCode::NotImplemented, what)
    }
}

/// The crate-wide result alias.
pub type WalletResult<T> = Result<T, WalletError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_strings_are_stable_snake_case() {
        assert_eq!(WalletErrorCode::InvalidInput.as_str(), "invalid_input");
        assert_eq!(
            WalletErrorCode::InsufficientFunds.as_str(),
            "insufficient_funds"
        );
        assert_eq!(
            WalletErrorCode::SubscriberLagged.as_str(),
            "subscriber_lagged"
        );
    }

    #[test]
    fn code_serializes_as_snake_case() {
        let json = serde_json::to_string(&WalletErrorCode::SpendValidationFailed).unwrap();
        assert_eq!(json, "\"spend_validation_failed\"");
    }

    #[test]
    fn constructors_set_the_code() {
        let e = WalletError::invalid_input("bad address");
        assert_eq!(e.code, WalletErrorCode::InvalidInput);
        assert!(e.to_string().contains("bad address"));

        let e = WalletError::not_implemented("engine::build");
        assert_eq!(e.code, WalletErrorCode::NotImplemented);
    }

    #[test]
    fn error_round_trips_through_json() {
        let e = WalletError::new(WalletErrorCode::SigningFailed, "user declined");
        let json = serde_json::to_string(&e).unwrap();
        let back: WalletError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, WalletErrorCode::SigningFailed);
        assert_eq!(back.message, "user declined");
    }
}
