//! `client::build` — the key-free spend builder + coin selection, surfaced for app-local building.
//!
//! [`crate::engine::build`] and [`crate::engine::selection`] are **key-free** (SPEC §1.4): they take
//! spendable coins, a synthetic-PUBLIC-key lookup ([`SpendInputs`]), and a change puzzle hash — all
//! public material — and return an [`crate::types::UnsignedSpend`]. They never hold or touch a secret
//! key. The `engine::…` import path names the ENGINE HOST, but a consumer that runs under DEFAULT
//! features (engine + client both compiled — the topology dig-app uses, SPEC §1.3) may legitimately
//! build spends LOCALLY without being an engine host. This module is the honest import path for that:
//! `use dig_wallet_backend::client::build::…` instead of reaching through `engine::…`.
//!
//! # Custody (SPEC §1.4)
//! This re-exports ONLY the key-free public surface — the builder ([`SdkSpendBuilder`],
//! [`SpendBuilder`]), its public-material input provider ([`SpendInputs`]), and coin selection. It
//! deliberately exposes NO secret-side / signing-oracle internals; the private key stays behind
//! [`crate::client::signer`]. Re-export (`pub use`) only — no logic lives here.
//!
//! Available whenever the `engine` seam is compiled alongside `client` (the default). The items
//! themselves physically live under `src/engine/` so `tests/key_isolation.rs`'s `src/engine/**` scan
//! keeps proving they name no secret material.
//!
//! ```
//! use dig_wallet_backend::client::build::{SdkSpendBuilder, SpendBuilder, SpendInputs};
//! use dig_wallet_backend::client::build::{select_for_spend, SelectionOutcome, DEFAULT_COIN_CAP};
//! ```

pub use crate::engine::build::{SdkSpendBuilder, SpendBuilder, SpendInputs};
pub use crate::engine::selection::{
    select_for_consolidation, select_for_spend, SelectionOutcome, DEFAULT_COIN_CAP,
};
