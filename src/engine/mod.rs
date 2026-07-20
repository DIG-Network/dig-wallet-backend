//! The `engine` seam — imported by dig-node-service (SPEC §3).
//!
//! Owns the single running wallet INSTANCE. The engine is identity-*parameterized* (fed an
//! [`crate::types::IdentityRef`] — public material — plus a [`signer::RemoteSigner`] callback
//! it invokes to sign); it NEVER holds a private key and NEVER signs. It tracks state
//! ([`state::WalletStore`]), syncs from peers ([`sync::SyncConfig`]), builds unsigned spends
//! ([`build::SpendBuilder`]), emits events ([`events::EventSink`]), and broadcasts already-signed
//! bundles ([`broadcast::Broadcaster`]).
//!
//! # Key-isolation invariant (SPEC §1.4)
//! No type in this seam's public API is or transitively exposes a `chia::bls::SecretKey`,
//! mnemonic, or seed. This is enforced primarily by `tests/key_isolation.rs`, which asserts the
//! engine + shared-`types` SOURCE names no secret identifier (the real API-isolation enforcer).
//! CI additionally builds this seam standalone without the client/signing feature
//! (`--no-default-features --features engine`) so no client-side signing/custody CODE is compiled into
//! an engine-only build — a complementary signal, NOT a proof of secret-freedom (the `chia` crate
//! that defines `SecretKey` is a non-optional dependency and is always linked). The private key
//! lives only behind [`signer::RemoteSigner`], implemented client-side.

pub mod broadcast;
pub mod build;
pub mod build_options;
pub mod events;
pub mod persist;
pub mod selection;
pub mod signer;
pub mod state;
pub mod sync;

pub use broadcast::{Broadcaster, MempoolBroadcaster, MempoolClient, MempoolStatus};
pub use build::{SdkSpendBuilder, SpendBuilder, SpendInputs};
pub use build_options::OptionBuilder;
pub use events::{DeltaLog, EventSink, PersistentEventLog, DEFAULT_HISTORY_CAPACITY};
pub use persist::{SqliteDeltaLog, SqliteWalletStore};
pub use selection::{
    select_for_consolidation, select_for_spend, SelectionOutcome, DEFAULT_COIN_CAP,
};
pub use signer::RemoteSigner;
pub use state::{CoinChange, InMemoryWalletStore, WalletStore};
pub use sync::{order_dial_candidates, ChainFallback, PeerCoinSource, SyncConfig, SyncEngine};

use crate::types::Network;

/// Configuration for a wallet engine instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    /// Which Chia network to operate on.
    pub network: Network,
    /// The filesystem path to the state store database.
    pub db_path: String,
    /// The peer sync loop configuration.
    pub sync: SyncConfig,
}

impl EngineConfig {
    /// A mainnet configuration with the given state-store path and default sync settings.
    pub fn mainnet(db_path: impl Into<String>) -> Self {
        Self {
            network: Network::Mainnet,
            db_path: db_path.into(),
            sync: SyncConfig::default(),
        }
    }
}

/// The running wallet engine — the single instance dig-node-service hosts.
///
/// Composes the read store, the spend builder, and broadcast into one handle. The concrete
/// instance (owning the SQLite store, the peer sync loop, and the chia-wallet-sdk builders) is
/// a later lane; this trait is the seam contract those consumers program against.
pub trait WalletEngine: WalletStore + SpendBuilder + Broadcaster {
    /// The event emitter this engine publishes state changes to.
    fn events(&self) -> &EventSink;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_config_uses_defaults() {
        let cfg = EngineConfig::mainnet("/data/wallet.db");
        assert_eq!(cfg.network, Network::Mainnet);
        assert_eq!(cfg.db_path, "/data/wallet.db");
        assert!(cfg.sync.ipv6_first);
    }
}
