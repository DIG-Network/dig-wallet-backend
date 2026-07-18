//! `engine::sync` — the peer sync loop configuration (SPEC §7).
//!
//! The sync loop subscribes to peer puzzle-state updates (IPv6-first per §5.2), applies
//! coin-state deltas to [`super::state::WalletStore`], handles reorgs, and publishes
//! [`crate::types::WalletEvent`]s via [`super::events::EventSink`]. The running loop is a
//! later lane; this seam defines its configuration surface.

/// Configuration for the peer sync loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncConfig {
    /// Prefer IPv6 candidates when dialing peers, falling back to IPv4 (§5.2).
    pub ipv6_first: bool,
    /// The maximum number of coins to track before the coin-cap consolidation kicks in.
    pub coin_cap: usize,
    /// Fallback point-read endpoints (chia-query / coinset) used only while syncing.
    pub fallback_endpoints: Vec<String>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            ipv6_first: true,
            coin_cap: 500,
            fallback_endpoints: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_ipv6_first() {
        let cfg = SyncConfig::default();
        assert!(cfg.ipv6_first, "peer comms are IPv6-first (§5.2)");
        assert_eq!(cfg.coin_cap, 500);
        assert!(cfg.fallback_endpoints.is_empty());
    }
}
