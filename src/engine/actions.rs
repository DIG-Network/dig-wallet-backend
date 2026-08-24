//! `engine::actions` — asset visibility, refresh requests, and the peer/network book (#44).
//!
//! These are the wallet's *housekeeping* verbs: the ones that change what the user sees or how the
//! wallet talks to the chain, without building a spend. They share one property that shapes the
//! whole module.
//!
//! # The engine records INTENT; the transport does the work
//!
//! "Resync this CAT" and "re-download this NFT's metadata" read like network operations, and in a
//! monolithic wallet they would be. Here they cannot be: the engine seam is deliberately
//! network-free — every transport ([`super::sync::PeerCoinSource`], [`super::sync::ChainFallback`],
//! [`super::broadcast::MempoolClient`]) is injected — and reaching for an HTTP client inside an
//! action would put a socket in the one layer built not to have one.
//!
//! So a refresh action MARKS an asset stale and the sync loop clears the mark when it next reads
//! that asset. That is honest about what the engine knows: it can say *this needs refreshing*, and
//! it genuinely cannot say *this has been refreshed*.
//!
//! # What is deliberately NOT here: peer DISCOVERY
//!
//! #44 lists `discover_peers` alongside add/remove/list. It is not implemented, and that is a
//! boundary rather than an omission: discovery belongs to `dig-pex`/`dig-dht`, and pulling a
//! discovery stack into the wallet backend would both distort this crate's scope and duplicate a
//! capability that already has an owner (Appendix B). The peer BOOK below is the wallet's side of
//! that contract — a caller that has discovered peers by any means registers them here.
//!
//! # Key isolation
//!
//! Nothing here touches key material. The derivation index is a COUNTER — how many addresses to
//! watch — not a key and not a derivation (SPEC §1.4, #908).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Mutex, RwLock};

use crate::types::Network;

/// Whether an asset is shown to the user.
///
/// A hidden asset is still tracked and still spendable — hiding is a DISPLAY decision, never a
/// custody one. A wallet that stopped tracking a hidden asset would silently lose the user's money
/// the moment they hid the wrong row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Visibility {
    /// Shown in the wallet's asset lists.
    #[default]
    Visible,
    /// Tracked and spendable, but not listed.
    Hidden,
}

/// Which family an asset belongs to, so one visibility table can serve all of them.
///
/// Keyed separately rather than by a bare id because a CAT asset id and an NFT launcher id are both
/// 32-byte hex and could collide in a single flat table — improbable, but a collision would hide
/// the wrong asset, and nothing about the value would reveal why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssetKind {
    /// A CAT, keyed by asset id.
    Cat,
    /// An NFT, keyed by launcher id.
    Nft,
    /// A DID, keyed by launcher id.
    Did,
    /// A collection, keyed by collection id.
    Collection,
}

/// Per-asset display state and pending refresh requests.
///
/// Held beside the coin store rather than inside it because none of this is chain state: it is the
/// user's preferences plus a to-do list for the sync loop, and mixing it into the store would make
/// a reorg rollback able to erase a user's choices.
#[derive(Debug, Default)]
pub struct AssetActions {
    visibility: RwLock<BTreeMap<(AssetKind, String), Visibility>>,
    stale: RwLock<BTreeMap<AssetKind, Vec<String>>>,
}

impl AssetActions {
    /// An empty action table: everything visible, nothing stale.
    pub fn new() -> Self {
        Self::default()
    }

    /// Show or hide an asset.
    pub fn set_visibility(&self, kind: AssetKind, id: impl Into<String>, visibility: Visibility) {
        self.visibility
            .write()
            .expect("visibility lock")
            .insert((kind, id.into()), visibility);
    }

    /// Whether an asset is shown. Unknown assets are [`Visibility::Visible`]: a newly-discovered
    /// asset the user has never had an opinion about must appear, or the wallet would silently omit
    /// incoming value.
    pub fn visibility(&self, kind: AssetKind, id: &str) -> Visibility {
        self.visibility
            .read()
            .expect("visibility lock")
            .get(&(kind, id.to_string()))
            .copied()
            .unwrap_or_default()
    }

    /// Request that an asset be re-read from chain — `resync_cat` and `redownload_nft` (#44).
    ///
    /// Idempotent: asking twice before the sync loop has acted leaves ONE request, so a user
    /// tapping refresh repeatedly cannot inflate the queue the loop must drain.
    pub fn request_refresh(&self, kind: AssetKind, id: impl Into<String>) {
        let id = id.into();
        let mut stale = self.stale.write().expect("stale lock");
        let entry = stale.entry(kind).or_default();
        if !entry.contains(&id) {
            entry.push(id);
        }
    }

    /// The assets of `kind` awaiting a refresh, in request order.
    pub fn pending_refresh(&self, kind: AssetKind) -> Vec<String> {
        self.stale
            .read()
            .expect("stale lock")
            .get(&kind)
            .cloned()
            .unwrap_or_default()
    }

    /// Clear an asset's refresh request — called by the sync loop once it has re-read the asset.
    ///
    /// Returns whether a request was actually outstanding, so a caller can tell "I cleared a real
    /// request" from "there was nothing to clear".
    pub fn clear_refresh(&self, kind: AssetKind, id: &str) -> bool {
        let mut stale = self.stale.write().expect("stale lock");
        let Some(entry) = stale.get_mut(&kind) else {
            return false;
        };
        let before = entry.len();
        entry.retain(|pending| pending != id);
        before != entry.len()
    }
}

/// How far along the HD address path the wallet watches.
///
/// This is a WATCH WINDOW, not a key: it says how many addresses to subscribe to, and widening it
/// makes the wallet see coins it was previously blind to. Deriving the addresses themselves is the
/// client seam's job, because that needs the key (SPEC §1.4).
#[derive(Debug, Default)]
pub struct DerivationWindow {
    index: Mutex<u32>,
}

impl DerivationWindow {
    /// A window starting at `index`.
    pub fn starting_at(index: u32) -> Self {
        Self {
            index: Mutex::new(index),
        }
    }

    /// The current index.
    pub fn index(&self) -> u32 {
        *self.index.lock().expect("derivation lock")
    }

    /// Widen the window by `count`, returning the new index.
    ///
    /// Saturating rather than wrapping: an overflow that wrapped to zero would NARROW the window to
    /// nothing, and a wallet that suddenly watches no addresses reports an empty balance for coins
    /// it still owns. Saturating is wrong in a way the user can see; wrapping is wrong in a way that
    /// looks like theft.
    pub fn increase(&self, count: u32) -> u32 {
        let mut index = self.index.lock().expect("derivation lock");
        *index = index.saturating_add(count);
        *index
    }
}

/// A peer the wallet knows how to reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerEntry {
    /// Where to dial the peer.
    pub address: SocketAddr,
}

/// The wallet's peer book plus its network and delta-sync policy (#44).
///
/// Discovery is NOT here (see the module docs) — this is the registry a caller populates from
/// whatever discovery mechanism it uses, plus the "prefer this one" choice on top.
#[derive(Debug)]
pub struct NetworkBook {
    peers: RwLock<Vec<PeerEntry>>,
    target: RwLock<Option<SocketAddr>>,
    network: RwLock<Network>,
    delta_sync: RwLock<bool>,
}

impl NetworkBook {
    /// An empty book on `network`, with delta sync enabled.
    ///
    /// Delta sync defaults ON because a full re-sync of every address on every pass is the
    /// expensive path, and a wallet that silently chose it would look slow rather than
    /// misconfigured.
    pub fn new(network: Network) -> Self {
        Self {
            peers: RwLock::new(Vec::new()),
            target: RwLock::new(None),
            network: RwLock::new(network),
            delta_sync: RwLock::new(true),
        }
    }

    /// Register a peer. Idempotent — adding a known peer twice does not duplicate it.
    pub fn add_peer(&self, address: SocketAddr) {
        let mut peers = self.peers.write().expect("peer lock");
        if !peers.iter().any(|peer| peer.address == address) {
            peers.push(PeerEntry { address });
        }
    }

    /// Forget a peer, returning whether it was known.
    ///
    /// Removing the TARGET peer also clears the target, because a preference pointing at a peer the
    /// wallet has forgotten would keep the dial path trying an address it was just told to drop.
    pub fn remove_peer(&self, address: SocketAddr) -> bool {
        let mut peers = self.peers.write().expect("peer lock");
        let before = peers.len();
        peers.retain(|peer| peer.address != address);
        let removed = before != peers.len();

        if removed {
            let mut target = self.target.write().expect("target lock");
            if *target == Some(address) {
                *target = None;
            }
        }
        removed
    }

    /// Every known peer, ordered IPv6-first (§5.2).
    ///
    /// The ordering is applied on READ rather than on insert so it survives however the book was
    /// populated — a caller that added peers in IPv4-first order still gets an IPv6-first dial list.
    pub fn peers(&self) -> Vec<PeerEntry> {
        let peers = self.peers.read().expect("peer lock");
        let addresses: Vec<SocketAddr> = peers.iter().map(|peer| peer.address).collect();
        super::sync::order_dial_candidates(&addresses, true)
            .into_iter()
            .map(|address| PeerEntry { address })
            .collect()
    }

    /// Prefer `address` for future dials.
    ///
    /// Returns whether the peer was known. Targeting an UNKNOWN peer is refused rather than
    /// silently registering it: a typo'd address would otherwise become both the preference and the
    /// only peer the wallet trusts, which fails as an outage rather than as a rejected input.
    pub fn target_peer(&self, address: SocketAddr) -> bool {
        let known = self
            .peers
            .read()
            .expect("peer lock")
            .iter()
            .any(|peer| peer.address == address);
        if known {
            *self.target.write().expect("target lock") = Some(address);
        }
        known
    }

    /// The preferred peer, if one is set and still known.
    pub fn target(&self) -> Option<SocketAddr> {
        *self.target.read().expect("target lock")
    }

    /// The selected network.
    pub fn network(&self) -> Network {
        *self.network.read().expect("network lock")
    }

    /// Select a network.
    ///
    /// Switching networks CLEARS the peer book and the target: a mainnet peer cannot serve testnet
    /// state, and keeping the list would leave the wallet dialing peers that answer about a
    /// different chain — the worst kind of wrong answer, because it is well-formed.
    pub fn set_network(&self, network: Network) {
        *self.network.write().expect("network lock") = network;
        self.peers.write().expect("peer lock").clear();
        *self.target.write().expect("target lock") = None;
    }

    /// Whether incremental (delta) sync is enabled.
    pub fn delta_sync(&self) -> bool {
        *self.delta_sync.read().expect("delta lock")
    }

    /// Enable or disable incremental sync.
    pub fn set_delta_sync(&self, enabled: bool) {
        *self.delta_sync.write().expect("delta lock") = enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}")
            .parse()
            .expect("a valid v4 addr")
    }

    fn addr_v6(port: u16) -> SocketAddr {
        format!("[::1]:{port}").parse().expect("a valid v6 addr")
    }

    #[test]
    fn an_asset_nobody_has_an_opinion_about_is_visible() {
        let actions = AssetActions::new();
        assert_eq!(
            actions.visibility(AssetKind::Cat, "unknown"),
            Visibility::Visible
        );
    }

    #[test]
    fn hiding_one_asset_does_not_hide_another_of_the_same_kind() {
        let actions = AssetActions::new();
        actions.set_visibility(AssetKind::Nft, "hidden-one", Visibility::Hidden);
        assert_eq!(
            actions.visibility(AssetKind::Nft, "hidden-one"),
            Visibility::Hidden
        );
        assert_eq!(
            actions.visibility(AssetKind::Nft, "other-one"),
            Visibility::Visible
        );
    }

    /// The same id under two families must be independently controllable — the reason the table is
    /// keyed by `(kind, id)` and not by id alone.
    #[test]
    fn the_same_id_in_two_families_is_hidden_independently() {
        let actions = AssetActions::new();
        let shared = "ab".repeat(32);
        actions.set_visibility(AssetKind::Cat, shared.clone(), Visibility::Hidden);
        assert_eq!(
            actions.visibility(AssetKind::Cat, &shared),
            Visibility::Hidden
        );
        assert_eq!(
            actions.visibility(AssetKind::Nft, &shared),
            Visibility::Visible
        );
    }

    #[test]
    fn refresh_requests_are_idempotent_and_clearable() {
        let actions = AssetActions::new();
        actions.request_refresh(AssetKind::Cat, "asset");
        actions.request_refresh(AssetKind::Cat, "asset");
        assert_eq!(actions.pending_refresh(AssetKind::Cat), vec!["asset"]);

        assert!(actions.clear_refresh(AssetKind::Cat, "asset"));
        assert!(actions.pending_refresh(AssetKind::Cat).is_empty());
        assert!(
            !actions.clear_refresh(AssetKind::Cat, "asset"),
            "clearing nothing must report that nothing was cleared"
        );
    }

    #[test]
    fn a_refresh_request_is_scoped_to_its_family() {
        let actions = AssetActions::new();
        actions.request_refresh(AssetKind::Nft, "launcher");
        assert!(actions.pending_refresh(AssetKind::Cat).is_empty());
    }

    #[test]
    fn widening_the_derivation_window_saturates_rather_than_wrapping() {
        let window = DerivationWindow::starting_at(u32::MAX - 1);
        assert_eq!(window.increase(10), u32::MAX);
        assert_eq!(
            window.index(),
            u32::MAX,
            "an overflow must never narrow the watch window to zero"
        );
    }

    #[test]
    fn adding_a_known_peer_twice_keeps_one_entry() {
        let book = NetworkBook::new(Network::Mainnet);
        book.add_peer(addr(8444));
        book.add_peer(addr(8444));
        assert_eq!(book.peers().len(), 1);
    }

    /// §5.2: the dial list is IPv6-first however the book was filled — hence a v4 peer added FIRST.
    #[test]
    fn the_peer_list_is_ipv6_first_regardless_of_insertion_order() {
        let book = NetworkBook::new(Network::Mainnet);
        book.add_peer(addr(8444));
        book.add_peer(addr_v6(8444));
        assert_eq!(
            book.peers()
                .iter()
                .map(|peer| peer.address.is_ipv6())
                .collect::<Vec<_>>(),
            vec![true, false]
        );
    }

    #[test]
    fn targeting_an_unknown_peer_is_refused() {
        let book = NetworkBook::new(Network::Mainnet);
        assert!(!book.target_peer(addr(8444)));
        assert_eq!(book.target(), None);
    }

    #[test]
    fn removing_the_targeted_peer_clears_the_target() {
        let book = NetworkBook::new(Network::Mainnet);
        book.add_peer(addr(8444));
        assert!(book.target_peer(addr(8444)));
        assert!(book.remove_peer(addr(8444)));
        assert_eq!(
            book.target(),
            None,
            "a preference must not survive the peer it points at"
        );
    }

    /// Removing a peer that is NOT the target must leave the target alone — the control that
    /// separates "clears the right target" from "clears the target on any removal".
    #[test]
    fn removing_another_peer_leaves_the_target_intact() {
        let book = NetworkBook::new(Network::Mainnet);
        book.add_peer(addr(8444));
        book.add_peer(addr(8445));
        assert!(book.target_peer(addr(8444)));
        assert!(book.remove_peer(addr(8445)));
        assert_eq!(book.target(), Some(addr(8444)));
    }

    #[test]
    fn switching_network_clears_peers_that_cannot_serve_it() {
        let book = NetworkBook::new(Network::Mainnet);
        book.add_peer(addr(8444));
        book.target_peer(addr(8444));

        book.set_network(Network::Testnet);

        assert_eq!(book.network(), Network::Testnet);
        assert!(
            book.peers().is_empty(),
            "mainnet peers cannot serve testnet"
        );
        assert_eq!(book.target(), None);
    }

    #[test]
    fn delta_sync_is_on_by_default_and_toggles() {
        let book = NetworkBook::new(Network::Mainnet);
        assert!(book.delta_sync());
        book.set_delta_sync(false);
        assert!(!book.delta_sync());
    }
}
