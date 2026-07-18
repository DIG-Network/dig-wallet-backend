# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.2.0] - 2026-07-18

### Features
- **engine:** state store + sync/fallback data layer (#1000). Concrete `InMemoryWalletStore`
  (coins/CATs/NFTs/DIDs/history, balance derivation, reorg rollback) implementing `WalletStore`,
  and `SyncEngine` (coin-state ingestion with event emission, reorg handling, IPv6-first dial
  ordering per §5.2, and dual-source fallback routing — peer-first with chia-query/coinset
  point-read fallback per SPEC §7). Engine-only; no private key, no signing (key isolation §1.4).

## [0.1.0] - 2026-07-18

### Features
- **dig-wallet-backend:** SPEC + shared types + engine/client seam skeleton (#998) (#1)


