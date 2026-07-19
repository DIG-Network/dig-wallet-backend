# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.7.0] - 2026-07-19

### Features
- **engine:** SQLite persistence backing for WalletStore + a persistent CatchUp event log (#1118) —
  `SqliteWalletStore` (durable coin/CAT/NFT/DID/tx/sync state surviving restarts, versioned
  migrations, WAL journaling) and `SqliteDeltaLog` (an unbounded on-disk `CatchUp` that swaps in
  behind `&dyn CatchUp` with no call-site change). `EventSink::with_persistent_log` dual-writes
  every published event for durability. No secret material is ever persisted (key-isolation §1.4).

## [0.6.1] - 2026-07-19

### Refactor
- **signer:** Source AGG_SIG_ME from dig-constants (signer==engine) (#8)

## [0.6.0] - 2026-07-19

### Features
- **engine:** Wire event emit points + in-memory catch-up (#1002) (#7)

## [0.5.0] - 2026-07-19

### Features
- **types:** Consume dig-events-protocol as the canonical event contract (#6)

## [0.4.0] - 2026-07-18

### Features
- **engine:** Unsigned-build + broadcast + coin-selection (#1001) (#4)

## [0.3.0] - 2026-07-18

### Features
- **client:** Implement custody seam — LocalSigner, HD derivation, WalletClient (#1003) (#3)

## [0.2.0] - 2026-07-18

### Features
- **engine:** State store + sync/fallback data layer (#1000) (#2)

## [0.1.0] - 2026-07-18

### Features
- **dig-wallet-backend:** SPEC + shared types + engine/client seam skeleton (#998) (#1)


