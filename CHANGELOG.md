# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [Unreleased]

### Features
- **engine:** Wire event emit points + in-memory catch-up (#1002) — `funds_sent` on a spent coin,
  `new_tip`/`confirmation`/`transaction_failed` chain-watch emitters, and a concrete in-memory
  `DeltaLog` implementing `dig_events_protocol::CatchUp` (bounded ring; SQLite-backed swap seam is
  #1118). Cursors are now 1-based so `Cursor::default()` backfills the whole window.

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


