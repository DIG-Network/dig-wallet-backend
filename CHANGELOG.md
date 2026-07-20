# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.10.0] - 2026-07-20

### Features
- **engine:** Economic action surface — offers + tips beside options (unsigned build) (#1122, #1127)
  - Tips: `TipBuilder::build_tip` + `build_auto_tip` compose the canonical `dig-tips` builders; the
    capped honest auto-tip (§6.0) decides first and builds nothing on a skip.
  - Offers: `OfferBuilder` make/take/cancel validated request surface, gated pending the
    wire-serializable assemble/combine seam (#1122).
  - Options: security-critical exercise-atomicity dependency-guard test (mint shipped in 0.9.0).
  - Engine builds UNSIGNED only; the client `LocalSigner` is unchanged (identity boundary #908).

## [0.9.0] - 2026-07-20

### Features
- **options:** Option mint suite; transfer/exercise seams pending dig-options 0.2.0 (#12)

## [0.8.1] - 2026-07-19

### Bug Fixes
- **deps:** Use crates.io dig-identity, not git (unblocks publish) (#11)

## [0.8.0] - 2026-07-19

### Features
- **client:** G1-ECDH decap capability on the key-holder seam (#10)

## [0.7.0] - 2026-07-19

### Features
- **engine:** SQLite persistence backing for WalletStore + CatchUp (#1118) (#9)

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


