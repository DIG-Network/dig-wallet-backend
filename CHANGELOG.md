# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.14.0] - 2026-07-21

### Bug Fixes
- **signer:** Sign standard-layer synthetic-key spends (#1368) — `find_key` now also matches the BLS
  synthetic key (`derive_synthetic`, canonical `DEFAULT_HIDDEN_PUZZLE_HASH`) curried into
  `p2_delegated_puzzle_or_hidden_puzzle`, so normal XCH/CAT sends can be signed. Previously every
  standard-layer spend failed with `SigningFailed`.

### Features
- **signer:** Verify coin spends before signing (#1058) — `client::verify::{analyze, derive_summary}`
  independently reconstructs a spend's value flow from its `CoinSpend`s via the chia-wallet-sdk
  drivers. `sign_unsigned` gates on it fail-closed: the required signatures signed are RE-DERIVED from
  the verified coin spends (the engine-supplied `required_signatures` is untrusted — only cross-checked
  — so it cannot be used as a signing oracle), every change output must return to the wallet, the
  engine summary must match the re-derived recipients + fee, and any spend that cannot be fully
  accounted for is refused — closing the blind-signing gap. `client::review::decode` renders the
  authoritative re-derived summary and exposes a `verified` flag (false when a spend can't be
  independently decoded).

### Notes
- **Signing is scoped to XCH + CAT sends (fail-closed).** `LocalSigner::sign_unsigned` currently signs
  only the standard-layer XCH send and CAT send classes `client::verify` can independently decode.
  Offer (settlement), option, and tip `UnsignedSpend`s routed through it are REFUSED
  (`SpendValidationFailed`) until their verify decoders land (tracked follow-up). No live consumer
  signs offers/options/tips via this `LocalSigner` today (dig-node uses its own wallet; dig-app signs
  its money-path in-app), so this stays a minor release.

## [0.13.0] - 2026-07-21

### Bug Fixes
- **offers:** Offers hardening bundle (#1122 triple-gate findings) (#18)

## [0.12.1] - 2026-07-20

### Bug Fixes
- **engine:** Auto-tip decision-ordering + doc/summary nits (#1310) (#17)

## [0.12.0] - 2026-07-20

### Features
- **engine:** Wire option exercise + transfer over dig-options v0.2.0 (#1123) (#16)

## [0.11.0] - 2026-07-20

### Features
- **engine:** Offers surface — make/take/cancel/combine/summarize (#1122) (#15)

## [0.10.0] - 2026-07-20

### Features
- **engine:** $DIG tipping surface + option-exercise atomicity guard (unsigned build) (#14)

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


