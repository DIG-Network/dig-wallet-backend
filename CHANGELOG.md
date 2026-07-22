# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.15.0] - 2026-07-22

### Bug Fixes
- **verify:** Bind puzzle_reveal to coin + require sole committed AGG_SIG_ME (#1518, #1519) (#20)

## [0.16.0] - 2026-07-22

### Features
- **signer:** Canonical Chia wallet money-key derivation for `LocalSigner` (#1522). Adds
  `MasterKey::wallet_signing_key` / `wallet_public_key` and `LocalSigner::new_canonical` /
  `with_canonical_wallet_keys` over `master_to_wallet_unhardened(seed, ix).derive_synthetic()` — the
  synthetic wallet path byte-identical to dig-account's `WalletKey`, the pre-cutover dig-app wallet,
  and every standard Chia wallet (incl. Sage). `find_key` + `owns_puzzle_hash` search the canonical
  synthetic address set under this scheme, so a money-spending consumer controls the address funds
  actually live at (the legacy `m/44'` profile path is a distinct, never-funded set kept for internal
  callers). Cross-round-trip golden pins the derivation against dig-account's frozen vector; a drift
  = fund-lock and the golden fails. Additive — all v0.15.0 signing invariants (re-derive-from-coin-
  spends, AGG_SIG_ME-only, quote-form, reveal-bound-to-coin, sole-committed-ME) preserved.

## [0.14.0] - 2026-07-22

### Bug Fixes
- **signer:** Sign standard-layer synthetic-key spends + verify coin_spends pre-sign (#1368, #1058) (#19)

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


