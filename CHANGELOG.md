# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.22.0] - 2026-08-07

### Features
- **client:** Surface the offer-make requested payment as a distinct `received` leg so the maker sees
  the trade both ways at the confirm (#2241)

### Security
- **client:** Enforce the offer-binding rule (MR-6) at the BUNDLE level: a settlement sink is accepted
  iff it carries a requested-payment announcement (`AssertPuzzleAnnouncement` /
  `AssertCoinAnnouncement`) itself OR is transitively co-spend-tied, through the concurrency ring, to a
  coin that does — refused otherwise. This still refuses a concurrency-only (announcement-free) bundle
  and any unbound sink, while correctly accepting a legitimate multi-offered-coin make (offer XCH + a
  CAT, or two distinct CATs) whose announcement rides only one offered coin (#2241)
- **client:** Mark the engine-declared `received` leg as unverified in the confirm renderer
  ("Receive (unverified) …") so a maker never reads egress-grade assurance into the upside claim (#2241)

## [0.21.0] - 2026-08-06

### Features
- **client:** Add no-fallback decode_verified for the pre-sign consent path (#2209)

## [0.20.0] - 2026-08-06

### Features
- **client:** Sign option transfer via singleton accounting; refuse exercise (#1511 PR-C)

## [0.19.0] - 2026-08-06

### Features
- **client:** Decode + sign offer make/take/cancel via settlement-layer accounting (#1511 PR-B)

## [0.18.0] - 2026-08-06

### Features
- **client:** Sign tips spends via ownership-based recipient/change classification (#1511 PR-A)

## [0.17.0] - 2026-08-05

### Chores
- **deps:** Migrate to chia 0.36.1 / chia-wallet-sdk 0.34 family (#24)

## [0.16.2] - 2026-07-29

### Testing
- **hd:** Pin the money path to Sage's address for a 24-word phrase (#23)

## [0.16.1] - 2026-07-28

### Bug Fixes
- **verify:** Make value-conservation arithmetic total, never modulo 2^64 (#22)

## [0.16.0] - 2026-07-22

### Features
- **signer:** Canonical Chia wallet money-key derivation for LocalSigner (#21)

## [0.15.0] - 2026-07-22

### Bug Fixes
- **verify:** Bind puzzle_reveal to coin + require sole committed AGG_SIG_ME (#1518, #1519) (#20)

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


