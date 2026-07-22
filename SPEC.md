# dig-wallet-backend — SPECIFICATION

Normative specification for the DIG Network's canonical, event-driven Chia wallet backend. This is
the authoritative contract an independent reimplementation could be built against. Keywords **MUST**,
**MUST NOT**, **SHOULD**, **MAY** are used per RFC 2119.

The crate is clean-room: its design is informed by the feature set of established Chia wallet backends
but copies no code, schema, or API shape from any of them. It replaces `dig-l1-wallet`; consumers are
refactored to the interface defined here (no backwards-compatibility shim).

---

## 1. Overview + trust boundary

### 1.1 What this crate is

One library exporting **two carefully-partitioned seams** plus the shared layer they meet over:

- **`engine`** — imported by **dig-node-service**. Hosts the single running wallet INSTANCE: state
  tracking, peer sync, unsigned-spend construction, event emission, and broadcast of already-signed
  bundles. It is identity-*parameterized* and holds NO private key.
- **`client`** — used by **dig-app**. The event SUBSCRIBER, spend review/decode, the SIGNER that holds the
  key, the identity provider, and the local address book.
- **`types`** — the shared, I/O-free wire contract both seams import. It contains NO secret material.

### 1.2 Topology (normative)

- There is exactly **ONE** running wallet engine instance in the ecosystem, hosted by
  dig-node-service. dig-app does NOT run its own instance.
- dig-app **provides the identity** (public material) and **performs all signing**. The engine is fed
  an `IdentityRef` (which identity to operate as) plus a `RemoteSigner` callback it invokes to sign.
- The two seams meet over the dig-app ↔ engine control IPC: the engine seam is the SERVER side, the
  client seam is the CLIENT side.

### 1.3 Cargo features

| Feature | Always on? | Compiles |
|---|---|---|
| (`types`) | yes (not a toggle) | shared data + event taxonomy + errors; no I/O, no secrets |
| `engine` | default | the engine seam + its async runtime; NO secret-key crate path |
| `client` | default | the client seam; the ONLY place secret material is compiled in |

An engine consumer (dig-node) **MUST** depend with `default-features = false, features = ["engine"]`
so the client `LocalSigner` (and its secret-key code) is never compiled into the engine host. A client
consumer (dig-app) enables `features = ["client"]`. Each side thereby compiles only its half.

### 1.4 The key-isolation invariant (the crate's central security property)

**The private key MUST live only behind the client seam's signer; it MUST NEVER enter the engine.** No
engine-seam type is, contains, or transitively exposes a `chia::bls::SecretKey`, mnemonic, or seed.
The engine holds only an `Arc<dyn RemoteSigner>` and calls OUT to it.

This is enforced by two complementary release gates. **Source isolation is the primary, authoritative
enforcer**; the standalone build is a weaker corroborating signal, NOT an independent compile-proof
(the `chia` crate that defines `SecretKey` is a non-optional dependency and is always linked, so
feature-gating alone cannot prove no secret type is reachable):

1. **Source isolation (primary)** — `tests/key_isolation.rs` asserts no code (comment- and
   string-literal-aware) in `src/engine/**` OR `src/types/**` names a secret-bearing identifier:
   `SecretKey`, `PrivateKey`, `SigningKey`, `Keypair`, `Mnemonic`, `Seed`, `master_sk`, `from_seed`,
   `from_mnemonic`. The shared `types` layer is scanned too because the engine imports it — a secret
   smuggled through `types` would otherwise evade an engine-only scan. Substring matching also catches
   `as`-aliased re-exports (`use … SecretKey as Sk;`, `type Foo = SecretKey;`) at their declaration.
2. **Standalone build (corroborating)** — CI builds the engine seam without the client/signing feature
   (`--no-default-features --features engine`), so no client-side signing/custody CODE compiles into an
   engine-only build. CI job "Engine seam builds standalone".

### 1.5 The trust diagram

```
 dig-app (client seam)                       dig-node-service (engine seam)
 IdentityProvider  --- IdentityRef ---> WalletEngine (1 instance)
   (public only)                          state · sync · build
 WalletClient      <-- WalletEvent ----   EventSink (emit)
   subscribe/catch_up   (stream)          RemoteSigner (calls OUT)
 review/decode
 LocalSigner (KEY) <-- UnsignedSpend ---  (never holds key)
   sign()          --- SignedBundle --->  broadcast
```

The ONLY things crossing INTO the engine are `IdentityRef` (public) and `SignedBundle` (post-sign).
Coming OUT: the `WalletEvent` stream and `UnsignedSpend` (for signing). `SecretKey`/mnemonic/seed
MUST NOT appear in any engine-seam type or IPC message.

---

## 2. Shared types (`types`)

Pure, I/O-free, serde-serializable. The wire contract between the seams. **No secret type appears in
this layer.**

### 2.1 Identity (public material only)

- `WalletId(u32)` — the BLS master public-key fingerprint. Identifies; does not authorize.
- `Did(String)` — a `did:chia:` identifier in bech32m text form.
- `IdentityRef { wallet_id: WalletId, did: Option<Did>, profile_ix: u32 }` — the ONLY identity object
  that crosses into the engine. `profile_ix` selects a #997 master-HD → profile derivation slot
  (`0` = root).

### 2.2 Values + records

- `Amount(u64)` / `AssetId(String)` — the canonical `dig-events-protocol` newtypes (re-exported, not
  redefined here — #1067/#1072). **Wire form (normative):** `Amount` serializes ALWAYS as a decimal
  string, so a JavaScript/TypeScript consumer maps it to a single `bigint` via `BigInt(str)` — one
  code path, never a silent precision loss past `Number.MAX_SAFE_INTEGER`. Deserialization is lenient:
  it also accepts a bare JSON number, for legacy/hand-written JSON. `AssetId` is the CAT tail hash
  hex string; absence = native XCH.
- `Address(String)`, `Puzzlehash(String)` (lowercase hex, no `0x`).
- `Network` ∈ { `mainnet`, `testnet`, `simulator` }.
- `CoinRecord`, `CatRecord`, `NftRecord`, `DidRecord`, `Balance { confirmed, spendable }`.
- `TransactionSummary { outputs: Vec<SpendOutput>, fee: Amount }`,
  `SpendOutput { address, amount, asset_id: Option<AssetId> }`, `TransactionRecord`.

### 2.3 Spend objects (the signing-seam payloads)

- `RequiredSignature { public_key: chia::bls::PublicKey, message: Vec<u8> }` — the public key whose
  secret must sign, and the exact bytes to sign. `message` is hex on the wire. Storing the **public**
  key keeps the request key-free.
- `UnsignedSpend { coin_spends: Vec<CoinSpend>, required_signatures: Vec<RequiredSignature>,
  summary: TransactionSummary }` — built by the engine, handed OUT for review + signing.
- `SignedBundle { bundle: chia::protocol::SpendBundle }` — produced client-side, returned for broadcast.

### 2.4 Spend-intent requests

- `SendXchRequest { identity, to, amount, fee }`, `SendCatRequest { identity, asset_id, to, amount,
  fee }` — pure data both seams import (client sends them; engine consumes them).
- Offer request/response types (the offers surface, §3c): `MakeOfferRequest`, `AssembleOfferRequest`,
  `TakeOfferRequest`, `FinalizeTakeRequest`, `CancelOfferRequest`, `CombineOffersRequest`,
  `SummarizeOfferRequest`, and the responses `PendingOfferBuild { build_id, unsigned }`,
  `OfferString { offer, offer_id }`, `OfferSummary` (which also carries `offer_id`), plus the opaque
  handle `OfferBuildId`. `offer_id` is the offer's stable ecosystem id — `sha256` of the uncompressed
  offer bundle as lowercase hex (the same value dexie, Sage, and Chia's `Offer.name()` use), so a
  consumer keys/tracks an offer by it independent of the bech32 compression. All are pure serde
  data — NO chia-wallet-sdk allocator type (`Offer`/`RequestedPayments`/`AssetInfo`/`SpendContext`)
  ever crosses the seam; the non-serializable build state stays engine-side (§3c).

### 2.5 Errors (machine contract)

`WalletError { code: WalletErrorCode, message: String }`. Consumers **MUST** branch on `code`, never
on `message`. `WalletErrorCode` is append-only (a released code's meaning never changes; codes are
never reused). Catalogue (snake_case wire form):

| Code | Meaning |
|---|---|
| `invalid_input` | a value failed to parse / violated an encoding invariant |
| `unknown_identity` | the requested identity is not known to the engine |
| `insufficient_funds` | coin selection could not satisfy the spend |
| `spend_validation_failed` | a spend failed pre-broadcast validation (fail-closed) |
| `signing_failed` | the client signer rejected or failed to produce a signature |
| `transport` | a chain/peer transport failure (dial, sync, broadcast) |
| `storage` | a state-store read/write/migration failure |
| `subscriber_lagged` | a subscriber lost events; catch up via a cursor |
| `not_implemented` | a contracted capability not yet built in this build |

---

## 3. Engine seam (`engine`)

Owns the running instance. Identity-parameterized; NEVER holds a private key; NEVER signs.

- **`WalletEngine: WalletStore + SpendBuilder + Broadcaster`** — the composed instance handle, plus
  `events() -> &EventSink`. Started with `(EngineConfig, IdentityRef, Arc<dyn RemoteSigner>,
  EventSink)`.
- **`EngineConfig { network, db_path, sync: SyncConfig }`**.
- **`engine::state::WalletStore`** (read surface, all scoped to an `IdentityRef`): `balance`, `coins`,
  `cats`, `nfts`, `dids`, `history`, `sync_status`. MUST NOT accept or return secret material.
  `InMemoryWalletStore` is the concrete backing (coins/CATs/NFTs/DIDs/history indexed per
  `WalletId`, balance derived from unspent coins, reorg rollback to a fork height). Its mutation
  surface (`apply_coin_state` → `CoinChange`, `rollback_to`, `set_peak`, `set_sync_status`,
  `upsert_*`, `record_transaction`) is engine-internal — the sync loop drives it; the client seam
  sees only the read trait over IPC.
- **`engine::persist::SqliteWalletStore`** — the persistent (SQLite) backing for the same read +
  mutation surface as `InMemoryWalletStore`; a drop-in whose coin/CAT/NFT/DID/transaction/sync state
  survives a process restart. It classifies a coin update with the SAME rule as the in-memory
  backing, so the observable `CoinChange` result and every read are identical across the two
  backings (backend-parity). Amounts are stored as decimal TEXT (full `u64` range); the schema is
  brought forward by versioned, additive migrations on open (§5.1 spirit — never a destructive
  rewrite); WAL journaling gives crash-safe atomic writes. It MUST NOT persist any secret material —
  only public coin/asset/transaction/sync state (SPEC §1.4; asserted by an on-disk no-secret test).
- **`engine::persist::SqliteDeltaLog`** — the persistent `CatchUp` backing: an unbounded on-disk
  event log that backfills every retained event with a cursor strictly greater than `since`, in
  cursor order, narrowed by the same `EnumSet<EventKind>` filter as the in-memory `DeltaLog`. It
  implements `CatchUp<Error = WalletError>`, so a consumer holding `&dyn CatchUp` swaps to it with no
  call-site change, and `PersistentEventLog`, so an `EventSink` created with
  `EventSink::with_persistent_log` dual-writes every published event into it. Appends are idempotent
  on the cursor. This removes the in-memory window bound (§5.3): a subscriber offline longer than the
  in-memory ring can still recover the full missed range.
- **`engine::sync::SyncConfig { ipv6_first, coin_cap, fallback_endpoints }`** — the peer sync loop.
  Peer dialing MUST be IPv6-first with IPv4 fallback (§5.2 ecosystem rule). Fallback point-read
  endpoints are used only while syncing / for out-of-DB reads.
- **`engine::build::SpendBuilder`** — `build_send_xch`, `build_send_cat`, … each returning an
  `UnsignedSpend`. Spends MUST be built with chia-wallet-sdk driver constructors (never hand-rolled
  CLVM), MUST be deterministic given the same inputs + coin set, and MUST be validated fail-closed
  before they can broadcast. The builder MUST NOT sign. `SdkSpendBuilder` is the concrete
  implementation: it selects coins (§ selection), constructs the unsigned `CoinSpend`s via
  `StandardLayer`/`Cat`/`Conditions`/`SpendContext`, extracts the key-free `required_signatures`
  via chia-wallet-sdk's `RequiredSignature::from_coin_spends`, and validates fail-closed (value
  conservation, and a spend that requires no signatures or produces no coin spends is rejected).
  The PUBLIC spend inputs (full input coins with parent, the synthetic PUBLIC key per puzzle
  hash, the change puzzle hash) are supplied by the injected `SpendInputs` provider — NEVER a
  secret key (SPEC §1.4).
- **`engine::selection`** — capped, high-value-first coin selection: `select_for_spend(coins,
  target, cap) -> SelectionOutcome` (`Selected { coins, total, change }` /
  `NeedsConsolidation { .. }` / `InsufficientFunds { .. }`), `select_for_consolidation(coins,
  cap)`, and `DEFAULT_COIN_CAP`. Deterministic (descending amount, tie-broken by coin id) and
  pure. `NeedsConsolidation` (enough value, too fragmented to reach the target within `cap`) is
  never conflated with `InsufficientFunds` (genuine shortfall). Mirrors the ecosystem selection
  contract (`digstore-chain::selection`).
- **`engine::broadcast::Broadcaster::submit(SignedBundle)`** — relays an ALREADY-signed bundle. MUST
  NOT sign. `MempoolBroadcaster` is the concrete implementation over an injected `MempoolClient`
  (the peer `send_transaction` / mempool): a `MempoolStatus::Accepted`/`AlreadyInMempool` is
  success, a `Rejected { reason }` is a fail-closed `spend_validation_failed`, and a transport
  failure propagates as `transport`.
- **`engine::events::EventSink`** (THE EMITTER) — `publish(WalletEvent) -> Cursor` (stamps a
  monotonic 1-based cursor, records it in the in-memory delta log, best-effort fan-out),
  `subscribe()`, `catch_up_log() -> DeltaLog`, `subscriber_count()`. `DeltaLog` is the in-memory
  `CatchUp` backfill source (bounded ring, `DEFAULT_HISTORY_CAPACITY` events; the persistent
  SQLite-backed backing is #1118, behind the same trait). §5.
- **`engine::signer::RemoteSigner::sign(UnsignedSpend) -> SignedBundle`** — the callback the engine
  invokes. The engine holds `Arc<dyn RemoteSigner>`, never a key. In dig-node-service the concrete
  impl is the IPC proxy to dig-app.
- **`engine::signer::RemoteSigner::dh([u8;48]) -> [u8;48]`** — the recipient DECAP callback: the
  key holder performs the G1-ECDH `dh(identity_sk, peer_g1)` with the held dig-identity key and
  returns the 48-byte compressed shared G1 point for the dig-message KEM/KDF. A DH operation, NOT a
  signature — the one identity key does both, on group-separated primitives (sign = BLS G2, DH = G1).
  The default trait method fail-closes (a signer without an identity key refuses); key holders
  override it. `peer_g1` MUST be subgroup- and non-identity-checked BEFORE the scalar multiplication
  (invalid-curve / small-subgroup key-recovery defense); only the shared secret is returned, never
  the scalar. Neither the argument nor the return carries secret key material.

### 3a. Options — covered-option actions (`engine::build_options`)

- **`engine::build_options::OptionBuilder`** — `build_mint_option`, `build_transfer_option`,
  `build_exercise_option`, each composing the canonical `dig-options` (CHIP-0042) builders (never
  hand-rolled option CLVM) and returning an UNSIGNED result. The builder MUST NOT sign; the
  `required_signatures` are extracted through the SAME key-free `RequiredSignature::from_coin_spends`
  path as every other spend, so signer == engine by construction.
- **Mint** (`build_mint_option`) locks an XCH underlying and issues the option singleton via
  `dig_options::create`, returning `MintedOption { unsigned, handle }`. `dig_options::create` funds
  the locked underlying + the 1-mojo singleton from ONE funding coin and has no change output; the
  funding coin's excess over `underlying + 1` is an implicit fee, which the builder bounds above by
  the caller's `fee` (a mint MUST NOT burn more than the caller consented to). The returned
  `OptionHandle` carries the terms (not recoverable from the on-chain singleton) + the ids to locate
  the option and its underlying.
- **Exercise atomicity (SECURITY-CRITICAL invariant).** On exercise the unlocked underlying lands on
  a BARE anyone-can-claim settlement coin. Consensus forces the strike payment to the creator but
  does NOT force the underlying claim back to the holder — that leg is BUILDER-ENFORCED ONLY. The
  exercise `UnsignedSpend` MUST carry the FULL bundle intact, INCLUDING the settlement leg that
  claims the unlocked underlying (a settlement-puzzle coin of the underlying amount) to the holder;
  no path may drop or reorder it, and a caller MUST broadcast the whole bundle — a subset strands the
  underlying for any mempool watcher to steal after the holder has paid the strike. This invariant is
  pinned by a dependency-guard conformance test (`exercise_bundle_includes_the_underlying_claim_leg`).
- **Transfer + exercise are wired over `dig-options` v0.2.0** — `build_transfer_option` composes
  `dig_options::transfer`; `build_exercise_option` composes `dig_options::exercise`. Both are
  key-free and network-free: the engine cannot fetch an option's live singleton or recover a
  `dig_options::CreatedOption`, so the CLIENT supplies the option's current on-chain state.
- **The on-chain-projection contract (`OptionOnChainState`).** `TransferOptionRequest` and
  `ExerciseOptionRequest` each carry an `OptionOnChainState { option_parent_coin,
  option_parent_puzzle_reveal, option_parent_solution, underlying_coin }` — a WIRE-ONLY projection
  (hex + amounts, no SDK types) the client fetches: the option singleton's CURRENT parent spend (so
  the engine `parse_child`s the live option, which may have been transferred since mint) and the
  locked-underlying coin. The engine decodes it to `chia_protocol::{Coin, Program}` internally.
- **Fail-closed rehydration (NC-9 — the engine never trusts the projection).** Before composing any
  spend the engine (a) asserts the parsed option's launcher id equals the retained handle's launcher
  id (rejecting a substituted option), then (b) `dig_options::rehydrate`s the terms, which
  independently re-derives + checks the option's three on-chain commitments — the 1-of-2
  exercise/clawback path, the underlying delegated-puzzle hash, and the underlying-coin-id binding —
  so a tampered underlying coin, a wrong strike, or a wrong term is rejected. The authorizing key is
  the PARSED option's current `p2_puzzle_hash` (the current owner), not the handle's original owner;
  a wallet that holds no key for it is not the current owner and cannot operate the option.
- **Exercise strike funding + fee.** The strike is funded from a single spendable XCH coin AT the
  option's current-owner puzzle hash covering the strike; its excess over the strike is an implicit
  fee bounded above by the caller's `fee` (the exercise path has no change output, mirroring mint).
  **Transfer fee.** `dig_options::transfer` spends only the 1-mojo singleton and takes no fee; a
  requested farmer fee is honoured with a SEPARATE engine-side fee-coin spend linked to the singleton
  via `assert_concurrent_spend` (atomic; never silently dropped).

### 3b. Tips — $DIG tipping actions (`engine::build_tips`)

- **`engine::build_tips::TipBuilder`** — `build_tip` (an explicit CAT tip) and `build_auto_tip` (the
  guarded, honest auto-tip), composing the canonical `dig-tips` (`build_tip` / `build_tip_if_allowed`)
  builders, returning UNSIGNED results. A tip is a single CAT payment; `required_signatures` come from
  the SAME key-free path as every other spend. The builder resolves the input CATs to a SINGLE
  authorizing key (the largest key-controlled p2 group) — a single-key tip.
- **The honest auto-tip (§6.0 $DIG North Star).** `build_auto_tip` runs the capped decision FIRST
  against the `AutoTipPolicy` (enabled, mode, per-tip amount, per-day count + amount caps) and today's
  `TipLedger`, BEFORE resolving any tip inputs; it builds a spend ONLY when the decision is
  `TipDecision::Tip`, and builds NOTHING on any skip (disabled, below threshold, not approved, cap
  reached). Because the decision is made before inputs are resolved, a disabled/capped auto-tip on a
  wallet with no spendable CAT returns its honest Skip outcome — never a spurious `InsufficientFunds`.
  A capped/declined tip can therefore never be constructed — the default-on money movement is honest,
  capped, and one-flag-off, and never gates consuming content.
- **The caps are only as strong as the consumer's ledger persistence.** The engine is STATELESS with
  respect to the `TipLedger`: it decides against the snapshot the consumer supplies but does not itself
  record that a tip fired. The CONSUMER therefore MUST atomically persist the updated `TipLedger`
  (advancing the per-day count + amount) before or in the same durable transaction as broadcasting the
  signed tip — otherwise a crash between broadcast and persistence lets the same daily budget be spent
  again, silently exceeding the honest ceiling. The per-day caps hold only under that atomic persistence.

### 3c. Offers — Chia offer actions (`engine::build_offer`)

- **`engine::build_offer::OfferBuilder`** — the offers surface (make, take, cancel, combine,
  summarize), composing the canonical `dig-offers` (CHIP-0023/CHIP-0024 settlement) builders. It
  NEVER signs, NEVER auto-broadcasts, and NEVER hand-rolls offer/settlement CLVM — the
  make-must-NOT-settle (no-self-fund) rule and take's settlement-announcement assertions live INSIDE
  `dig-offers` and are preserved by composing it. `required_signatures` come from the SAME key-free
  path as every other spend.
- **Engine-side stateful TWO-CALL make/take.** Making and taking each split into build → (client
  signs) → assemble/finalize, and the two phases MUST share ONE `SpendContext`. That context — and
  the requested-payment metadata (make) or parsed `Offer` (take) it carries — is a non-serializable
  SDK allocator object, so it MUST NOT cross the seam: `dig_offers::make_assemble` and
  `take_combine` use NO secret key (they transform an ALREADY-SIGNED bundle plus public data), so
  assembly runs ENGINE-side. The intermediate is parked in `engine::offer_state::PendingOffers`
  between the two calls, keyed by an opaque, engine-generated `OfferBuildId`; only that id and the
  `UnsignedSpend` cross the wire. A parked build is single-use and is swept after `PENDING_TTL`
  (300 s) so an abandoned build cannot leak memory. No key material is ever parked.
  - **Make** (`build_make` → sign → `assemble_make`): `MakeOfferRequest { identity, offered,
    requested, fee }` → `PendingOfferBuild { build_id, unsigned }`; then `AssembleOfferRequest {
    build_id, signed }` → `OfferString { offer, offer_id }` (the `offer1…` string, via
    `encode_offer`, plus the offer's stable id).
  - **Take** (`build_take` → sign → `finalize_take`): `TakeOfferRequest { identity, offer, fee }` →
    `PendingOfferBuild`; then `FinalizeTakeRequest { build_id, signed }` → `SignedBundle` — the
    atomic settlement bundle, broadcastable but NEVER auto-pushed (the caller broadcasts it). The
    taker's XCH/CAT fund selection shares `engine::selection::select_for_spend` with ordinary sends,
    so an over-cap taker selection reports `NeedsConsolidation` (surfaced as `insufficient_funds`
    with a consolidation message) identically to a send.
  - **Cancel** (single build call): `CancelOfferRequest { identity, offer, fee }` → `UnsignedSpend`,
    signed + broadcast through the ordinary spend path (same shape as a send). **Fail-closed:** if
    the wallet holds no standard-layer key for ANY of the offer's offered coins — it is not the
    maker, or the offer's coins are CAT/NFT coins reclaimable only through their native layer —
    cancel returns `spend_validation_failed` rather than an empty, non-signable spend.
  - **Combine** (pure): `CombineOffersRequest { offers }` → `OfferString { offer, offer_id }`.
  - **Summarize** (pure): `SummarizeOfferRequest { offer }` → `OfferSummary { offer_id, offered,
    requested, arbitrage, royalties }`.
- **No-self-fund invariant.** A make spends ONLY the offered assets; the requested side is an
  assertion, never a settle action — the maker never funds both sides. (Proven by the two-party
  simulator round-trip, where the maker holds ONLY the offered asset yet make succeeds.)
- **v0.11.0 scope.** XCH↔CAT offers (make/take/cancel/combine/summarize). NFT offer legs are
  deferred (they need spendable-NFT resolution through the input provider); `$DIG` is a CAT, so the
  CAT legs cover the value flow.

**NOT in the engine seam:** key custody, mnemonic generation, a `sign()` implementation (only the
trait it calls), any HD seed.

---

## 4. CLIENT seam (`client`)

Used by dig-app. The subscriber + identity provider + signer.

- **`client::WalletClient`** — the dig-app-side handle over the control IPC. Proxied reads (`balance`,
  `coins`, `cats`, `history`, `sync_status`); spend-intent (`request_send_xch`, `request_send_cat`)
  that ask the engine to BUILD and return an `UnsignedSpend` for review + signing. The client MUST
  NOT build or sign locally.
- **`client::subscribe`** — `filter_events(events, filter)` (the pure filter core), `Subscription`
  (a live filtered stream over the engine broadcast), and the `CatchUp::catch_up(since, filter)`
  backfill trait. §5.
- **`client::verify`** — INDEPENDENT re-derivation of a spend's value flow from its `CoinSpend`s
  alone (never the engine-supplied summary). `analyze(&[CoinSpend]) -> SpendEffect { recipients,
  change, fee }` parses each coin spend back through the chia-wallet-sdk drivers it was built with
  (`Cat::parse` for a CAT, `StandardLayer` for standard XCH), runs each puzzle+solution to obtain its
  conditions, sorts `CREATE_COIN`s into hinted (recipient) vs un-hinted (change), sums `RESERVE_FEE`,
  and enforces per-asset value conservation. Before trusting a reveal it MUST bind the reveal to the
  coin: `sha256tree(puzzle_reveal)` MUST equal `coin.puzzle_hash`, or the reveal is a substituted
  puzzle the coin never committed to and the spend is refused (#1518). For every standard-layer coin
  it MUST also find EXACTLY ONE `AGG_SIG_ME` condition whose message equals `sha256tree(delegated_
  puzzle)` — zero (nothing binds a signature to the coin), more than one (a second `AGG_SIG_ME` could
  launder a blank-check signature for another coin through a benign carrier), or a wrong-hash
  `AGG_SIG_ME` are each refused (#1519). `derive_summary(&[CoinSpend]) -> TransactionSummary`
  wraps it for display. Only the standard-XCH-send and CAT-send classes the engine builds are
  decodable; any coin spend that cannot be FULLY accounted for (a foreign puzzle, undecodable bytes,
  a value leak/mint) is refused fail-closed with `WalletErrorCode::SpendValidationFailed`.
- **`client::review::decode(&UnsignedSpend) -> HumanReadableSummary`** — deterministic, side-effect-free
  decode of a spend into human-readable lines ("Send 1.5 XCH to xch1… · Fee 0.0001 XCH", coin-spend
  and required-signature counts) for the native-confirm UI. The rendered value flow is re-derived via
  `client::verify::derive_summary` (the authoritative summary), so the confirm dialog shows what the
  transaction ACTUALLY does. The user reviews; they do not trust blindly.
- **`client::signer`** — `IdentitySigner { identity(), sign(UnsignedSpend) -> SignedBundle }` and
  `LocalSigner` (holds a `chia::bls::SecretKey`, exposes only `public_key()` + `identity()` +
  `identity_public_key_bytes()` + `decap(peer_g1)`). `LocalSigner` also implements the engine's
  `RemoteSigner` (both `sign` and `dh`), registered over IPC. **This is the ONLY module that touches
  secret material, compiled only under `client`.** The HD/keystore/mnemonic primitives (#997
  master-HD → profile derivation, the dig-identity key at `m/12381'/8444'/9'/0'`, at-rest encryption,
  BIP-39) live behind this seam (§8). Custody controls, all fail-closed:
  1. **Synthetic-key matching (#1368).** A standard-layer (`p2_delegated_puzzle_or_hidden_puzzle`)
     spend requires the BLS SYNTHETIC key curried into the coin's puzzle, not the raw derived key.
     `find_key` matches BOTH the raw derived key and its `derive_synthetic()` (against the canonical
     `DEFAULT_HIDDEN_PUZZLE_HASH`, via chia-puzzle-types' `DeriveSynthetic`), returning the synthetic
     secret key when it authorizes the spend. A required signature whose key cannot be reproduced is
     refused.
  2. **AGG_SIG_ME binding.** Every signed message MUST end with the network genesis challenge; an
     unbound (`AGG_SIG_UNSAFE`) message is refused.
  3. **Verify-before-sign (#1058).** `sign_unsigned` FIRST re-derives the spend via `client::verify`,
     requires every change output to return to a wallet-owned puzzle hash (no exfiltration), and
     requires the engine-supplied summary to match the re-derived recipients + fee. The required
     signatures actually signed are RE-DERIVED from the verified coin spends via
     `SdkRequiredSignature::from_coin_spends` — the engine-supplied `required_signatures` field is
     UNTRUSTED (only cross-checked, never the signing source), so a malicious engine cannot use it as
     a signing oracle to obtain an `AGG_SIG_ME` over an arbitrary delegated puzzle. No `bls_sign`
     runs until the coin spends are independently accounted for — the signer never blind-signs.
  4. **Quote-form delegated puzzle.** `verify::analyze` requires every standard-layer spend's
     delegated puzzle (from the standard-layer solution) to be the canonical quoted, solution-
     independent form `(q . conditions)` (CLVM quote, opcode `1`), on both the XCH and CAT-inner
     paths. The standard layer signs `sha256tree(delegated_puzzle) || coin_id || genesis`, which does
     NOT commit to the delegated puzzle's solution; a solution-malleable delegated puzzle would make
     the same signature a reusable blank check authorizing different outputs. Only a bare quote makes
     `sha256tree(delegated_puzzle)` fully commit to the exact conditions. Non-quote → refused
     fail-closed. Only non-ME agg_sig conditions are additionally rejected (see control 1).
  5. **Reveal-bound-to-coin (#1518).** `verify::analyze` requires `sha256tree(puzzle_reveal) ==
     coin.puzzle_hash` for every coin spend before decoding it, so the value flow it derives is always
     the coin's OWN on-chain-committed program, never a substituted reveal.
  6. **Sole committed AGG_SIG_ME (#1519).** `verify::analyze` requires each standard-layer coin to
     carry EXACTLY ONE `AGG_SIG_ME`, committing to `sha256tree(delegated_puzzle)` — the message the
     re-derived outputs come from. Zero, duplicate, or wrong-hash `AGG_SIG_ME` is refused, so no
     extra signature can be laundered and the signed message provably matches the reviewed outputs.
  - **Signing scope (fail-closed).** `sign_unsigned` signs ONLY the standard-XCH-send and CAT-send
    classes `client::verify` can decode. An offer (settlement), option, or tip `UnsignedSpend` routed
    through it is refused (`SpendValidationFailed`) until its verify decoder lands.
- **`client::identity::IdentityProvider`** — `active_identity()`, `tracked_public_keys()`. Supplies the
  engine public material only. `HdIdentity` additionally exposes `identity_public_key_bytes()` (the
  48-byte G1 identity key published to slot `0x0010`) and `decap(peer_g1)` (the dig-message recipient
  open — G1-ECDH against the held identity key), alongside its domain-separated `sign_identity_message`.
- **`client::addressbook::AddressBook`** — local label → address contacts (`set`/`get`/`label_for`/
  `remove`/`entries`). No network, no keys.

**NOT in the client seam:** peer sync, the SQLite indexer, the chia-query fallback (engine-only; dig-app
reads via `WalletClient` over IPC).

---

## 5. Event system

The engine EMITS; dig-app SUBSCRIBES to a FILTERED view. Event-driven, poll ONLY on a gap.

The wire types (`WalletEvent`, `EventKind`, `Cursor`, `EmittedEvent`, `SyncLifecycle`, `SyncStatus`)
and the `WalletId`/`Amount`/`AssetId` payload newtypes are defined ONCE, in the `dig-events-protocol`
crate, and re-exported here (`crate::types`) — the ONE ecosystem definition so a second implementation
can never drift from this one (#1067/#1072). `EventSink` implements that crate's `EventEmitter` trait;
a subscriber's backfill implements its `CatchUp` trait. This crate owns only the machinery that
produces, persists, and streams events — the bus (`engine::events::EventSink`), the delta catch-up
store (`engine::events::DeltaLog`, in-memory now; SQLite-backed is #1118, behind the same `CatchUp`
trait), and the live subscription wrapper (`client::subscribe::Subscription`).

### 5.1 Taxonomy

`WalletEvent` is serde-tagged by `type` in snake_case (`{"type":"funds_received",…}`) so a machine
consumer branches on a stable discriminant. Variants:

`funds_received`, `funds_sent`, `coin_state_changed`, `confirmation`, `transaction_failed`,
`new_tip`, `sync_progress` (carries the tri-state `SyncLifecycle` ∈ { `idle`, `syncing`, `synced` }),
`cat_info`, `did_info`, `nft_data`, `derivation`. Each carries the fields documented in the crate
API. `WalletEvent::kind()` returns the `EventKind` discriminant used for filtering.

### 5.2 Emit + subscribe

- **Emit (engine):** `EventSink::publish(event) -> Cursor` — assigns the next monotonic per-instance
  cursor (1-based; `Cursor::default()` = 0 is the "seen nothing" sentinel), records the event in the
  delta log, and fans it out. Publishing with no subscribers is a best-effort no-op for the live
  fan-out, but the event is ALWAYS recorded in the delta log so a later subscriber can catch up to it.
- **Emit points (engine wiring):** the sync loop emits `funds_received` on a new inbound coin and
  `funds_sent` when a tracked coin becomes spent (with `coin_state_changed` on every coin transition),
  `sync_progress` as sync advances / on reorg; the chain-watch loop calls `observe_tip` (`new_tip`),
  `confirm_transaction` (`confirmation`), and `fail_transaction` (`transaction_failed`).
- **Subscribe (client):** a subscriber passes an `EnumSet<EventKind>` FILTER and receives only matching
  events (e.g. #970 subscribes `funds_received | funds_sent`; #979 subscribes `coin_state_changed |
  new_tip`). Non-matching events are skipped transparently.

### 5.3 Catch-up (poll-only-on-gap)

The live broadcast does NOT replay history. A lagging or reconnecting subscriber observes a lag
signal, then calls `catch_up(since_cursor, filter)` ONCE to fetch the missed range from the engine's
delta log (`DeltaLog`), then resumes live. `catch_up` returns every retained `EmittedEvent` with a
cursor STRICTLY GREATER than `since`, in cursor order, narrowed by the same `EnumSet<EventKind>`
filter as the live stream (so live and catch-up deliver an identical filtered view). Every delivered
event is an `EmittedEvent { cursor, event }`; the subscriber remembers the last cursor. The in-memory
`DeltaLog` retains a bounded window (`DEFAULT_HISTORY_CAPACITY`); a gap older than the window is
unrecoverable in-memory — the persistent SQLite-backed catch-up (#1118) removes that bound behind the
same `CatchUp` trait, with no consumer call-site change. This is the normative "event-driven, poll
only for catch-up" contract. #979 Subscription adopts this exact pattern.

---

## 6. The IPC contract

- The seams meet over the dig-app ↔ engine control IPC (the paired-token control channel). The engine
  seam is the server; the client seam is the client.
- Over IPC: read/build/broadcast are request/response; the event stream is bridged as server-push
  (SSE/WS on the dual transport). In-process (DIG-Browser cdylib) the raw broadcast receiver is used.
- The client side is `client::transport::IpcWalletClient<T: ControlTransport>`: it marshals each
  read / spend-intent as a named JSON request over an injected `ControlTransport`. The stable,
  append-only method names are `wallet.balance`, `wallet.coins`, `wallet.cats`, `wallet.history`,
  `wallet.sync_status`, `wallet.request_send_xch`, `wallet.request_send_cat`.
- **Key-isolation invariant on the wire:** the only messages crossing INTO the engine carry
  `IdentityRef` (public) or `SignedBundle` (post-sign). No IPC message carries a secret key, mnemonic,
  or seed. §1.4.
- Authorization rides the existing paired-token channel; an unauthorized caller MUST be rejected
  before any wallet operation.

---

## 7. Sync + fallback

- The sync loop subscribes to peer puzzle-state updates and applies coin-state deltas to the store,
  handling reorgs by rolling back to the fork point.
- Peer dialing is IPv6-first, IPv4-fallback (§5.2 ecosystem rule); candidate ordering advertises IPv6
  first.
- A fallback point-read source (chia-query / coinset) is used only while syncing or for reads not yet
  in the local store; it is engine-internal and never exposed on the client seam.
- Implemented by `engine::sync::SyncEngine` over injected transports: `PeerCoinSource` (the primary
  peer stream) and `ChainFallback` (the point-read source). `ingest` applies coin-state deltas and
  emits a `WalletEvent` per change (`FundsReceived` on a new inbound coin, `CoinStateChanged`
  otherwise); `handle_reorg` rolls the store back and emits the reverted state; `resolve_coin` reads
  local-first and falls to the point-read source for out-of-DB reads; `sync_with_fallback` prefers
  the peer and routes to the fallback only on a `transport` failure. `order_dial_candidates` orders a
  peer's candidate addresses IPv6-first (§5.2).

---

## 8. HD / keys / custody (client side)

All of the following live behind the `client` seam and NEVER in the engine:

- **Master seed → profiles** (#997): a master HD seed derives per-profile keys; `IdentityRef.profile_ix`
  selects the profile. The derivation is deterministic and specified with golden vectors (§9).
- **At-rest encryption:** the seed/keystore is encrypted at rest (app-data location per the ecosystem
  data-location rule). Concrete scheme specified when the custody lane lands.
- **BIP-39** mnemonic import/export.
- **Canonical wallet (money) key — the funded key (#1522):** the derivation that controls real funds
  is `master_to_wallet_unhardened(SecretKey::from_seed(seed), index).derive_synthetic()` — the
  unhardened wallet child `m/12381/8444/2/index` made synthetic against the canonical
  `DEFAULT_HIDDEN_PUZZLE_HASH`. The SYNTHETIC public key curries the standard transaction puzzle, so
  its puzzle-tree-hash is the wallet's on-chain XCH address. This is **byte-identical to dig-account's
  `WalletKey`, the pre-cutover dig-app wallet, and every standard Chia wallet (incl. Sage)** —
  cross-pinned by a golden vector (§9) against dig-account's frozen vector (all-`0x42` seed → pk
  `884cc9a2…` / puzzle-hash `e05ec4f5…` / addr `xch1up0vfat…`). Exposed as
  `MasterKey::wallet_signing_key(index)` / `wallet_public_key(index)`. A money-spending consumer MUST
  sign through this key set (`LocalSigner::new_canonical` / `with_canonical_wallet_keys`); signing over
  the legacy path below fund-LOCKS coins at the canonical address.
- **Legacy profile derivation (#997):** the master seed also derives per-profile keys via the hardened
  path `m/44'/8444'/{profile_ix}'` (BIP-32/44 hardened, Chia coin type 8444); a profile's
  receive/signing keys are unhardened children of that account node. This is a DISTINCT, never-funded
  key set (`MasterKey::address_key`, `LocalSigner::new`'s default `WalletKeyScheme::LegacyProfile`),
  retained only for pre-canonical internal callers — it does NOT control wallet funds. This lives in
  `client::hd::MasterKey` (`Zeroizing` seed, wiped on drop; no `Debug`/`Serialize`/`Clone` exposing the
  secret).
- **Master-key source seam:** the unlocked `MasterKey` is produced by a `MasterKeySource`
  implementation. At-rest encryption is NOT re-implemented here — `dig-keystore`
  (`Keystore<L1WalletBls>`, DIGLW1 / AES-256-GCM / Argon2id) is the canonical keystore and provides
  the `MasterKeySource`. Implementations MUST fail-closed on a locked/absent/corrupt store.
- **Signing:** `LocalSigner` matches each `RequiredSignature.public_key` to a derived key — per its
  `WalletKeyScheme`, either the canonical synthetic wallet keys (`new_canonical`, the funded set) or
  the legacy profile keys (`new`) — signs the `message` with augmented BLS, and aggregates into the
  `SignedBundle`. `find_key` (which secret authorizes a spend) and `owns_puzzle_hash` (which change
  outputs return to the wallet) both search the scheme's address set across the address gap.
- **Identity key + G1-ECDH decap:** a SINGLE per-wallet dig-identity key derives at the hardened path
  `m/12381'/8444'/9'/0'` (dig-identity SPEC §6a.1) — DISTINCT from the Chia wallet keys; it secures no
  coins. Its 48-byte compressed G1 public key is the value published to slot `0x0010`. The recipient
  DECAP of a dig-message seal is the G1-ECDH `dh(identity_sk, peer_g1) = identity_sk · peer_g1`
  (`MasterKey::identity_dh`, surfaced as `LocalSigner::decap` / `HdIdentity::decap` /
  `RemoteSigner::dh`), returning the 48-byte compressed shared G1 point for the KEM/KDF. The curve
  arithmetic + subgroup checks are reused from `dig-identity` `g1_dh` (never re-rolled). **Custody:**
  `peer_g1` is subgroup- and non-identity-checked BEFORE the scalar multiplication (invalid-curve /
  small-subgroup key-recovery defense); only the shared secret is returned, never the scalar. The one
  key does both sign (G2) and DH (G1) on group-separated, path-disjoint primitives.
- **Custody controls (fail-closed).** The signer MUST refuse to produce a signature unless (a) the
  message is bound to the network — it ends with the network's AGG_SIG_ME additional data (genesis
  challenge), which rejects unbound `AGG_SIG_UNSAFE` messages that could be replayed against another
  coin — and (b) it can reproduce the required public key from its own derivation. Application-level
  identity signatures (e.g. auth challenges, `client::identity::HdIdentity`) MUST be domain-separated
  with a `DIGNET-<domain>-v1` framing and NEVER computed over raw caller-supplied bytes, so an
  identity signature can never collide with a spend signature.

---

## 9. Conformance + golden vectors; security properties

- **Amount always-string wire form:** round-trip vectors at `0`, `1`, `MAX_JS_SAFE_INTEGER`,
  `MAX_JS_SAFE_INTEGER + 1`, `u64::MAX` — every value serializes as a decimal string; a bare JSON
  number still deserializes (lenient). Owned + KAT-tested in `dig-events-protocol`.
- **Event serialization:** every `WalletEvent` variant round-trips through its snake_case tagged form
  (KAT-tested in `dig-events-protocol`, the canonical source of the event taxonomy).
- **Filter semantics:** `filter_events` and the live subscription apply identical inclusion rules.
- **Key isolation (security):** the engine + shared-`types` source names no secret identifier
  (primary gate); the engine seam builds standalone without the client/signing feature (corroborating
  gate). §1.4.
- **Determinism:** a spend build is deterministic given identical inputs + coin set (a build test
  asserts identical inputs yield an identical `UnsignedSpend`; validated fail-closed — value
  conservation + a non-empty required-signature set — before broadcast).
- **Coin selection:** high-value-first, tie-broken by coin id; `NeedsConsolidation` is
  distinguished from `InsufficientFunds`; boundary + one-over-cap vectors are tested.
- **Unsigned-only:** an `UnsignedSpend` carries `required_signatures` (public key + message
  descriptors), never a produced signature — the engine build never signs (key-isolation test +
  build-seam tests).
- **HD derivation:** master-seed → profile key golden vectors (specified with the custody lane).
- **G1-ECDH decap (security):** the decap round-trip is symmetric (`dh(our_sk, peer_pub) ==
  dh(peer_sk, our_pub)`, matching dig-identity's `g1_dh` KAT); a malformed / off-curve / small-subgroup
  / identity peer point is rejected fail-closed BEFORE the scalar multiplication; self-decap
  (sender == recipient) is valid; the decap output is the shared secret only (not public material, no
  scalar leak); the sign path is unchanged alongside decap; the identity key is distinct from the
  wallet coin keys.

Future lanes (state/sync, build/broadcast, custody, consumer migration) extend §3–§8 with concrete
implementations and their conformance vectors; the seam boundary and the key-isolation invariant
defined here are the fixed contract they MUST NOT violate.
