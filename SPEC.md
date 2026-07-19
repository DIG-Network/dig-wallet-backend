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
  sees only the read trait over IPC. A persistent (SQLite) backing is a later drop-in over the same
  surface.
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
- **`client::review::decode(&UnsignedSpend) -> HumanReadableSummary`** — deterministic, side-effect-free
  decode of a spend into human-readable lines ("Send 1.5 XCH to xch1… · Fee 0.0001 XCH", coin-spend
  and required-signature counts) for the native-confirm UI. The user reviews; they do not trust
  blindly.
- **`client::signer`** — `IdentitySigner { identity(), sign(UnsignedSpend) -> SignedBundle }` and
  `LocalSigner` (holds a `chia::bls::SecretKey`, exposes only `public_key()` + `identity()`).
  `LocalSigner` also implements the engine's `RemoteSigner`, registered over IPC. **This is the ONLY
  module that touches secret material, compiled only under `client`.** The HD/keystore/mnemonic
  primitives (#997 master-HD → profile derivation, at-rest encryption, BIP-39) live behind this seam
  (§8).
- **`client::identity::IdentityProvider`** — `active_identity()`, `tracked_public_keys()`. Supplies the
  engine public material only.
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
- **Master-key derivation (#997):** the master seed derives per-profile keys via the hardened path
  `m/44'/8444'/{profile_ix}'` (BIP-32/44 hardened, Chia coin type 8444); a profile's receive/signing
  keys are unhardened children of that account node. This lives in `client::hd::MasterKey`
  (`Zeroizing` seed, wiped on drop; no `Debug`/`Serialize`/`Clone` exposing the secret).
- **Master-key source seam:** the unlocked `MasterKey` is produced by a `MasterKeySource`
  implementation. At-rest encryption is NOT re-implemented here — `dig-keystore`
  (`Keystore<L1WalletBls>`, DIGLW1 / AES-256-GCM / Argon2id) is the canonical keystore and provides
  the `MasterKeySource`. Implementations MUST fail-closed on a locked/absent/corrupt store.
- **Signing:** `LocalSigner` matches each `RequiredSignature.public_key` to a derived key, signs the
  `message` with augmented BLS, and aggregates into the `SignedBundle`.
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

Future lanes (state/sync, build/broadcast, custody, consumer migration) extend §3–§8 with concrete
implementations and their conformance vectors; the seam boundary and the key-isolation invariant
defined here are the fixed contract they MUST NOT violate.
