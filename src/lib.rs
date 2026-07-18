//! # dig-wallet-backend
//!
//! The canonical, event-driven Chia wallet backend for the DIG Network. It exports **two
//! carefully-partitioned seams** (see `SPEC.md`) plus the shared `types` layer they meet over:
//!
//! - [`engine`] — imported by **dig-node-service**. The single running wallet INSTANCE: state
//!   tracking, peer sync, unsigned-spend construction, event emission, and broadcast. It is
//!   identity-*parameterized* (fed public [`types::IdentityRef`] material + a
//!   [`engine::RemoteSigner`] callback) and **NEVER holds a private key or signs**.
//! - [`client`] — used by **dig-app**. The event SUBSCRIBER, spend review/decode, the SIGNER that
//!   HOLDS the key, the identity provider, and the local address book.
//! - [`types`] — the shared, I/O-free wire contract both seams import. Contains NO secret material.
//!
//! ## The key-isolation invariant (SPEC §1d)
//! The private key lives ONLY behind [`client::signer`] (compiled under the `client` feature). No
//! engine-seam type is or transitively exposes a `chia::bls::SecretKey`, mnemonic, or seed. This
//! is enforced two ways: the engine seam compiles standalone with no secret-key path
//! (`--no-default-features --features engine`), and `tests/key_isolation.rs` asserts the engine
//! source names no secret type.
//!
//! ## Features
//! - `types` — always compiled (both seams depend on it).
//! - `engine` — the engine-seam code + its async runtime.
//! - `client` — the client-seam code (the only place secret material is compiled in).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod types;

#[cfg(feature = "engine")]
pub mod engine;

#[cfg(feature = "client")]
pub mod client;
