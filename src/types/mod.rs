//! The shared `types` layer — the wire contract both seams import (SPEC §2).
//!
//! Pure, I/O-free data: identities, values/records, the event taxonomy, spend objects, and
//! the catalogued error type. This layer is ALWAYS compiled (it is not feature-gated) and
//! deliberately contains NO secret material — no `SecretKey`, mnemonic, or seed ever appears
//! here (the key-isolation invariant, SPEC §1d).
//!
//! The event taxonomy + its `WalletId`/`Amount`/`AssetId` payload newtypes are NOT defined
//! here — they are re-exported from the canonical `dig-events-protocol` crate, the ONE
//! ecosystem definition the engine emits against and dig-app subscribes against (#1067, #1072).

pub mod error;
pub mod identity;
pub mod request;
pub mod spend;
pub mod value;

pub use dig_events_protocol::{
    filter_events, Amount, AssetId, CatchUp, Cursor, EmittedEvent, EventEmitter, EventKind,
    SyncLifecycle, SyncStatus, WalletEvent, WalletId,
};
pub use error::{WalletError, WalletErrorCode, WalletResult};
pub use identity::{Did, IdentityRef};
pub use request::{SendCatRequest, SendXchRequest};
pub use spend::{RequiredSignature, SignedBundle, UnsignedSpend};
pub use value::{
    Address, Balance, CatRecord, CoinRecord, DidRecord, Network, NftRecord, SpendOutput,
    TransactionRecord, TransactionSummary,
};
