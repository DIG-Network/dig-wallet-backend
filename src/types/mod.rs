//! The shared `types` layer — the wire contract both seams import (SPEC §2).
//!
//! Pure, I/O-free data: identities, values/records, the event taxonomy, spend objects, and
//! the catalogued error type. This layer is ALWAYS compiled (it is not feature-gated) and
//! deliberately contains NO secret material — no `SecretKey`, mnemonic, or seed ever appears
//! here (the key-isolation invariant, SPEC §1d).

pub mod error;
pub mod event;
pub mod identity;
pub mod request;
pub mod spend;
pub mod value;

pub use error::{WalletError, WalletErrorCode, WalletResult};
pub use event::{Cursor, EmittedEvent, EventKind, SyncLifecycle, SyncStatus, WalletEvent};
pub use identity::{Did, IdentityRef, WalletId};
pub use request::{SendCatRequest, SendXchRequest};
pub use spend::{RequiredSignature, SignedBundle, UnsignedSpend};
pub use value::{
    Address, Amount, AssetId, Balance, CatRecord, CoinRecord, DidRecord, Network, NftRecord,
    SpendOutput, TransactionRecord, TransactionSummary, MAX_JS_SAFE_INTEGER,
};
