pub mod channel;
pub mod connect;
pub mod crypto;
pub mod direct_message;
pub mod file_transfer;
pub mod idstore;
pub mod netstats;
pub mod own_next_keys;
pub mod platform;
pub mod proto;
pub mod rekey;
pub mod session;
pub mod sysstats;
pub mod voice;
pub mod voice_stream;
pub mod server;
pub mod ui;

/// Shared catch-all error type for the client's connection/session flow
/// (`connect`, `session`) - not a meaningful domain error, just whatever
/// `?` needs to bubble up to `main.rs`. `pub` (not `pub(crate)`) so a
/// `pub fn` like `connect::resolve_my_keypair` can return it and still be
/// callable from `test/connect_test.rs`, which links against this crate
/// like any other external caller.
pub type BoxError = Box<dyn std::error::Error>;
