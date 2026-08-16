pub mod client;
pub mod crypto;
pub mod p2p_proto;
pub mod platform;
pub mod proto;
pub mod server;
pub mod settings;
pub mod validation;

/// Shared catch-all error type for the client's connection/session flow
/// (`connect`, `session`) - not a meaningful domain error, just whatever
/// `?` needs to bubble up to `main.rs`. `pub` (not `pub(crate)`) so a
/// `pub fn` like `connect::resolve_my_keypair` can return it and still be
/// callable from `test/connect_test.rs`, which links against this crate
/// like any other external caller.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
