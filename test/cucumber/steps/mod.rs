//! Step definitions, grouped by the part of the system they drive.
//!
//! Every module is compiled into the runner; cucumber collects the steps
//! themselves through the attribute macros, so a module only has to exist
//! here to be registered.
//!
//! The rule these all follow: **the assertions live in Rust, the intent lives
//! in Gherkin**. A `Then` step never degrades to "the operation succeeded" -
//! where the pre-migration Rust test checked ten properties, the step that
//! replaced it checks the same ten.

pub mod channels;
pub mod connect;
pub mod control_channel;
pub mod daemon;
pub mod delivery;
pub mod direct_punch;
pub mod encryption;
pub mod file_transfer;
pub mod identity;
pub mod identity_continuity;
pub mod malformed_input;
pub mod messaging;
pub mod otp;
pub mod otp_mail;
pub mod pq_hybrid;
pub mod presence;
pub mod reconnect;
pub mod server;
pub mod status;
pub mod ui_common;
pub mod voice;
