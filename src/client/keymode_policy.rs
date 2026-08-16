//! Client-side policy predicates over `proto::KeyMode` - what this client
//! may address and how it pins identities. Deliberately NOT in the shared
//! `proto` module: these encode client trust/addressability rules, not
//! protocol facts, and the server never consults them.

use crate::proto::KeyMode;

/// A `PqHybrid` recipient can only be addressed by a `PqHybrid` sender -
/// the hybrid scheme's signing step (`docs/PROTOCOL.md` §13) needs *our
/// own* ML-DSA-87+RSA-sign identity; every other `KeyMode` pair works
/// (RSA-OAEP needs no sender identity). An unreachable recipient is
/// silently excluded, like any other partial-delivery case in this app.
pub fn can_address(recipient_key_mode: KeyMode, own_key_mode: KeyMode) -> bool {
    recipient_key_mode != KeyMode::PqHybrid || own_key_mode == KeyMode::PqHybrid
}

/// Whether `key_mode` participates in `id_store`'s byte-comparison pinning
/// (`session::check_identity`) - true for identities stable across
/// reconnects by construction (`Rsa`/`PqHybrid`: file-loaded; `Password`:
/// re-derived from the same password). `false` for `PerMessage` (its key
/// is *supposed* to change - it has its own signature-based §12.6
/// mechanism) and `None` (no continuity by design).
pub fn uses_byte_comparison_pinning(key_mode: KeyMode) -> bool {
    matches!(
        key_mode,
        KeyMode::Rsa | KeyMode::Password | KeyMode::PqHybrid
    )
}
