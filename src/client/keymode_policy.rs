//! Client-side policy predicates over `proto::KeyMode` - what this client
//! may address and how it pins identities. Deliberately NOT in the shared
//! `proto` module: these encode client trust/addressability rules, not
//! protocol facts, and the server never consults them.

use crate::proto::KeyMode;

/// A `PqHybrid` recipient can only be addressed by a `PqHybrid` sender - the
/// hybrid scheme's signing step (`docs/PROTOCOL.md` §13) needs *our own*
/// ML-DSA-87+RSA-sign identity, which only exists when our own `my_key` is
/// also `pq_hybrid`. Every other `KeyMode` pair works exactly as before
/// (RSA-OAEP needs no sender identity at all). An unreachable recipient is
/// silently excluded, same as any other partial-delivery case in this app
/// (an offline member, a not-yet-fresh `rsa_per_msg` key, ...).
///
/// A pure, `SessionState`-free predicate (just the two `KeyMode`s involved)
/// so it's directly unit-testable without a live session
/// (`test/hybrid_crypto_test.rs`).
pub fn can_address(recipient_key_mode: KeyMode, own_key_mode: KeyMode) -> bool {
    recipient_key_mode != KeyMode::PqHybrid || own_key_mode == KeyMode::PqHybrid
}

/// Whether `key_mode` participates in `id_store`'s simple byte-comparison
/// pinning (`session::check_identity`) - true for every static identity whose
/// key is stable across reconnects by construction (`Rsa`: loaded from a
/// file; `Password`: re-derived from the same password; `PqHybrid`: loaded
/// from a keybundle file, `docs/PROTOCOL.md` §13 - the same reasoning as
/// `Rsa`). `false` for `PerMessage` (its own signature-based §12.6
/// mechanism, since its key is *supposed* to change every rotation) and
/// `None` (no continuity mechanism at all, by design). A pure predicate so
/// it's directly unit-testable (`test/hybrid_crypto_test.rs`).
pub fn uses_byte_comparison_pinning(key_mode: KeyMode) -> bool {
    matches!(
        key_mode,
        KeyMode::Rsa | KeyMode::Password | KeyMode::PqHybrid
    )
}
