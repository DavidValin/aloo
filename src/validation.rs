//! Validation rules shared by the client and the server for values whose
//! acceptance criteria must agree byte-for-byte on both sides of the wire -
//! unlike e.g. `ui_connect_popup::NICKNAME_MAX_LEN`, which only the client
//! enforces, a channel name or channel password is meaningful to reject on
//! the server too (the server must never trust the client). Also home to
//! `is_storable`, the one validation predicate the client's flat-file
//! stores all share.

/// Channel names are capped at this many Unicode scalar values, counted
/// with `.chars().count()` (not byte length - TB-140's precedent, so a
/// multi-byte character is never split mid-encoding by a truncation and,
/// here, so counting matches what a human typing sees).
pub const CHANNEL_NAME_MAX_LEN: usize = 21;

/// True for an ASCII letter, digit, or '-' - a channel name's entire
/// allowed charset. No other punctuation, no whitespace, no non-ASCII.
pub fn channel_name_char_allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// True if `name` is non-empty, at most `CHANNEL_NAME_MAX_LEN` characters,
/// and every character passes `channel_name_char_allowed`. Used
/// identically by the client (reject at input time,
/// `ui::channel::handle_join_popup_key`) and the server (reject at
/// `JoinChannel` handling time, `server::Registry::join_channel`).
pub fn channel_name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= CHANNEL_NAME_MAX_LEN
        && name.chars().all(channel_name_char_allowed)
}

/// Channel passwords are capped at this many characters.
pub const CHANNEL_PASSWORD_MAX_LEN: usize = 50;

/// The exact "basic symbols" allowed in a channel password beyond ASCII
/// letters/digits (docs/PROTOCOL.md §6.5). Deliberately excludes
/// whitespace (ambiguous in a masked field), quotes and backslash (common
/// copy/paste and shell-quoting hazards for a value typed twice).
pub const CHANNEL_PASSWORD_SYMBOLS: &[char] = &[
    '!', '@', '#', '$', '%', '^', '&', '*', '-', '_', '+', '=', '.', ',',
];

/// True for an ASCII letter, digit, or a member of `CHANNEL_PASSWORD_SYMBOLS`.
pub fn channel_password_char_allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || CHANNEL_PASSWORD_SYMBOLS.contains(&c)
}

/// True for an empty password too (empty means "none set/typed" - callers
/// requiring non-empty check that separately). Applies only to a password
/// being **set** (channel creation), never to a join-time guess - a guess
/// is compared with `crypto::constant_time_eq` regardless of whether it
/// looks well-formed (docs/PROTOCOL.md §6.5).
pub fn channel_password_is_valid(password: &str) -> bool {
    password.chars().count() <= CHANNEL_PASSWORD_MAX_LEN
        && password.chars().all(channel_password_char_allowed)
}

/// Whether `s` is safe to use as a field in one of the client's
/// tab-delimited flat-file stores (`idstore`, `own_next_keys`, `connect`'s
/// cache): no tab (field delimiter), no newline/carriage-return (record
/// delimiter). Nicknames and hosts are attacker-controlled or user-typed,
/// and accepting a delimiter would let records be injected into the local
/// file; hex-encoded fields can't collide with either.
pub fn is_storable(s: &str) -> bool {
    !s.contains('\t') && !s.contains('\n') && !s.contains('\r')
}
