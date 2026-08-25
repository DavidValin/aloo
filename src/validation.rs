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
pub const CHANNEL_NAME_MAX_LEN: usize = 30;

/// True for an ASCII letter, digit, '-', or '_' - a channel name's entire
/// allowed charset (the same charset `nickname_is_registrable` uses). No
/// other punctuation, no whitespace, no non-ASCII.
pub fn channel_name_char_allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// The `#` a channel is *shown* with everywhere it is named
/// (`docs/SPEC.md` "Connected UI"). Decoration, not part of the name: it
/// is never sent on the wire and never stored.
pub const CHANNEL_DISPLAY_PREFIX: char = '#';

/// A channel name as someone may have typed or configured it, with that
/// decorative `#` taken back off.
///
/// The name on screen carries one, so someone typing a channel in has
/// every reason to type it the way they just read it. Only a leading one
/// is dropped, and only one: `#` is not in the allowed charset, so
/// anywhere else in the string it is a genuine mistake and stays there to
/// be refused by `channel_name_is_valid` rather than being quietly
/// deleted.
pub fn normalize_channel_name(name: &str) -> &str {
    let name = name.trim();
    name.strip_prefix(CHANNEL_DISPLAY_PREFIX).unwrap_or(name)
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
/// tab-delimited flat-file stores (`idstore`, `connect`'s
/// cache): no tab (field delimiter), no newline/carriage-return (record
/// delimiter). Nicknames and hosts are attacker-controlled or user-typed,
/// and accepting a delimiter would let records be injected into the local
/// file; hex-encoded fields can't collide with either.
pub fn is_storable(s: &str) -> bool {
    !s.contains('\t') && !s.contains('\n') && !s.contains('\r')
}

/// A registered nickname is at most this many characters - the same cap
/// the connect popup enforces while typing
/// (`client::tui::ui_connect_popup::NICKNAME_MAX_LEN`).
pub const NICKNAME_MAX_LEN: usize = 11;

/// Whether `nickname` can name an account in the server's users registry
/// (`server::users_registry`): 1 to `NICKNAME_MAX_LEN` ASCII letters,
/// digits, `-` or `_`. Stricter than the popup's own filter (which only
/// refuses whitespace) because the registry keeps each account in a
/// directory *named after the nickname*: `..`, a path separator, or a
/// leading `.` would escape or hide it, and anything non-ASCII raises
/// case-folding and normalisation questions a directory name cannot
/// answer. The server applies this to `Auth` and `Register` alike, so an
/// unregistrable name is refused before it ever reaches the filesystem.
///
/// Also excludes Windows-reserved device names (`is_windows_reserved_name`):
/// the registry ships for Windows too (release.yml), and a directory
/// literally named `con` or `nul` cannot be created there at all - the
/// nickname would break its own registration rather than merely
/// mis-rendering, so this is refused up front like every other
/// filesystem-unsafe shape above.
pub fn nickname_is_registrable(nickname: &str) -> bool {
    !nickname.is_empty()
        && nickname.len() <= NICKNAME_MAX_LEN
        && nickname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !is_windows_reserved_name(nickname)
}

/// Windows' reserved device names - matched case-insensitively, and only as
/// a whole component: `name` is either an entire nickname (which cannot
/// contain `.`) or a filename's *stem*, the part before its first `.`,
/// since Windows reserves e.g. `CON.txt` the same way it reserves bare
/// `CON` (`safe_filename` in `client::file_transfer` passes the stem;
/// `nickname_is_registrable` above passes the whole nickname). A real name
/// that merely starts with one of these, e.g. `console`, is unaffected -
/// only an exact match is reserved.
pub fn is_windows_reserved_name(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    RESERVED.iter().any(|reserved| reserved.eq_ignore_ascii_case(name))
}

/// A deliberately shallow check on a registration email address: one `@`
/// with something on each side, no whitespace, and - the part that
/// actually matters - no CR/LF, since the address ends up in an SMTP
/// header line and a newline in it would let a client inject further
/// headers. Whether the mailbox exists is what the activation code proves.
pub fn email_is_plausible(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && email.len() <= 254
        && !email.chars().any(|c| c.is_whitespace() || c == '<' || c == '>' || c == ',')
}

/// The address the server should listen on, from a `--bind` value (or the
/// `server_bind` setting) and a port.
///
/// Parsing the host on its own, rather than pasting `"{bind}:{port}"`
/// together and parsing that as a whole socket address, is what makes an
/// IPv6 bind work at all: `"::"` and `"::1"` produce `":::7878"` and
/// `"::1:7878"`, neither of which is a valid socket address, so every plain
/// IPv6 form was rejected outright and only the bracketed `"[::]"` spelling
/// - which nothing documents or suggests - could be used. A bracketed form
/// is still accepted, since that is what the flag's own error message used
/// to push people towards and what any surviving settings file may hold.
///
/// A host name is deliberately still not accepted: which of a name's
/// addresses to bind is ambiguous, and the answer decides which address
/// family clients (and therefore the direct-link UDP sockets they derive
/// from it) end up using.
pub fn parse_bind_addr(bind: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    let host = bind.trim();
    // `[::]` / `[::1]`: the bracketed spelling, with the brackets serving
    // only to separate host from port in a combined string that isn't used
    // here.
    let unbracketed = match (host.strip_prefix('['), host.strip_suffix(']')) {
        (Some(_), Some(_)) => &host[1..host.len() - 1],
        _ => host,
    };
    unbracketed
        .parse::<std::net::IpAddr>()
        .map(|ip| std::net::SocketAddr::new(ip, port))
        .map_err(|_| {
            format!(
                "not a valid IP address to bind: {bind:?} - use an address such as \
                 0.0.0.0 (every IPv4 interface), :: (every interface of both \
                 families, where the OS allows it), or a specific interface's own \
                 address"
            )
        })
}
