//! The server's users registry: who may log in, and with what password
//! (docs/PROTOCOL.md §5).
//!
//! One directory per account under `~/.aloo/users/<nickname>/`:
//!
//! ```text
//! ~/.aloo/users/alice/key                      hex of the 32-byte derived key
//! ~/.aloo/users/alice/email.txt                where the activation code went
//! ~/.aloo/users/alice/1724400000_activate.txt  12-digit code; present only
//!                                              while activation is pending
//! ```
//!
//! The `key` file holds an AES-256-sized key *derived* from the nickname and
//! the password (`derive_user_key`), never the password itself: a login
//! re-derives it from what the client sent and compares the two in
//! constant time. Activation is the presence or absence of the
//! `<timestamp_utc>_activate.txt` file - the timestamp in its name is the
//! registration time in Unix seconds (UTC), and the code inside it stops
//! being accepted `ACTIVATION_VALIDITY_SECS` after that. Activating an
//! account is simply removing that file, whichever of the two paths does
//! it: the client's activation popup (`ClientMessage::Activate`) or the web
//! endpoint the activation email links to (`crate::server::activation`).
//!
//! Everything here is plain synchronous file I/O on a handful of small
//! files. The one async thing is `send_activation_email`, a deliberately
//! small SMTP client (implicit TLS on 465, STARTTLS elsewhere, `AUTH PLAIN`)
//! - enough to hand one message to one relay, which is all the server ever
//! needs to do.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto;
use crate::validation;

/// Activation codes are this many decimal digits.
pub const ACTIVATION_CODE_LEN: usize = 12;

/// How long an activation code is accepted for, counted from the
/// registration timestamp in the `_activate.txt` file's name.
pub const ACTIVATION_VALIDITY_SECS: u64 = 60 * 60;

/// PBKDF2-HMAC-SHA256 rounds `UsersRegistry::open` derives keys with.
/// Tens of milliseconds per login on ordinary hardware in a release
/// build - invisible to a user connecting once, a real cost to anyone
/// guessing passwords against a copied `key` file.
///
/// `pbkdf2_hmac`'s loop is generic over the hash and gets monomorphized
/// (and therefore optimized, or not) into whichever crate calls it -
/// unlike `rsa`/`num-bigint`'s concrete-typed hot paths, this crate's own
/// `[profile.dev.package."*"]` override cannot speed it up in a `dev`
/// build, where it costs on the order of 200ms per call instead of the
/// ~10ms a release build sees. `UsersRegistry::open_with_iterations` is
/// the escape hatch tests use for the same reason `crypto::KeyPair`'s
/// tests use a smaller `TEST_BITS` than the real RSA-4096.
pub const USER_KEY_ITERATIONS: u32 = 100_000;

/// Salt domain for `derive_user_key`, so the same password registered
/// under two nicknames (or in some other application using the same
/// construction) never yields the same key.
const USER_KEY_SALT_DOMAIN: &[u8] = b"aloo/users/v1:";

const KEY_FILE: &str = "key";
const EMAIL_FILE: &str = "email.txt";
const ACTIVATE_SUFFIX: &str = "_activate.txt";
/// A superadmin's `/deactivate` marker - the presence of this file in an
/// account's directory blocks login, exactly the way an `_activate.txt`
/// file blocks it for a different reason. No timestamp in the name: a
/// deactivation has no expiry, unlike a pending activation code.
const DEACTIVATE_FILE: &str = "deactivated.txt";

/// `~/.aloo/users` - same home resolution as every other store
/// (`crate::platform::aloo_dir`), and the directory the `--register-user`
/// / `--change-password` CLI operations edit in place.
pub fn default_dir() -> PathBuf {
    crate::platform::aloo_dir().join("users")
}

/// Unix seconds, UTC - the clock every registration timestamp and
/// activation deadline is measured on.
pub fn now_utc() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The 32-byte key an account's `key` file holds:
/// `PBKDF2-HMAC-SHA256(password, "aloo/users/v1:" ++ nickname,
/// USER_KEY_ITERATIONS)`. Salted with the nickname so the same password
/// under two names gives two unrelated keys.
pub fn derive_user_key(nickname: &str, password: &str) -> [u8; 32] {
    derive_user_key_with_iterations(nickname, password, USER_KEY_ITERATIONS)
}

/// `derive_user_key` with an explicit round count - what
/// `UsersRegistry::open_with_iterations` plumbs through so a test registry
/// can derive in microseconds instead of the ~200ms `USER_KEY_ITERATIONS`
/// costs in a `dev` build (see that constant's doc).
pub fn derive_user_key_with_iterations(nickname: &str, password: &str, iterations: u32) -> [u8; 32] {
    let mut salt = Vec::with_capacity(USER_KEY_SALT_DOMAIN.len() + nickname.len());
    salt.extend_from_slice(USER_KEY_SALT_DOMAIN);
    salt.extend_from_slice(nickname.as_bytes());
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut key);
    key
}

/// A fresh `ACTIVATION_CODE_LEN`-digit code. Each digit is drawn by
/// rejection sampling from the OS random source, so no digit is likelier
/// than another - a modulo on a raw byte would favour 0-5 slightly.
pub fn generate_activation_code() -> String {
    let mut code = String::with_capacity(ACTIVATION_CODE_LEN);
    while code.len() < ACTIVATION_CODE_LEN {
        for byte in crypto::random_bytes(ACTIVATION_CODE_LEN * 2) {
            if byte < 250 && code.len() < ACTIVATION_CODE_LEN {
                code.push(char::from(b'0' + byte % 10));
            }
        }
    }
    code
}

/// Whether `code` has the shape of an activation code - checked before
/// any comparison so a wrong-shaped submission costs nothing.
pub fn activation_code_is_well_formed(code: &str) -> bool {
    code.len() == ACTIVATION_CODE_LEN && code.bytes().all(|b| b.is_ascii_digit())
}

/// Why a registration (or a CLI edit) was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    /// See `validation::nickname_is_registrable`.
    InvalidNickname,
    /// See `validation::email_is_plausible`.
    InvalidEmail,
    /// An account of that name exists and is active.
    AlreadyRegistered,
    /// An account of that name exists with an activation code that is
    /// still valid - it can be activated, not replaced, until the code
    /// expires.
    ActivationPending,
    /// `change_password` on a name nobody registered.
    NotRegistered,
    /// The password is empty.
    EmptyPassword,
    Io(String),
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterError::InvalidNickname => write!(
                f,
                "nickname must be 1-{} letters, digits, '-' or '_'",
                validation::NICKNAME_MAX_LEN
            ),
            RegisterError::InvalidEmail => write!(f, "that does not look like an email address"),
            RegisterError::AlreadyRegistered => write!(f, "that nickname is already registered"),
            RegisterError::ActivationPending => write!(
                f,
                "that nickname is registered and waiting for its activation code"
            ),
            RegisterError::NotRegistered => write!(f, "no such registered nickname"),
            RegisterError::EmptyPassword => write!(f, "password must not be empty"),
            RegisterError::Io(e) => write!(f, "users registry error: {e}"),
        }
    }
}

impl std::error::Error for RegisterError {}

impl From<io::Error> for RegisterError {
    fn from(e: io::Error) -> Self {
        RegisterError::Io(e.to_string())
    }
}

/// What `register` produced: the code that went into the
/// `<created_at_utc>_activate.txt` file, and that timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub code: String,
    pub created_at_utc: u64,
}

/// The answer to a login attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthCheck {
    /// Right nickname, right password, activated, not deactivated.
    Ok,
    /// Right nickname and password, but a superadmin's `/deactivate` is in
    /// effect (the `deactivated.txt` marker is present) - outranks
    /// `ActivationPending` if somehow both apply, since it's the more
    /// specific, more recent administrative action either way.
    Deactivated { reason: String },
    /// Right nickname and password, but the `_activate.txt` file is still
    /// there. `expired` when its code is past `ACTIVATION_VALIDITY_SECS`,
    /// in which case the account has to be registered again.
    ActivationPending { expired: bool },
    /// No such account, or wrong password - deliberately one answer, so a
    /// login attempt cannot be used to find out which names exist.
    Rejected,
}

/// An account's outstanding activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingActivation {
    pub code: String,
    pub created_at_utc: u64,
    pub path: PathBuf,
}

impl PendingActivation {
    pub fn is_expired(&self, now_utc: u64) -> bool {
        now_utc.saturating_sub(self.created_at_utc) > ACTIVATION_VALIDITY_SECS
    }
}

/// The answer to an activation attempt, from either path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationOutcome {
    Activated,
    WrongCode,
    Expired,
    /// No such account, or nothing pending on it. One answer for both, for
    /// the same reason `AuthCheck::Rejected` is one answer.
    NothingPending,
}

/// The registry itself: a directory, and the rules for what is in it.
/// Cheap to clone (it is only the path); every method re-reads the files
/// it needs, so an edit made by `aloo --register-user` on the same
/// machine is seen by the next login with no restart.
#[derive(Debug, Clone)]
pub struct UsersRegistry {
    dir: PathBuf,
    /// `USER_KEY_ITERATIONS` in production; a test registry
    /// (`open_with_iterations`) uses far fewer so the suite doesn't pay a
    /// `dev`-build PBKDF2 tax on every login it drives.
    iterations: u32,
}

impl UsersRegistry {
    /// Opens (creating if needed) the registry at `dir`, deriving keys
    /// with `USER_KEY_ITERATIONS`.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        Self::open_with_iterations(dir, USER_KEY_ITERATIONS)
    }

    /// `open`, with the PBKDF2 round count overridden - see
    /// `USER_KEY_ITERATIONS`'s doc for why a test registry needs this.
    pub fn open_with_iterations(dir: impl Into<PathBuf>, iterations: u32) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir, iterations })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The account directory for `nickname`, or `None` for a name that
    /// may not be one (`validation::nickname_is_registrable`) - which is
    /// also what keeps a nickname from ever naming a path outside `dir`.
    fn user_dir(&self, nickname: &str) -> Option<PathBuf> {
        validation::nickname_is_registrable(nickname).then(|| self.dir.join(nickname))
    }

    /// Whether an account exists at all, activated or not.
    pub fn is_registered(&self, nickname: &str) -> bool {
        self.user_dir(nickname)
            .is_some_and(|d| d.join(KEY_FILE).is_file())
    }

    /// The email a registration was sent to; `None` for an account
    /// created by `register_manual`, which has none.
    pub fn email_of(&self, nickname: &str) -> Option<String> {
        let dir = self.user_dir(nickname)?;
        fs::read_to_string(dir.join(EMAIL_FILE))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Every registered nickname, sorted - what the CLI lists.
    pub fn nicknames(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.path().join(KEY_FILE).is_file())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// Creates an account awaiting activation (docs/PROTOCOL.md §5.3):
    /// writes the derived key, the email, and a fresh code in
    /// `<now_utc>_activate.txt`. A name whose previous registration was
    /// never activated and whose code has since expired is registered
    /// afresh - the old files are replaced - since nothing of value was
    /// ever behind it.
    pub fn register(
        &self,
        nickname: &str,
        password: &str,
        email: &str,
        now_utc: u64,
    ) -> Result<Registration, RegisterError> {
        let dir = self
            .user_dir(nickname)
            .ok_or(RegisterError::InvalidNickname)?;
        if !validation::email_is_plausible(email) {
            return Err(RegisterError::InvalidEmail);
        }
        if password.is_empty() {
            return Err(RegisterError::EmptyPassword);
        }
        if dir.join(KEY_FILE).is_file() {
            match self.pending_activation(nickname) {
                Some(pending) if pending.is_expired(now_utc) => {
                    fs::remove_dir_all(&dir)?;
                }
                Some(_) => return Err(RegisterError::ActivationPending),
                None => return Err(RegisterError::AlreadyRegistered),
            }
        }
        fs::create_dir_all(&dir)?;
        write_key(&dir, nickname, password, self.iterations)?;
        fs::write(dir.join(EMAIL_FILE), format!("{email}\n"))?;
        let code = generate_activation_code();
        fs::write(
            dir.join(format!("{now_utc}{ACTIVATE_SUFFIX}")),
            format!("{code}\n"),
        )?;
        Ok(Registration {
            code,
            created_at_utc: now_utc,
        })
    }

    /// `aloo --register-user`: an account with no email and nothing to
    /// activate, usable the moment this returns. Refuses to overwrite an
    /// existing account of any state - `change_password` is the edit for
    /// one that exists.
    pub fn register_manual(&self, nickname: &str, password: &str) -> Result<(), RegisterError> {
        let dir = self
            .user_dir(nickname)
            .ok_or(RegisterError::InvalidNickname)?;
        if password.is_empty() {
            return Err(RegisterError::EmptyPassword);
        }
        if dir.join(KEY_FILE).is_file() {
            return Err(RegisterError::AlreadyRegistered);
        }
        fs::create_dir_all(&dir)?;
        write_key(&dir, nickname, password, self.iterations)?;
        Ok(())
    }

    /// `aloo --change-password`: rewrites the derived key. Takes effect on
    /// the next login, since every login re-reads the file. Leaves a
    /// pending activation exactly as it was.
    pub fn change_password(&self, nickname: &str, password: &str) -> Result<(), RegisterError> {
        let dir = self
            .user_dir(nickname)
            .ok_or(RegisterError::InvalidNickname)?;
        if password.is_empty() {
            return Err(RegisterError::EmptyPassword);
        }
        if !dir.join(KEY_FILE).is_file() {
            return Err(RegisterError::NotRegistered);
        }
        write_key(&dir, nickname, password, self.iterations)?;
        Ok(())
    }

    /// The login check (docs/PROTOCOL.md §5.1). Derives the key from what
    /// the client sent and compares it, in constant time, against the
    /// `key` file. The derivation runs whether or not the account exists,
    /// so an unknown name costs the same time as a wrong password.
    pub fn check_credentials(&self, nickname: &str, password: &str, now_utc: u64) -> AuthCheck {
        let derived = derive_user_key_with_iterations(nickname, password, self.iterations);
        let Some(dir) = self.user_dir(nickname) else {
            return AuthCheck::Rejected;
        };
        let stored = fs::read_to_string(dir.join(KEY_FILE))
            .ok()
            .and_then(|hex| crypto::hex_decode(hex.trim()))
            .unwrap_or_default();
        if !crypto::constant_time_eq(&stored, &derived) {
            return AuthCheck::Rejected;
        }
        // Checked only once the password is already known to be right -
        // preserves the same timing-safety property `ActivationPending`
        // already relies on: only someone who actually knows the password
        // learns anything about the account's state beyond "wrong".
        if let Some(reason) = self.deactivation_reason(nickname) {
            return AuthCheck::Deactivated { reason };
        }
        match self.pending_activation(nickname) {
            Some(pending) => AuthCheck::ActivationPending {
                expired: pending.is_expired(now_utc),
            },
            None => AuthCheck::Ok,
        }
    }

    /// The `<timestamp>_activate.txt` file for `nickname`, if one is
    /// there. Should two ever exist (a crash between `register`'s removal
    /// and its rewrite), the most recent wins.
    pub fn pending_activation(&self, nickname: &str) -> Option<PendingActivation> {
        let dir = self.user_dir(nickname)?;
        let mut best: Option<PendingActivation> = None;
        for entry in fs::read_dir(&dir).ok()?.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(stamp) = name.strip_suffix(ACTIVATE_SUFFIX) else {
                continue;
            };
            let Ok(created_at_utc) = stamp.parse::<u64>() else {
                continue;
            };
            let Ok(code) = fs::read_to_string(entry.path()) else {
                continue;
            };
            let candidate = PendingActivation {
                code: code.trim().to_string(),
                created_at_utc,
                path: entry.path(),
            };
            if best
                .as_ref()
                .is_none_or(|b| candidate.created_at_utc > b.created_at_utc)
            {
                best = Some(candidate);
            }
        }
        best
    }

    /// A login attempt against an account whose activation code has
    /// expired: replaces the stale `<old_ts>_activate.txt` with a fresh
    /// `<now_utc>_activate.txt` carrying a new code, exactly what
    /// `register` already does when the same expired-pending account is
    /// registered again - except this leaves `key`/`email.txt` untouched,
    /// since a login attempt (unlike a register attempt) carries no new
    /// password or email to replace them with. `None` if there is no
    /// expired pending activation to reissue against (nothing pending at
    /// all, or a code that hasn't expired yet - `activate` is the answer
    /// for that case).
    pub fn reissue_activation(&self, nickname: &str, now_utc: u64) -> io::Result<Option<Registration>> {
        let Some(pending) = self.pending_activation(nickname) else {
            return Ok(None);
        };
        if !pending.is_expired(now_utc) {
            return Ok(None);
        }
        let dir = self
            .user_dir(nickname)
            .expect("pending_activation already resolved this nickname to a directory");
        fs::remove_file(&pending.path)?;
        let code = generate_activation_code();
        fs::write(dir.join(format!("{now_utc}{ACTIVATE_SUFFIX}")), format!("{code}\n"))?;
        Ok(Some(Registration { code, created_at_utc: now_utc }))
    }

    /// Activates `nickname` if `code` is the pending one and still valid -
    /// by removing the `_activate.txt` file, which is all activation is.
    /// An expired code is reported as such and left in place; `register`
    /// replaces it when the user registers again.
    pub fn activate(&self, nickname: &str, code: &str, now_utc: u64) -> ActivationOutcome {
        let Some(pending) = self.pending_activation(nickname) else {
            return ActivationOutcome::NothingPending;
        };
        if !activation_code_is_well_formed(code)
            || !crypto::constant_time_eq(pending.code.as_bytes(), code.as_bytes())
        {
            return ActivationOutcome::WrongCode;
        }
        if pending.is_expired(now_utc) {
            return ActivationOutcome::Expired;
        }
        match fs::remove_file(&pending.path) {
            Ok(()) => ActivationOutcome::Activated,
            // Already gone: someone activated it between our read and
            // our remove. That is the outcome asked for.
            Err(e) if e.kind() == io::ErrorKind::NotFound => ActivationOutcome::Activated,
            Err(_) => ActivationOutcome::WrongCode,
        }
    }

    /// A superadmin's `/deactivate <nickname> <reason>`: writes the
    /// `deactivated.txt` marker, blocking every future login until a
    /// matching `admin_force_activate`. A no-op error (not silently
    /// ignored) on a nickname the registry could never hold.
    pub fn deactivate(&self, nickname: &str, reason: &str) -> io::Result<()> {
        let dir = self
            .user_dir(nickname)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid nickname"))?;
        fs::write(dir.join(DEACTIVATE_FILE), format!("{reason}\n"))
    }

    /// The reason `nickname` was deactivated, if it currently is.
    pub fn deactivation_reason(&self, nickname: &str) -> Option<String> {
        let dir = self.user_dir(nickname)?;
        fs::read_to_string(dir.join(DEACTIVATE_FILE))
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// A superadmin's `/activate <nickname>`: clears *both* markers that
    /// can block a login, whichever are present - a still-pending emailed
    /// registration code (bypassing it, without the code) and a prior
    /// `deactivate` (reversing it). Deliberately named differently from
    /// the code-checking `activate` above even though both slash commands
    /// are spelled `/activate`: one underlying concept ("make this
    /// account able to log in right now"), two call sites. A harmless
    /// no-op on an account that was never blocked at all.
    pub fn admin_force_activate(&self, nickname: &str) -> io::Result<()> {
        let Some(dir) = self.user_dir(nickname) else {
            return Ok(());
        };
        match fs::remove_file(dir.join(DEACTIVATE_FILE)) {
            Ok(()) | Err(_) => {} // absent is exactly the goal, not an error
        }
        if let Some(pending) = self.pending_activation(nickname) {
            let _ = fs::remove_file(pending.path);
        }
        Ok(())
    }

    /// Removes an account entirely - what a failed activation email
    /// delivery does with the registration it was for, so the name is
    /// not left half-registered behind a code nobody received.
    pub fn remove(&self, nickname: &str) -> io::Result<()> {
        let Some(dir) = self.user_dir(nickname) else {
            return Ok(());
        };
        match fs::remove_dir_all(dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

fn write_key(dir: &Path, nickname: &str, password: &str, iterations: u32) -> io::Result<()> {
    let key = derive_user_key_with_iterations(nickname, password, iterations);
    fs::write(dir.join(KEY_FILE), format!("{}\n", crypto::hex_encode(&key)))
}

// ---------------------------------------------------------------------
// Activation email
// ---------------------------------------------------------------------

/// The SMTP relay activation emails go out through - the four
/// `server_smtp_*` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl SmtpConfig {
    /// `Some` only when the host and port are both set; a username and
    /// password are optional (a relay that trusts the server's address
    /// needs neither).
    pub fn from_settings(settings: &crate::settings::Settings) -> Option<Self> {
        Some(Self {
            host: settings.server_smtp_host.clone()?,
            port: settings.server_smtp_port?,
            username: settings.server_smtp_username.clone().unwrap_or_default(),
            password: settings.server_smtp_password.clone().unwrap_or_default(),
        })
    }

    /// The envelope/`From:` address: the username when it is an address
    /// itself (the usual case with a hosted relay), else `aloo@<host>`.
    pub fn from_address(&self) -> String {
        if self.username.contains('@') {
            self.username.clone()
        } else {
            format!("aloo@{}", self.host)
        }
    }
}

/// The URL an activation email links to, for a server that has a public
/// `server_activation_url`: `<base>/activate?nickname=<n>&code=<c>`.
pub fn activation_link(base_url: &str, nickname: &str, code: &str) -> String {
    format!(
        "{}/activate?nickname={nickname}&code={code}",
        base_url.trim_end_matches('/')
    )
}

/// The full RFC 5322 message for one activation, ready for `DATA`.
/// `nickname` and `code` are registry-validated (letters/digits/`-`/`_`
/// and digits respectively) and `to` passed `validation::email_is_plausible`,
/// so none of them can break out of a header line.
pub fn activation_email(
    from: &str,
    to: &str,
    nickname: &str,
    code: &str,
    activation_url: Option<&str>,
) -> String {
    let date = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_default();
    let hours = ACTIVATION_VALIDITY_SECS / 3600;
    let mut body = format!(
        "Hello {nickname},\r\n\r\n\
         Your aloo activation code is: {code}\r\n\r\n\
         It is valid for {hours} hour(s) from now. The first time you connect as \
         {nickname}, aloo will ask for it.\r\n"
    );
    if let Some(base) = activation_url {
        body.push_str(&format!(
            "\r\nOr activate your account in a browser:\r\n{}\r\n",
            activation_link(base, nickname, code)
        ));
    }
    body.push_str("\r\nIf you did not register, ignore this message.\r\n");
    format!(
        "From: aloo <{from}>\r\nTo: <{to}>\r\nSubject: aloo: activate your account \"{nickname}\"\r\n\
         Date: {date}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\r\n{body}"
    )
}

/// Sends the activation email for a fresh `register` through `smtp`.
/// Port 465 is implicit TLS; any other port starts in the clear and
/// upgrades with `STARTTLS` when the relay offers it, and otherwise goes
/// on in the clear (logged, since a real relay always offers it - the
/// clear path exists for a relay on the server's own machine).
pub async fn send_activation_email(
    smtp: &SmtpConfig,
    to: &str,
    nickname: &str,
    code: &str,
    activation_url: Option<&str>,
) -> Result<(), String> {
    let from = smtp.from_address();
    let message = activation_email(&from, to, nickname, code, activation_url);
    tokio::time::timeout(SMTP_TIMEOUT, smtp_submit(smtp, &from, to, &message))
        .await
        .map_err(|_| format!("timed out talking to {}:{}", smtp.host, smtp.port))?
}

/// The whole exchange, greeting to `QUIT`, must fit in this.
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);

async fn smtp_submit(
    smtp: &SmtpConfig,
    from: &str,
    to: &str,
    message: &str,
) -> Result<(), String> {
    let tcp = tokio::net::TcpStream::connect((smtp.host.as_str(), smtp.port))
        .await
        .map_err(|e| format!("could not reach {}:{}: {e}", smtp.host, smtp.port))?;
    let mut stream: super::ssl::BoxedStream = if smtp.port == 465 {
        super::ssl::connect(Some(&super::ssl::client_connector(None)?), &smtp.host, tcp)
            .await
            .map_err(|e| format!("TLS to {}: {e}", smtp.host))?
    } else {
        Box::new(tcp)
    };
    let mut secured = smtp.port == 465;

    let (code, _) = smtp_read(&mut stream).await?;
    if code != 220 {
        return Err(format!("relay refused the connection ({code})"));
    }
    let (code, lines) = smtp_command(&mut stream, "EHLO aloo").await?;
    if code != 250 {
        return Err(format!("EHLO refused ({code})"));
    }
    if !secured && lines.iter().any(|l| l.eq_ignore_ascii_case("STARTTLS")) {
        let (code, _) = smtp_command(&mut stream, "STARTTLS").await?;
        if code != 220 {
            return Err(format!("STARTTLS refused ({code})"));
        }
        stream = super::ssl::connect(
            Some(&super::ssl::client_connector(None)?),
            &smtp.host,
            stream,
        )
        .await
        .map_err(|e| format!("STARTTLS to {}: {e}", smtp.host))?;
        secured = true;
        let (code, _) = smtp_command(&mut stream, "EHLO aloo").await?;
        if code != 250 {
            return Err(format!("EHLO after STARTTLS refused ({code})"));
        }
    }
    if !secured {
        crate::log_warn!(
            "SMTP relay {}:{} offers no TLS - the activation email (and any SMTP password) travel in the clear",
            smtp.host,
            smtp.port
        );
    }
    if !smtp.username.is_empty() {
        let auth = base64(&format!("\0{}\0{}", smtp.username, smtp.password).into_bytes());
        let (code, _) = smtp_command(&mut stream, &format!("AUTH PLAIN {auth}")).await?;
        if code != 235 {
            return Err(format!("SMTP authentication failed ({code})"));
        }
    }
    let (code, _) = smtp_command(&mut stream, &format!("MAIL FROM:<{from}>")).await?;
    if code != 250 {
        return Err(format!("MAIL FROM refused ({code})"));
    }
    let (code, _) = smtp_command(&mut stream, &format!("RCPT TO:<{to}>")).await?;
    if code != 250 && code != 251 {
        return Err(format!("the relay refused the recipient ({code})"));
    }
    let (code, _) = smtp_command(&mut stream, "DATA").await?;
    if code != 354 {
        return Err(format!("DATA refused ({code})"));
    }
    let mut data = String::with_capacity(message.len() + 8);
    for line in message.split("\r\n") {
        if line.starts_with('.') {
            data.push('.');
        }
        data.push_str(line);
        data.push_str("\r\n");
    }
    data.push_str(".\r\n");
    stream
        .write_all(data.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let (code, _) = smtp_read(&mut stream).await?;
    if code != 250 {
        return Err(format!("message not accepted ({code})"));
    }
    let _ = smtp_command(&mut stream, "QUIT").await;
    Ok(())
}

async fn smtp_command(
    stream: &mut super::ssl::BoxedStream,
    command: &str,
) -> Result<(u16, Vec<String>), String> {
    stream
        .write_all(format!("{command}\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    smtp_read(stream).await
}

/// Reads one (possibly multi-line) reply: `NNN-text` lines continue it,
/// `NNN text` ends it. Returns the code and the text of every line. SMTP
/// is lock-step, so reading until the terminating line can never swallow
/// part of a later reply.
async fn smtp_read(stream: &mut super::ssl::BoxedStream) -> Result<(u16, Vec<String>), String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("relay read error: {e}"))?;
        if n == 0 {
            return Err("relay closed the connection".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Err("relay reply too long".into());
        }
        let text = String::from_utf8_lossy(&buf);
        let complete = text.ends_with("\r\n")
            && text
                .trim_end_matches("\r\n")
                .rsplit("\r\n")
                .next()
                .is_some_and(|last| last.len() >= 4 && last.as_bytes()[3] == b' ');
        if !complete {
            continue;
        }
        let lines: Vec<&str> = text.trim_end_matches("\r\n").split("\r\n").collect();
        let code = lines
            .last()
            .and_then(|l| l[..3].parse::<u16>().ok())
            .ok_or_else(|| format!("malformed relay reply: {text:?}"))?;
        return Ok((
            code,
            lines
                .iter()
                .map(|l| l.get(4..).unwrap_or("").to_string())
                .collect(),
        ));
    }
}

/// Standard base64 with padding - `AUTH PLAIN`'s one encoding need, small
/// enough not to be worth a dependency.
pub fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
