//! Async subprocess wrapper around the real `otp` command
//! (github.com/DavidValin/otp-toolkit) - the *only* place this app ever spawns it.
//! aloo contains no one-time-pad cryptography or keychain-format code of
//! its own; every operation here is a call into the real binary.
//!
//! `otp`'s own state lives in a `.keychain/` directory relative to the
//! process's current working directory (README: "The keychain location is
//! not configurable"), so every spawn here is pinned to one stable
//! `working_dir` (`~/.aloo/otp/`) holding every contact's keychain
//! together - never the app's own current directory.
//!
//! Verified directly against the installed binary (`otp v1.4.0`, newer than
//! the `otp --help` text originally read from source - it added `--status
//! --porcelain` and `--recover-last` beyond what the plan for this module
//! was first drafted against): `--status <contact> --porcelain` prints
//! stable `key=value` lines even on some non-zero exit codes (`4`
//! redelivery pending, `5` delivery confirmation outstanding, `6` key
//! material rolled back), so `status` below treats any exit code other than
//! `1` (error / contact not found) as "parse the porcelain output".

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Every subprocess call in this module is pinned to this one directory -
/// `otp`'s own `.keychain/` lives directly inside it, holding all of this
/// app's OTP contacts together (never the app's own CWD, and never one
/// directory per contact).
#[derive(Debug, Clone)]
pub struct OtpCliConfig {
    pub binary_path: PathBuf,
    pub working_dir: PathBuf,
}

impl OtpCliConfig {
    /// Resolution order for the binary: `ALOO_OTP_BIN` env var >
    /// `~/.aloo/settings`'s `otp_binary_path` > the literal `"otp"`, left
    /// for the OS to resolve against `PATH` at spawn time. Never fetched,
    /// downloaded, or built - see `binary_available` for the fail-closed
    /// detection path. Loads settings itself (rather than taking a
    /// `&Settings`) since the client connect path doesn't otherwise thread
    /// `Settings` down to session construction.
    pub fn resolve() -> Self {
        let settings =
            crate::settings::Settings::load_or_create(&crate::settings::default_path())
                .unwrap_or_else(|_| crate::settings::Settings::default());
        let binary_path = std::env::var_os("ALOO_OTP_BIN")
            .map(PathBuf::from)
            .or(settings.otp_binary_path.map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("otp"));
        let working_dir = crate::platform::aloo_dir().join("otp");
        let _ = std::fs::create_dir_all(&working_dir);
        Self {
            binary_path,
            working_dir,
        }
    }
}

/// Cheap up-front existence/exec check, used to fail closed with install
/// instructions before ever offering OTP in the UI - aloo never attempts to
/// fetch, clone, or build `otp` itself.
pub fn binary_available(cfg: &OtpCliConfig) -> bool {
    std::process::Command::new(&cfg.binary_path)
        .arg("-h")
        .current_dir(&cfg.working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// The outcome of one `--encrypt`/`--decrypt` call, mapped from the exit
/// code (README/`--help`: `0` success, `3` `KEYCHAIN_REDELIVERED`, anything
/// else an error).
#[derive(Debug)]
pub enum OtpCliOutcome {
    Ok(Vec<u8>),
    /// No new key was consumed; the bytes recovered belong to a crash from
    /// an earlier run, not this call's input. Caller must re-invoke - see
    /// `encrypt_retrying`/`decrypt_retrying`.
    Redelivered,
    Error(String),
}

async fn run(cfg: &OtpCliConfig, args: &[&str], stdin_data: &[u8]) -> io::Result<(i32, Vec<u8>, Vec<u8>)> {
    let mut child = Command::new(&cfg.binary_path)
        .args(args)
        .current_dir(&cfg.working_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("stdin was piped");
    let data = stdin_data.to_vec();
    let write = async move {
        let _ = stdin.write_all(&data).await;
        drop(stdin);
    };
    let (_, output) = tokio::join!(write, child.wait_with_output());
    let output = output?;
    Ok((
        output.status.code().unwrap_or(-1),
        output.stdout,
        output.stderr,
    ))
}

async fn encrypt_decrypt(
    cfg: &OtpCliConfig,
    contact: &str,
    data: &[u8],
    assume_delivered: bool,
    mode: &str,
) -> io::Result<OtpCliOutcome> {
    let mut args = vec!["-c", contact, mode];
    if assume_delivered {
        args.push("-y");
    }
    let (code, stdout, stderr) = run(cfg, &args, data).await?;
    Ok(match code {
        0 => OtpCliOutcome::Ok(stdout),
        3 => OtpCliOutcome::Redelivered,
        _ => OtpCliOutcome::Error(String::from_utf8_lossy(&stderr).into_owned()),
    })
}

pub async fn encrypt(
    cfg: &OtpCliConfig,
    contact: &str,
    plaintext: &[u8],
    assume_delivered: bool,
) -> io::Result<OtpCliOutcome> {
    encrypt_decrypt(cfg, contact, plaintext, assume_delivered, "--encrypt").await
}

pub async fn decrypt(
    cfg: &OtpCliConfig,
    contact: &str,
    ciphertext: &[u8],
    assume_delivered: bool,
) -> io::Result<OtpCliOutcome> {
    encrypt_decrypt(cfg, contact, ciphertext, assume_delivered, "--decrypt").await
}

/// A redelivered result means no new key was consumed and today's real
/// input was never processed - see `README.md`/`--help`: "re-run to send
/// it". Bounded so a repeatedly-crash-looping keychain can't hang the
/// caller forever.
const MAX_REDELIVER_RETRIES: u32 = 3;

pub async fn encrypt_retrying(
    cfg: &OtpCliConfig,
    contact: &str,
    plaintext: &[u8],
    assume_delivered: bool,
) -> io::Result<OtpCliOutcome> {
    for _ in 0..MAX_REDELIVER_RETRIES {
        match encrypt(cfg, contact, plaintext, assume_delivered).await? {
            OtpCliOutcome::Redelivered => continue,
            other => return Ok(other),
        }
    }
    Ok(OtpCliOutcome::Error(
        "otp: exceeded redelivery retries".to_string(),
    ))
}

pub async fn decrypt_retrying(
    cfg: &OtpCliConfig,
    contact: &str,
    ciphertext: &[u8],
    assume_delivered: bool,
) -> io::Result<OtpCliOutcome> {
    for _ in 0..MAX_REDELIVER_RETRIES {
        match decrypt(cfg, contact, ciphertext, assume_delivered).await? {
            OtpCliOutcome::Redelivered => continue,
            other => return Ok(other),
        }
    }
    Ok(OtpCliOutcome::Error(
        "otp: exceeded redelivery retries".to_string(),
    ))
}

fn path_to_arg(path: &Path) -> io::Result<&str> {
    path.to_str()
        .ok_or_else(|| io::Error::other("otp: non-UTF-8 path"))
}

/// The outcome of one file-to-file `--encrypt`/`--decrypt` call. Unlike
/// `OtpCliOutcome`, success carries nothing - the result is already sitting
/// in `dst` on disk, never buffered as a `Vec<u8>` in this process. This is
/// what keeps an OTP-wrapped file/voice transfer's memory use bounded the
/// same way the plain (non-OTP) transfer already is - `client::file_transfer`'s
/// worker threads only ever hold one small chunk at a time, and piping
/// `otp`'s own stdin/stdout directly to/from files preserves that instead
/// of reading a whole file into memory just to hand it to this module.
#[derive(Debug)]
pub enum FileCliOutcome {
    Ok,
    /// Same meaning as `OtpCliOutcome::Redelivered` - `dst` now holds a
    /// replayed earlier result, not this call's input; retry (see
    /// `encrypt_file_retrying`/`decrypt_file_retrying`), which re-creates
    /// (truncates) `dst` before trying again.
    Redelivered,
    Error(String),
}

async fn run_file_to_file(
    cfg: &OtpCliConfig,
    args: &[&str],
    src: &Path,
    dst: &Path,
) -> io::Result<(i32, Vec<u8>)> {
    let stdin_file = std::fs::File::open(src)?;
    let stdout_file = std::fs::File::create(dst)?;
    let child = Command::new(&cfg.binary_path)
        .args(args)
        .current_dir(&cfg.working_dir)
        .stdin(Stdio::from(stdin_file))
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::piped())
        .spawn()?;
    let output = child.wait_with_output().await?;
    Ok((output.status.code().unwrap_or(-1), output.stderr))
}

async fn encrypt_decrypt_file(
    cfg: &OtpCliConfig,
    contact: &str,
    src: &Path,
    dst: &Path,
    assume_delivered: bool,
    mode: &str,
) -> io::Result<FileCliOutcome> {
    let mut args = vec!["-c", contact, mode];
    if assume_delivered {
        args.push("-y");
    }
    let (code, stderr) = run_file_to_file(cfg, &args, src, dst).await?;
    Ok(match code {
        0 => FileCliOutcome::Ok,
        3 => FileCliOutcome::Redelivered,
        _ => FileCliOutcome::Error(String::from_utf8_lossy(&stderr).into_owned()),
    })
}

/// File-to-file counterpart of `encrypt`: `src`'s bytes go to `otp`'s stdin,
/// its stdout is written straight to `dst`, with no buffering of the file's
/// content in this process at any point.
pub async fn encrypt_file(
    cfg: &OtpCliConfig,
    contact: &str,
    src: &Path,
    dst: &Path,
    assume_delivered: bool,
) -> io::Result<FileCliOutcome> {
    encrypt_decrypt_file(cfg, contact, src, dst, assume_delivered, "--encrypt").await
}

pub async fn decrypt_file(
    cfg: &OtpCliConfig,
    contact: &str,
    src: &Path,
    dst: &Path,
    assume_delivered: bool,
) -> io::Result<FileCliOutcome> {
    encrypt_decrypt_file(cfg, contact, src, dst, assume_delivered, "--decrypt").await
}

pub async fn encrypt_file_retrying(
    cfg: &OtpCliConfig,
    contact: &str,
    src: &Path,
    dst: &Path,
    assume_delivered: bool,
) -> io::Result<FileCliOutcome> {
    for _ in 0..MAX_REDELIVER_RETRIES {
        match encrypt_file(cfg, contact, src, dst, assume_delivered).await? {
            FileCliOutcome::Redelivered => continue,
            other => return Ok(other),
        }
    }
    Ok(FileCliOutcome::Error(
        "otp: exceeded redelivery retries".to_string(),
    ))
}

pub async fn decrypt_file_retrying(
    cfg: &OtpCliConfig,
    contact: &str,
    src: &Path,
    dst: &Path,
    assume_delivered: bool,
) -> io::Result<FileCliOutcome> {
    for _ in 0..MAX_REDELIVER_RETRIES {
        match decrypt_file(cfg, contact, src, dst, assume_delivered).await? {
            FileCliOutcome::Redelivered => continue,
            other => return Ok(other),
        }
    }
    Ok(FileCliOutcome::Error(
        "otp: exceeded redelivery retries".to_string(),
    ))
}

/// `otp --new-key-pair <size_mb> <name_a> <name_b>`: reads `2 * size_mb`
/// megabytes of true randomness from stdin (README: two independent
/// chunks - one per generated party's role), writes both `<name_a>_keys/`
/// and `<name_b>_keys/` under `cfg.working_dir`.
pub async fn new_key_pair(
    cfg: &OtpCliConfig,
    size_mb: u32,
    name_a: &str,
    name_b: &str,
) -> io::Result<()> {
    let total_bytes = (size_mb as usize) * 1024 * 1024 * 2;
    let randomness = crate::crypto::random_bytes(total_bytes);
    let size_str = size_mb.to_string();
    let args = ["--new-key-pair", &size_str, name_a, name_b];
    let (code, _stdout, stderr) = run(cfg, &args, &randomness).await?;
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(String::from_utf8_lossy(&stderr).into_owned()))
    }
}

pub async fn add_contact(
    cfg: &OtpCliConfig,
    name: &str,
    enc_key_file: &Path,
    dec_key_file: &Path,
) -> io::Result<()> {
    let enc = path_to_arg(enc_key_file)?;
    let dec = path_to_arg(dec_key_file)?;
    let args = ["--add-contact", name, enc, dec];
    let (code, _stdout, stderr) = run(cfg, &args, &[]).await?;
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(String::from_utf8_lossy(&stderr).into_owned()))
    }
}

/// `otp --remove-contact <name>`: deletes a contact's keychain entry
/// outright, pad material and all. Used only to clear a genuinely stale,
/// unusable local entry (`client::otp`'s asymmetric-provisioning recovery,
/// triggered by the peer's own explicit "I don't have a matching key"
/// report) - never in response to anything not already authenticated over
/// the underlying `pq_hybrid` channel. The caller treats a failure here as
/// best-effort (logged, not fatal): even an entry this couldn't remove
/// will simply make the next `--add-contact` fail the same way it already
/// was, not corrupt anything.
pub async fn remove_contact(cfg: &OtpCliConfig, name: &str) -> io::Result<()> {
    let (code, _stdout, stderr) = run(cfg, &["--remove-contact", name], &[]).await?;
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(String::from_utf8_lossy(&stderr).into_owned()))
    }
}

/// `otp --has-contact <name>` (exit 0 exists, 1 doesn't) - the check that
/// lets aloo adopt a contact the user provisioned themselves out-of-band,
/// or a previous run's completed provisioning, without ever running the
/// PqHybrid-channel handshake.
pub async fn has_contact(cfg: &OtpCliConfig, name: &str) -> io::Result<bool> {
    let (code, _stdout, _stderr) = run(cfg, &["--has-contact", name], &[]).await?;
    Ok(code == 0)
}

/// One contact's live state, parsed from `otp --status <name> --porcelain`.
/// `enc_ack_outstanding`/`dec_ack_outstanding` are read directly from the
/// CLI's own bookkeeping rather than duplicated locally - see
/// `client::otp`'s send-path gating, which checks `enc_ack_outstanding`
/// before ever calling `encrypt` again for a contact.
#[derive(Debug, Clone, Default)]
pub struct ContactStatus {
    pub enc_sequence: u64,
    pub enc_key_remaining: u64,
    pub enc_meta_state: String,
    pub enc_redelivery_pending: bool,
    pub enc_ack_outstanding: bool,
    pub dec_sequence: u64,
    pub dec_key_remaining: u64,
    pub dec_meta_state: String,
    pub dec_redelivery_pending: bool,
    pub dec_ack_outstanding: bool,
}

fn parse_status_porcelain(bytes: &[u8]) -> ContactStatus {
    let text = String::from_utf8_lossy(bytes);
    let mut s = ContactStatus::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "enc_sequence" => s.enc_sequence = value.parse().unwrap_or(0),
            "enc_key_remaining" => s.enc_key_remaining = value.parse().unwrap_or(0),
            "enc_meta_state" => s.enc_meta_state = value.to_string(),
            "enc_redelivery_pending" => s.enc_redelivery_pending = value == "1",
            "enc_ack_outstanding" => s.enc_ack_outstanding = value == "1",
            "dec_sequence" => s.dec_sequence = value.parse().unwrap_or(0),
            "dec_key_remaining" => s.dec_key_remaining = value.parse().unwrap_or(0),
            "dec_meta_state" => s.dec_meta_state = value.to_string(),
            "dec_redelivery_pending" => s.dec_redelivery_pending = value == "1",
            "dec_ack_outstanding" => s.dec_ack_outstanding = value == "1",
            _ => {}
        }
    }
    s
}

/// `None` when the contact doesn't exist (exit `1`); every other exit code
/// (`0` clean, `4` redelivery pending, `5` ack outstanding, `6` rolled
/// back) still prints the full porcelain field set, which is what this
/// parses regardless of which of those it was.
pub async fn status(cfg: &OtpCliConfig, contact: &str) -> io::Result<Option<ContactStatus>> {
    let (code, stdout, _stderr) = run(cfg, &["--status", contact, "--porcelain"], &[]).await?;
    if code == 1 {
        return Ok(None);
    }
    Ok(Some(parse_status_porcelain(&stdout)))
}

/// One contact's pad-position detail, parsed from `otp --show-contact
/// <name>` - the only `otp` command that reports each direction's *offset*
/// into its pad (bytes already consumed), which `--status --porcelain`
/// does not expose. Drives the OTP session header's live `<Seq> <Offset>
/// <remaining>` figures (`client::tui::direct_message::render_otp_header`).
#[derive(Debug, Clone, Default)]
pub struct ContactDetail {
    pub enc_sequence: u64,
    pub enc_offset: u64,
    pub enc_key_remaining: u64,
    pub dec_sequence: u64,
    pub dec_offset: u64,
    pub dec_key_remaining: u64,
}

/// `--show-contact` has no `--porcelain` mode (verified directly against
/// the installed binary - passing the flag is silently ignored), so this
/// parses its human-readable `Label: value` lines instead. Its exit code is
/// always `0` even for a contact that doesn't exist (also verified
/// directly - the error lands on stderr with nothing on stdout), so a
/// missing `Contact:` line, not the exit code, is what this treats as "no
/// such contact". stdout is prefixed with a status line (`OK`) ahead of the
/// `Contact:` block, so this looks for that line anywhere rather than
/// requiring it first.
fn parse_show_contact(text: &str) -> Option<ContactDetail> {
    if !text.lines().any(|line| line.trim_start().starts_with("Contact:")) {
        return None;
    }
    let mut d = ContactDetail::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("EncryptionKeyOffset:") {
            d.enc_offset = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("EncryptedSequence:") {
            d.enc_sequence = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("EncryptionKey:") {
            d.enc_key_remaining = parse_bytes_in_parens(v).unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("DecryptionKeyOffset:") {
            d.dec_offset = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("DecryptedSequence:") {
            d.dec_sequence = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("DecryptionKey:") {
            d.dec_key_remaining = parse_bytes_in_parens(v).unwrap_or(0);
        }
    }
    Some(d)
}

/// Pulls the byte count out of `"******* (1048571 bytes)"`.
fn parse_bytes_in_parens(s: &str) -> Option<u64> {
    let inside = s.split('(').nth(1)?;
    inside.trim_end().strip_suffix("bytes)")?.trim().parse().ok()
}

/// `None` when the contact doesn't exist - see `parse_show_contact`'s doc
/// for why that's read from the output, not the exit code.
pub async fn show_contact(cfg: &OtpCliConfig, contact: &str) -> io::Result<Option<ContactDetail>> {
    let (_code, stdout, _stderr) = run(cfg, &["--show-contact", contact], &[]).await?;
    Ok(parse_show_contact(&String::from_utf8_lossy(&stdout)))
}

pub enum RecoverDirection {
    Sent,
    Received,
}

/// `otp --recover-last <name> --sent|--received`: re-streams the kept safety
/// copy of the last delivered payload without consuming any key - used for
/// a manual resend if aloo's own in-memory retry queue was lost (e.g. a
/// crash) but the peer never actually got the bytes. `None` on exit `2`
/// (nothing awaits confirmation) or any error.
pub async fn recover_last(
    cfg: &OtpCliConfig,
    contact: &str,
    direction: RecoverDirection,
) -> io::Result<Option<Vec<u8>>> {
    let flag = match direction {
        RecoverDirection::Sent => "--sent",
        RecoverDirection::Received => "--received",
    };
    let (code, stdout, _stderr) = run(cfg, &["--recover-last", contact, flag], &[]).await?;
    Ok(if code == 0 { Some(stdout) } else { None })
}

/// File-output counterpart of `recover_last`: `--recover-last` takes no
/// stdin of its own (nothing to feed it - it just re-streams what it
/// already kept), so its stdout is piped straight to `dst` rather than
/// buffered as a `Vec<u8>` here, the same bounded-memory reasoning as
/// `encrypt_file`/`decrypt_file` - a recovered file/voice send's ciphertext
/// can be arbitrarily large. `Some(())` on success (the recovered bytes are
/// now sitting in `dst`), `None` on exit `2` (nothing awaits confirmation)
/// or any error, same convention as `recover_last`.
pub async fn recover_last_file(
    cfg: &OtpCliConfig,
    contact: &str,
    direction: RecoverDirection,
    dst: &Path,
) -> io::Result<Option<()>> {
    let flag = match direction {
        RecoverDirection::Sent => "--sent",
        RecoverDirection::Received => "--received",
    };
    let stdout_file = std::fs::File::create(dst)?;
    let child = Command::new(&cfg.binary_path)
        .args(["--recover-last", contact, flag])
        .current_dir(&cfg.working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::piped())
        .spawn()?;
    let output = child.wait_with_output().await?;
    Ok(if output.status.code() == Some(0) {
        Some(())
    } else {
        None
    })
}
