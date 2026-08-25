//! Desktop notifications, for the events a daemon has no screen to show
//! (`docs/SPEC.md` "Running in background mode").
//!
//! Deliberately shaped like its sibling `crate::client::global_ptt`: a
//! capability check that can say "not here" without failing anything, a
//! pure predicate behind it that tests can drive with synthetic values,
//! and a fire-and-forget send. Both modules exist for the same reason -
//! reaching out of the terminal into whatever windowing system happens to
//! be running - and both must degrade to silence rather than to an error.
//!
//! ## What this cannot do
//!
//! It cannot place a notification, and it cannot reliably control how long
//! one stays up. No OS notification API exposes either to the sending
//! application: placement belongs to the notification daemon (GNOME and
//! KDE put them where the user configured; Windows uses the bottom-right
//! Action Center; macOS the top-right), and GNOME ignores expiry hints
//! outright. `DEFAULT_TIMEOUT` is therefore a *request*, honoured where
//! the platform honours it. An artifact that genuinely controlled both
//! would have to be a borderless always-on-top window of our own, which
//! means a GUI toolkit in a terminal application.
//!
//! ## Backends
//!
//! Each is a subprocess rather than a linked library, for the same reason
//! `client::otp_cli` shells out: it keeps a large, platform-specific
//! dependency out of the build, and the thing being invoked is a stable
//! user-facing command rather than an internal API.

use std::process::{Command, Stdio};
use std::time::Duration;

/// How long a notification asks to stay up. Honoured on desktops that
/// honour expiry hints at all - see the module doc.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(8);

/// One notification to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub summary: String,
    pub body: String,
    pub timeout: Duration,
}

impl Notification {
    pub fn new(summary: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            body: body.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// Whether this machine has a windowing system that could show a
/// notification at all.
///
/// A daemon started from a text console, or over ssh, has none - and
/// spawning `notify-send` there would fail once per event, filling the
/// daemon log with noise for something that was never going to work.
pub fn is_available() -> bool {
    if cfg!(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )) {
        // Same X11/Wayland-over-D-Bus story as Linux on every one of these
        // - none of them has a window server the way macOS/Windows do, so
        // the same "is a real display actually up" check applies.
        has_display(
            std::env::var_os("DISPLAY").is_some(),
            std::env::var_os("WAYLAND_DISPLAY").is_some(),
        )
    } else {
        // macOS and Windows always have a window server for a logged-in
        // user's session, and a daemon that is running at all is running
        // inside one.
        true
    }
}

/// The pure decision behind `is_available` on Linux, split out so it is
/// testable against synthetic values without mutating the real process
/// environment (unsafe under parallel tests) - exactly the split
/// `global_ptt::is_wayland_session` uses, for the same reason.
///
/// Either display protocol will do. Unlike the global hotkey, which
/// genuinely needs X11, notifications go over D-Bus and work identically
/// under Wayland.
pub fn has_display(x11: bool, wayland: bool) -> bool {
    x11 || wayland
}

/// Shows `notification`, if this machine can show one at all.
///
/// Fire-and-forget by design: it returns immediately, and a failure is
/// silent. This is called from the session's `select!` loop, where a
/// notification daemon that is wedged (a real and not rare state) must not
/// be able to stall voice, and where "the toast did not appear" is never
/// worth interrupting a conversation over.
pub fn notify(notification: Notification) {
    if !is_available() {
        return;
    }
    // A detached thread rather than a blocking spawn: `Command::spawn`
    // itself can block on a busy system, and this runs on the async
    // runtime's thread.
    std::thread::spawn(move || {
        let _ = show(&notification);
    });
}

/// Runs the platform's notification command. Separated from `notify` so
/// the spawning policy and the platform dispatch stay independently
/// readable.
fn show(n: &Notification) -> std::io::Result<()> {
    let mut command = build_command(n);
    // The child is fully detached: a notification tool that never exits
    // must not become a zombie the daemon accumulates one of per event.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    // Reaped here rather than left for the OS: this is already a
    // throwaway thread, so waiting costs nothing and keeps the process
    // table clean over a daemon's uptime of weeks.
    let _ = child.wait();
    Ok(())
}

/// `notify-send` is part of libnotify, a freedesktop.org desktop
/// component rather than a Linux-kernel one - any of these BSDs running
/// the same D-Bus/X11/Wayland desktop stacks Linux does ships it the same
/// way, and none has a notification command of its own the way macOS and
/// Windows do.
#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn build_command(n: &Notification) -> Command {
    // `--` guards against a summary or body that begins with a dash being
    // read as a flag.
    let mut command = Command::new("notify-send");
    command
        .arg("--app-name=aloo")
        .arg(format!("--expire-time={}", n.timeout.as_millis()))
        .arg("--")
        .arg(&n.summary)
        .arg(&n.body);
    command
}

#[cfg(target_os = "macos")]
fn build_command(n: &Notification) -> Command {
    let mut command = Command::new("osascript");
    command.arg("-e").arg(format!(
        "display notification {} with title \"aloo\" subtitle {}",
        applescript_string(&n.body),
        applescript_string(&n.summary),
    ));
    command
}

/// Quotes a value for embedding in an AppleScript literal.
///
/// `osascript -e` takes a *program*, not arguments, so an unescaped quote
/// or backslash in a nickname would end the string early and turn the rest
/// into script. Nicknames come from a remote peer, which makes this an
/// injection boundary rather than a formatting nicety.
#[cfg(target_os = "macos")]
fn applescript_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(target_os = "windows")]
fn build_command(n: &Notification) -> Command {
    let mut command = Command::new("powershell");
    command
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(windows_toast_script(&n.summary, &n.body));
    command
}

/// Builds the PowerShell that raises a toast.
///
/// Same injection boundary as the macOS branch - the summary carries a
/// remote-supplied nickname, and this is a script, not an argument list -
/// so single quotes in the values are doubled, which is PowerShell's own
/// escape inside a single-quoted string.
#[cfg(target_os = "windows")]
fn windows_toast_script(summary: &str, body: &str) -> String {
    let summary = summary.replace('\'', "''");
    let body = body.replace('\'', "''");
    format!(
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, \
         ContentType = WindowsRuntime] > $null; \
         $t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(\
         [Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
         $n = $t.GetElementsByTagName('text'); \
         $n.Item(0).AppendChild($t.CreateTextNode('{summary}')) > $null; \
         $n.Item(1).AppendChild($t.CreateTextNode('{body}')) > $null; \
         [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('aloo')\
         .Show([Windows.UI.Notifications.ToastNotification]::new($t))"
    )
}
