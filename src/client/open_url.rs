//! Opening a link in the OS default browser (Ctrl+O on a message that
//! carries one, `client::tui::ui::UiAction::OpenUrl`).
//!
//! Shelled out to the platform's own "open this" command, the same
//! reasoning `client::global_notification` uses for its own subprocess
//! backends: it is a stable user-facing command rather than a linkable
//! library, and it keeps a platform-specific toolkit out of the build.

use std::process::{Command, Stdio};

/// Opens `url` in the default browser, fire-and-forget - a detached
/// thread, mirroring `global_notification::notify`'s own shape, since the
/// underlying command can itself spawn a long-lived helper (a browser) and
/// must never be waited on from the session's own select loop. Returns
/// whether the command was even launched (the browser's own success or
/// failure happens out of sight either way) - `handle_ui_action` uses this
/// to decide what the status notice should say.
pub fn open(url: String) -> bool {
    match build_command(&url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            true
        }
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
fn build_command(url: &str) -> Command {
    let mut command = Command::new("xdg-open");
    command.arg(url);
    command
}

#[cfg(target_os = "macos")]
fn build_command(url: &str) -> Command {
    let mut command = Command::new("open");
    command.arg(url);
    command
}

#[cfg(target_os = "windows")]
fn build_command(url: &str) -> Command {
    // `start`'s first argument after the switches is its own window
    // title, so an empty one is required - otherwise a URL containing `&`
    // or spaces gets misread as that title instead of the target.
    let mut command = Command::new("cmd");
    command.args(["/C", "start", "", url]);
    command
}
