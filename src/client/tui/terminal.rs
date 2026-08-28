//! Terminal I/O for the TUI: raw mode + alternate screen on the way in,
//! the exact inverse on the way out, and the blocking input-reader thread
//! for the connected session. Lives in the TUI tier so `main.rs` needs no
//! `crossterm`/`ratatui` imports of its own.

use std::io::Stdout;

use crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture, Event,
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::BoxError;

/// Besides the terminal itself, returns whether this terminal actually
/// reports real key releases (Kitty keyboard protocol), queried directly
/// rather than just assumed from the `Push`/`PopKeyboardEnhancementFlags`
/// calls succeeding - a terminal can accept those escape sequences without
/// honoring them, and `UiState::tick_recording_timeout` needs a trustworthy
/// answer to know whether it's ever allowed to auto-stop a recording on
/// its own instead of waiting for a genuine release.
pub fn setup() -> Result<(Terminal<CrosstermBackend<Stdout>>, bool), BoxError> {
    // From here until `restore`, this process owns the screen: anything
    // written straight to it would land in the middle of a frame. Every
    // diagnostic is collected instead and replayed on the way out - see
    // `crate::log`.
    crate::log::silence();
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    // A terminal that honors this delivers a whole paste as one
    // `Event::Paste(String)` (newlines included) instead of a burst of
    // individual key events - what lets `session::SessionInput`'s paste
    // handling (`UiState::handle_paste`) submit a multi-line paste as one
    // message instead of it fragmenting on every embedded newline.
    crossterm::execute!(stdout, EnableBracketedPaste)?;
    // Lets the app see clicks/scroll as `Event::Mouse` instead of the
    // terminal handling them entirely on its own - most terminal
    // emulators still let a modifier key (commonly Shift) bypass this for
    // native text selection/copy, the same trade-off every other
    // mouse-aware TUI (vim's `mouse=a`, htop, ...) makes.
    crossterm::execute!(stdout, EnableMouseCapture)?;
    let keyboard_release_reporting =
        crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false);
    if keyboard_release_reporting {
        // `DISAMBIGUATE_ESCAPE_CODES` alongside the release reporting:
        // without it a terminal sends Ctrl+M as 0x0D, byte-identical to
        // Enter, so `Ctrl+M` (mute my own microphone on a call) could not
        // exist without breaking Enter. With it, the two arrive as
        // different key events. Everything else keeps arriving as the
        // same `KeyCode` crossterm already reported.
        crossterm::execute!(
            stdout,
            PushKeyboardEnhancementFlags(
                KeyboardEnhancementFlags::REPORT_EVENT_TYPES
                    | KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
            )
        )?;
    }
    let backend = CrosstermBackend::new(stdout);
    Ok((Terminal::new(backend)?, keyboard_release_reporting))
}

/// `setup`, wrapped as the `Surface` the rest of the client now takes
/// (`crate::client::tui::surface`). The ordinary, terminal-attached start
/// of the app - a daemon builds `Surface::Detached` instead and never
/// touches the real terminal at all.
pub fn setup_surface() -> Result<(super::surface::Surface, bool), BoxError> {
    let (terminal, keyboard_release_reporting) = setup()?;
    Ok((
        super::surface::Surface::Local(terminal),
        keyboard_release_reporting,
    ))
}

pub fn restore(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<(), BoxError> {
    let _ = crossterm::execute!(terminal.backend_mut(), PopKeyboardEnhancementFlags);
    let _ = crossterm::execute!(terminal.backend_mut(), DisableMouseCapture);
    let _ = crossterm::execute!(terminal.backend_mut(), DisableBracketedPaste);
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    disable_raw_mode()?;
    terminal.show_cursor()?;
    // The screen is the shell's again, so whatever had to stay quiet
    // while it was not can finally be read. Both calls come after the
    // terminal is genuinely handed back, never before.
    crate::log::unsilence();
    crate::log::drain();
    Ok(())
}

/// Undoes `setup_surface`. Only a `Local` surface has a real terminal to
/// give back - a `Detached`/`Attached` daemon never took one, and the
/// terminal an attached *viewer* is using belongs to that other process,
/// which restores its own on the way out.
pub fn restore_surface(surface: &mut super::surface::Surface) -> Result<(), BoxError> {
    if let super::surface::Surface::Local(terminal) = surface {
        restore(terminal)?;
    }
    Ok(())
}

/// The blocking terminal-input reader for the connected session:
/// `crossterm::event::read()` can't be awaited, so a dedicated OS thread
/// forwards every event onto a tokio channel that
/// `session::run_connected_session`'s select loop can consume. The thread
/// exits on its own once the receiver is dropped (send fails) or the
/// terminal goes away (read fails).
pub fn spawn_input_thread() -> tokio::sync::mpsc::UnboundedReceiver<Event> {
    let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    std::thread::spawn(move || {
        loop {
            match crossterm::event::read() {
                Ok(ev) => {
                    if input_tx.send(ev).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    input_rx
}

/// `spawn_input_thread`, wrapped as the `SessionInput` stream
/// `session::run_connected_session` now consumes - the terminal-attached
/// half of that enum. A daemon builds the same channel from its IPC
/// listener instead, and never reads this process's stdin at all.
pub fn spawn_session_input()
-> tokio::sync::mpsc::UnboundedReceiver<crate::client::session::SessionInput> {
    let mut events = spawn_input_thread();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            if tx
                .send(crate::client::session::SessionInput::Key(event))
                .is_err()
            {
                break;
            }
        }
    });
    rx
}
