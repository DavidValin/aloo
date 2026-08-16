//! Terminal lifecycle for the TUI: raw mode + alternate screen on the way
//! in, the exact inverse on the way out. Lives in the TUI tier so `main.rs`
//! needs no `crossterm`/`ratatui` imports of its own.

use std::io::Stdout;

use crossterm::event::{
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
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let keyboard_release_reporting =
        crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false);
    if keyboard_release_reporting {
        crossterm::execute!(
            stdout,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::REPORT_EVENT_TYPES)
        )?;
    }
    let backend = CrosstermBackend::new(stdout);
    Ok((Terminal::new(backend)?, keyboard_release_reporting))
}

pub fn restore(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<(), BoxError> {
    let _ = crossterm::execute!(terminal.backend_mut(), PopKeyboardEnhancementFlags);
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    disable_raw_mode()?;
    terminal.show_cursor()?;
    Ok(())
}
