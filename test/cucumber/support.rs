//! Rendering helpers shared by the UI-facing step definitions.
//!
//! These mirror the helpers the pre-migration UI tests used
//! (`test/ui_common.rs`), including the wide-glyph caveat: 🔒 and 🚨 occupy
//! two terminal cells and ratatui reserves a padding cell after them, so
//! reconstructing a row cell-by-cell yields a space that was never in the
//! source string. Assertions therefore check relative ordering rather than
//! one contiguous substring spanning an emoji.

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;

use aloo::ui::ui::UiState;
use aloo::ui::ui_connect_popup::ConnectPopupState;

pub fn buffer_of<F>(width: u16, height: u16, draw: F) -> Buffer
where
    F: FnOnce(&mut ratatui::Frame),
{
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f)).unwrap();
    terminal.backend().buffer().clone()
}

pub fn rows_of(buffer: &Buffer) -> Vec<String> {
    (0..buffer.area.height)
        .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
        .collect()
}

pub fn ui_buffer(state: &UiState, width: u16, height: u16) -> Buffer {
    buffer_of(width, height, |f| aloo::ui::ui::render(f, state))
}

pub fn ui_rows(state: &UiState) -> Vec<String> {
    rows_of(&ui_buffer(state, 100, 30))
}

/// A wider frame than the default: the sidebar is a fixed 20% of the width,
/// so a tagged name needs room before it is clipped like any other long entry.
pub fn ui_rows_wide(state: &UiState) -> Vec<String> {
    rows_of(&ui_buffer(state, 160, 30))
}

pub fn popup_rows(state: &ConnectPopupState, width: u16, height: u16) -> Vec<String> {
    rows_of(&buffer_of(width, height, |f| aloo::ui::ui_connect_popup::render(f, state)))
}

/// Whether `before` appears strictly earlier than `after` on the same row.
pub fn appears_before(rows: &[String], before: &str, after: &str) -> bool {
    rows.iter().any(|r| match (r.find(before), r.find(after)) {
        (Some(b), Some(a)) => b < a,
        _ => false,
    })
}

pub fn row_containing<'a>(rows: &'a [String], needle: &str) -> &'a String {
    rows.iter()
        .find(|r| r.contains(needle))
        .unwrap_or_else(|| panic!("no rendered row contains {needle:?}: {rows:?}"))
}

/// Top-left cell of the first occurrence of `text`, scanned cell-by-cell
/// because a wide glyph elsewhere on the row makes byte offsets into a joined
/// `String` disagree with real buffer columns.
pub fn find_text_start(buffer: &Buffer, text: &str) -> (u16, u16) {
    let want: Vec<String> = text.chars().map(|c| c.to_string()).collect();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            let matches = want.iter().enumerate().all(|(i, ch)| {
                let xi = x + i as u16;
                xi < buffer.area.width && buffer[(xi, y)].symbol() == ch
            });
            if matches {
                return (x, y);
            }
        }
    }
    panic!("text {text:?} not found in the rendered buffer");
}
