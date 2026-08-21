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

use aloo::client::tui::channel::HEADER_ROW_HEIGHT;
use aloo::client::tui::ui::UiState;
use aloo::client::tui::ui_connect_popup::ConnectPopupState;

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
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect()
}

pub fn ui_buffer(state: &UiState, width: u16, height: u16) -> Buffer {
    buffer_of(width, height, |f| aloo::client::tui::ui::render(f, state))
}

/// The message pane's scrollbar as `(thumb_rows, track_rows)` y-ranges, or
/// `None` when no scrollbar was drawn. Found by locating the thumb glyph
/// (`█`, which nothing else in the connected UI draws) and walking the
/// contiguous run of thumb/track glyphs around it in that same column, so
/// the assertion doesn't have to hardcode the pane's geometry.
pub fn message_scrollbar(buffer: &Buffer) -> Option<(Vec<u16>, Vec<u16>)> {
    let (x, y0) = (0..buffer.area.width)
        .flat_map(|x| (0..buffer.area.height).map(move |y| (x, y)))
        .find(|&(x, y)| buffer[(x, y)].symbol() == "\u{2588}")?;
    let is_bar = |y: u16| matches!(buffer[(x, y)].symbol(), "\u{2588}" | "\u{2591}");
    let mut top = y0;
    while top > 0 && is_bar(top - 1) {
        top -= 1;
    }
    let mut bottom = y0;
    while bottom + 1 < buffer.area.height && is_bar(bottom + 1) {
        bottom += 1;
    }
    let track: Vec<u16> = (top..=bottom).collect();
    let thumb = track
        .iter()
        .copied()
        .filter(|&y| buffer[(x, y)].symbol() == "\u{2588}")
        .collect();
    Some((thumb, track))
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
    rows_of(&buffer_of(width, height, |f| {
        aloo::client::tui::ui_connect_popup::render(f, state)
    }))
}

/// Whether `before` appears strictly earlier than `after` on the same row.
pub fn appears_before(rows: &[String], before: &str, after: &str) -> bool {
    rows.iter().any(|r| match (r.find(before), r.find(after)) {
        (Some(b), Some(a)) => b < a,
        _ => false,
    })
}

/// The rendered row the header's text sits on: the header block is
/// `HEADER_ROW_HEIGHT` rows tall with one blank line above and below it
/// (`docs/SPEC.md` "Connected UI"), so nothing there is on row 0.
pub const HEADER_TEXT_ROW: usize = 1;

/// The first rendered row below the whole header block - where the
/// sidebar, the message log and every dropdown start.
pub const FIRST_ROW_BELOW_HEADER: usize = HEADER_ROW_HEIGHT as usize;

/// The header's text row, carrying both selectors and the status figures.
pub fn header_row(rows: &[String]) -> &String {
    &rows[HEADER_TEXT_ROW]
}

/// The first row *below the header block* containing `needle`: the header
/// names the selected DM (a speech balloon and the peer's nickname) as
/// well as the selected channel, so a sidebar assertion about the same
/// person would otherwise match the selector rather than the roster entry.
pub fn sidebar_row_containing<'a>(rows: &'a [String], needle: &str) -> &'a String {
    rows.iter()
        .skip(FIRST_ROW_BELOW_HEADER)
        .find(|r| r.contains(needle))
        .unwrap_or_else(|| panic!("no row below the header contains {needle:?}: {rows:?}"))
}

/// `find_text_start`, from row `min_y` down - the same reason
/// `sidebar_row_containing` exists, for the colour assertions.
pub fn find_text_start_below(buffer: &Buffer, text: &str, min_y: u16) -> (u16, u16) {
    let want: Vec<String> = text.chars().map(|c| c.to_string()).collect();
    for y in min_y..buffer.area.height {
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
    panic!("text {text:?} not found at or below row {min_y}");
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

/// One popup's own rectangle, found from its title rather than from
/// whatever the renderer decided its size should be: `(x, y, width,
/// height)`, borders included.
///
/// A popup's title sits one column past its top-left corner, and its box
/// is the only run of border glyphs that starts there - the view drawn
/// underneath has borders of its own on the same rows, which is exactly
/// why this walks the box rather than trimming whitespace. `title` need
/// only be the *start* of the title, for the popups whose titles carry
/// their own key hints and are clipped on a narrow frame.
pub fn popup_rect(buffer: &Buffer, title: &str) -> (u16, u16, u16, u16) {
    let (title_x, y) = find_text_start(buffer, title);
    let x = title_x.saturating_sub(1);
    let width = (x..buffer.area.width)
        .position(|xi| buffer[(xi, y)].symbol() == "\u{2510}")
        .map(|w| w as u16 + 1)
        .unwrap_or(buffer.area.width - x);
    let height = (y..buffer.area.height)
        .position(|yi| buffer[(x, yi)].symbol() == "\u{2514}")
        .map(|h| h as u16 + 1)
        .unwrap_or(buffer.area.height - y);
    (x, y, width, height)
}

/// The rows *inside* the popup titled `title` - its own content, with
/// neither its borders nor anything the view behind it drew outside them.
pub fn popup_body(buffer: &Buffer, title: &str) -> Vec<String> {
    let (x, y, width, height) = popup_rect(buffer, title);
    ((y + 1)..(y + height).saturating_sub(1))
        .map(|yi| {
            ((x + 1)..(x + width).saturating_sub(1))
                .map(|xi| buffer[(xi, yi)].symbol())
                .collect::<String>()
        })
        .collect()
}
