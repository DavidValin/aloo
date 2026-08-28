//! A labelled, bordered text field and the terminal cursor that sits in
//! it - the two pieces every text-entry popup in this app draws
//! identically.
//!
//! Both used to be defined per popup: `render_bordered_field` twice
//! (byte-identical), `place_text_cursor` three times (twice
//! byte-identical, once with an extra `offset`). One of those copies even
//! carried a comment justifying itself on the grounds that there was "no
//! common one already importing both" - true when it was written, and
//! untrue since `widgets` came to exist.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::client::tui::ui::focus_border_style;

/// One `label`ed box with `value` inside it, bordered in the focused or
/// unfocused style - the connect form's `host`/`port`/`nickname` inputs
/// and the direct-punch editor's fields alike (`docs/SPEC.md`: "styled
/// with a border around the box"). Returns the inner `Rect` the value was
/// drawn into, so the caller can hand it straight to
/// [`place_text_cursor`].
pub(crate) fn render_bordered_field(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
) -> Rect {
    let block = Block::default()
        .title(label)
        .borders(Borders::ALL)
        .border_style(focus_border_style(focused));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(value), inner);
    inner
}

/// Places the blinking terminal cursor at the end of the typed text in
/// `inner` - mirroring `ui::render_input_bar`'s own cursor logic. Without
/// it a focused text field only *looks* focused (its value reversed) but
/// never shows where typing actually lands.
///
/// Clamped to the box: a value longer than `inner` is wide leaves the
/// cursor on the last column rather than drawing it outside the border.
pub(crate) fn place_text_cursor(frame: &mut Frame, inner: Rect, value: &str) {
    let cursor_x = inner.x + (value.chars().count() as u16).min(inner.width.saturating_sub(1));
    frame.set_cursor_position((cursor_x, inner.y));
}
