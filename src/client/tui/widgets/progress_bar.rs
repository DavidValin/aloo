//! One filled/unfilled progress bar, drawn the same way wherever a long
//! job reports how far it has got: a pad being generated or streamed
//! (`render::render_otp_keygen_popup`) and a shared-folder download
//! (`shared_browser`). Described once here rather than re-derived per
//! call site, so the two never drift into looking like different things.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

/// How many cells wide the bar itself is - the pad popup's own width,
/// kept as the default so every bar in the app reads at one size.
pub const DEFAULT_BAR_CELLS: usize = 40;

/// The bar as a `Line`, for a caller that wants to put it in a row of
/// its own making (a list item, say) rather than hand it a whole `Rect`.
///
/// `fraction` is clamped to `0.0..=1.0`, so a caller that has counted
/// more bytes than it expected cannot overrun the bar. `color` is the
/// filled half's colour: the caller's, because what a full bar means
/// differs - a finished download is green, a cancelled one is not.
pub fn progress_line(fraction: f64, cells: usize, color: Color, suffix: &str) -> Line<'static> {
    let fraction = fraction.clamp(0.0, 1.0);
    let filled = ((fraction * cells as f64).round() as usize).min(cells);
    Line::from(vec![
        Span::styled("\u{2588}".repeat(filled), Style::default().fg(color)),
        Span::styled(
            "\u{2591}".repeat(cells - filled),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(suffix.to_string()),
    ])
}

/// `progress_line` drawn into `area` - the whole-row form, and what the
/// pad popup uses.
pub fn render_progress_bar(
    frame: &mut Frame,
    area: Rect,
    fraction: f64,
    cells: usize,
    color: Color,
    suffix: &str,
) {
    frame.render_widget(
        Paragraph::new(progress_line(fraction, cells, color, suffix)),
        area,
    );
}

/// `fraction` as a whole percentage, clamped the same way - the number
/// every caller puts next to its bar.
pub fn percent_of(fraction: f64) -> u16 {
    (fraction.clamp(0.0, 1.0) * 100.0).round() as u16
}
