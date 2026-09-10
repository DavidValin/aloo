//! One transfer as three lines - its label line, its progress bar, and a
//! blank - drawn the same way wherever a transfer is listed: the
//! `Ctrl+D` popup and the browser's Downloads tab (`docs/PROTOCOL.md`
//! §7.8).

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::client::shared_folders::format_size;
use crate::client::transfer_log::{TransferRecord, TransferStatus};

use super::progress_bar::{DEFAULT_BAR_CELLS, percent_of, progress_line};
use super::text::elide_start;

/// The colour a status is drawn in, and its label.
pub fn status_style(status: &TransferStatus) -> (Color, String) {
    let color = match status {
        TransferStatus::Asking | TransferStatus::Running => Color::Yellow,
        TransferStatus::Completed => Color::Green,
        TransferStatus::Cancelled => Color::DarkGray,
        TransferStatus::Failed(_) => Color::Red,
    };
    (color, status.label())
}

/// `<done>/<total> files`, and how many of those were already on disk
/// and refused rather than transferred - said, because a resumed row
/// counts up from zero again and would otherwise read as starting over.
pub fn files_summary(item: &TransferRecord) -> String {
    let counted = match item.files_total {
        Some(total) => format!("{}/{total} files", item.files_done),
        None => format!("{} files", item.files_done),
    };
    if item.files_skipped > 0 {
        format!("{counted}, {} already had", item.files_skipped)
    } else {
        counted
    }
}

/// The three lines for `item`: `lead` spans (a selection marker, and a
/// direction arrow where the list mixes directions), the label elided
/// from the start to `path_width` so the file name stays visible, who
/// it was with, the status, the file counts, then the bar.
pub fn transfer_lines(
    item: &TransferRecord,
    lead: Vec<Span<'static>>,
    path_width: usize,
    with: &str,
) -> Vec<Line<'static>> {
    let (color, status) = status_style(&item.status);
    let mut head = lead;
    head.push(Span::styled(
        format!("{} ", elide_start(&item.label(), path_width)),
        Style::default().add_modifier(Modifier::BOLD),
    ));
    head.push(Span::styled(with.to_string(), Style::default().fg(Color::Gray)));
    head.push(Span::raw("  "));
    head.push(Span::styled(status, Style::default().fg(color)));
    head.push(Span::styled(
        format!("  {}", files_summary(item)),
        Style::default().fg(Color::DarkGray),
    ));
    let suffix = match item.fraction() {
        Some(f) => format!("  {}%  {}", percent_of(f), format_size(item.bytes_done)),
        None => format!("  {}", format_size(item.bytes_done)),
    };
    let mut bar = progress_line(item.fraction().unwrap_or(0.0), DEFAULT_BAR_CELLS, color, &suffix).spans;
    bar.insert(0, Span::raw("  "));
    vec![Line::from(head), Line::from(bar), Line::from("")]
}
