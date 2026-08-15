//! CPU / Conn header indicator steps (US-018).

use cucumber::{then, when};
use ratatui::style::Color;

use aloo::netstats::ConnQuality;

use crate::support::{appears_before, find_text_start, ui_buffer, ui_rows};
use crate::world::AlooWorld;

#[when(expr = "CPU usage is sampled at {int} percent")]
async fn cpu_sampled(w: &mut AlooWorld, pct: i64) {
    w.ui_mut().set_cpu_usage(pct as f32);
}

#[when(expr = "the connection quality is classified as {word}")]
async fn conn_classified(w: &mut AlooWorld, quality: String) {
    let q = match quality.as_str() {
        "Bad" => ConnQuality::Bad,
        "Normal" => ConnQuality::Normal,
        "Good" => ConnQuality::Good,
        "Unknown" => ConnQuality::Unknown,
        other => panic!("unknown connection quality {other:?} - expected Bad/Normal/Good/Unknown"),
    };
    w.ui_mut().set_conn_quality(q);
}

fn color_from_name(name: &str) -> Color {
    match name {
        "white" => Color::White,
        "red" => Color::Red,
        "yellow" => Color::Yellow,
        "green" => Color::Green,
        other => panic!("unknown color {other:?}"),
    }
}

#[then(expr = "the header shows {string} in {word}")]
async fn header_shows_colored(w: &mut AlooWorld, text: String, color_name: String) {
    let expected = color_from_name(&color_name);
    let buffer = ui_buffer(w.ui_ref(), 100, 30);
    let (x, y) = find_text_start(&buffer, &text);
    assert_eq!(buffer[(x, y)].fg, expected, "{text:?} should render {color_name}");
}

#[then(expr = "the header shows {string} right before {string}")]
async fn header_shows_before(w: &mut AlooWorld, before: String, after: String) {
    let rows = ui_rows(w.ui_ref());
    assert!(appears_before(&rows, &before, &after), "expected {before:?} right before {after:?}: {rows:?}");
}
