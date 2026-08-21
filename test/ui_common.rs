//! Shared test scaffolding for `ui_test.rs`, `ui_channel_test.rs`, and
//! `ui_direct_message_test.rs` - included via `#[path] mod ui_common;` in
//! each rather than declared as its own `[[test]]` target, so it compiles
//! as part of every consumer instead of as a standalone (empty) test
//! binary.
#![allow(dead_code)]

use aloo::proto::{ChannelInfo, ChannelKind, KeyMode, UserId, UserInfo};
use aloo::client::tui::channel::HEADER_ROW_HEIGHT;
use aloo::client::tui::ui::{MessageBody, UiAction, UiState};
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;

pub fn user(id: u64, name: &str) -> UserInfo {
    UserInfo {
        id: UserId(id),
        name: name.to_string(),
        public_key_der: vec![id as u8; 4],
        key_mode: KeyMode::Password,
    }
}

pub fn pq_hybrid_user(id: u64, name: &str) -> UserInfo {
    UserInfo {
        id: UserId(id),
        name: name.to_string(),
        public_key_der: vec![id as u8; 4],
        key_mode: KeyMode::PqHybrid,
    }
}

pub fn password_user(id: u64, name: &str) -> UserInfo {
    UserInfo {
        id: UserId(id),
        name: name.to_string(),
        public_key_der: vec![id as u8; 4],
        key_mode: KeyMode::Password,
    }
}

pub fn plain_user(id: u64, name: &str) -> UserInfo {
    UserInfo {
        id: UserId(id),
        name: name.to_string(),
        public_key_der: vec![id as u8; 4],
        key_mode: KeyMode::None,
    }
}

/// The OTP contact name every OTP test in this suite uses, and the two key
/// files a real session would have recorded beside it
/// (`otp_cli::contact_key_paths`).
pub const TEST_OTP_CONTACT: &str = "abcd1234";

/// An `OtpKeyStatus` around `detail`, carrying the key paths for
/// `TEST_OTP_CONTACT` - what `client::otp::refresh_otp_key_status` builds
/// from a real `otp --show-contact` reply.
pub fn otp_status(detail: aloo::client::otp_cli::ContactDetail) -> aloo::client::otp_cli::OtpKeyStatus {
    aloo::client::otp_cli::OtpKeyStatus {
        detail,
        contact_name: TEST_OTP_CONTACT.to_string(),
        enc_key_path: std::path::PathBuf::from(format!(
            "/tmp/aloo-test/otp/.keychain/{TEST_OTP_CONTACT}_enc.key"
        )),
        dec_key_path: std::path::PathBuf::from(format!(
            "/tmp/aloo-test/otp/.keychain/{TEST_OTP_CONTACT}_dec.key"
        )),
    }
}

pub fn press(state: &mut UiState, code: KeyCode) -> Option<UiAction> {
    state.handle_key(code, KeyModifiers::NONE, KeyEventKind::Press)
}

pub fn ctrl(state: &mut UiState, code: KeyCode) -> Option<UiAction> {
    state.handle_key(code, KeyModifiers::CONTROL, KeyEventKind::Press)
}

pub fn type_str(state: &mut UiState, s: &str) {
    for c in s.chars() {
        press(state, KeyCode::Char(c));
    }
}

pub fn joined_general_with(members: Vec<UserInfo>) -> UiState {
    let mut state = UiState::new("me".into());
    state.set_own_id(UserId(1));
    state.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
    state.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    for m in members {
        // `seed_member`, not `on_user_joined`: this describes the channel's
        // starting roster, not a live join happening during the test - see
        // `seed_member`'s doc.
        state.seed_member("general", m);
    }
    state
}

/// Fills `general`'s log with `n` distinct incoming texts (`msg0`, `msg1`,
/// ...). A channel is just the cheapest way to get entries into a message
/// log - the scrolling behavior this feeds in `ui_test.rs` is
/// `crate::client::tui::ui`'s, shared by the private-room view.
pub fn push_n_channel_texts(state: &mut UiState, n: usize) {
    for i in 0..n {
        state.on_channel_message(
            "general",
            UserId(2),
            "bob".into(),
            MessageBody::Text(format!("msg{i}")),
        );
    }
}

/// A small, deterministic temp directory tree (one file, one subdirectory
/// with a nested file) for tests that need to drive the in-TUI file browser
/// (`file_browser::FileBrowserState`) without depending on whatever
/// happens to be in the process's real current directory - same pattern
/// `ui_connect_popup_test.rs::make_tree` already uses for the connect
/// popup's own browser tests. Each call gets a unique path (PID + a
/// nanosecond timestamp) so parallel test runs never collide.
pub fn make_temp_file_tree() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "aloo-ui-file-send-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let sub = root.join("subdir");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(root.join("file.txt"), b"hello file transfer").unwrap();
    std::fs::write(sub.join("nested.txt"), b"nested").unwrap();
    root
}

/// Puts `state` on a call we host, with the call modal already folded
/// away into its tab (`Esc`) - what most call tests want, since an open
/// modal deliberately absorbs every key (including anything typed into
/// the compose bar). Tests that are *about* the modal call `begin_call`
/// themselves instead.
pub fn on_call_minimized(state: &mut UiState, call_id: u64, channel: Option<String>) {
    let host = state.own_id.expect("own id must be set before a call starts");
    state.begin_call(call_id, channel, host);
    state
        .call
        .as_mut()
        .expect("begin_call just set it")
        .minimized = true;
}

/// The rendered row the header's text sits on: the header block is
/// `HEADER_ROW_HEIGHT` rows tall with one blank line above and below it
/// (`docs/SPEC.md` "Connected UI"), so nothing there is on row 0.
pub const HEADER_TEXT_ROW: usize = 1;

/// The first rendered row below the whole header block - where the
/// sidebar, the message log and every dropdown start.
pub const FIRST_ROW_BELOW_HEADER: usize = HEADER_ROW_HEIGHT as usize;

/// The header's text row, the one carrying both selectors and the status
/// figures.
pub fn header_row(state: &UiState) -> String {
    rendered_rows(state)[HEADER_TEXT_ROW].clone()
}

pub fn rendered_rows(state: &UiState) -> Vec<String> {
    rendered_rows_at(state, 100, 30)
}

/// The message pane's scrollbar as `(thumb_rows, track_rows)` y-ranges, or
/// `None` when no scrollbar was drawn. Found by locating the thumb glyph
/// (`█`, which nothing else in the connected UI draws) and walking the
/// contiguous run of thumb/track glyphs around it in that same column, so
/// callers don't have to hardcode the pane's geometry.
pub fn message_scrollbar(buffer: &ratatui::buffer::Buffer) -> Option<(Vec<u16>, Vec<u16>)> {
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

/// Whether `before` appears strictly earlier than `after` in the same row,
/// used instead of matching one contiguous substring spanning an emoji.
/// 🔒/🚨 are wide (2-cell) glyphs and ratatui's buffer reserves a padding
/// cell right after them; reconstructing text via `cell.symbol()` per
/// column then sees an extra space that was never in the source string.
/// That's an artifact of this cell-by-cell reconstruction, not a real
/// extra space on screen - `key_mode_label_matches_the_documented_tag_convention`
/// and `format_with_name_puts_per_message_tag_after_the_name_and_others_before`
/// (proto_test.rs) already pin the exact strings at the data level; these
/// render tests only need to confirm relative ordering.
pub fn appears_before(rows: &[String], before: &str, after: &str) -> bool {
    rows.iter().any(|r| match (r.find(before), r.find(after)) {
        (Some(b), Some(a)) => b < a,
        _ => false,
    })
}

/// The whole frame rendered at an explicit size, for the tests whose
/// subject *is* the geometry - `rendered_rows`' fixed 100x30 is the right
/// default everywhere else.
pub fn rendered_rows_at(state: &UiState, width: u16, height: u16) -> Vec<String> {
    rows_of(&buffer_at(state, width, height))
}

pub fn buffer_at(state: &UiState, width: u16, height: u16) -> ratatui::buffer::Buffer {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| aloo::client::tui::ui::render(f, state))
        .unwrap();
    terminal.backend().buffer().clone()
}

pub fn rows_of(buffer: &ratatui::buffer::Buffer) -> Vec<String> {
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect()
}

/// One popup's own rectangle, found from its title rather than from
/// whatever the renderer decided its size should be: `(x, y, width,
/// height)`, borders included.
///
/// A popup's title sits one column past its top-left corner, and its box
/// is the only run of border glyphs that starts there - the view drawn
/// underneath has borders of its own on the same rows, which is exactly
/// why this walks the box rather than trimming whitespace. Panics if
/// `title` is not on screen, so a test that meant to open a popup cannot
/// silently pass without one.
///
/// `title` need only be the *start* of the title, which is what a caller
/// wants for the several popups whose titles carry their own key hints
/// and are clipped on a narrow frame.
pub fn popup_rect(buffer: &ratatui::buffer::Buffer, title: &str) -> (u16, u16, u16, u16) {
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
pub fn popup_body(buffer: &ratatui::buffer::Buffer, title: &str) -> Vec<String> {
    let (x, y, width, height) = popup_rect(buffer, title);
    ((y + 1)..(y + height).saturating_sub(1))
        .map(|yi| {
            ((x + 1)..(x + width).saturating_sub(1))
                .map(|xi| buffer[(xi, yi)].symbol())
                .collect::<String>()
        })
        .collect()
}

/// A marker string nothing in the UI's own chrome contains, pushed into a
/// message log so a popup drawn over it can be checked for leaking it
/// through (`docs/SPEC.md` "Connected UI": a popup replaces what is behind
/// it rather than compositing over it).
pub const BEHIND_MARKER: &str = "ZZQQ-behind-marker-ZZQQ";

/// A channel view whose log is nothing but `BEHIND_MARKER`, so any row a
/// popup fails to clear shows it.
pub fn state_with_marker_behind() -> UiState {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    for _ in 0..40 {
        state.on_channel_message(
            "general",
            UserId(2),
            "bob".into(),
            MessageBody::Text(BEHIND_MARKER.repeat(6)),
        );
    }
    state
}

/// Locates the top-left buffer cell of the first occurrence of `text`,
/// scanning cell-by-cell (rather than `rows.find`) since a wide 2-cell
/// glyph elsewhere on the row can make byte offsets into a joined `String`
/// disagree with actual buffer `x` columns - see `appears_before`'s doc
/// comment above for the same caveat.
pub fn find_text_start(buffer: &ratatui::buffer::Buffer, text: &str) -> (u16, u16) {
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
