//! Shared test scaffolding for `ui_test.rs`, `ui_channel_test.rs`, and
//! `ui_direct_message_test.rs` - included via `#[path] mod ui_common;` in
//! each rather than declared as its own `[[test]]` target, so it compiles
//! as part of every consumer instead of as a standalone (empty) test
//! binary.
#![allow(dead_code)]

use aloo::proto::{ChannelInfo, ChannelKind, KeyMode, UserId, UserInfo};
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

pub fn rendered_rows(state: &UiState) -> Vec<String> {
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| aloo::client::tui::ui::render(f, state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect()
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
