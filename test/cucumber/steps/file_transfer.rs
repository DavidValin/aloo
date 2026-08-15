//! `/file`: sending and receiving a file attachment (US-019).

use cucumber::{given, then, when};

use aloo::file_transfer;
use aloo::proto::UserId;
use aloo::ui::file_send::{FileConfirmChoice, FileSendState, FileSendTarget};
use aloo::ui::ui::{MessageBody, Mode, UiAction};
use aloo::ui::ui_connect_popup::FileBrowserState;

use crate::steps::ui_common::id_for;
use crate::support::ui_rows_wide;
use crate::world::AlooWorld;

fn write_temp_file(filename: &str, contents: &[u8]) -> std::path::PathBuf {
    let suffix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("aloo-cucumber-file-transfer-{}-{suffix}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(filename);
    std::fs::write(&path, contents).unwrap();
    path
}

/// Jumps straight to the Send file/Discard confirmation box for `path`,
/// rather than replaying browser navigation keystrokes - the exact
/// keystroke sequence to get there is already pinned by
/// `test/ui_file_send_test.rs`; these scenarios are about what happens
/// once a file has been picked.
fn open_confirm(w: &mut AlooWorld, target: FileSendTarget, path: std::path::PathBuf) {
    let browser = FileBrowserState::open(path.parent().unwrap().to_path_buf()).unwrap();
    w.ui_mut().file_send =
        Some(FileSendState { target, browser, confirm: Some(path), confirm_focus: FileConfirmChoice::Discard, error: None });
    w.ui_mut().mode = Mode::FileSend;
}

#[given(expr = "I have selected the file {string} containing {string} to send to the channel")]
async fn selected_file_for_channel(w: &mut AlooWorld, filename: String, contents: String) {
    let path = write_temp_file(&filename, contents.as_bytes());
    open_confirm(w, FileSendTarget::Channel("general".into()), path);
}

#[given(expr = "I have selected the file {string} containing {string} to send to {word}")]
async fn selected_file_for_dm(w: &mut AlooWorld, filename: String, contents: String, name: String) {
    let path = write_temp_file(&filename, contents.as_bytes());
    open_confirm(w, FileSendTarget::Direct(UserId(id_for(&name))), path);
}

#[given("I have selected an oversized file to send to the channel")]
async fn selected_oversized_file(w: &mut AlooWorld) {
    let path = write_temp_file("big.bin", &vec![0u8; (file_transfer::MAX_FILE_BYTES + 1) as usize]);
    open_confirm(w, FileSendTarget::Channel("general".into()), path);
}

#[then(expr = "sending {string} as a file to the channel is requested, addressed to {word} and {word}")]
async fn file_send_requested_channel(w: &mut AlooWorld, filename: String, a: String, b: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::SendFileChannel { channel, filename: f, recipients, .. } => {
            assert_eq!(channel, "general");
            assert_eq!(f, &filename);
            let ids: Vec<UserId> = recipients.iter().map(|(id, _, _)| *id).collect();
            assert_eq!(ids, vec![UserId(id_for(&a)), UserId(id_for(&b))]);
        }
        other => panic!("expected SendFileChannel, got {other:?}"),
    }
}

#[then(expr = "sending {string} as a file to {word} is requested")]
async fn file_send_requested_dm(w: &mut AlooWorld, filename: String, name: String) {
    let want = UserId(id_for(&name));
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::SendFileDirect { to, filename: f, .. } => {
            assert_eq!(*to, want);
            assert_eq!(f, &filename);
        }
        other => panic!("expected SendFileDirect, got {other:?}"),
    }
}

#[then("the file selection is discarded, returning to the browser")]
async fn file_discarded(w: &mut AlooWorld) {
    assert!(w.action_was_none);
    let fs = w.ui_ref().file_send.as_ref().expect("still in the /file flow, not bounced out of it");
    assert!(fs.confirm.is_none(), "Discard should return to the browser, not stay on the confirmation box");
}

#[then("the file is rejected as too large")]
async fn file_rejected_too_large(w: &mut AlooWorld) {
    assert!(w.action_was_none, "an oversized file must not be sent");
    let fs = w.ui_ref().file_send.as_ref().expect("still in the /file flow");
    assert!(fs.error.is_some(), "an inline error should explain why nothing was sent");
}

#[given(expr = "{word} sends me the file {string} in the channel")]
#[when(expr = "{word} sends me the file {string} in the channel")]
async fn peer_sends_file_channel(w: &mut AlooWorld, name: String, filename: String) {
    let id = UserId(id_for(&name));
    w.ui_mut().on_channel_message("general", id, name, MessageBody::File { filename, data: vec![1, 2, 3] });
}

#[then(expr = "the message log shows a file {string} from {word}")]
async fn log_shows_file(w: &mut AlooWorld, filename: String, name: String) {
    let state = w.ui_ref();
    let entry = state.channels[0]
        .log
        .iter()
        .find(|e| e.from == UserId(id_for(&name)))
        .unwrap_or_else(|| panic!("no log entry from {name}"));
    match &entry.body {
        MessageBody::File { filename: f, .. } => assert_eq!(f, &filename),
        other => panic!("expected a file message, got {other:?}"),
    }
    let rows = ui_rows_wide(state);
    assert!(rows.iter().any(|r| r.contains('\u{1F4CE}')), "expected the paperclip icon to render: {rows:?}");
}

#[then(expr = "{word}'s file {string} is held, not shown")]
async fn file_held(w: &mut AlooWorld, name: String, filename: String) {
    let id = UserId(id_for(&name));
    let state = w.ui_ref();
    assert!(state.is_trust_gated(id));
    assert!(state.channels[0].log.is_empty(), "a held file must not appear in the visible log yet");
    let held = state.pending_messages.get(&id).expect("nothing held for this peer");
    assert!(
        held.iter().any(|h| matches!(&h.entry.body, MessageBody::File { filename: f, .. } if f == &filename)),
        "the held file should still be waiting for a trust decision"
    );
}
