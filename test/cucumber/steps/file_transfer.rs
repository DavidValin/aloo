//! `/file`: sending and receiving a file attachment, consent-gated and
//! streamed (US-019).

use cucumber::{given, then, when};

use aloo::client::file_transfer::MAX_FILENAME_CHARS;
use aloo::proto::UserId;
use aloo::client::tui::file_send::{FileConfirmChoice, FileSendState, FileSendTarget};
use aloo::client::tui::ui::{FileTransferStatus, MessageBody, Mode, PendingFileOffer, UiAction};
use aloo::client::file_browser::FileBrowserState;
use crossterm::event::{KeyCode, KeyModifiers};

use crate::steps::ui_common::{id_for, press_key};
use crate::support::ui_rows_wide;
use crate::world::AlooWorld;

/// Every offer in these scenarios uses this `stream_id` - only one transfer
/// is ever in flight at a time per scenario, so there's nothing to
/// disambiguate.
const STREAM_ID: u64 = 1;

fn write_temp_file(filename: &str, contents: &[u8]) -> std::path::PathBuf {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "aloo-cucumber-file-transfer-{}-{suffix}",
        std::process::id()
    ));
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
    w.ui_mut().file_send = Some(FileSendState {
        target,
        browser,
        confirm: Some(path),
        confirm_focus: FileConfirmChoice::Discard,
        error: None,
    });
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

#[given("I have selected a large file to send to the channel")]
async fn selected_large_file(w: &mut AlooWorld) {
    let path = write_temp_file("big.bin", &vec![0u8; 5 * 1024 * 1024]);
    open_confirm(w, FileSendTarget::Channel("general".into()), path);
}

#[given("I have selected a file with a 250-character filename to send to the channel")]
async fn selected_long_named_file(w: &mut AlooWorld) {
    let name = format!("{}.txt", "a".repeat(250));
    let path = write_temp_file(&name, b"data");
    open_confirm(w, FileSendTarget::Channel("general".into()), path);
}

#[then(
    expr = "sending {string} as a file to the channel is requested, addressed to {word} and {word}"
)]
async fn file_send_requested_channel_addressed(
    w: &mut AlooWorld,
    filename: String,
    a: String,
    b: String,
) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::SendFileChannel {
            channel,
            filename: f,
            recipients,
            ..
        } => {
            assert_eq!(channel, "general");
            assert_eq!(f, &filename);
            let ids: Vec<UserId> = recipients.iter().map(|(id, _, _)| *id).collect();
            assert_eq!(ids, vec![UserId(id_for(&a)), UserId(id_for(&b))]);
        }
        other => panic!("expected SendFileChannel, got {other:?}"),
    }
}

#[then(expr = "sending {string} as a file to the channel is requested")]
async fn file_send_requested_channel(w: &mut AlooWorld, filename: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::SendFileChannel {
            channel,
            filename: f,
            ..
        } => {
            assert_eq!(channel, "general");
            assert_eq!(f, &filename);
        }
        other => panic!("expected SendFileChannel, got {other:?}"),
    }
}

#[then(expr = "sending {string} as a file to {word} is requested")]
async fn file_send_requested_dm(w: &mut AlooWorld, filename: String, name: String) {
    let want = UserId(id_for(&name));
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::SendFileDirect {
            to, filename: f, ..
        } => {
            assert_eq!(*to, want);
            assert_eq!(f, &filename);
        }
        other => panic!("expected SendFileDirect, got {other:?}"),
    }
}

#[then("the file selection is discarded, returning to the browser")]
async fn file_discarded(w: &mut AlooWorld) {
    assert!(w.action_was_none);
    let fs = w
        .ui_ref()
        .file_send
        .as_ref()
        .expect("still in the /file flow, not bounced out of it");
    assert!(
        fs.confirm.is_none(),
        "Discard should return to the browser, not stay on the confirmation box"
    );
}

#[then("the offered filename is cropped to 230 characters")]
async fn filename_cropped(w: &mut AlooWorld) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::SendFileChannel { filename, .. } => {
            assert_eq!(filename.chars().count(), MAX_FILENAME_CHARS)
        }
        other => panic!("expected SendFileChannel, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Receiving: the Accept/Reject popup
// ---------------------------------------------------------------------

#[given(expr = "{word} offers me the file {string} of {int} bytes in the channel")]
#[when(expr = "{word} offers me the file {string} of {int} bytes in the channel")]
async fn peer_offers_file_channel(w: &mut AlooWorld, name: String, filename: String, size: u64) {
    let id = UserId(id_for(&name));
    let offer = PendingFileOffer {
        from: id,
        from_name: name,
        filename,
        size,
        stream_id: STREAM_ID,
        channel: Some("general".into()),
        otp_contact_name: None,
    };
    if w.ui_ref().is_trust_gated(id) {
        w.ui_mut().hold_file_offer(offer);
    } else {
        w.ui_mut().push_file_offer(offer);
    }
}

#[then(expr = "a file offer popup from {word} for {string} of {int} bytes is shown")]
async fn offer_popup_shown(w: &mut AlooWorld, name: String, filename: String, size: u64) {
    let offer = w
        .ui_ref()
        .file_offer_open()
        .expect("no file offer popup is open");
    assert_eq!(offer.from_name, name);
    assert_eq!(offer.filename, filename);
    assert_eq!(offer.size, size);
    let rows = ui_rows_wide(w.ui_ref());
    assert!(
        rows.iter()
            .any(|r| r.contains(&name) && r.contains(&filename)),
        "expected the offer text to render: {rows:?}"
    );
}

#[then(expr = "bob's file offer for {string} is held, not shown")]
async fn offer_held(w: &mut AlooWorld, filename: String) {
    let id = UserId(id_for("bob"));
    assert!(
        w.ui_ref().file_offer_open().is_none(),
        "a held offer must not show a popup yet"
    );
    assert!(w.ui_ref().is_trust_gated(id));
    let _ = filename;
}

/// Confirms Accept with the default focus (no toggle needed) - proves
/// Accept is focused by default the same way `accept_review` proves
/// `Reject`'s default for identity review, by observing the resulting
/// action rather than reading private focus state.
#[then(expr = "the file offer from {word} for {string} is accepted")]
async fn offer_accepted_by_default(w: &mut AlooWorld, name: String, filename: String) {
    let want = UserId(id_for(&name));
    match w.last_action {
        Some(UiAction::AcceptFileOffer { from, stream_id }) => {
            assert_eq!(from, want);
            assert_eq!(stream_id, STREAM_ID);
        }
        ref other => {
            panic!("expected AcceptFileOffer (Accept must be focused by default), got {other:?}")
        }
    }
    let _ = filename;
}

/// Presses Enter (Accept is focused by default) and applies the same
/// session-layer effect `session::accept_file_offer` would - creating the
/// in-progress log row - the same way `accept_review` (identity.rs)
/// simulates `session::handle_ui_action`'s side effect directly rather than
/// running a live network layer.
#[when("I accept the file offer")]
async fn accept_file_offer(w: &mut AlooWorld) {
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
    match w.last_action {
        Some(UiAction::AcceptFileOffer { from, stream_id }) => {
            let offer = w
                .ui_mut()
                .take_file_offer(from, stream_id)
                .expect("offer should still be queued");
            w.ui_mut().on_channel_file_offer_accepted(
                "general",
                from,
                offer.from_name,
                stream_id,
                offer.filename,
                offer.size,
            );
        }
        ref other => panic!("expected AcceptFileOffer, got {other:?}"),
    }
}

#[when(expr = "that transfer reaches {int} of {int} bytes")]
async fn transfer_progress(w: &mut AlooWorld, bytes: u64, total: u64) {
    let id = UserId(id_for("bob"));
    w.ui_mut().set_file_progress(id, STREAM_ID, bytes);
    let _ = total;
}

#[when("that transfer completes")]
async fn transfer_completes(w: &mut AlooWorld) {
    let id = UserId(id_for("bob"));
    w.ui_mut().set_file_completed(id, STREAM_ID);
}

#[then(expr = "the message log shows an in-progress file {string} from {word}")]
async fn log_shows_in_progress(w: &mut AlooWorld, filename: String, name: String) {
    let state = w.ui_ref();
    let entry = state.channels[0]
        .log
        .iter()
        .find(|e| e.from == UserId(id_for(&name)))
        .expect("no log entry");
    match &entry.body {
        MessageBody::File {
            filename: f,
            status,
            ..
        } => {
            assert_eq!(f, &filename);
            assert!(
                matches!(status, FileTransferStatus::InProgress { .. }),
                "expected InProgress, got {status:?}"
            );
        }
        other => panic!("expected a file message, got {other:?}"),
    }
}

#[then(expr = "the message log shows {string} at {int} percent")]
async fn log_shows_percent(w: &mut AlooWorld, filename: String, pct: u32) {
    let rows = ui_rows_wide(w.ui_ref());
    assert!(
        rows.iter()
            .any(|r| r.contains(&filename) && r.contains(&format!("{pct}%"))),
        "expected {filename} at {pct}%: {rows:?}"
    );
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
        MessageBody::File {
            filename: f,
            status,
            ..
        } => {
            assert_eq!(f, &filename);
            assert_eq!(*status, FileTransferStatus::Completed);
        }
        other => panic!("expected a file message, got {other:?}"),
    }
    let rows = ui_rows_wide(state);
    assert!(
        rows.iter().any(|r| r.contains('\u{1F4CE}')),
        "expected the paperclip icon to render: {rows:?}"
    );
}

// ---------------------------------------------------------------------
// Rejection
// ---------------------------------------------------------------------

/// Simulates the rest of the pipeline `session::handle_send_file`/
/// `handle_server_message`'s `FileRejected` arm would normally do: creating
/// the pending row (session, not `ui::file_send`, is what allocates the
/// `stream_id` and hence logs it - see `crate::channel::handle_send_file`'s
/// doc) and then flipping it to `Rejected`.
#[when("bob rejects my file offer")]
async fn bob_rejects(w: &mut AlooWorld) {
    let Some(UiAction::SendFileChannel {
        channel,
        filename,
        size,
        ..
    }) = w.last_action.clone()
    else {
        panic!(
            "expected a prior SendFileChannel action, got {:?}",
            w.last_action
        );
    };
    w.ui_mut()
        .log_own_file_offer_channel(&channel, "bob", STREAM_ID, filename, size, None);
    let me = w.ui_ref().own_id.unwrap();
    w.ui_mut().set_file_rejected(me, STREAM_ID);
}

#[then(expr = "my file {string} to bob is shown as rejected")]
async fn my_file_shown_rejected(w: &mut AlooWorld, filename: String) {
    let state = w.ui_ref();
    let entry = state.channels[0]
        .log
        .iter()
        .find(|e| e.outgoing)
        .expect("no outgoing log entry");
    match &entry.body {
        MessageBody::File {
            filename: f,
            status,
            ..
        } => {
            assert_eq!(f, &filename);
            assert_eq!(*status, FileTransferStatus::Rejected);
        }
        other => panic!("expected a file message, got {other:?}"),
    }
}
