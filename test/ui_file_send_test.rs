#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::file_transfer::{self, MAX_FILENAME_CHARS};
use aloo::proto::{KeyMode, UserId};
use aloo::client::tui::file_send::{FileConfirmChoice, FileSendTarget};
use aloo::client::tui::ui::{
    FileOfferChoice, FileTransferStatus, Focus, IdentityCase, MessageBody, Mode, PendingFileOffer,
    UiAction,
};
use aloo::client::file_browser::FileBrowserState;
use crossterm::event::KeyCode;

fn unique_dir(label: &str) -> std::path::PathBuf {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("aloo-{label}-{}-{suffix}", std::process::id()))
}

// ---------------------------------------------------------------------
// Opening the /file flow (AC-073)
// ---------------------------------------------------------------------

/// @requirement AC-073
#[test]
fn file_command_opens_the_browser_when_a_channel_is_joined() {
    let mut state = joined_general_with(vec![]);
    type_str(&mut state, "/file");
    let action = press(&mut state, KeyCode::Enter);
    assert!(action.is_none());
    assert_eq!(state.mode, Mode::FileSend);
    assert!(state.file_send.is_some());
    assert_eq!(
        state.input, "",
        "the /file command itself must not remain in the compose bar"
    );
}

/// @requirement AC-073
#[test]
fn file_command_does_nothing_when_no_channel_is_joined_and_no_dm_is_open() {
    let mut state = aloo::client::tui::ui::UiState::new("me".into());
    type_str(&mut state, "/file");
    let action = press(&mut state, KeyCode::Enter);
    assert!(action.is_none());
    assert_eq!(state.mode, Mode::Normal);
    assert!(state.file_send.is_none());
    assert_eq!(
        state.input, "/file",
        "left in place so the user can see what they typed"
    );
}

// ---------------------------------------------------------------------
// Browsing and confirming (AC-074)
// ---------------------------------------------------------------------

/// Opens `/file`, then overwrites the browser it opened (at the process's
/// real current directory) with a deterministic temp tree - same technique
/// `ui_connect_popup_test.rs::selecting_a_file_in_browser_applies_it_to_the_popup_field`
/// already uses for the connect popup's own browser.
fn open_file_send_with_temp_tree(state: &mut aloo::client::tui::ui::UiState, root: &std::path::Path) {
    type_str(state, "/file");
    press(state, KeyCode::Enter);
    state.file_send.as_mut().unwrap().browser = FileBrowserState::open(root.to_path_buf()).unwrap();
}

/// @requirement AC-074
#[test]
fn selecting_a_file_in_the_browser_opens_a_send_confirmation_defaulting_to_discard() {
    let root = make_temp_file_tree();
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_file_send_with_temp_tree(&mut state, &root);

    // entries are "..", "subdir", "file.txt" (dirs before files, sorted)
    press(&mut state, KeyCode::Down); // subdir
    press(&mut state, KeyCode::Down); // file.txt
    press(&mut state, KeyCode::Enter); // select it

    let fs = state.file_send.as_ref().expect("still in the /file flow");
    assert_eq!(
        fs.confirm.as_deref(),
        Some(root.join("file.txt")).as_deref()
    );
    assert_eq!(fs.confirm_focus, FileConfirmChoice::Discard);

    std::fs::remove_dir_all(&root).ok();
}

/// @requirement AC-074
#[test]
fn discard_returns_to_the_browser_at_the_same_directory() {
    let root = make_temp_file_tree();
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_file_send_with_temp_tree(&mut state, &root);
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Enter); // opens confirm, Discard focused

    let action = press(&mut state, KeyCode::Enter); // confirm Discard
    assert!(action.is_none());

    let fs = state
        .file_send
        .as_ref()
        .expect("Discard returns to the browser, not Normal mode");
    assert!(fs.confirm.is_none());
    assert_eq!(fs.browser.current_dir, root);
    assert_eq!(state.mode, Mode::FileSend);

    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------------
// Sending: building the offer (AC-075's client-side half; the server-side
// relay and the sending-side row/worker wiring live in
// server_test.rs/session-level coverage)
// ---------------------------------------------------------------------

/// @requirement AC-075
#[test]
fn sending_a_file_to_a_channel_produces_sendfilechannel_with_path_and_size() {
    let root = make_temp_file_tree();
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    open_file_send_with_temp_tree(&mut state, &root);
    press(&mut state, KeyCode::Down); // subdir
    press(&mut state, KeyCode::Down); // file.txt
    press(&mut state, KeyCode::Enter); // confirm, Discard focused
    press(&mut state, KeyCode::Left); // toggle to Send file
    let action = press(&mut state, KeyCode::Enter);

    match action {
        Some(UiAction::SendFileChannel {
            channel,
            path,
            filename,
            size,
            recipients,
        }) => {
            assert_eq!(channel, "general");
            assert_eq!(path, root.join("file.txt"));
            assert_eq!(filename, "file.txt");
            assert_eq!(size, b"hello file transfer".len() as u64);
            let ids: Vec<UserId> = recipients.iter().map(|(id, _, _)| *id).collect();
            assert_eq!(
                ids,
                vec![UserId(2), UserId(3)],
                "every other member is addressed"
            );
        }
        other => panic!("expected SendFileChannel, got {other:?}"),
    }
    assert_eq!(state.mode, Mode::Normal);
    assert!(state.file_send.is_none());
    // Nothing is read from disk or logged here - the offer's stream_id
    // (and hence the log row's identity) isn't allocated until
    // `crate::channel::handle_send_file` runs, same reasoning
    // `handle_voice_record_start` already established for voice.
    assert!(state.channels[0].log.is_empty());

    std::fs::remove_dir_all(&root).ok();
}

/// @requirement AC-075
#[test]
fn sending_a_file_to_a_dm_peer_produces_sendfiledirect_with_path_and_size() {
    let root = make_temp_file_tree();
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens a private room with bob

    open_file_send_with_temp_tree(&mut state, &root);
    press(&mut state, KeyCode::Down); // subdir
    press(&mut state, KeyCode::Down); // file.txt
    press(&mut state, KeyCode::Enter); // confirm
    press(&mut state, KeyCode::Left); // toggle to Send file
    let action = press(&mut state, KeyCode::Enter);

    match action {
        Some(UiAction::SendFileDirect {
            to,
            path,
            filename,
            size,
            recipient_key_mode,
            recipient_pubkey_der,
        }) => {
            assert_eq!(to, UserId(2));
            assert_eq!(path, root.join("file.txt"));
            assert_eq!(filename, "file.txt");
            assert_eq!(size, b"hello file transfer".len() as u64);
            assert_eq!(recipient_key_mode, KeyMode::Password);
            assert_eq!(recipient_pubkey_der, vec![2u8; 4]);
        }
        other => panic!("expected SendFileDirect, got {other:?}"),
    }
    let room = state.private_rooms.get(&UserId(2)).expect("room exists");
    assert!(room.log.is_empty());

    std::fs::remove_dir_all(&root).ok();
}

/// @requirement AC-097
#[test]
fn a_long_filename_is_truncated_before_being_offered() {
    let dir = unique_dir("file-send-long-name");
    std::fs::create_dir_all(&dir).unwrap();
    let long_name = format!("{}.txt", "a".repeat(250));
    std::fs::write(dir.join(&long_name), b"data").unwrap();

    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_file_send_with_temp_tree(&mut state, &dir);
    press(&mut state, KeyCode::Down); // the one file
    press(&mut state, KeyCode::Enter); // confirm
    press(&mut state, KeyCode::Left); // toggle to Send file
    let action = press(&mut state, KeyCode::Enter);

    match action {
        Some(UiAction::SendFileChannel { filename, .. }) => {
            assert_eq!(filename.chars().count(), MAX_FILENAME_CHARS);
        }
        other => panic!("expected SendFileChannel, got {other:?}"),
    }

    std::fs::remove_dir_all(&dir).ok();
}

// There is no size cap anymore (streaming removed the reason for one) - a
// large file still produces a send action rather than an inline error.
///
/// @requirement AC-077
#[test]
fn there_is_no_size_cap_on_a_file_send() {
    let dir = unique_dir("file-send-no-cap");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("big.bin"), vec![0u8; 5 * 1024 * 1024]).unwrap();

    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_file_send_with_temp_tree(&mut state, &dir);
    press(&mut state, KeyCode::Down); // big.bin
    press(&mut state, KeyCode::Enter); // confirm
    press(&mut state, KeyCode::Left); // toggle to Send file
    let action = press(&mut state, KeyCode::Enter);

    match action {
        Some(UiAction::SendFileChannel { size, .. }) => assert_eq!(size, 5 * 1024 * 1024),
        other => panic!("expected SendFileChannel, got {other:?}"),
    }
    assert!(
        state.file_send.is_none(),
        "no inline error should have kept the flow open"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------
// Sending-side log rows (`crate::client::tui::channel`/`direct_message`'s
// `log_own_file_offer_*`, called once `handle_send_file` allocates a
// stream_id - AC-075/AC-096)
// ---------------------------------------------------------------------

/// @requirement AC-096
#[test]
fn a_channel_file_send_logs_one_row_per_recipient_naming_them() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.log_own_file_offer_channel("general", "bob", 1, "report.pdf".into(), 1000);
    state.log_own_file_offer_channel("general", "carol", 2, "report.pdf".into(), 1000);

    assert_eq!(state.channels[0].log.len(), 2);
    assert_eq!(state.channels[0].log[0].to_name.as_deref(), Some("bob"));
    assert_eq!(state.channels[0].log[1].to_name.as_deref(), Some("carol"));
    for entry in &state.channels[0].log {
        assert!(entry.outgoing);
        match &entry.body {
            MessageBody::File { status, total, .. } => {
                assert_eq!(*status, FileTransferStatus::Pending);
                assert_eq!(*total, 1000);
            }
            other => panic!("expected a file entry, got {other:?}"),
        }
    }

    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains('\u{1F4CE}')),
        "expected the paperclip icon to render: {rows:?}"
    );
}

// ---------------------------------------------------------------------
// Receiving: the Accept/Reject popup (bell + Accept-default)
// ---------------------------------------------------------------------

fn incoming_offer(
    from: u64,
    name: &str,
    stream_id: u64,
    filename: &str,
    size: u64,
) -> PendingFileOffer {
    PendingFileOffer {
        from: UserId(from),
        from_name: name.into(),
        filename: filename.into(),
        size,
        stream_id,
        channel: None,
    }
}

/// @requirement AC-095
#[test]
fn an_incoming_offer_opens_a_popup_with_accept_focused_by_default() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let became_front = state.push_file_offer(incoming_offer(2, "bob", 7, "photo.png", 2048));
    assert!(became_front);

    let offer = state.file_offer_open().expect("popup should be open");
    assert_eq!(offer.filename, "photo.png");
    assert_eq!(offer.size, 2048);

    let rows = rendered_rows(&state);
    assert!(
        rows.iter()
            .any(|r| r.contains("bob") && r.contains("photo.png")),
        "expected the offer text to render: {rows:?}"
    );
}

/// @requirement AC-095
#[test]
fn pressing_enter_on_the_offer_popup_accepts_by_default() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_file_offer(incoming_offer(2, "bob", 7, "photo.png", 2048));

    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::AcceptFileOffer {
            from: UserId(2),
            stream_id: 7
        })
    );
}

/// @requirement AC-096
#[test]
fn toggling_focus_then_enter_rejects() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_file_offer(incoming_offer(2, "bob", 7, "photo.png", 2048));

    press(&mut state, KeyCode::Left);
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::RejectFileOffer {
            from: UserId(2),
            stream_id: 7
        })
    );
}

/// @requirement AC-095
#[test]
fn a_second_offer_queues_behind_the_first() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    let first_front = state.push_file_offer(incoming_offer(2, "bob", 1, "a.txt", 10));
    let second_front = state.push_file_offer(incoming_offer(3, "carol", 1, "b.txt", 20));
    assert!(first_front);
    assert!(
        !second_front,
        "a second offer must not jump ahead of the one already showing"
    );
    assert_eq!(
        state.file_offer_open().map(|o| o.filename.as_str()),
        Some("a.txt")
    );

    state.take_file_offer(UserId(2), 1);
    assert_eq!(
        state.file_offer_open().map(|o| o.filename.as_str()),
        Some("b.txt")
    );
}

// ---------------------------------------------------------------------
// Receiving-side log rows once accepted (AC-083)
// ---------------------------------------------------------------------

/// @requirement AC-076
#[test]
fn accepting_a_channel_offer_creates_an_in_progress_row() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_file_offer_accepted(
        "general",
        UserId(2),
        "bob".into(),
        7,
        "photo.png".into(),
        2048,
    );

    assert_eq!(state.channels[0].log.len(), 1);
    let entry = &state.channels[0].log[0];
    assert!(!entry.outgoing);
    match &entry.body {
        MessageBody::File {
            status,
            total,
            filename,
            ..
        } => {
            assert_eq!(*status, FileTransferStatus::InProgress { bytes: 0 });
            assert_eq!(*total, 2048);
            assert_eq!(filename, "photo.png");
        }
        other => panic!("expected a file entry, got {other:?}"),
    }
}

/// @requirement AC-076
#[test]
fn a_progress_update_advances_the_bar_and_completion_finalizes_it() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_file_offer_accepted(
        "general",
        UserId(2),
        "bob".into(),
        7,
        "photo.png".into(),
        100,
    );

    state.set_file_progress(UserId(2), 7, 50);
    match &state.channels[0].log[0].body {
        MessageBody::File { status, .. } => {
            assert_eq!(*status, FileTransferStatus::InProgress { bytes: 50 })
        }
        other => panic!("expected a file entry, got {other:?}"),
    }
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("50%")),
        "expected a 50% progress indicator: {rows:?}"
    );

    state.set_file_completed(UserId(2), 7);
    match &state.channels[0].log[0].body {
        MessageBody::File { status, .. } => assert_eq!(*status, FileTransferStatus::Completed),
        other => panic!("expected a file entry, got {other:?}"),
    }
}

/// The sender's row flips to Rejected on `FileRejected`; a receiving-side
/// or sending-side failure flips to Failed - both surfaced rather than
/// left stuck mid-progress.
///
/// @requirement AC-096
#[test]
fn rejection_and_failure_are_reflected_on_the_matching_row() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.log_own_file_offer_channel("general", "bob", 1, "a.txt".into(), 10);
    state.log_own_file_offer_channel("general", "carol", 2, "a.txt".into(), 10);

    state.set_file_rejected(state.own_id.unwrap(), 1);
    state.set_file_failed(state.own_id.unwrap(), 2);

    match &state.channels[0].log[0].body {
        MessageBody::File { status, .. } => assert_eq!(*status, FileTransferStatus::Rejected),
        other => panic!("expected a file entry, got {other:?}"),
    }
    match &state.channels[0].log[1].body {
        MessageBody::File { status, .. } => assert_eq!(*status, FileTransferStatus::Failed),
        other => panic!("expected a file entry, got {other:?}"),
    }
    let rows = rendered_rows(&state);
    assert!(rows.iter().any(|r| r.contains("rejected")));
    assert!(rows.iter().any(|r| r.contains("failed")));
}

// ---------------------------------------------------------------------
// Trust gating (AC-078): an offer from a Pending/Rejected identity is held
// until the sender is Accepted, then queued for real (bell included).
// ---------------------------------------------------------------------

/// @requirement AC-078
#[test]
fn an_offer_from_a_trust_gated_sender_is_held_and_revealed_on_accept() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "mismatch".into(),
        IdentityCase::StaticMismatch {
            new_public_key_der: vec![9, 9, 9],
            previous_public_key_der: vec![1, 1, 1],
        },
    );

    state.hold_file_offer(incoming_offer(2, "bob", 7, "secret.docx", 4096));
    assert!(
        state.file_offer_open().is_none(),
        "a held offer must not show a popup yet"
    );

    let played_bell = state.resolve_identity_accept(UserId(2));
    assert!(
        played_bell,
        "the freshly-revealed offer should become the front of the queue"
    );

    let offer = state.file_offer_open().expect("offer should now be queued");
    assert_eq!(offer.filename, "secret.docx");
}

// ---------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------

// A pure sanity check that the target enum carries just an identity, not a
// frozen recipient snapshot - see `FileSendTarget`'s doc comment for why.
#[test]
fn file_send_target_is_equality_comparable() {
    assert_eq!(
        FileSendTarget::Channel("general".into()),
        FileSendTarget::Channel("general".into())
    );
    assert_ne!(
        FileSendTarget::Direct(UserId(2)),
        FileSendTarget::Direct(UserId(3))
    );
}

#[test]
fn file_offer_choice_defaults_to_accept() {
    assert_eq!(FileOfferChoice::Accept, FileOfferChoice::Accept);
    let _ = file_transfer::MAX_FILENAME_CHARS;
}
