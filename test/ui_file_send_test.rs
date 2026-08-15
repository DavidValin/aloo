#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::file_transfer;
use aloo::proto::{KeyMode, UserId};
use aloo::ui::file_send::{FileConfirmChoice, FileSendTarget};
use aloo::ui::ui::{Focus, FileSaveState, IdentityCase, MessageBody, Mode, UiAction};
use aloo::ui::ui_connect_popup::FileBrowserState;
use crossterm::event::KeyCode;

fn unique_dir(label: &str) -> std::path::PathBuf {
    let suffix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
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
    assert_eq!(state.input, "", "the /file command itself must not remain in the compose bar");
}

/// @requirement AC-073
#[test]
fn file_command_does_nothing_when_no_channel_is_joined_and_no_dm_is_open() {
    let mut state = aloo::ui::ui::UiState::new("me".into());
    type_str(&mut state, "/file");
    let action = press(&mut state, KeyCode::Enter);
    assert!(action.is_none());
    assert_eq!(state.mode, Mode::Normal);
    assert!(state.file_send.is_none());
    assert_eq!(state.input, "/file", "left in place so the user can see what they typed");
}

// ---------------------------------------------------------------------
// Browsing and confirming (AC-074)
// ---------------------------------------------------------------------

/// Opens `/file`, then overwrites the browser it opened (at the process's
/// real current directory) with a deterministic temp tree - same technique
/// `ui_connect_popup_test.rs::selecting_a_file_in_browser_applies_it_to_the_popup_field`
/// already uses for the connect popup's own browser.
fn open_file_send_with_temp_tree(state: &mut aloo::ui::ui::UiState, root: &std::path::Path) {
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
    assert_eq!(fs.confirm.as_deref(), Some(root.join("file.txt")).as_deref());
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

    let fs = state.file_send.as_ref().expect("Discard returns to the browser, not Normal mode");
    assert!(fs.confirm.is_none());
    assert_eq!(fs.browser.current_dir, root);
    assert_eq!(state.mode, Mode::FileSend);

    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------------
// Sending (AC-075's client-side half; the server-side relay is covered by
// server_test.rs's content_file_envelope_relays_through_route_channel_message_like_any_other_content)
// ---------------------------------------------------------------------

/// @requirement AC-075
#[test]
fn sending_a_file_to_a_channel_produces_sendfilechannel_and_logs_it_optimistically() {
    let root = make_temp_file_tree();
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    open_file_send_with_temp_tree(&mut state, &root);
    press(&mut state, KeyCode::Down); // subdir
    press(&mut state, KeyCode::Down); // file.txt
    press(&mut state, KeyCode::Enter); // confirm, Discard focused
    press(&mut state, KeyCode::Left); // toggle to Send file
    let action = press(&mut state, KeyCode::Enter);

    match action {
        Some(UiAction::SendFileChannel { channel, filename, data, recipients }) => {
            assert_eq!(channel, "general");
            assert_eq!(filename, "file.txt");
            assert_eq!(data, b"hello file transfer");
            let ids: Vec<UserId> = recipients.iter().map(|(id, _, _)| *id).collect();
            assert_eq!(ids, vec![UserId(2), UserId(3)], "every other member is addressed");
        }
        other => panic!("expected SendFileChannel, got {other:?}"),
    }
    assert_eq!(state.mode, Mode::Normal);
    assert!(state.file_send.is_none());
    assert_eq!(state.channels[0].log.len(), 1, "sent file should be logged locally straight away");
    assert_eq!(
        state.channels[0].log[0].body,
        MessageBody::File { filename: "file.txt".into(), data: b"hello file transfer".to_vec() }
    );
    assert!(state.channels[0].log[0].outgoing);

    std::fs::remove_dir_all(&root).ok();
}

/// @requirement AC-075
#[test]
fn sending_a_file_to_a_dm_peer_produces_sendfiledirect_and_logs_it_optimistically() {
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
        Some(UiAction::SendFileDirect { to, filename, data, recipient_key_mode, recipient_pubkey_der }) => {
            assert_eq!(to, UserId(2));
            assert_eq!(filename, "file.txt");
            assert_eq!(data, b"hello file transfer");
            assert_eq!(recipient_key_mode, KeyMode::Rsa);
            assert_eq!(recipient_pubkey_der, vec![2u8; 4]);
        }
        other => panic!("expected SendFileDirect, got {other:?}"),
    }
    let room = state.private_rooms.get(&UserId(2)).expect("room exists");
    assert_eq!(room.log.len(), 1);
    assert_eq!(room.log[0].body, MessageBody::File { filename: "file.txt".into(), data: b"hello file transfer".to_vec() });

    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------------
// Size cap (AC-077)
// ---------------------------------------------------------------------

/// @requirement AC-077
#[test]
fn an_oversized_file_shows_an_inline_error_and_is_not_sent() {
    let dir = unique_dir("file-send-oversized");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("big.bin"), vec![0u8; (file_transfer::MAX_FILE_BYTES + 1) as usize]).unwrap();

    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_file_send_with_temp_tree(&mut state, &dir);
    press(&mut state, KeyCode::Down); // big.bin (no subdirectory here)
    press(&mut state, KeyCode::Enter); // confirm
    press(&mut state, KeyCode::Left); // toggle to Send file
    let action = press(&mut state, KeyCode::Enter);

    assert!(action.is_none(), "an oversized file must not be sent");
    let fs = state.file_send.as_ref().expect("stays in the flow so a different file can be picked");
    assert!(fs.error.is_some(), "an inline error should be shown");
    assert!(fs.confirm.is_some(), "still on the confirmation box, not bounced back to the browser");

    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------
// Trust gating (AC-078)
// ---------------------------------------------------------------------

/// @requirement AC-078
#[test]
fn a_file_from_a_trust_gated_sender_is_held_and_revealed_on_accept() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "mismatch".into(),
        IdentityCase::StaticMismatch { new_public_key_der: vec![9, 9, 9], previous_public_key_der: vec![1, 1, 1] },
    );
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::File { filename: "secret.txt".into(), data: vec![1, 2, 3] },
    );
    assert!(state.channels[0].log.is_empty(), "held file must not appear in the visible log yet");
    assert!(state.is_trust_gated(UserId(2)));

    state.resolve_identity_accept(UserId(2));

    assert!(!state.is_trust_gated(UserId(2)));
    assert_eq!(state.channels[0].log.len(), 1, "the held file must be revealed on accept");
    assert_eq!(state.channels[0].log[0].body, MessageBody::File { filename: "secret.txt".into(), data: vec![1, 2, 3] });
}

// ---------------------------------------------------------------------
// Receiving + saving (AC-076)
// ---------------------------------------------------------------------

/// @requirement AC-076
#[test]
fn enter_on_a_file_log_entry_opens_the_save_popup_prefilled_with_the_default_path() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::File { filename: "weird/../name.txt".into(), data: vec![9, 9] },
    );
    state.focus = Focus::Messages;

    let action = press(&mut state, KeyCode::Enter);
    assert!(action.is_none());
    assert_eq!(state.mode, Mode::FileSave);
    let fs = state.file_save.as_ref().expect("save popup open");
    assert_eq!(fs.filename, "weird/../name.txt");
    assert_eq!(fs.data, vec![9, 9]);
    let expected = file_transfer::default_download_dir().join("name.txt").display().to_string();
    assert_eq!(fs.path_input, expected, "the default path must use only the sanitized final path component");
}

/// @requirement AC-076
#[test]
fn saving_writes_the_file_to_the_typed_path() {
    let dir = unique_dir("file-save-write");
    let target = dir.join("out.txt");
    let mut state = joined_general_with(vec![]);
    state.file_save =
        Some(FileSaveState { filename: "out.txt".into(), data: b"hi there".to_vec(), path_input: target.display().to_string() });
    state.mode = Mode::FileSave;

    let action = press(&mut state, KeyCode::Enter);

    assert!(action.is_none());
    assert_eq!(state.mode, Mode::Normal);
    assert!(state.file_save.is_none());
    assert_eq!(std::fs::read(&target).unwrap(), b"hi there");

    std::fs::remove_dir_all(&dir).ok();
}

// A pure sanity check that the target enum carries just an identity, not a
// frozen recipient snapshot - see `FileSendTarget`'s doc comment for why.
#[test]
fn file_send_target_is_equality_comparable() {
    assert_eq!(FileSendTarget::Channel("general".into()), FileSendTarget::Channel("general".into()));
    assert_ne!(FileSendTarget::Direct(UserId(2)), FileSendTarget::Direct(UserId(3)));
}
