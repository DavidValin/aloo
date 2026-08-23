#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::contacts::ContactRow;
use aloo::client::file_browser::FileBrowserState;
use aloo::client::tui::contacts::{DeleteChoice, InstallField};
use aloo::client::tui::ui::{Mode, UiAction};
use aloo::proto::KeyMode;
use crossterm::event::KeyCode;

fn row(nickname: &str, key_mode: Option<KeyMode>) -> ContactRow {
    ContactRow {
        nickname: nickname.to_string(),
        last_seen_unix: None,
        key_mode,
        otp_contact_name: None,
        otp: None,
    }
}

fn otp_eligible_row(nickname: &str) -> ContactRow {
    ContactRow {
        otp_contact_name: Some(format!("otpname-{nickname}")),
        ..row(nickname, Some(KeyMode::PqHybrid))
    }
}

fn otp_installed_row(nickname: &str) -> ContactRow {
    ContactRow {
        otp: Some(aloo::client::contacts::ContactOtpDetail {
            enc_sequence: 3,
            enc_offset: 300,
            enc_key_remaining: 700_000,
            dec_sequence: 2,
            dec_offset: 200,
            dec_key_remaining: 100_000,
            enc_key_path: std::path::PathBuf::from("/tmp/otp/.keychain/x_enc.key"),
            dec_key_path: std::path::PathBuf::from("/tmp/otp/.keychain/x_dec.key"),
        }),
        ..otp_eligible_row(nickname)
    }
}

// ---------------------------------------------------------------------
// Opening the modal
// ---------------------------------------------------------------------

#[test]
fn contacts_command_opens_the_modal_empty_and_requests_a_gather() {
    let mut state = joined_general_with(vec![]);
    type_str(&mut state, "/contacts");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, Some(UiAction::OpenContacts));
    assert_eq!(state.mode, Mode::Contacts);
    assert!(state.contacts.as_ref().unwrap().rows.is_empty());
    assert_eq!(state.input, "");
}

#[test]
fn set_contacts_rows_populates_the_modal_and_clamps_selection() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None), row("bob", None)]);
    assert_eq!(state.contacts.as_ref().unwrap().rows.len(), 2);
    assert_eq!(state.contacts.as_ref().unwrap().selected, 0);
}

#[test]
fn set_contacts_rows_is_a_no_op_once_the_modal_is_closed() {
    let mut state = joined_general_with(vec![]);
    // Never opened - the session's answer arrived (or, in a test, was
    // simulated) after Esc already closed it.
    state.set_contacts_rows(vec![row("alice", None)]);
    assert!(state.contacts.is_none());
}

// ---------------------------------------------------------------------
// Navigating the list, closing it
// ---------------------------------------------------------------------

#[test]
fn up_and_down_wrap_around_the_row_list() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None), row("bob", None), row("carol", None)]);

    press(&mut state, KeyCode::Down);
    assert_eq!(state.contacts.as_ref().unwrap().selected, 1);
    press(&mut state, KeyCode::Up);
    assert_eq!(state.contacts.as_ref().unwrap().selected, 0);
    press(&mut state, KeyCode::Up);
    assert_eq!(
        state.contacts.as_ref().unwrap().selected,
        2,
        "Up from the first row wraps to the last"
    );
}

#[test]
fn esc_on_the_list_closes_the_whole_modal() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]);
    let action = press(&mut state, KeyCode::Esc);
    assert!(action.is_none());
    assert!(state.contacts.is_none());
    assert_eq!(state.mode, Mode::Normal);
}

// ---------------------------------------------------------------------
// Delete confirmation (Cancel-by-default, matching every other destructive
// popup in this app)
// ---------------------------------------------------------------------

#[test]
fn d_opens_delete_confirmation_defaulting_to_cancel() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]);
    press(&mut state, KeyCode::Char('d'));
    assert_eq!(
        state.contacts.as_ref().unwrap().confirm_delete,
        Some(DeleteChoice::Cancel)
    );
}

#[test]
fn confirming_cancel_returns_to_the_list_without_an_action() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]);
    press(&mut state, KeyCode::Char('d'));
    let action = press(&mut state, KeyCode::Enter);
    assert!(action.is_none());
    assert!(state.contacts.as_ref().unwrap().confirm_delete.is_none());
    assert!(state.contacts.is_some(), "the modal itself stays open");
}

#[test]
fn confirming_delete_produces_deletecontact_for_the_selected_nickname() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None), row("bob", None)]);
    press(&mut state, KeyCode::Down); // select bob
    press(&mut state, KeyCode::Char('d'));
    press(&mut state, KeyCode::Left); // toggle Cancel -> Delete
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::DeleteContact {
            nickname: "bob".to_string()
        })
    );
    assert!(state.contacts.as_ref().unwrap().confirm_delete.is_none());
}

#[test]
fn esc_on_the_delete_confirmation_returns_to_the_list() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]);
    press(&mut state, KeyCode::Char('d'));
    press(&mut state, KeyCode::Esc);
    assert!(state.contacts.as_ref().unwrap().confirm_delete.is_none());
    assert!(state.contacts.is_some());
}

// ---------------------------------------------------------------------
// Install OTP key
// ---------------------------------------------------------------------

#[test]
fn o_on_an_ineligible_contact_refuses_and_shows_a_status_notice() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", Some(KeyMode::PqHybrid))]);
    let action = press(&mut state, KeyCode::Char('o'));
    assert!(action.is_none());
    assert!(state.contacts.as_ref().unwrap().install.is_none());
    assert!(state.status_notice.is_some());
}

#[test]
fn o_on_an_eligible_contact_opens_the_install_popup_focused_on_enc_path() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_eligible_row("alice")]);
    press(&mut state, KeyCode::Char('o'));
    let install = state.contacts.as_ref().unwrap().install.as_ref().expect("popup open");
    assert_eq!(install.focus, InstallField::EncPath);
    assert_eq!(install.enc_path, "");
    assert_eq!(install.dec_path, "");
}

#[test]
fn tab_cycles_enc_dec_install_and_wraps() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_eligible_row("alice")]);
    press(&mut state, KeyCode::Char('o'));

    press(&mut state, KeyCode::Tab);
    assert_eq!(
        state.contacts.as_ref().unwrap().install.as_ref().unwrap().focus,
        InstallField::DecPath
    );
    press(&mut state, KeyCode::Tab);
    assert_eq!(
        state.contacts.as_ref().unwrap().install.as_ref().unwrap().focus,
        InstallField::Install
    );
    press(&mut state, KeyCode::Tab);
    assert_eq!(
        state.contacts.as_ref().unwrap().install.as_ref().unwrap().focus,
        InstallField::EncPath,
        "wraps back to the first field"
    );
    press(&mut state, KeyCode::BackTab);
    assert_eq!(
        state.contacts.as_ref().unwrap().install.as_ref().unwrap().focus,
        InstallField::Install,
        "BackTab from the first field wraps to the last"
    );
}

/// Opens `/contacts`, an eligible row's install popup, then overwrites
/// whichever field's browser it opens with a deterministic temp tree -
/// same technique `ui_file_send_test.rs::open_file_send_with_temp_tree`
/// already uses.
fn open_install_popup(state: &mut aloo::client::tui::ui::UiState, nickname: &str) {
    state.open_contacts();
    state.set_contacts_rows(vec![otp_eligible_row(nickname)]);
    press(state, KeyCode::Char('o'));
}

fn overwrite_browser(state: &mut aloo::client::tui::ui::UiState, root: &std::path::Path) {
    let install = state.contacts.as_mut().unwrap().install.as_mut().unwrap();
    let (_, browser) = install.browser.as_mut().expect("Enter should have opened a browser");
    *browser = FileBrowserState::open(root.to_path_buf()).unwrap();
}

#[test]
fn enter_on_enc_path_opens_a_browser_and_selecting_a_file_fills_it_in() {
    let root = make_temp_file_tree();
    let mut state = joined_general_with(vec![]);
    open_install_popup(&mut state, "alice");

    press(&mut state, KeyCode::Enter); // opens browser on EncPath
    overwrite_browser(&mut state, &root);
    press(&mut state, KeyCode::Down); // subdir
    press(&mut state, KeyCode::Down); // file.txt
    press(&mut state, KeyCode::Enter); // select it

    let install = state.contacts.as_ref().unwrap().install.as_ref().unwrap();
    assert_eq!(install.enc_path, root.join("file.txt").display().to_string());
    assert!(install.browser.is_none(), "closes back to the form");
    assert_eq!(install.focus, InstallField::EncPath, "focus is unchanged");

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn esc_on_the_install_browser_returns_to_the_form_not_the_list() {
    let root = make_temp_file_tree();
    let mut state = joined_general_with(vec![]);
    open_install_popup(&mut state, "alice");
    press(&mut state, KeyCode::Enter);
    overwrite_browser(&mut state, &root);

    press(&mut state, KeyCode::Esc);
    assert!(state.contacts.as_ref().unwrap().install.as_ref().unwrap().browser.is_none());
    assert!(state.contacts.as_ref().unwrap().install.is_some());

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn esc_on_the_install_form_returns_to_the_list_not_closing_the_modal() {
    let mut state = joined_general_with(vec![]);
    open_install_popup(&mut state, "alice");
    press(&mut state, KeyCode::Esc);
    assert!(state.contacts.as_ref().unwrap().install.is_none());
    assert!(state.contacts.is_some());
}

#[test]
fn install_with_both_paths_set_produces_installotpkey() {
    let root = make_temp_file_tree();
    let mut state = joined_general_with(vec![]);
    open_install_popup(&mut state, "alice");

    press(&mut state, KeyCode::Enter); // browse EncPath
    overwrite_browser(&mut state, &root);
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Down); // file.txt
    press(&mut state, KeyCode::Enter);

    press(&mut state, KeyCode::Tab); // DecPath
    press(&mut state, KeyCode::Enter); // browse DecPath
    overwrite_browser(&mut state, &root);
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Enter); // subdir
    press(&mut state, KeyCode::Down); // nested.txt
    press(&mut state, KeyCode::Enter);

    press(&mut state, KeyCode::Tab); // Install
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::InstallOtpKey {
            nickname: "alice".to_string(),
            enc_path: root.join("file.txt"),
            dec_path: root.join("subdir").join("nested.txt"),
        })
    );

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn install_with_a_missing_path_shows_an_inline_error_and_produces_no_action() {
    let mut state = joined_general_with(vec![]);
    open_install_popup(&mut state, "alice");
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab); // Install, both paths still empty
    let action = press(&mut state, KeyCode::Enter);
    assert!(action.is_none());
    assert!(state.contacts.as_ref().unwrap().install.as_ref().unwrap().error.is_some());
}

#[test]
fn set_contacts_install_error_is_a_no_op_once_the_popup_is_closed() {
    let mut state = joined_general_with(vec![]);
    open_install_popup(&mut state, "alice");
    press(&mut state, KeyCode::Esc); // back to the list
    state.set_contacts_install_error("too late".to_string());
    assert!(state.contacts.as_ref().unwrap().install.is_none());
}

#[test]
fn close_contacts_install_drops_the_popup_back_to_the_list() {
    let mut state = joined_general_with(vec![]);
    open_install_popup(&mut state, "alice");
    state.close_contacts_install();
    assert!(state.contacts.as_ref().unwrap().install.is_none());
    assert!(state.contacts.is_some());
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

#[test]
fn rendering_shows_the_header_and_every_nicknames_row() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", Some(KeyMode::PqHybrid)), row("bob", None)]);

    let body = popup_body(&buffer_at(&state, 140, 30), "Contacts");
    let joined = body.join("\n");
    assert!(joined.contains("nickname"));
    assert!(joined.contains("alice"));
    assert!(joined.contains("bob"));
    assert!(joined.contains("never"), "bob has never been seen");
    assert!(joined.contains("unknown"), "bob's encryption method is unrecorded");
}

#[test]
fn an_eligible_but_uninstalled_contact_hints_at_o_to_install() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_eligible_row("alice")]);

    let body = popup_body(&buffer_at(&state, 160, 30), "Contacts").join("\n");
    assert!(body.contains("o to install"));
}

#[test]
fn an_installed_contacts_row_shows_its_otp_pad_figures_in_each_direction() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_installed_row("alice")]);

    let body = popup_body(&buffer_at(&state, 200, 30), "Contacts").join("\n");
    assert!(body.contains("dec"));
    assert!(body.contains("enc"));
    // Same MB-figure formatting the /otp DM header uses.
    assert!(body.contains("MB"));
}

fn otp_installed_row_with(
    nickname: &str,
    dec_sequence: u64,
    dec_offset: u64,
    dec_key_remaining: u64,
    enc_sequence: u64,
    enc_offset: u64,
    enc_key_remaining: u64,
) -> ContactRow {
    ContactRow {
        otp: Some(aloo::client::contacts::ContactOtpDetail {
            enc_sequence,
            enc_offset,
            enc_key_remaining,
            dec_sequence,
            dec_offset,
            dec_key_remaining,
            enc_key_path: std::path::PathBuf::from("/tmp/otp/.keychain/x_enc.key"),
            dec_key_path: std::path::PathBuf::from("/tmp/otp/.keychain/x_dec.key"),
        }),
        ..otp_eligible_row(nickname)
    }
}

/// Every column - including each OTP sub-figure (seq/offset/remaining, in
/// both directions) - must line up down the list, however many digits a
/// given row's numbers happen to have. A row with tiny figures and one
/// with huge ones must still put "enc:" (and every column after it) at
/// exactly the same screen column.
#[test]
fn otp_sub_columns_stay_aligned_across_wildly_different_digit_counts() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![
        otp_installed_row_with("alice", 1, 2, 500, 3, 4, 900),
        otp_installed_row_with("bob", 123_456, 987_654, 999_999_999, 7, 80_000, 1_000),
    ]);

    let buffer = buffer_at(&state, 220, 30);
    let body = popup_body(&buffer, "Contacts");
    let alice_row = body
        .iter()
        .find(|r| r.contains("alice"))
        .expect("alice's row should render");
    let bob_row = body
        .iter()
        .find(|r| r.contains("bob"))
        .expect("bob's row should render");

    let enc_x = |row: &str| row.find("enc:").expect("every installed row shows an enc: field");
    assert_eq!(
        enc_x(alice_row),
        enc_x(bob_row),
        "the enc: field must start at the same column regardless of how many digits \
         the dec: figures before it have\nalice: {alice_row:?}\nbob:   {bob_row:?}"
    );
}

#[test]
fn an_empty_list_says_so_instead_of_an_empty_box() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    let body = popup_body(&buffer_at(&state, 140, 30), "Contacts").join("\n");
    assert!(body.contains("no contacts pinned yet"));
}

#[test]
fn the_delete_confirmation_names_the_selected_contact() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]);
    press(&mut state, KeyCode::Char('d'));

    let body = popup_body(&buffer_at(&state, 140, 30), "Delete contact").join("\n");
    assert!(body.contains("alice"));
}

#[test]
fn the_install_popup_names_the_selected_contact_and_explains_new_key_pair() {
    let mut state = joined_general_with(vec![]);
    open_install_popup(&mut state, "alice");
    let body = popup_body(&buffer_at(&state, 160, 30), "Install OTP key").join("\n");
    assert!(body.contains("alice"));
    assert!(body.contains("--new-key-pair"));
    assert!(body.contains("otp-toolkit"));
}
