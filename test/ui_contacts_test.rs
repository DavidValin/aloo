#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::contacts::ContactRow;
use aloo::client::file_browser::FileBrowserState;
use aloo::client::tui::contacts::{ContactKeyKind, DeleteChoice, InstallField};
use aloo::client::tui::ui::{Mode, UiAction};
use aloo::crypto::otp::OtpPurpose;
use aloo::proto::KeyMode;
use crossterm::event::KeyCode;

fn row(nickname: &str, key_mode: Option<KeyMode>) -> ContactRow {
    let pqh_fingerprint = if key_mode == Some(KeyMode::PqHybrid) {
        Some(format!("fp-{nickname}"))
    } else {
        None
    };
    ContactRow {
        nickname: nickname.to_string(),
        last_seen_unix: None,
        key_mode,
        otp_contact_name: None,
        otp: None,
        otp_mail_contact_name: None,
        otp_mail: None,
        pqh_fingerprint,
        pqh_pinned_from: None,
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
            purpose: aloo::crypto::otp::OtpPurpose::Live,
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

/// A single (or empty) contact list must never shrink-wrap the popup down
/// to a cramped sliver - the list itself sizes at `rows + 4`, floored at 7
/// so there is always room to read comfortably.
///
/// @requirement AC-306
#[test]
fn the_popup_is_at_least_seven_lines_tall_with_only_one_contact() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", Some(KeyMode::PqHybrid))]);

    let (_, _, _, height) = popup_rect(&buffer_at(&state, 140, 30), "Contacts");
    assert!(height >= 7, "expected at least 7 lines, got {height}");
}

/// The empty-list case goes through the same height floor, not a smaller
/// one of its own.
///
/// @requirement AC-306
#[test]
fn the_popup_is_at_least_seven_lines_tall_with_no_contacts_at_all() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();

    let (_, _, _, height) = popup_rect(&buffer_at(&state, 140, 30), "Contacts");
    assert!(height >= 7, "expected at least 7 lines, got {height}");
}

/// The shortcut hints in the title bar must stand out from the plain
/// "Contacts" label rather than blending into the border's default color.
///
/// @requirement AC-306
#[test]
fn the_titles_shortcut_hints_are_colored_differently_from_the_label() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", Some(KeyMode::PqHybrid))]);

    let buffer = buffer_at(&state, 140, 30);
    let (label_x, label_y) = find_text_start(&buffer, "Contacts");
    let (hint_x, hint_y) = find_text_start(&buffer, "switch key");
    assert_ne!(
        buffer[(label_x, label_y)].fg,
        buffer[(hint_x, hint_y)].fg,
        "the shortcut hints must not share the label's color"
    );
}

/// @requirement AC-298
#[test]
fn an_eligible_but_uninstalled_contact_shows_a_crossed_otp_badge() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_eligible_row("alice")]);

    let body = popup_body(&buffer_at(&state, 160, 30), "Contacts").join("\n");
    assert!(body.contains("PQH"), "PQH is pinned: {body:?}");
    assert!(body.contains("\u{274c}"), "OTP isn't installed yet, shown as a cross: {body:?}");
    assert!(body.contains("OTP"), "the OTP badge itself renders: {body:?}");
}

/// @requirement AC-299
#[test]
fn an_installed_otp_keys_details_popup_shows_its_pad_figures_in_each_direction() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_installed_row("alice")]);
    press(&mut state, KeyCode::Right); // Pqh -> Otp
    press(&mut state, KeyCode::Enter); // open the OTP key's details

    let body = popup_body(&buffer_at(&state, 200, 30), "alice").join("\n");
    assert!(body.contains("dec"));
    assert!(body.contains("enc"));
    // Same MB-figure formatting the /otp DM header uses.
    assert!(body.contains("MB"));
}

/// Every column must still line up down the list even though the row no
/// longer carries OTP's own seq/offset/remaining figures (moved to the key
/// details popup) - just the three fixed-width key badges now, so two
/// contacts with very different nickname lengths must still put the
/// badges at the same screen column once padded.
/// @requirement AC-298
#[test]
fn key_badges_stay_aligned_regardless_of_nickname_length() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![
        otp_installed_row("a"),
        otp_installed_row("a-much-longer-nickname"),
    ]);

    let buffer = buffer_at(&state, 220, 30);
    let body = popup_body(&buffer, "Contacts");
    let xs: Vec<usize> = body.iter().filter_map(|r| r.find("PQH")).collect();
    assert_eq!(xs.len(), 2, "both rows should render a PQH badge: {body:?}");
    assert!(xs.windows(2).all(|w| w[0] == w[1]), "badges must line up: {body:?}");
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
    let body = popup_body(&buffer_at(&state, 160, 30), "Install OTP session").join("\n");
    assert!(body.contains("alice"));
    assert!(body.contains("--new-key-pair"));
    assert!(body.contains("otp-toolkit"));
}

// ---------------------------------------------------------------------
// The key details popup: navigation
// ---------------------------------------------------------------------

/// @requirement AC-298
#[test]
fn left_and_right_on_the_list_cycle_the_selected_key_and_wrap() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]);
    assert_eq!(state.contacts.as_ref().unwrap().selected_key, ContactKeyKind::Pqh);
    press(&mut state, KeyCode::Right);
    assert_eq!(state.contacts.as_ref().unwrap().selected_key, ContactKeyKind::Otp);
    press(&mut state, KeyCode::Right);
    assert_eq!(state.contacts.as_ref().unwrap().selected_key, ContactKeyKind::OtpMail);
    press(&mut state, KeyCode::Right);
    assert_eq!(
        state.contacts.as_ref().unwrap().selected_key,
        ContactKeyKind::Pqh,
        "wraps back to the first key"
    );
    press(&mut state, KeyCode::Left);
    assert_eq!(
        state.contacts.as_ref().unwrap().selected_key,
        ContactKeyKind::OtpMail,
        "Left from the first key wraps to the last"
    );
}

/// @requirement AC-298
#[test]
fn enter_on_the_list_opens_the_details_popup_for_the_selected_row_and_key() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_eligible_row("alice")]);
    press(&mut state, KeyCode::Right); // Pqh -> Otp
    press(&mut state, KeyCode::Enter);

    let detail = state.contacts.as_ref().unwrap().detail.as_ref().expect("opened");
    assert_eq!(detail.nickname, "alice");
    assert_eq!(detail.kind, ContactKeyKind::Otp);
}

/// @requirement AC-299
#[test]
fn esc_on_the_details_popup_closes_it_without_touching_the_list() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]);
    press(&mut state, KeyCode::Enter);
    assert!(state.contacts.as_ref().unwrap().detail.is_some());
    press(&mut state, KeyCode::Esc);
    assert!(state.contacts.as_ref().unwrap().detail.is_none());
    assert!(state.contacts.is_some(), "the list itself stays open");
}

/// @requirement AC-299
#[test]
fn left_and_right_inside_the_details_popup_switch_which_key_it_shows() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]);
    press(&mut state, KeyCode::Enter); // opens on Pqh
    press(&mut state, KeyCode::Right);
    assert_eq!(
        state.contacts.as_ref().unwrap().detail.as_ref().unwrap().kind,
        ContactKeyKind::Otp
    );
}

/// @requirement AC-299
#[test]
fn the_details_popup_yellow_explanation_names_this_keys_purpose() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]);
    press(&mut state, KeyCode::Enter); // Pqh
    let body = popup_body(&buffer_at(&state, 160, 30), "alice").join("\n");
    assert!(body.contains("pin the identity"), "PQH's own explanation: {body:?}");

    press(&mut state, KeyCode::Right); // Otp
    let body = popup_body(&buffer_at(&state, 160, 30), "alice").join("\n");
    assert!(body.contains("live One Time Pad sessions"), "OTP's own explanation: {body:?}");

    press(&mut state, KeyCode::Right); // OtpMail
    let body = popup_body(&buffer_at(&state, 160, 30), "alice").join("\n");
    assert!(body.contains("deliver Mails"), "OTP mail's own explanation: {body:?}");
}

// ---------------------------------------------------------------------
// The key details popup: deleting a present key
// ---------------------------------------------------------------------

/// @requirement AC-299
#[test]
fn deleting_a_present_pqh_key_asks_first_then_sends_deletecontact_and_closes_the_popup() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_installed_row("alice")]); // key_mode PqHybrid
    press(&mut state, KeyCode::Enter); // details on Pqh, present
    assert!(press(&mut state, KeyCode::Enter).is_none(), "first Enter only opens the confirm");
    assert!(state.contacts.as_ref().unwrap().detail.as_ref().unwrap().confirm.is_some());

    press(&mut state, KeyCode::Left); // toggle Cancel -> Delete
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, Some(UiAction::DeleteContact { nickname: "alice".to_string() }));
    assert!(
        state.contacts.as_ref().unwrap().detail.is_none(),
        "nothing left to show once the identity pin itself is gone"
    );
}

/// @requirement AC-299
#[test]
fn cancelling_a_delete_confirm_leaves_the_key_and_the_popup_alone() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_installed_row("alice")]);
    press(&mut state, KeyCode::Enter);
    press(&mut state, KeyCode::Enter); // open confirm (defaults to Cancel)
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
    assert!(state.contacts.as_ref().unwrap().detail.is_some(), "the popup stays open");
    assert!(
        state.contacts.as_ref().unwrap().detail.as_ref().unwrap().confirm.is_none(),
        "back to the main view, not the confirm"
    );
}

/// @requirement AC-299
#[test]
fn deleting_a_present_otp_key_sends_deletecontactkey_live_and_leaves_the_popup_open() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_installed_row("alice")]);
    press(&mut state, KeyCode::Right); // Otp
    press(&mut state, KeyCode::Enter); // details, present
    press(&mut state, KeyCode::Enter); // open confirm
    press(&mut state, KeyCode::Left); // toggle Cancel -> Delete

    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::DeleteContactKey { nickname: "alice".to_string(), purpose: OtpPurpose::Live })
    );
    assert!(
        state.contacts.as_ref().unwrap().detail.is_some(),
        "the PQH pin and the other purpose are untouched - the popup stays put"
    );
}

/// @requirement AC-299
#[test]
fn deleting_a_present_otp_mail_key_sends_deletecontactkey_mail() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    let mail_row = ContactRow {
        otp_mail_contact_name: Some("mail-name".to_string()),
        otp_mail: Some(aloo::client::contacts::ContactOtpDetail {
            enc_sequence: 0,
            enc_offset: 0,
            enc_key_remaining: 1,
            dec_sequence: 0,
            dec_offset: 0,
            dec_key_remaining: 1,
            enc_key_path: std::path::PathBuf::from("/tmp/enc"),
            dec_key_path: std::path::PathBuf::from("/tmp/dec"),
        }),
        ..row("alice", Some(KeyMode::PqHybrid))
    };
    state.set_contacts_rows(vec![mail_row]);
    press(&mut state, KeyCode::Right);
    press(&mut state, KeyCode::Right); // OtpMail
    press(&mut state, KeyCode::Enter);
    press(&mut state, KeyCode::Enter); // open confirm
    press(&mut state, KeyCode::Left); // toggle Cancel -> Delete

    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::DeleteContactKey { nickname: "alice".to_string(), purpose: OtpPurpose::Mail })
    );
}

// ---------------------------------------------------------------------
// The key details popup: creating/installing a missing key
// ---------------------------------------------------------------------

/// @requirement AC-299
#[test]
fn enter_on_a_missing_otp_key_opens_the_install_popup_with_the_right_purpose() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_eligible_row("alice")]); // otp: None
    press(&mut state, KeyCode::Right); // Otp
    press(&mut state, KeyCode::Enter); // details, missing
    press(&mut state, KeyCode::Enter); // Create/Install action

    let install = state.contacts.as_ref().unwrap().install.as_ref().expect("opened");
    assert_eq!(install.nickname, "alice");
    assert_eq!(install.purpose, OtpPurpose::Live);
}

/// @requirement AC-299
#[test]
fn enter_on_a_missing_mail_key_opens_the_install_popup_with_mail_purpose() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_eligible_row("alice")]);
    press(&mut state, KeyCode::Right);
    press(&mut state, KeyCode::Right); // OtpMail
    press(&mut state, KeyCode::Enter);
    press(&mut state, KeyCode::Enter);

    let install = state.contacts.as_ref().unwrap().install.as_ref().expect("opened");
    assert_eq!(install.purpose, OtpPurpose::Mail);
}

/// @requirement AC-299
#[test]
fn escaping_the_install_popup_opened_from_details_returns_to_the_details_popup() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![otp_eligible_row("alice")]);
    press(&mut state, KeyCode::Right);
    press(&mut state, KeyCode::Enter);
    press(&mut state, KeyCode::Enter); // opens install
    press(&mut state, KeyCode::Esc);
    assert!(state.contacts.as_ref().unwrap().install.is_none());
    assert!(
        state.contacts.as_ref().unwrap().detail.is_some(),
        "closing install falls back to the details popup that opened it, not the list"
    );
}

/// @requirement AC-301
#[test]
fn enter_on_a_missing_pqh_key_opens_a_file_browser() {
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]); // no pq_hybrid pin
    press(&mut state, KeyCode::Enter); // details on Pqh, missing
    press(&mut state, KeyCode::Enter); // Create key

    assert!(
        state.contacts.as_ref().unwrap().detail.as_ref().unwrap().pqh_browser.is_some(),
        "opens the identity-card file browser"
    );
}

/// @requirement AC-301
#[test]
fn selecting_a_card_file_sends_pinidentitycard_and_closes_the_browser() {
    let root = make_temp_file_tree();
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]);
    press(&mut state, KeyCode::Enter);
    press(&mut state, KeyCode::Enter); // opens browser

    {
        let detail = state.contacts.as_mut().unwrap().detail.as_mut().unwrap();
        let browser = detail.pqh_browser.as_mut().unwrap();
        *browser = FileBrowserState::open(root.clone()).unwrap();
    }
    press(&mut state, KeyCode::Down); // subdir
    press(&mut state, KeyCode::Down); // file.txt
    let action = press(&mut state, KeyCode::Enter);

    assert_eq!(
        action,
        Some(UiAction::PinIdentityCard { nickname: "alice".to_string(), path: root.join("file.txt") })
    );
    assert!(state.contacts.as_ref().unwrap().detail.as_ref().unwrap().pqh_browser.is_none());

    std::fs::remove_dir_all(&root).ok();
}

/// @requirement AC-301
#[test]
fn esc_on_the_pqh_browser_returns_to_the_details_popup() {
    let root = make_temp_file_tree();
    let mut state = joined_general_with(vec![]);
    state.open_contacts();
    state.set_contacts_rows(vec![row("alice", None)]);
    press(&mut state, KeyCode::Enter);
    press(&mut state, KeyCode::Enter);
    {
        let detail = state.contacts.as_mut().unwrap().detail.as_mut().unwrap();
        let browser = detail.pqh_browser.as_mut().unwrap();
        *browser = FileBrowserState::open(root.clone()).unwrap();
    }
    press(&mut state, KeyCode::Esc);
    assert!(state.contacts.as_ref().unwrap().detail.as_ref().unwrap().pqh_browser.is_none());
    assert!(state.contacts.as_ref().unwrap().detail.is_some());

    std::fs::remove_dir_all(&root).ok();
}
