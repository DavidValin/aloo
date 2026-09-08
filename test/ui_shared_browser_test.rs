//! The shared-folder surfaces (US-066): the `/info` popup's "Browse
//! shared files" button, the browser popup it opens, the once-per-room
//! DM notice, the Ctrl+S File Sharing tab, and the offer-parking that
//! makes a file this side asked for arrive with no popup.
//!
//! UI only - what the session does with these actions is
//! `shared_session_test.rs`, and the filesystem work is
//! `shared_folders_test.rs`.

#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::shared_folders::{SharedEntry, SharedError};
use aloo::client::tui::settings_popup::{SettingsField, SettingsTab};
use aloo::client::tui::shared_browser::{format_entry_row, format_entry_time};
use aloo::client::tui::ui::{Focus, MessageBody, Mode, PendingFileOffer, UiAction, UiState};
use aloo::proto::UserId;
use crossterm::event::KeyCode;

const BOB: UserId = UserId(2);

fn entry(name: &str, is_dir: bool, size: u64) -> SharedEntry {
    SharedEntry {
        name: name.into(),
        is_dir,
        size,
        created_unix: Some(1_700_000_000),
        modified_unix: Some(1_700_003_600),
    }
}

/// A state viewing a DM with bob, who shares `names` with us.
fn dm_with_sharing_bob(names: &[&str]) -> UiState {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    state.set_peer_shares(BOB, names.iter().map(|n| n.to_string()).collect());
    state
}

/// Opens the browser the way a user does: `/info`, then Enter on the
/// button.
fn open_browser(state: &mut UiState) {
    type_str(state, "/info");
    press(state, KeyCode::Enter);
    assert!(state.user_info.is_some(), "the info popup opened");
    press(state, KeyCode::Enter);
}

// ---------------------------------------------------------------------
// The /info button
// ---------------------------------------------------------------------

/// @requirement AC-457
#[test]
fn the_info_popup_offers_browse_shared_files_only_for_a_peer_who_shares() {
    let mut sharing = dm_with_sharing_bob(&["Photos"]);
    type_str(&mut sharing, "/info");
    press(&mut sharing, KeyCode::Enter);
    let rows = rendered_rows(&sharing);
    assert!(
        rows.iter().any(|r| r.contains("Browse shared files")),
        "the button is offered: {rows:?}"
    );

    let mut plain = dm_with_sharing_bob(&[]);
    type_str(&mut plain, "/info");
    press(&mut plain, KeyCode::Enter);
    let rows = rendered_rows(&plain);
    assert!(
        !rows.iter().any(|r| r.contains("Browse shared files")),
        "nothing shared, so no button: {rows:?}"
    );
}

/// @requirement AC-457
#[test]
fn enter_on_the_info_popup_opens_the_browser_at_the_peers_shares() {
    let mut state = dm_with_sharing_bob(&["Photos", "Public"]);
    open_browser(&mut state);

    assert!(state.user_info.is_none(), "the info popup gave way to the browser");
    assert_eq!(state.mode, Mode::SharedFiles);
    let browser = state.shared_browser.as_ref().expect("the browser is open");
    assert_eq!(browser.peer, BOB);
    assert_eq!(browser.share, None, "it opens on the share list itself");
    let names: Vec<&str> = browser.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["Photos", "Public"]);
    assert!(
        browser.entries.iter().all(|e| e.is_dir),
        "a share is entered like a folder"
    );
}

/// @requirement AC-457
#[test]
fn enter_does_nothing_on_the_info_popup_of_a_peer_who_shares_nothing() {
    let mut state = dm_with_sharing_bob(&[]);
    type_str(&mut state, "/info");
    press(&mut state, KeyCode::Enter);
    let action = press(&mut state, KeyCode::Enter);
    assert!(action.is_none());
    assert!(state.shared_browser.is_none(), "there is nothing to browse");
    assert!(state.user_info.is_some(), "and the popup stays as it was");
}

/// @requirement AC-457
#[test]
fn esc_closes_the_browser() {
    let mut state = dm_with_sharing_bob(&["Photos"]);
    open_browser(&mut state);
    press(&mut state, KeyCode::Esc);
    assert!(state.shared_browser.is_none());
    assert_eq!(state.mode, Mode::Normal);
}

// ---------------------------------------------------------------------
// Browsing
// ---------------------------------------------------------------------

/// @requirement AC-451
#[test]
fn entering_a_share_asks_the_peer_for_its_listing_and_shows_loading() {
    let mut state = dm_with_sharing_bob(&["Photos"]);
    open_browser(&mut state);
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::RequestSharedListing {
            peer: BOB,
            share: "Photos".into(),
            rel_path: String::new(),
        })
    );
    let browser = state.shared_browser.as_ref().unwrap();
    assert!(browser.loading, "nothing is known until they answer");
    assert!(browser.entries.is_empty());
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("loading")),
        "the wait is visible: {rows:?}"
    );
}

/// @requirement AC-451
#[test]
fn a_listing_answer_fills_the_view_and_a_stale_one_is_dropped() {
    let mut state = dm_with_sharing_bob(&["Photos"]);
    open_browser(&mut state);
    press(&mut state, KeyCode::Enter);

    // An answer for a folder the user has already left changes nothing.
    state.set_shared_listing(BOB, "Photos", "somewhere/else", vec![entry("stale.txt", false, 1)], false, None);
    assert!(
        state.shared_browser.as_ref().unwrap().entries.is_empty(),
        "an answer to a view already left is dropped"
    );

    state.set_shared_listing(
        BOB,
        "Photos",
        "",
        vec![entry("trip", true, 0), entry("beach.jpg", false, 2_500)],
        false,
        None,
    );
    let browser = state.shared_browser.as_ref().unwrap();
    assert!(!browser.loading);
    assert_eq!(browser.entries.len(), 2);
    assert_eq!(browser.selected, 0);
}

/// @requirement AC-451
#[test]
fn rows_show_name_created_updated_and_size() {
    let mut state = dm_with_sharing_bob(&["Photos"]);
    open_browser(&mut state);
    press(&mut state, KeyCode::Enter);
    state.set_shared_listing(BOB, "Photos", "", vec![entry("beach.jpg", false, 2_500)], false, None);

    let rows = rendered_rows_at(&state, 120, 40);
    let row = rows
        .iter()
        .find(|r| r.contains("beach.jpg"))
        .expect("the file has a row");
    assert!(row.contains("2.5 KB"), "the size is shown: {row}");
    let created = format_entry_time(Some(1_700_000_000));
    let updated = format_entry_time(Some(1_700_003_600));
    assert!(row.contains(&created), "created is shown ({created}): {row}");
    assert!(row.contains(&updated), "updated is shown ({updated}): {row}");
    assert!(
        rows.iter().any(|r| r.contains("name") && r.contains("created") && r.contains("updated") && r.contains("size")),
        "the columns are named: {rows:?}"
    );
}

/// A folder has no size to show, and reads as one.
/// @requirement AC-451
#[test]
fn a_folder_row_names_itself_as_one_and_shows_no_size() {
    let row = format_entry_row(&entry("trip", true, 0), 100);
    assert!(row.contains("trip/"), "{row}");
    assert!(!row.contains(" B"), "a folder has no size of its own: {row}");
}

/// A missing timestamp is shown as such rather than as an epoch date.
/// @requirement AC-451
#[test]
fn an_unknown_time_shows_as_a_dash() {
    assert_eq!(format_entry_time(None), "-");
}

/// @requirement AC-451
#[test]
fn backspace_walks_up_and_back_to_the_share_list() {
    let mut state = dm_with_sharing_bob(&["Photos"]);
    open_browser(&mut state);
    press(&mut state, KeyCode::Enter);
    state.set_shared_listing(BOB, "Photos", "", vec![entry("trip", true, 0)], false, None);

    // Into `trip`.
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::RequestSharedListing {
            peer: BOB,
            share: "Photos".into(),
            rel_path: "trip".into(),
        })
    );
    state.set_shared_listing(BOB, "Photos", "trip", vec![entry("beach.jpg", false, 10)], false, None);
    assert_eq!(state.shared_browser.as_ref().unwrap().location(), "/Photos/trip");

    // Back up to the share's root - another ask.
    let action = press(&mut state, KeyCode::Backspace);
    assert_eq!(
        action,
        Some(UiAction::RequestSharedListing {
            peer: BOB,
            share: "Photos".into(),
            rel_path: String::new(),
        })
    );

    // And back to the share list, which needs nothing from the peer.
    let action = press(&mut state, KeyCode::Backspace);
    assert!(action.is_none(), "the share list is already known");
    let browser = state.shared_browser.as_ref().unwrap();
    assert_eq!(browser.share, None);
    assert_eq!(browser.location(), "/");
    assert_eq!(browser.entries.len(), 1, "the peer's shares again");
}

/// @requirement AC-451, AC-459
#[test]
fn the_peers_error_is_shown_rather_than_an_empty_folder() {
    let mut state = dm_with_sharing_bob(&["Photos"]);
    open_browser(&mut state);
    press(&mut state, KeyCode::Enter);
    state.set_shared_listing(
        BOB,
        "Photos",
        "",
        Vec::new(),
        false,
        Some(SharedError::ShareUnavailable),
    );

    let rows = rendered_rows_at(&state, 110, 40);
    assert!(
        rows.iter().any(|r| r.contains("not readable on their machine")),
        "the reason names whose machine is at fault: {rows:?}"
    );
    // A failed folder leaves nothing on screen to act on, so the keys
    // that still do something are named with it.
    assert!(
        rows.iter().any(|r| r.contains("Backspace: back to their folders")),
        "the way back is offered, not only Esc: {rows:?}"
    );
}

/// The way back actually works from the error, not just in the hint.
/// @requirement AC-459
#[test]
fn backspace_leaves_a_folder_that_would_not_open() {
    let mut state = dm_with_sharing_bob(&["Photos", "Public"]);
    open_browser(&mut state);
    press(&mut state, KeyCode::Enter);
    state.set_shared_listing(
        BOB,
        "Photos",
        "",
        Vec::new(),
        false,
        Some(SharedError::ShareUnavailable),
    );

    let action = press(&mut state, KeyCode::Backspace);
    assert!(action.is_none(), "the share list needs nothing from them");
    let browser = state.shared_browser.as_ref().expect("still open");
    assert_eq!(browser.share, None, "back at their folders");
    assert!(browser.error.is_none(), "and the failure is cleared");
    assert_eq!(browser.entries.len(), 2, "both of their folders again");
    assert_eq!(state.mode, Mode::SharedFiles, "Esc is not the only way out");
}

/// @requirement AC-452, AC-453
#[test]
fn pressing_d_asks_for_the_selected_file_or_folder() {
    let mut state = dm_with_sharing_bob(&["Photos"]);
    open_browser(&mut state);

    // On a share row, before entering it at all.
    let action = press(&mut state, KeyCode::Char('d'));
    assert_eq!(
        action,
        Some(UiAction::DownloadShared {
            peer: BOB,
            share: "Photos".into(),
            rel_path: String::new(),
        }),
        "a whole share can be pulled from the top level"
    );

    press(&mut state, KeyCode::Enter);
    state.set_shared_listing(
        BOB,
        "Photos",
        "",
        vec![entry("day1", true, 0), entry("beach.jpg", false, 10)],
        false,
        None,
    );
    let action = press(&mut state, KeyCode::Char('d'));
    assert_eq!(
        action,
        Some(UiAction::DownloadShared {
            peer: BOB,
            share: "Photos".into(),
            rel_path: "day1".into(),
        }),
        "a folder row asks for everything under it"
    );

    press(&mut state, KeyCode::Down);
    let action = press(&mut state, KeyCode::Char('d'));
    assert_eq!(
        action,
        Some(UiAction::DownloadShared {
            peer: BOB,
            share: "Photos".into(),
            rel_path: "beach.jpg".into(),
        }),
        "a file row asks for that file"
    );
}

// ---------------------------------------------------------------------
// The DM notice
// ---------------------------------------------------------------------

/// @requirement AC-454
#[test]
fn opening_a_dm_with_a_sharing_peer_prints_the_notice_once() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.set_peer_shares(BOB, vec!["Photos".into()]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);

    let expected = "bob has given you access to files, type /info to access";
    let notices = state.private_rooms[&BOB]
        .log
        .iter()
        .filter(|e| matches!(&e.body, MessageBody::System(text) if text == expected))
        .count();
    assert_eq!(notices, 1, "said exactly once, in bob's own room");

    // Leaving and coming back does not say it again.
    press(&mut state, KeyCode::Esc);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    let notices = state.private_rooms[&BOB]
        .log
        .iter()
        .filter(|e| matches!(&e.body, MessageBody::System(text) if text == expected))
        .count();
    assert_eq!(notices, 1, "a revisit is not news");
}

/// @requirement AC-454
#[test]
fn an_announce_while_the_dm_is_open_prints_the_notice_and_a_withdrawal_resets_it() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    let expected = "bob has given you access to files, type /info to access";
    assert!(
        !state.private_rooms[&BOB]
            .log
            .iter()
            .any(|e| matches!(&e.body, MessageBody::System(text) if text == expected)),
        "nothing shared yet, so nothing said"
    );

    state.set_peer_shares(BOB, vec!["Photos".into()]);
    let notices = state.private_rooms[&BOB]
        .log
        .iter()
        .filter(|e| matches!(&e.body, MessageBody::System(text) if text == expected))
        .count();
    assert_eq!(notices, 1, "the room is on screen, so it is said now");

    // Taking it away and granting it again is news again.
    state.set_peer_shares(BOB, Vec::new());
    assert!(state.peer_shares.get(&BOB).is_none());
    state.set_peer_shares(BOB, vec!["Photos".into()]);
    let notices = state.private_rooms[&BOB]
        .log
        .iter()
        .filter(|e| matches!(&e.body, MessageBody::System(text) if text == expected))
        .count();
    assert_eq!(notices, 2, "granted anew, so said anew");
}

/// A link dropping and coming back is not a fresh grant: the peer
/// re-announces the same folders, and the room must not be told all over
/// again. Only a genuine withdrawal re-arms it.
/// @requirement AC-454
#[test]
fn a_link_flap_does_not_reprint_the_notice() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.set_peer_shares(BOB, vec!["Photos".into()]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    let expected = "bob has given you access to files, type /info to access";
    let notices = |state: &UiState| {
        state.private_rooms[&BOB]
            .log
            .iter()
            .filter(|e| matches!(&e.body, MessageBody::System(text) if text == expected))
            .count()
    };
    assert_eq!(notices(&state), 1);

    // The link drops - what they share is no longer browsable, but they
    // have not withdrawn it.
    state.forget_peer_shares_until_they_return(BOB);
    assert!(state.peer_shares.get(&BOB).is_none());
    // ...and comes back, with the same announce.
    state.set_peer_shares(BOB, vec!["Photos".into()]);
    assert_eq!(notices(&state), 1, "a flap is not news to announce twice");

    // A genuine withdrawal followed by a fresh grant is.
    state.set_peer_shares(BOB, Vec::new());
    state.set_peer_shares(BOB, vec!["Photos".into()]);
    assert_eq!(notices(&state), 2, "granted anew, so said anew");
}

/// The wording is specified, so it is pinned rather than paraphrased.
/// @requirement AC-454
#[test]
fn the_notice_wording_is_exact() {
    assert_eq!(
        UiState::share_notice_text("alice"),
        "alice has given you access to files, type /info to access"
    );
}

/// A peer's announce also updates a browser sitting on their share list.
/// @requirement AC-450
#[test]
fn a_withdrawn_share_disappears_from_an_open_browser() {
    let mut state = dm_with_sharing_bob(&["Photos", "Public"]);
    open_browser(&mut state);
    assert_eq!(state.shared_browser.as_ref().unwrap().entries.len(), 2);

    state.set_peer_shares(BOB, vec!["Public".into()]);
    let browser = state.shared_browser.as_ref().unwrap();
    let names: Vec<&str> = browser.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["Public"], "what they took back is gone");
}

// ---------------------------------------------------------------------
// Offers this side asked for
// ---------------------------------------------------------------------

fn offer_with_dest(dest: Option<std::path::PathBuf>) -> PendingFileOffer {
    PendingFileOffer {
        from: BOB,
        from_name: "bob".into(),
        filename: "beach.jpg".into(),
        size: 10,
        stream_id: 5,
        channel: None,
        otp_contact_name: None,
        shared_request_id: dest.as_ref().map(|_| 7),
        auto_dest: dest,
    }
}

/// @requirement AC-455
#[test]
fn an_offer_with_a_destination_is_parked_for_automatic_acceptance_not_shown() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let shown = state.push_file_offer(offer_with_dest(Some("/tmp/aloo-x/beach.jpg".into())));

    assert!(!shown, "no popup, and so no bell either");
    assert!(state.file_offer_open().is_none());
    assert_eq!(
        state.take_auto_accepts(),
        vec![(BOB, 5)],
        "it is handed to the session to accept"
    );
    assert!(
        state.take_auto_accepts().is_empty(),
        "handed over once, not on every pass"
    );
}

/// @requirement AC-455, AC-458
#[test]
fn an_offer_without_one_is_shown_exactly_as_before() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let shown = state.push_file_offer(offer_with_dest(None));

    assert!(shown, "the popup is what the user answers");
    assert_eq!(
        state.file_offer_open().map(|o| o.filename.clone()),
        Some("beach.jpg".to_string())
    );
    assert!(state.take_auto_accepts().is_empty());
}

/// An OTP-wrapped offer parks the same way - a shared download under a
/// live pad session is still a download this side asked for.
/// @requirement AC-458
#[test]
fn a_tagged_otp_offer_is_also_accepted_without_a_popup() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let mut offer = offer_with_dest(Some("/tmp/aloo-x/beach.jpg".into()));
    offer.otp_contact_name = Some("bob-otp".into());
    let shown = state.push_file_offer(offer);

    assert!(!shown);
    assert!(state.file_offer_open().is_none());
    assert_eq!(state.take_auto_accepts(), vec![(BOB, 5)]);
}

/// Ctrl+H is where a user looks for a key they have forgotten, so every
/// surface this feature adds has to be findable there - the tab that
/// shares a folder, the button that opens the browser, and the browser's
/// own keys.
/// @requirement AC-457
#[test]
fn the_help_overlay_documents_shared_folders() {
    let mut state = joined_general_with(vec![]);
    ctrl(&mut state, KeyCode::Char('h'));
    assert!(state.help_open);
    // Tall enough for the whole body, which is several screens on an
    // ordinary terminal and scrolled to in practice.
    let rows = rendered_rows_at(&state, 120, 400).join("\n");
    for needle in [
        "Shared folders",
        "File Sharing",
        "Browse shared files",
        "has given you access to files",
        "file_sharing_max_pct",
        "download the selected",
        "your Downloads",
        "cancel a running download",
        "Ctrl+D",
        "both directions and every person",
        "transfers_shortcut",
    ] {
        assert!(rows.contains(needle), "the help overlay never mentions {needle:?}");
    }
}

// ---------------------------------------------------------------------
// The Downloads tab
// ---------------------------------------------------------------------

/// A browser with two downloads on it: one still going, one finished.
fn browser_with_downloads() -> UiState {
    let mut state = dm_with_sharing_bob(&["Photos"]);
    open_browser(&mut state);
    state.start_shared_download(1, BOB, "bob".into(), "Photos".into(), "holiday".into());
    state.set_shared_download_plan(1, 4, 4_000);
    state.on_shared_download_progress(1, 1_000, std::time::Instant::now());
    state.start_shared_download(2, BOB, "bob".into(), "Photos".into(), String::new());
    state.set_shared_download_plan(2, 1, 100);
    state.finish_shared_download(2, None);
    state
}

fn downloads_tab(state: &mut UiState) {
    press(state, KeyCode::Tab);
}

/// @requirement AC-463
#[test]
fn tab_switches_to_downloads_and_the_title_counts_what_is_running() {
    let mut state = browser_with_downloads();
    let rows = rendered_rows_at(&state, 110, 40);
    assert!(
        rows.iter().any(|r| r.contains("Downloading 1...")),
        "the title says what is going on behind the Files tab: {rows:?}"
    );

    downloads_tab(&mut state);
    assert_eq!(
        state.shared_browser.as_ref().unwrap().tab,
        aloo::client::tui::shared_browser::SharedBrowserTab::Downloads
    );
    let rows = rendered_rows_at(&state, 110, 40);
    assert!(rows.iter().any(|r| r.contains("Photos/holiday")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("c: cancel")), "{rows:?}");
}

/// Everything still going is listed above everything finished with, so
/// the rows that need attention are the ones in view.
/// @requirement AC-463
#[test]
fn running_downloads_are_listed_above_finished_ones() {
    let state = browser_with_downloads();
    let rows = state.shared_download_rows();
    assert_eq!(rows[0].request_id, 1, "the running one first");
    assert_eq!(rows[1].request_id, 2);
    assert!(rows[0].status.is_active());
    assert!(!rows[1].status.is_active());
}

/// @requirement AC-463
#[test]
fn a_download_shows_a_progress_bar_and_its_counts() {
    let mut state = browser_with_downloads();
    downloads_tab(&mut state);
    let rows = rendered_rows_at(&state, 110, 40);
    let joined = rows.join("\n");
    assert!(joined.contains("25%"), "1000 of 4000 bytes: {joined}");
    assert!(joined.contains("\u{2588}"), "the bar is drawn: {joined}");
    assert!(joined.contains("0/4 files"), "{joined}");
}

/// @requirement AC-464
#[test]
fn c_cancels_a_running_download_and_r_resumes_a_stopped_one() {
    let mut state = browser_with_downloads();
    downloads_tab(&mut state);

    // The running one is selected first.
    let action = press(&mut state, KeyCode::Char('c'));
    assert_eq!(action, Some(UiAction::CancelSharedDownload { request_id: 1 }));
    // Resume does nothing while it is still running - the session has
    // not answered the cancel yet.
    assert!(press(&mut state, KeyCode::Char('r')).is_none());

    // Once stopped, resume is what it offers instead.
    state.cancel_shared_download(1);
    let action = press(&mut state, KeyCode::Char('r'));
    assert_eq!(action, Some(UiAction::ResumeSharedDownload { request_id: 1 }));
    assert!(
        press(&mut state, KeyCode::Char('c')).is_none(),
        "and cancel no longer applies"
    );
}

/// @requirement AC-464
#[test]
fn x_removes_a_finished_row_and_never_a_running_one() {
    let mut state = browser_with_downloads();
    downloads_tab(&mut state);

    // On the running row: refused, so nothing is forgotten while it is
    // still writing to disk.
    press(&mut state, KeyCode::Char('x'));
    assert_eq!(state.transfers.records().len(), 2);

    // On the finished one: removed.
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Char('x'));
    assert_eq!(state.transfers.records().len(), 1);
    assert_eq!(state.transfers.records()[0].request_id, 1);
}

/// @requirement AC-464
#[test]
fn capital_x_clears_every_finished_row_and_leaves_the_rest() {
    let mut state = browser_with_downloads();
    state.start_shared_download(3, BOB, "bob".into(), "Photos".into(), "old".into());
    state.finish_shared_download(3, Some("the link went away".into()));
    downloads_tab(&mut state);

    press(&mut state, KeyCode::Char('X'));
    assert_eq!(state.transfers.records().len(), 1, "only the running one is left");
    assert!(state.transfers.records()[0].status.is_active());
}

/// A download that finished shows full, and one that was stopped keeps
/// what it had - the row is a record, not a live count that resets.
/// @requirement AC-463
#[test]
fn a_finished_download_reads_as_done_and_a_cancelled_one_as_cancelled() {
    let mut state = browser_with_downloads();
    state.finish_shared_download(1, None);
    let done = state.shared_download(1).unwrap();
    assert_eq!(done.status.label(), "done");
    assert_eq!(done.fraction(), Some(1.0), "a finished bar reads full");

    state.start_shared_download(9, BOB, "bob".into(), "Photos".into(), "x".into());
    state.set_shared_download_plan(9, 2, 1_000);
    state.on_shared_download_progress(9, 250, std::time::Instant::now());
    state.cancel_shared_download(9);
    let stopped = state.shared_download(9).unwrap();
    assert_eq!(stopped.status.label(), "cancelled");
    assert_eq!(stopped.fraction(), Some(0.25), "what it had got is kept");
}

/// The header says something is arriving, and stops saying it when
/// nothing is.
/// @requirement AC-465
#[test]
fn the_header_shows_a_blinking_arrow_and_the_speed_while_downloading() {
    let mut state = browser_with_downloads();
    let now = std::time::Instant::now();
    state.on_shared_download_progress(1, 100_000, now);
    state.tick_download_speed(now);
    let kbps = state.fileshare_download_kbps.expect("a speed while running");
    assert!(kbps > 0, "{kbps}");

    state.blink_on = true;
    let rows = rendered_rows_at(&state, 140, 40);
    // The header is the row carrying the connection indicators, whatever
    // else is drawn above or over it.
    let header = rows
        .iter()
        .find(|r| r.contains("Conn:"))
        .cloned()
        .unwrap_or_else(|| panic!("no header row in {rows:?}"));
    assert!(header.contains("\u{2193}"), "the arrow is shown: {header}");
    assert!(header.contains(&format!("{kbps} kbps")), "{header}");

    // Nothing running: nothing shown.
    state.finish_shared_download(1, None);
    state.finish_shared_download(2, None);
    state.tick_download_speed(now);
    assert!(state.fileshare_download_kbps.is_none());
}

// ---------------------------------------------------------------------
// The File Sharing settings tab
// ---------------------------------------------------------------------

fn open_file_sharing_tab() -> UiState {
    let mut state = joined_general_with(vec![]);
    state.open_settings();
    for _ in 0..3 {
        press(&mut state, KeyCode::Tab);
    }
    assert_eq!(
        state.settings_popup.as_ref().unwrap().tab,
        SettingsTab::FileSharing
    );
    state
}

fn focused(state: &UiState) -> SettingsField {
    state.settings_popup.as_ref().unwrap().focused_field()
}

/// @requirement AC-449
#[test]
fn the_file_sharing_tab_holds_the_two_numbers_and_the_share_list() {
    let mut state = open_file_sharing_tab();
    assert_eq!(focused(&state), SettingsField::FileSharingLinkSpeedKbps);
    press(&mut state, KeyCode::Down);
    assert_eq!(focused(&state), SettingsField::FileSharingMaxPct);
    press(&mut state, KeyCode::Down);
    assert_eq!(focused(&state), SettingsField::Shares);

    let rows = rendered_rows_at(&state, 110, 46);
    assert!(
        rows.iter().any(|r| r.contains("file_sharing_link_speed_kbps")),
        "{rows:?}"
    );
    assert!(rows.iter().any(|r| r.contains("shared folders")), "{rows:?}");
}

/// A link speed needs more digits than a percentage does.
/// @requirement AC-449
#[test]
fn the_link_speed_box_takes_more_digits_than_a_percentage() {
    let mut state = open_file_sharing_tab();
    // The box opens holding the stored value (0 by default), so it is
    // cleared before typing rather than typed onto.
    press(&mut state, KeyCode::Backspace);
    type_str(&mut state, "12345678901");
    let draft = &state.settings_popup.as_ref().unwrap().draft;
    assert_eq!(
        draft.file_sharing_link_speed_kbps, "12345678",
        "eight digits is the cap"
    );

    press(&mut state, KeyCode::Down);
    for _ in 0..8 {
        press(&mut state, KeyCode::Backspace);
    }
    type_str(&mut state, "1234");
    let draft = &state.settings_popup.as_ref().unwrap().draft;
    assert_eq!(draft.file_sharing_max_pct, "123", "a percentage is three");
}

/// @requirement AC-449
#[test]
fn the_upload_budget_is_the_two_settings_multiplied() {
    let mut state = open_file_sharing_tab();
    for _ in 0..8 {
        press(&mut state, KeyCode::Backspace);
    }
    type_str(&mut state, "8000");
    let draft = state.settings_popup.as_ref().unwrap().draft.clone();
    // 8000 kbit/s is 1 MB/s; the default half of it is 500 KB/s.
    assert_eq!(draft.file_sharing_rate(), Some(500_000));
}

/// @requirement AC-448
#[test]
fn adding_a_share_from_the_tab_saves_the_whole_list() {
    let mut state = open_file_sharing_tab();
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Down);
    assert_eq!(focused(&state), SettingsField::Shares);

    press(&mut state, KeyCode::Char('a'));
    assert!(state.settings_popup.as_ref().unwrap().shares.edit.is_some());
    // A real folder: the form refuses one it could not serve (see
    // `a_share_the_form_cannot_serve_is_refused_where_it_was_typed`).
    let dir = std::env::temp_dir().join(format!("aloo-share-form-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("Photos")).unwrap();
    let path = dir.join("Photos");
    type_str(&mut state, &path.display().to_string());
    press(&mut state, KeyCode::Tab);
    // The form starts on `all`; replace it with two nicknames.
    for _ in 0..3 {
        press(&mut state, KeyCode::Backspace);
    }
    type_str(&mut state, "alice,bob");
    press(&mut state, KeyCode::Tab);
    let action = press(&mut state, KeyCode::Enter);

    match action {
        Some(UiAction::SaveShares(shares)) => {
            assert_eq!(shares.len(), 1);
            assert_eq!(
                shares[0].to_setting_value(),
                format!("{},alice,bob", path.display())
            );
            assert_eq!(shares[0].name(), "Photos");
        }
        other => panic!("expected SaveShares, got {other:?}"),
    }
    assert!(
        state.settings_popup.as_ref().unwrap().shares.edit.is_none(),
        "the form closes on a save"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-448
#[test]
fn a_duplicate_folder_name_is_refused_in_the_form() {
    let mut state = open_file_sharing_tab();
    state.set_share_rows(vec![aloo::settings::SharedFolder::parse("/srv/a/Photos,all").unwrap()]);
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Down);

    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "/srv/b/Photos");
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    let action = press(&mut state, KeyCode::Enter);

    assert!(action.is_none(), "nothing is saved");
    let edit = state
        .settings_popup
        .as_ref()
        .unwrap()
        .shares
        .edit
        .as_ref()
        .expect("the form stays open with the reason on it");
    assert!(
        edit.error.as_deref().unwrap_or_default().contains("already shared"),
        "{:?}",
        edit.error
    );
}

/// A folder nobody can read is a share nobody can browse - refused in
/// the form, where the person who can fix it is standing.
/// @requirement AC-459
#[test]
fn a_share_the_form_cannot_serve_is_refused_where_it_was_typed() {
    let mut state = open_file_sharing_tab();
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Char('a'));
    // A relative path: it would resolve against wherever aloo was
    // started, and read as an ordinary "not found" on the other side.
    type_str(&mut state, "Public");
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    let action = press(&mut state, KeyCode::Enter);

    assert!(action.is_none(), "nothing is saved");
    let edit = state
        .settings_popup
        .as_ref()
        .unwrap()
        .shares
        .edit
        .as_ref()
        .expect("the form stays open with the reason on it");
    let reason = edit.error.clone().unwrap_or_default();
    assert!(reason.contains("relative"), "{reason:?}");
}

/// @requirement AC-448
#[test]
fn an_unparseable_share_is_refused_with_the_parsers_own_reason() {
    let mut state = open_file_sharing_tab();
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Char('a'));
    // A path but nobody to share it with.
    type_str(&mut state, "/srv/Photos");
    press(&mut state, KeyCode::Tab);
    for _ in 0..3 {
        press(&mut state, KeyCode::Backspace);
    }
    press(&mut state, KeyCode::Tab);
    let action = press(&mut state, KeyCode::Enter);

    assert!(action.is_none());
    assert!(
        state.settings_popup.as_ref().unwrap().shares.edit.as_ref().unwrap().error.is_some()
    );
}

/// @requirement AC-448
#[test]
fn deleting_a_share_saves_the_list_without_it() {
    let mut state = open_file_sharing_tab();
    state.set_share_rows(vec![
        aloo::settings::SharedFolder::parse("/srv/Photos,all").unwrap(),
        aloo::settings::SharedFolder::parse("/srv/Public,all").unwrap(),
    ]);
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Down);
    let action = press(&mut state, KeyCode::Char('d'));
    match action {
        Some(UiAction::SaveShares(shares)) => {
            assert_eq!(shares.len(), 1);
            assert_eq!(shares[0].name(), "Public");
        }
        other => panic!("expected SaveShares, got {other:?}"),
    }
}
