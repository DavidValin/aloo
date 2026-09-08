//! Shared folders (US-066): naming a folder to share, being told about
//! someone else's, browsing it and asking for what is in it.
//!
//! Everything here is the UI's own decisions - the wire exchange behind
//! them is `test/shared_session_test.rs`, and the filesystem work
//! `test/shared_folders_test.rs`.

use cucumber::{given, then, when};

use aloo::client::shared_folders::SharedEntry;
use aloo::client::tui::settings_popup::{SettingsField, SettingsTab};
use aloo::client::tui::ui::{Focus, MessageBody, Mode, PendingFileOffer, UiAction};
use aloo::proto::UserId;
use crossterm::event::{KeyCode, KeyModifiers};

use crate::steps::ui_common::{id_for, press_key};
use crate::support::ui_rows_wide;
use crate::world::AlooWorld;

/// The two timestamps every scenario's entries carry - fixed, so a row's
/// rendering is checked against a known value rather than "now".
const CREATED: u64 = 1_700_000_000;
const UPDATED: u64 = 1_700_003_600;

fn entry(name: &str, is_dir: bool, size: u64) -> SharedEntry {
    SharedEntry {
        name: name.into(),
        is_dir,
        size,
        created_unix: Some(CREATED),
        modified_unix: Some(UPDATED),
    }
}

// ---------------------------------------------------------------------
// Given / When - the settings tab
// ---------------------------------------------------------------------

#[given("I move to the File Sharing tab")]
#[when("I move to the File Sharing tab")]
async fn move_to_file_sharing_tab(w: &mut AlooWorld) {
    for _ in 0..SettingsTab::ALL.len() {
        if w.ui_ref().settings_popup.as_ref().expect("popup open").tab
            == SettingsTab::FileSharing
        {
            return;
        }
        press_key(w, KeyCode::Tab, KeyModifiers::NONE);
    }
    panic!("the File Sharing tab was not reached");
}

/// A real folder for a scenario to share - the form refuses one it could
/// not serve (`shared_folders::share_root_problem`), so a scenario names
/// a folder under this run's own scratch directory rather than a path
/// that happens not to exist.
fn scenario_folder(sub: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("aloo-cucumber-shares-{}", std::process::id()))
        .join(sub);
    std::fs::create_dir_all(&dir).expect("a scratch folder to share");
    dir
}

/// Walks to the share list and fills in the add form, exactly as a user
/// would - the form builds the settings line itself.
#[given(expr = "I share my folder {string} with {string}")]
#[when(expr = "I share my folder {string} with {string}")]
async fn share_folder(w: &mut AlooWorld, sub: String, access: String) {
    let path = scenario_folder(&sub).display().to_string();
    for _ in 0..8 {
        if w.ui_ref()
            .settings_popup
            .as_ref()
            .expect("popup open")
            .focused_field()
            == SettingsField::Shares
        {
            break;
        }
        press_key(w, KeyCode::Down, KeyModifiers::NONE);
    }
    press_key(w, KeyCode::Char('a'), KeyModifiers::NONE);
    for c in path.chars() {
        press_key(w, KeyCode::Char(c), KeyModifiers::NONE);
    }
    press_key(w, KeyCode::Tab, KeyModifiers::NONE);
    // The form offers `all`; whatever the scenario asked for replaces it.
    for _ in 0..3 {
        press_key(w, KeyCode::Backspace, KeyModifiers::NONE);
    }
    for c in access.chars() {
        press_key(w, KeyCode::Char(c), KeyModifiers::NONE);
    }
    press_key(w, KeyCode::Tab, KeyModifiers::NONE);
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
}

// ---------------------------------------------------------------------
// Given / When - the other side's shares
// ---------------------------------------------------------------------

#[given(expr = "{word} has shared {string} with me")]
#[when(expr = "{word} has shared {string} with me")]
async fn peer_has_shared(w: &mut AlooWorld, name: String, shares: String) {
    let peer = UserId(id_for(&name));
    let names: Vec<String> = shares.split(',').map(|s| s.trim().to_string()).collect();
    w.ui_mut().set_peer_shares(peer, names);
}

#[when(expr = "{word} shares {string} with me instead")]
async fn peer_shares_instead(w: &mut AlooWorld, name: String, shares: String) {
    peer_has_shared(w, name, shares).await;
}

#[given(expr = "I have opened the shared files browser for {word}")]
#[when(expr = "I open the shared files browser for {word}")]
async fn open_browser(w: &mut AlooWorld, name: String) {
    crate::steps::ui_common::open_private_room(w, name).await;
    for c in "/info".chars() {
        press_key(w, KeyCode::Char(c), KeyModifiers::NONE);
    }
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(
        w.ui_ref().mode,
        Mode::SharedFiles,
        "the browser should be open"
    );
}

#[when(expr = "I leave and reopen the room with {word}")]
async fn leave_and_reopen(w: &mut AlooWorld, name: String) {
    press_key(w, KeyCode::Esc, KeyModifiers::NONE);
    crate::steps::ui_common::open_private_room(w, name).await;
}

#[given(expr = "{word} answers with the folder {string} and the file {string} of {int} bytes")]
#[when(expr = "{word} answers with the folder {string} and the file {string} of {int} bytes")]
async fn peer_answers_listing(
    w: &mut AlooWorld,
    name: String,
    folder: String,
    file: String,
    size: u64,
) {
    let peer = UserId(id_for(&name));
    let (share, rel_path) = {
        let browser = w.ui_ref().shared_browser.as_ref().expect("the browser is open");
        (
            browser.share.clone().unwrap_or_default(),
            browser.rel_path.clone(),
        )
    };
    w.ui_mut().set_shared_listing(
        peer,
        &share,
        &rel_path,
        vec![entry(&folder, true, 0), entry(&file, false, size)],
        false,
        None,
    );
}

/// An offer for a file this side asked for: it carries the destination
/// the owner's tag named, which is what keeps it out of the popup.
#[when(expr = "{word} offers me {string} as a file I asked for")]
async fn peer_offers_requested_file(w: &mut AlooWorld, name: String, filename: String) {
    let peer = UserId(id_for(&name));
    let shown = w.ui_mut().push_file_offer(PendingFileOffer {
        from: peer,
        from_name: name,
        filename,
        size: 2048,
        stream_id: 1,
        channel: None,
        otp_contact_name: None,
        auto_dest: Some(std::path::PathBuf::from("/tmp/aloo-shared/beach.jpg")),
        shared_request_id: Some(1),
    });
    assert!(!shown, "a file this side asked for never becomes a popup");
}

// ---------------------------------------------------------------------
// Then
// ---------------------------------------------------------------------

#[then(expr = "the saved shares are {string}")]
async fn saved_shares_are(w: &mut AlooWorld, expected: String) {
    let rows = &w.ui_ref().settings_popup.as_ref().expect("popup open").shares.rows;
    let names: Vec<String> = rows.iter().map(|r| r.name()).collect();
    let want: Vec<String> = expected.split(',').map(|s| s.trim().to_string()).collect();
    assert_eq!(names, want);
}

#[then(expr = "the saved share line ends with {string}")]
async fn saved_share_line_ends_with(w: &mut AlooWorld, expected: String) {
    match w.last_action.clone() {
        Some(UiAction::SaveShares(shares)) => {
            let lines: Vec<String> = shares.iter().map(|s| s.to_setting_value()).collect();
            assert!(
                lines.iter().any(|l| l.ends_with(&expected)),
                "expected a line ending {expected:?} among {lines:?}"
            );
        }
        other => panic!("expected the whole list to be saved, got {other:?}"),
    }
}

#[then("the share form refuses it as already shared")]
async fn share_form_refuses_duplicate(w: &mut AlooWorld) {
    let edit = w
        .ui_ref()
        .settings_popup
        .as_ref()
        .expect("popup open")
        .shares
        .edit
        .as_ref()
        .expect("the form stays open with the reason on it");
    let reason = edit.error.clone().unwrap_or_default();
    assert!(reason.contains("already shared"), "{reason:?}");
}

#[then(expr = "the room with {word} says {string}")]
async fn room_says(w: &mut AlooWorld, name: String, expected: String) {
    let peer = UserId(id_for(&name));
    let room = w.ui_ref().private_rooms.get(&peer).expect("the room exists");
    assert!(
        room.log
            .iter()
            .any(|e| matches!(&e.body, MessageBody::System(text) if *text == expected)),
        "expected {expected:?} in {:?}",
        room.log.iter().map(|e| e.body.clone()).collect::<Vec<_>>()
    );
}

#[then(expr = "the room with {word} says once {string}")]
async fn room_says_once(w: &mut AlooWorld, name: String, expected: String) {
    let peer = UserId(id_for(&name));
    let room = w.ui_ref().private_rooms.get(&peer).expect("the room exists");
    let count = room
        .log
        .iter()
        .filter(|e| matches!(&e.body, MessageBody::System(text) if *text == expected))
        .count();
    assert_eq!(count, 1, "said exactly once, however often the room is opened");
}

#[then("the user info popup offers to browse shared files")]
async fn info_offers_browse(w: &mut AlooWorld) {
    assert!(w.ui_ref().user_info.is_some(), "the info popup is open");
    let rows = ui_rows_wide(w.ui_ref());
    assert!(
        rows.iter().any(|r| r.contains("Browse shared files")),
        "{rows:?}"
    );
}

#[then("the user info popup does not offer to browse shared files")]
async fn info_does_not_offer_browse(w: &mut AlooWorld) {
    assert!(w.ui_ref().user_info.is_some(), "the info popup is open");
    let rows = ui_rows_wide(w.ui_ref());
    assert!(
        !rows.iter().any(|r| r.contains("Browse shared files")),
        "{rows:?}"
    );
}

#[then(expr = "the shared files browser is open on {word}'s shares")]
async fn browser_open_on_shares(w: &mut AlooWorld, name: String) {
    let peer = UserId(id_for(&name));
    assert_eq!(w.ui_ref().mode, Mode::SharedFiles);
    let browser = w.ui_ref().shared_browser.as_ref().expect("the browser is open");
    assert_eq!(browser.peer, peer);
    assert_eq!(browser.share, None, "it opens on the share list");
    assert!(!browser.entries.is_empty(), "their shares are listed");
}

#[then(expr = "a listing of {string} is requested from {word}")]
async fn listing_requested(w: &mut AlooWorld, share: String, name: String) {
    let peer = UserId(id_for(&name));
    match w.last_action.clone() {
        Some(UiAction::RequestSharedListing {
            peer: to,
            share: asked,
            rel_path,
        }) => {
            assert_eq!(to, peer);
            assert_eq!(asked, share);
            assert_eq!(rel_path, "", "a share is entered at its root");
        }
        other => panic!("expected a listing request, got {other:?}"),
    }
}

#[then("the browser says it is loading")]
async fn browser_loading(w: &mut AlooWorld) {
    assert!(
        w.ui_ref().shared_browser.as_ref().expect("open").loading,
        "nothing is known until the owner answers"
    );
    let rows = ui_rows_wide(w.ui_ref());
    assert!(rows.iter().any(|r| r.contains("loading")), "{rows:?}");
}

#[then(expr = "the browser row for {string} shows its size as {string}")]
async fn row_shows_size(w: &mut AlooWorld, filename: String, size: String) {
    let rows = ui_rows_wide(w.ui_ref());
    let row = rows
        .iter()
        .find(|r| r.contains(&filename))
        .unwrap_or_else(|| panic!("no row for {filename:?} in {rows:?}"));
    assert!(row.contains(&size), "{row}");
}

#[then(expr = "the browser row for {string} shows a created and an updated time")]
async fn row_shows_times(w: &mut AlooWorld, filename: String) {
    let created = aloo::client::tui::shared_browser::format_entry_time(Some(CREATED));
    let updated = aloo::client::tui::shared_browser::format_entry_time(Some(UPDATED));
    let rows = ui_rows_wide(w.ui_ref());
    let row = rows
        .iter()
        .find(|r| r.contains(&filename))
        .unwrap_or_else(|| panic!("no row for {filename:?} in {rows:?}"));
    assert!(row.contains(&created), "created {created:?} missing from {row}");
    assert!(row.contains(&updated), "updated {updated:?} missing from {row}");
}

#[then("the browser names the columns name, created, updated and size")]
async fn browser_names_columns(w: &mut AlooWorld) {
    let rows = ui_rows_wide(w.ui_ref());
    assert!(
        rows.iter().any(|r| {
            r.contains("name") && r.contains("created") && r.contains("updated") && r.contains("size")
        }),
        "{rows:?}"
    );
}

#[then(expr = "downloading {string} from {word}'s {string} is requested")]
async fn download_requested(w: &mut AlooWorld, rel_path: String, name: String, share: String) {
    let peer = UserId(id_for(&name));
    match w.last_action.clone() {
        Some(UiAction::DownloadShared {
            peer: to,
            share: asked,
            rel_path: path,
        }) => {
            assert_eq!(to, peer);
            assert_eq!(asked, share);
            assert_eq!(path, rel_path);
        }
        other => panic!("expected a download request, got {other:?}"),
    }
}

#[then("no file offer popup is shown")]
async fn no_offer_popup(w: &mut AlooWorld) {
    assert!(
        w.ui_ref().file_offer_open().is_none(),
        "a file this side asked for is never put to the user again"
    );
}

#[then("that offer is handed to the session to accept")]
async fn offer_handed_over(w: &mut AlooWorld) {
    let parked = w.ui_mut().take_auto_accepts();
    assert_eq!(parked.len(), 1, "exactly one offer is waiting to be accepted");
}

#[then(expr = "the browser lists only {string}")]
async fn browser_lists_only(w: &mut AlooWorld, expected: String) {
    let browser = w.ui_ref().shared_browser.as_ref().expect("the browser is open");
    let names: Vec<String> = browser.entries.iter().map(|e| e.name.clone()).collect();
    let want: Vec<String> = expected.split(',').map(|s| s.trim().to_string()).collect();
    assert_eq!(names, want);
}

/// The sidebar is where a DM is opened from, and a scenario that only
/// named the peer has not focused it yet.
#[given(expr = "focus is on bob in the sidebar")]
async fn focus_bob(w: &mut AlooWorld) {
    w.ui_mut().focus = Focus::Sidebar;
}

// ---------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------

/// A download part-way through, without a peer on the other end: the row
/// is the thing under test here, and the wire exchange behind it is
/// `test/shared_session_test.rs`.
#[given(expr = "a download of {string} from {word} is half done")]
#[when(expr = "a download of {string} from {word} is half done")]
async fn half_done_download(w: &mut AlooWorld, what: String, name: String) {
    let peer = UserId(id_for(&name));
    let (share, rel_path) = match what.split_once('/') {
        Some((share, rel)) => (share.to_string(), rel.to_string()),
        None => (what.clone(), String::new()),
    };
    let state = w.ui_mut();
    state.start_shared_download(1, peer, name, share, rel_path);
    state.set_shared_download_plan(1, 4, 4_000);
    state.on_shared_download_progress(1, 2_000, std::time::Instant::now());
}

#[given(expr = "a download of {string} from {word} has finished")]
async fn finished_download(w: &mut AlooWorld, what: String, name: String) {
    let peer = UserId(id_for(&name));
    let (share, rel_path) = match what.split_once('/') {
        Some((share, rel)) => (share.to_string(), rel.to_string()),
        None => (what.clone(), String::new()),
    };
    let state = w.ui_mut();
    state.start_shared_download(2, peer, name, share, rel_path);
    state.set_shared_download_plan(2, 1, 100);
    state.finish_shared_download(2, None);
}

#[then(expr = "the browser title says {string}")]
async fn browser_title_says(w: &mut AlooWorld, expected: String) {
    let rows = ui_rows_wide(w.ui_ref());
    assert!(
        rows.iter().any(|r| r.contains(&expected)),
        "expected {expected:?} in {rows:?}"
    );
}

#[then(expr = "the downloads tab shows {string} with a progress bar")]
async fn downloads_tab_shows(w: &mut AlooWorld, label: String) {
    let rows = ui_rows_wide(w.ui_ref());
    assert!(
        rows.iter().any(|r| r.contains(&label)),
        "expected {label:?} in {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains('\u{2588}')),
        "expected a progress bar in {rows:?}"
    );
}

#[then(expr = "cancelling that download is requested")]
async fn cancel_requested(w: &mut AlooWorld) {
    match w.last_action.clone() {
        Some(UiAction::CancelSharedDownload { request_id }) => assert_eq!(request_id, 1),
        other => panic!("expected a cancel, got {other:?}"),
    }
}

#[then(expr = "the downloads tab still lists {int} downloads")]
async fn downloads_tab_lists(w: &mut AlooWorld, count: usize) {
    assert_eq!(w.ui_ref().transfers.records().len(), count);
}

#[then(expr = "the room with {word} holds no file row")]
async fn room_holds_no_file_row(w: &mut AlooWorld, name: String) {
    let peer = UserId(id_for(&name));
    let Some(room) = w.ui_ref().private_rooms.get(&peer) else {
        return;
    };
    assert!(
        !room
            .log
            .iter()
            .any(|e| matches!(e.body, MessageBody::File { .. })),
        "a download must not write a row into the conversation"
    );
}

// ---------------------------------------------------------------------
// Layout and overlapping folders - the filesystem rules, driven directly
// ---------------------------------------------------------------------

/// A real folder tree to share, and the share line for it.
fn shared_tree(sub: &str, files: &[&str]) -> aloo::settings::SharedFolder {
    let root = scenario_folder(&format!("tree-{sub}"));
    for file in files {
        let path = root.join(file);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, "content").unwrap();
    }
    aloo::settings::SharedFolder::parse(&format!("{},all", root.display())).unwrap()
}

#[given(expr = "{word} shares a folder holding {string}")]
async fn peer_shares_tree(w: &mut AlooWorld, _name: String, file: String) {
    w.shared_tree = Some(shared_tree("layout", &[file.as_str()]));
}

#[when(expr = "I download {string} from it")]
async fn download_from_tree(w: &mut AlooWorld, rel: String) {
    let share = w.shared_tree.clone().expect("a shared tree");
    let (files, error) =
        aloo::client::shared_folders::collect_download(&share.root(), &rel, &[]);
    assert!(error.is_none(), "{error:?}");
    w.collected = files
        .into_iter()
        .map(|f| {
            aloo::client::shared_folders::download_dest(
                std::path::Path::new("fileshare"),
                "bob",
                "Photos",
                &f.rel_path,
            )
        })
        .collect();
}

#[then(expr = "the file lands under {string}")]
async fn file_lands_under(w: &mut AlooWorld, expected: String) {
    let shown: Vec<String> = w
        .collected
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    assert!(
        shown.iter().any(|p| p.ends_with(&expected)),
        "expected a path ending {expected:?} among {shown:?}"
    );
}

#[given(expr = "{word} shares a folder with me holding a folder only {word} may see")]
async fn overlapping_shares(w: &mut AlooWorld, _owner: String, other: String) {
    let wide = shared_tree("wide", &["notes.txt", "payroll/salaries.csv"]);
    let narrow = aloo::settings::SharedFolder::parse(&format!(
        "{},{other}",
        wide.root().join("payroll").display()
    ))
    .unwrap();
    w.shared_tree = Some(wide.clone());
    w.forbidden = aloo::client::shared_folders::forbidden_roots(&[wide, narrow], "me");
}

#[then("browsing it does not list the folder only alice may see")]
async fn overlap_not_listed(w: &mut AlooWorld) {
    let share = w.shared_tree.clone().expect("a shared tree");
    let (entries, _) =
        aloo::client::shared_folders::list_directory(&share.root(), "", &w.forbidden).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["notes.txt"], "the nested share must not be listed");
}

#[then("asking for that folder by name is refused")]
async fn overlap_refused(w: &mut AlooWorld) {
    let share = w.shared_tree.clone().expect("a shared tree");
    let err =
        aloo::client::shared_folders::resolve_shared_path(&share.root(), "payroll", &w.forbidden)
            .unwrap_err();
    assert_eq!(err, aloo::client::shared_folders::SharedError::NoSuchShare);
}

#[then("downloading the whole share leaves it out")]
async fn overlap_left_out(w: &mut AlooWorld) {
    let share = w.shared_tree.clone().expect("a shared tree");
    let (files, _) =
        aloo::client::shared_folders::collect_download(&share.root(), "", &w.forbidden);
    let rels: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
    assert_eq!(rels, vec!["notes.txt"]);
}

// ---------------------------------------------------------------------
// The global transfers popup
// ---------------------------------------------------------------------

fn transfer(
    direction: aloo::client::transfer_log::TransferDirection,
    id: u64,
    peer: &str,
    what: &str,
    status: aloo::client::transfer_log::TransferStatus,
) -> aloo::client::transfer_log::TransferRecord {
    let (share, rel_path) = match what.split_once('/') {
        Some((share, rel)) => (share.to_string(), rel.to_string()),
        None => (what.to_string(), String::new()),
    };
    aloo::client::transfer_log::TransferRecord {
        request_id: id,
        direction,
        peer_name: peer.to_string(),
        share,
        rel_path,
        status,
        files_total: Some(4),
        bytes_total: Some(4_000),
        files_done: 1,
        bytes_done: 1_000,
        files_skipped: 0,
        started_unix: aloo::client::transfer_log::now_unix(),
    }
}

#[given(expr = "a download of {string} from {word} is running")]
async fn a_download_running(w: &mut AlooWorld, what: String, peer: String) {
    use aloo::client::transfer_log::{TransferDirection, TransferStatus};
    w.ui_mut().transfers.start(transfer(
        TransferDirection::Download,
        1,
        &peer,
        &what,
        TransferStatus::Running,
    ));
}

#[given(expr = "an upload of {string} to {word} is running")]
async fn an_upload_running(w: &mut AlooWorld, what: String, peer: String) {
    use aloo::client::transfer_log::{TransferDirection, TransferStatus};
    w.ui_mut().transfers.start(transfer(
        TransferDirection::Upload,
        2,
        &peer,
        &what,
        TransferStatus::Running,
    ));
}

#[given(expr = "an upload of {string} to {word} has finished")]
async fn an_upload_finished(w: &mut AlooWorld, what: String, peer: String) {
    use aloo::client::transfer_log::{TransferDirection, TransferStatus};
    w.ui_mut().transfers.start(transfer(
        TransferDirection::Upload,
        2,
        &peer,
        &what,
        TransferStatus::Completed,
    ));
}

#[given("I press the transfers shortcut")]
#[when("I press the transfers shortcut")]
async fn press_transfers_shortcut(w: &mut AlooWorld) {
    // Whatever the settings say it is - the default here, since no
    // scenario changes it.
    let chord = w.ui_ref().transfers_shortcut.clone();
    let mut modifiers = KeyModifiers::NONE;
    if chord.ctrl {
        modifiers |= KeyModifiers::CONTROL;
    }
    if chord.alt {
        modifiers |= KeyModifiers::ALT;
    }
    let code = match chord.key {
        aloo::settings::KeyChordKey::Char(c) => KeyCode::Char(c),
        aloo::settings::KeyChordKey::Function(n) => KeyCode::F(n),
    };
    press_key(w, code, modifiers);
}

#[then("the transfers popup is open")]
async fn transfers_popup_open(w: &mut AlooWorld) {
    assert!(
        w.ui_ref().transfers_popup.is_some(),
        "the transfers popup should be open"
    );
}

#[then("the transfers popup is closed")]
async fn transfers_popup_closed(w: &mut AlooWorld) {
    assert!(w.ui_ref().transfers_popup.is_none());
}

#[then(expr = "the transfers popup lists {string} from {word}")]
async fn popup_lists_from(w: &mut AlooWorld, what: String, peer: String) {
    let rows = ui_rows_wide(w.ui_ref());
    let want = format!("from {peer}");
    assert!(
        rows.iter().any(|r| r.contains(&what) && r.contains(&want)),
        "expected {what:?} {want:?} in {rows:?}"
    );
}

#[then(expr = "the transfers popup lists {string} to {word}")]
async fn popup_lists_to(w: &mut AlooWorld, what: String, peer: String) {
    let rows = ui_rows_wide(w.ui_ref());
    let want = format!("to {peer}");
    assert!(
        rows.iter().any(|r| r.contains(&what) && r.contains(&want)),
        "expected {what:?} {want:?} in {rows:?}"
    );
}

#[then(expr = "the transfers popup says {int} transfer is running")]
async fn popup_says_running(w: &mut AlooWorld, count: usize) {
    let rows = ui_rows_wide(w.ui_ref());
    let want = format!("{count} running");
    assert!(
        rows.iter().any(|r| r.contains(&want)),
        "expected {want:?} in {rows:?}"
    );
}

#[then("cancelling that upload is requested")]
async fn cancel_upload_requested(w: &mut AlooWorld) {
    match w.last_action.clone() {
        Some(UiAction::CancelSharedUpload { request_id }) => assert_eq!(request_id, 2),
        other => panic!("expected an upload cancel, got {other:?}"),
    }
}
