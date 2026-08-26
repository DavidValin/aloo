//! "Add contact" (`client::tui::contacts::AddContactState`, device-pinning
//! plan §3): pinning a brand-new nickname+device before ever connecting to
//! them, then adding a PQH key for it right from the same popup.
//!
//! `handle_pin_identity_card_for_device` is exercised here against a real
//! `SessionState` because its whole distinguishing behaviour - unlike
//! `handle_pin_identity_card`, it must never close the details popup on
//! success, since Add Contact's point is letting the user keep going to
//! OTP/OTP MAIL right after - only shows up once `handle_open` has
//! actually re-gathered `ui_state.contacts.rows` from a real `IdStore`.
//! `contacts_test.rs` already covers `pin_identity_card_for_device`'s pure
//! pinning logic directly against a plain `IdStore`.

use aloo::client::connect::ResolvedIdentity;
use aloo::client::contacts;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::contacts::{ContactKeyDetailState, ContactKeyKind};
use aloo::client::tui::ui::UiState;
use aloo::crypto::otp::OtpPurpose;
use aloo::proto::KeyMode;

fn require_otp() -> bool {
    let probe = OtpCliConfig { binary_path: "otp".into(), working_dir: std::env::temp_dir() };
    if otp_cli::binary_available(&probe) {
        return true;
    }
    eprintln!(
        "skipping: 'otp' binary not found on PATH (or ALOO_OTP_BIN) - install otp-toolkit to \
         run this test locally: https://github.com/DavidValin/otp-toolkit"
    );
    false
}

async fn make_key_pair(cfg: &OtpCliConfig) -> (std::path::PathBuf, std::path::PathBuf) {
    otp_cli::new_key_pair(cfg, 1, "a", "b").await.expect("new_key_pair");
    (cfg.working_dir.join("a_keys").join("encryption_for_b.key"), cfg.working_dir.join("a_keys").join("decryption_from_b.key"))
}

const TEST_BITS: usize = 1024;

fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-contacts-add-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_identity_card(dir: &std::path::Path, nickname: &str) -> std::path::PathBuf {
    let (public, private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("generating a pq_hybrid bundle");
    let card = aloo::crypto::pq::make_identity_card(&private, &public, nickname).expect("signing an identity card");
    let path = dir.join(format!("{nickname}.card"));
    aloo::crypto::pq::save_identity_card(&card, &path).expect("saving the card");
    path
}

async fn session_for_test(label: &str) -> SessionState {
    session_for_test_with_otp(label, None).await
}

async fn session_for_test_with_otp(label: &str, otp: Option<OtpCliConfig>) -> SessionState {
    let (own_public, own_private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("own pq keygen");
    let own_public_der = aloo::proto::encode(&own_public).expect("own pq der");
    SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private: own_private, public_der: own_public_der },
        scratch: scratch(label),
        otp,
    })
    .await
}

/// The core property distinguishing Add Contact's PQH step from the
/// ordinary per-row "Create key": a successful pin must leave the details
/// popup open (so the user can carry on to OTP/OTP MAIL), and the new row
/// must already be visible by the time control returns.
/// @requirement AC-323
#[tokio::test]
async fn adding_a_pqh_key_from_a_new_contact_leaves_the_popup_open_with_the_new_row_visible() {
    let dir = scratch("card");
    let path = write_identity_card(&dir, "alice");
    let mut session = session_for_test("session").await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();
    ui.contacts.as_mut().unwrap().detail = Some(ContactKeyDetailState {
        nickname: "alice".to_string(),
        device_id: Some("laptop".to_string()),
        kind: ContactKeyKind::Pqh,
        confirm: None,
        pqh_browser: None,
        pqh_error: None,
        new_contact: true,
    });

    contacts::handle_pin_identity_card_for_device(
        &mut session,
        &mut ui,
        "alice".to_string(),
        "laptop".to_string(),
        path,
    )
    .await;

    assert!(
        ui.contacts.as_ref().unwrap().detail.is_some(),
        "unlike the ordinary per-row flow, a new-contact pin must not close the popup"
    );
    let rows = &ui.contacts.as_ref().unwrap().rows;
    let row = rows.iter().find(|r| r.nickname == "alice" && r.device_id.as_deref() == Some("laptop"));
    assert!(row.is_some(), "handle_open must have re-gathered the row the new pin just created");
    assert_eq!(row.unwrap().key_mode, Some(KeyMode::PqHybrid));
    assert!(ui.status_notice.is_some(), "a success notice, same convention as the ordinary flow");
}

/// The identity card is optional: submitting Add Contact with no card
/// imported still creates the contact, visible in the list with all
/// three key badges showing "no key" - the whole point of
/// `esc_on_the_add_contact_popup_cancels_without_creating_anything`
/// (`ui_contacts_test.rs`) being scoped to the pure-UI layer only.
/// @requirement AC-366
#[tokio::test]
async fn esc_after_submitting_with_no_card_still_leaves_a_bare_contact_pinned() {
    let mut session = session_for_test("bare-bound").await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();

    contacts::handle_add_bare_contact(&mut session, &mut ui, "alice".to_string(), "laptop".to_string())
        .await;

    let row = ui
        .contacts
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .find(|r| r.nickname == "alice" && r.device_id.as_deref() == Some("laptop"))
        .expect("the bare contact must already be a real row");
    assert_eq!(row.key_mode, None);
    assert!(row.otp.is_none());
    assert!(row.otp_mail.is_none());
    assert!(row.pqh_fingerprint.is_none());
}

/// A blank device_id claims the nickname's shared unbound slot instead of
/// one specific device - same "no keys yet" outcome.
/// @requirement AC-366
#[tokio::test]
async fn a_blank_device_id_creates_an_unbound_bare_contact() {
    let mut session = session_for_test("bare-unbound").await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();

    contacts::handle_add_bare_contact(&mut session, &mut ui, "alice".to_string(), String::new()).await;

    let row = ui
        .contacts
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .find(|r| r.nickname == "alice")
        .expect("the bare contact must already be a real row");
    assert_eq!(row.device_id, None, "a blank device_id pins the unbound slot");
    assert_eq!(row.key_mode, None);
}

/// The invariant `pin_bare_contact`/`pin_new_device_with_key_mode` exist
/// to uphold, proven end to end: importing a card for the exact device a
/// bare placeholder already reserved must fill it in place, not leave the
/// placeholder behind as a second, ghost "(unbound)"-style row.
/// @requirement AC-366
#[tokio::test]
async fn importing_a_card_over_a_bare_placeholder_does_not_leave_a_duplicate_row() {
    let dir = scratch("card-over-bare");
    let path = write_identity_card(&dir, "alice");
    let mut session = session_for_test("bare-then-card").await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();

    contacts::handle_add_bare_contact(&mut session, &mut ui, "alice".to_string(), "laptop".to_string())
        .await;
    contacts::handle_pin_identity_card_for_device(
        &mut session,
        &mut ui,
        "alice".to_string(),
        "laptop".to_string(),
        path,
    )
    .await;

    let rows: Vec<_> =
        ui.contacts.as_ref().unwrap().rows.iter().filter(|r| r.nickname == "alice").collect();
    assert_eq!(rows.len(), 1, "the placeholder must be filled in place, not duplicated");
    assert_eq!(rows[0].key_mode, Some(KeyMode::PqHybrid));
}

/// A nickname mismatch (the card vouches for someone else) must show
/// inline, exactly like the ordinary per-row flow's own error path - and
/// nothing must be pinned.
/// @requirement AC-323
#[tokio::test]
async fn a_mismatched_card_shows_an_inline_error_and_pins_nothing() {
    let dir = scratch("card-mismatch");
    let path = write_identity_card(&dir, "someone-else");
    let mut session = session_for_test("session-mismatch").await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();
    ui.contacts.as_mut().unwrap().detail = Some(ContactKeyDetailState {
        nickname: "alice".to_string(),
        device_id: Some("laptop".to_string()),
        kind: ContactKeyKind::Pqh,
        confirm: None,
        pqh_browser: None,
        pqh_error: None,
        new_contact: true,
    });

    contacts::handle_pin_identity_card_for_device(
        &mut session,
        &mut ui,
        "alice".to_string(),
        "laptop".to_string(),
        path,
    )
    .await;

    assert!(ui.contacts.as_ref().unwrap().detail.as_ref().unwrap().pqh_error.is_some());
    assert!(session.id_store_mut().get_for_device("alice", "laptop").is_none());
}

/// The end-to-end promise of "Add contact": pin PQH first, then OTP
/// becomes installable for that exact device in the very same sitting -
/// `install_otp_key`'s `otp_contact_name_for` needs a real pinned key to
/// derive a name from, which a brand-new contact only gets once the PQH
/// step above has run.
/// @requirement AC-323
#[tokio::test]
async fn otp_becomes_installable_right_after_pqh_is_added_from_the_same_popup() {
    if !require_otp() {
        return;
    }
    let dir = scratch("card-then-otp");
    let path = write_identity_card(&dir, "alice");
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp") };
    let mut session = session_for_test_with_otp("session-then-otp", Some(cfg.clone())).await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();
    ui.contacts.as_mut().unwrap().detail = Some(ContactKeyDetailState {
        nickname: "alice".to_string(),
        device_id: Some("laptop".to_string()),
        kind: ContactKeyKind::Pqh,
        confirm: None,
        pqh_browser: None,
        pqh_error: None,
        new_contact: true,
    });
    contacts::handle_pin_identity_card_for_device(
        &mut session,
        &mut ui,
        "alice".to_string(),
        "laptop".to_string(),
        path,
    )
    .await;
    let row = ui
        .contacts
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .find(|r| r.nickname == "alice" && r.device_id.as_deref() == Some("laptop"))
        .expect("PQH step must have created the row");
    assert!(row.otp_contact_name.is_some(), "a real pin now exists, so an OTP name can be derived");

    let (enc, dec) = make_key_pair(&cfg).await;
    contacts::handle_install_otp_key(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
        OtpPurpose::Live,
        enc,
        dec,
    )
    .await;
    let row = ui
        .contacts
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .find(|r| r.nickname == "alice" && r.device_id.as_deref() == Some("laptop"))
        .expect("still there after the OTP install refresh");
    assert!(row.otp.is_some(), "OTP install must succeed now that PQH is pinned");
}
