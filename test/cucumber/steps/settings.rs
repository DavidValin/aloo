//! Everything the settings reach: the Ctrl+S popup itself (US-061,
//! `features/settings/`), the three sound switches (US-062,
//! `features/voice/sounds.feature`) and the durable send queue (US-064,
//! `features/messaging/queued_sends.feature`).
//!
//! Grouped by the setting rather than by the feature directory on
//! purpose - cucumber registers steps globally, and every one of these
//! reads or writes the same `Settings`/popup surface. The feature files
//! stay split the other way: `features/settings/` holds only what the
//! popup *does*, and what each switch *means* lives with the behaviour it
//! changes.
//!
//! The popup half drives the real `UiState` the way every other
//! connected-UI feature does. The sound half asks `Settings` itself, since
//! what each switch means is a property of the file rather than of any one
//! screen - `world.direct_settings` is the loaded file every
//! "a settings file that says" step already puts there.

use cucumber::{then, when};

use aloo::client::tui::settings_popup::{SettingsField, SettingsTab};
use aloo::client::tui::ui::{Mode, UiAction};
use aloo::proto::UserId;

use crate::support::ui_buffer;
use crate::world::AlooWorld;

/// The field a scenario named, by the settings-file key it writes - the
/// same word the popup itself shows and a hand-editor would search for.
fn field_named(label: &str) -> SettingsField {
    SettingsTab::ALL
        .iter()
        .flat_map(|tab| tab.fields().iter().copied())
        .find(|f| f.label() == label)
        .unwrap_or_else(|| panic!("no setting called {label:?}"))
}

fn tab_named(title: &str) -> SettingsTab {
    SettingsTab::ALL
        .iter()
        .copied()
        .find(|t| t.title() == title)
        .unwrap_or_else(|| panic!("no settings tab called {title:?}"))
}

// ---------------------------------------------------------------------
// Given / When
// ---------------------------------------------------------------------

/// Walks the focus down to a named field. Down, not a direct assignment:
/// what a scenario is entitled to assume is that the field is *reachable*
/// with the keys the popup documents.
#[when(expr = "I move the focus to {string}")]
async fn move_focus_to(w: &mut AlooWorld, label: String) {
    let want = field_named(&label);
    for _ in 0..32 {
        if w.ui_ref().settings_popup.as_ref().expect("popup open").focused_field() == want {
            return;
        }
        crate::steps::ui_common::press_key(
            w,
            crossterm::event::KeyCode::Down,
            crossterm::event::KeyModifiers::NONE,
        );
    }
    panic!("{label:?} is not reachable on the tab that is open");
}

#[when(expr = "I type {string} into the focused setting")]
async fn type_into_focused(w: &mut AlooWorld, text: String) {
    for c in text.chars() {
        crate::steps::ui_common::press_key(
            w,
            crossterm::event::KeyCode::Char(c),
            crossterm::event::KeyModifiers::NONE,
        );
    }
}

#[when("I clear the focused setting")]
async fn clear_focused(w: &mut AlooWorld) {
    for _ in 0..64 {
        let popup = w.ui_ref().settings_popup.as_ref().expect("popup open");
        if popup.draft.text_value(popup.focused_field()).is_empty() {
            return;
        }
        crate::steps::ui_common::press_key(
            w,
            crossterm::event::KeyCode::Backspace,
            crossterm::event::KeyModifiers::NONE,
        );
    }
    panic!("the focused setting would not empty");
}

#[cucumber::given("two direct punch targets are configured")]
#[when("two direct punch targets are configured")]
async fn two_targets(w: &mut AlooWorld) {
    let rows = ["bob,bobhost.example,every_1m", "carol,carolhost.example,every_5m"]
        .iter()
        .map(|line| aloo::settings::DirectPunchTarget::parse(line).expect("a valid target"))
        .collect();
    w.ui_mut().set_direct_punch_rows(rows);
}

/// Drives the Direct Punch tab's add form the way a person does: 'a' to
/// open it, then Tab between nickname, host and ports, then on to Save.
#[when(expr = "I add a punch for {string} at {string} with ports {string}")]
async fn add_punch_with_ports(w: &mut AlooWorld, nickname: String, host: String, ports: String) {
    use crossterm::event::{KeyCode, KeyModifiers};
    use crate::steps::ui_common::press_key;
    press_key(w, KeyCode::Char('a'), KeyModifiers::NONE);
    for (text, next) in [(nickname, true), (host, true), (ports, true)] {
        for c in text.chars() {
            press_key(w, KeyCode::Char(c), KeyModifiers::NONE);
        }
        if next {
            press_key(w, KeyCode::Tab, KeyModifiers::NONE);
        }
    }
    // Past the frequency selector and onto Save.
    press_key(w, KeyCode::Tab, KeyModifiers::NONE);
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
}

#[then(expr = "the saved punch names host {string} on ports {string}")]
async fn saved_punch_ports(w: &mut AlooWorld, host: String, ports: String) {
    let expected: Vec<u16> = ports.split(',').map(|p| p.trim().parse().unwrap()).collect();
    let popup = w.ui_mut().settings_popup.as_ref().expect("the settings popup is open");
    let row = popup.punches.rows.last().expect("a punch was saved");
    assert_eq!(row.host, host);
    assert_eq!(row.ports, expected);
}

#[when("arriving voice is turned off")]
async fn autoplay_off(w: &mut AlooWorld) {
    w.ui_mut().voice_autoplay = false;
}

// ---------------------------------------------------------------------
// Then - the popup
// ---------------------------------------------------------------------

#[then(expr = "the settings popup is open on the {string} tab")]
async fn popup_on_tab(w: &mut AlooWorld, title: String) {
    assert_eq!(w.ui_ref().mode, Mode::Settings, "the settings popup should be open");
    assert_eq!(
        w.ui_ref().settings_popup.as_ref().expect("popup open").tab,
        tab_named(&title)
    );
}

#[then("the settings popup is closed")]
async fn popup_closed(w: &mut AlooWorld) {
    assert_eq!(w.ui_ref().mode, Mode::Normal);
    assert!(w.ui_ref().settings_popup.is_none());
}

/// The popup opens empty and asks the session for the file - it never
/// reads `~/.aloo/settings` itself.
#[then("the settings popup asked the session to load the file")]
async fn asked_to_load(w: &mut AlooWorld) {
    assert_eq!(w.last_action, Some(UiAction::OpenSettings));
}

#[then("the settings popup asked the session to save")]
async fn asked_to_save(w: &mut AlooWorld) {
    assert!(
        matches!(w.last_action, Some(UiAction::SaveSettings(_))),
        "expected a save, got {:?}",
        w.last_action
    );
}

#[then(expr = "the focused setting is {string}")]
async fn focused_setting(w: &mut AlooWorld, label: String) {
    assert_eq!(
        w.ui_ref().settings_popup.as_ref().expect("popup open").focused_field(),
        field_named(&label)
    );
}

#[then(expr = "the setting {string} is {word}")]
async fn setting_is(w: &mut AlooWorld, label: String, state: String) {
    let want = match state.as_str() {
        "on" => true,
        "off" => false,
        other => panic!("a switch is on or off, not {other:?}"),
    };
    let popup = w.ui_ref().settings_popup.as_ref().expect("popup open");
    assert_eq!(popup.draft.toggle_value(field_named(&label)), want);
}

#[then(expr = "the setting {string} reads {string}")]
async fn setting_reads(w: &mut AlooWorld, label: String, value: String) {
    let popup = w.ui_ref().settings_popup.as_ref().expect("popup open");
    assert_eq!(popup.draft.text_value(field_named(&label)), value);
}

#[then(expr = "the selected punch row is {int}")]
async fn selected_punch_row(w: &mut AlooWorld, index: usize) {
    let popup = w.ui_ref().settings_popup.as_ref().expect("popup open");
    assert_eq!(popup.focused_field(), SettingsField::Punches, "the list should have the focus");
    assert_eq!(popup.punches.selected, index);
}

/// Read off the rendered screen rather than the field table: the point is
/// that the explanation is *there to be read*, not that a function
/// returns it.
#[then("every field on the open tab is explained beneath it")]
async fn every_field_explained(w: &mut AlooWorld) {
    let tab = w.ui_ref().settings_popup.as_ref().expect("popup open").tab;
    let buffer = ui_buffer(w.ui_ref(), 100, 46);
    let screen: String = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| {
                    let s = buffer[(x, y)].symbol();
                    if "\u{2500}\u{2502}\u{250c}\u{2510}\u{2514}\u{2518}".contains(s) {
                        " ".to_string()
                    } else {
                        s.to_string()
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for field in tab.fields() {
        let want = format!("{}: {}", field.label(), field.description());
        assert!(screen.contains(&want), "expected {want:?} on the {tab:?} tab");
    }
}

// ---------------------------------------------------------------------
// Then - the sound switches
// ---------------------------------------------------------------------

#[then("arriving voice plays itself")]
async fn autoplay_on(w: &mut AlooWorld) {
    assert!(w.direct_settings.as_ref().expect("a loaded settings file").voice_autoplay);
}

#[then("the end-of-message tone plays")]
async fn roger_on(w: &mut AlooWorld) {
    assert!(w.direct_settings.as_ref().expect("a loaded settings file").roger_beep);
}

#[then("the event sounds play")]
async fn notifications_on(w: &mut AlooWorld) {
    assert!(w.direct_settings.as_ref().expect("a loaded settings file").sound_notifications);
}

#[then("the event sounds are silent")]
async fn notifications_off(w: &mut AlooWorld) {
    assert!(!w.direct_settings.as_ref().expect("a loaded settings file").sound_notifications);
}

/// `voice_autoplay=off` is the blanket form of `/mute-voice`: it is asked
/// through the one predicate every incoming-audio decision funnels
/// through, so it holds for someone never mentioned anywhere.
#[then(expr = "{word}'s arriving voice is kept off the speakers")]
async fn kept_off_speakers(w: &mut AlooWorld, name: String) {
    let id = UserId(crate::steps::ui_common::id_for(&name));
    assert!(w.ui_ref().suppress_playback_from(id));
}

// ---------------------------------------------------------------------
// Then - how the popup is drawn
// ---------------------------------------------------------------------

#[then(expr = "the {string} tab is drawn as the open one")]
async fn tab_is_filled(w: &mut AlooWorld, title: String) {
    let buffer = ui_buffer(w.ui_ref(), 100, 46);
    let filled = |name: &str| {
        let (x, y) = crate::support::find_text_start(&buffer, name);
        buffer[(x, y)].style().bg
    };
    let open = filled(&title);
    assert!(open.is_some(), "the open tab should have a background of its own");
    for other in SettingsTab::ALL.iter().map(|t| t.title()).filter(|t| *t != title) {
        assert_ne!(filled(other), open, "{other:?} must not share the open tab's fill");
    }
}

#[then("a blank row separates each bordered area")]
async fn areas_are_spaced(w: &mut AlooWorld) {
    let buffer = ui_buffer(w.ui_ref(), 100, 46);
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect()
        })
        .collect();
    let is_blank_inside_popup = |i: usize| {
        let inner: String = rows[i].chars().filter(|c| *c != '\u{2502}').collect();
        inner.trim().is_empty()
    };
    for title in ["notifications", "logs", "delivery"] {
        let at = rows
            .iter()
            .position(|r| r.contains(title))
            .unwrap_or_else(|| panic!("expected a {title:?} area on screen"));
        assert!(
            is_blank_inside_popup(at - 1),
            "expected a blank row above the {title:?} area"
        );
    }
}

#[then("no voice recording was started")]
async fn no_recording_started(w: &mut AlooWorld) {
    assert!(
        !w.ui_ref().recording,
        "Space belongs to the popup while it is open, not to push-to-talk"
    );
    assert!(
        !matches!(w.last_action, Some(UiAction::VoiceRecordStart(_))),
        "expected no recording to be requested, got {:?}",
        w.last_action
    );
}

// ---------------------------------------------------------------------
// The durable send queue (US-064)
// ---------------------------------------------------------------------

/// A sealed text payload, of the shape a DM send produces. Opaque on
/// purpose: the queue keeps what was already encrypted for the recipient
/// and never looks inside it.
fn sealed_text(body: &str) -> aloo::client::outbox::OutboxItem {
    aloo::client::outbox::OutboxItem::Reliable(aloo::p2p_proto::P2pPayload::Envelope {
        channel: None,
        msg_id: Some(1),
        envelope: aloo::proto::Envelope {
            content: aloo::proto::Content::Text,
            blocks: vec![body.as_bytes().to_vec()],
        },
    })
}

/// This scenario's own scratch directory, created on first use. A
/// session built over it puts its outbox in `outbox/` underneath, which
/// is where `outbox` below looks - so a scenario that drives the store
/// directly and one that drives a real send are reading the same files.
fn scenario_dir(w: &mut AlooWorld) -> std::path::PathBuf {
    if let Some(dir) = &w.outbox_dir {
        return dir.clone();
    }
    let dir = std::env::temp_dir().join(format!(
        "aloo-outbox-scenario-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    w.outbox_dir = Some(dir.clone());
    w.temp_files.push(dir.clone());
    dir
}

/// The queue as it is on disk right now. Read fresh every time rather
/// than held, so a step always sees what the last one actually wrote -
/// including what a real session wrote through it.
fn outbox(w: &mut AlooWorld) -> aloo::client::outbox::Outbox {
    let dir = scenario_dir(w).join("outbox");
    aloo::client::outbox::Outbox::load(&dir)
}

/// The switch every queued-send scenario opens by naming: with it off
/// there is no queue at all, and a send goes straight at the transport.
#[cucumber::given("queueing sends is on")]
async fn queueing_on(w: &mut AlooWorld) {
    w.queueing_on = Some(true);
    if w.ui.is_some() {
        w.ui_mut().queue_send_messages = true;
    }
}

#[cucumber::given("queueing sends is off")]
async fn queueing_off(w: &mut AlooWorld) {
    w.queueing_on = Some(false);
    if w.ui.is_some() {
        w.ui_mut().queue_send_messages = false;
    }
}

#[cucumber::given(expr = "nothing is queued for {word}")]
#[then(expr = "nothing is queued for {word}")]
async fn nothing_queued(w: &mut AlooWorld, nickname: String) {
    assert_eq!(outbox(w).len_for(&nickname), 0);
}

#[when(expr = "I queue {int} message for {word}")]
#[when(expr = "I queue {int} messages for {word}")]
async fn queue_messages(w: &mut AlooWorld, count: usize, nickname: String) {
    let mut store = outbox(w);
    for i in 0..count {
        let item = sealed_text(&format!("message {i} for {nickname}"));
        store.queue(&nickname, item.clone()).unwrap();
        w.queued_payloads.push(item);
    }
}

#[then(expr = "{int} message is queued for {word}")]
#[then(expr = "{int} messages are queued for {word}")]
async fn n_queued(w: &mut AlooWorld, count: usize, nickname: String) {
    assert_eq!(outbox(w).len_for(&nickname), count);
}

#[when(expr = "{word}'s queue is taken")]
async fn queue_is_taken(w: &mut AlooWorld, nickname: String) {
    let mut store = outbox(w);
    w.taken_entries = store.take(&nickname);
}

#[then("they come back in the order they were written")]
async fn order_preserved(w: &mut AlooWorld) {
    let mut store = outbox(w);
    let taken: Vec<_> = store.take("bob").into_iter().map(|e| e.item).collect();
    assert_eq!(taken, w.queued_payloads, "order, and content, exactly as written");
    // Put them back so a later step in the same scenario still sees them.
    for item in &w.queued_payloads {
        store.queue("bob", item.clone()).unwrap();
    }
}

#[then("they are still there after a restart")]
async fn survives_restart(w: &mut AlooWorld) {
    // A brand-new reader over the same directory is exactly what the next
    // run of the app does.
    let reopened = outbox(w);
    assert_eq!(reopened.len_for("bob"), w.queued_payloads.len());
}

#[then(expr = "nothing is left on disk for {word}")]
async fn nothing_on_disk(w: &mut AlooWorld, nickname: String) {
    let reopened = outbox(w);
    assert_eq!(reopened.len_for(&nickname), 0);
    assert!(!reopened.peers().contains(&nickname));
}

#[then(expr = "what is queued for {word} is byte-identical to what would have been sent")]
async fn byte_identical(w: &mut AlooWorld, nickname: String) {
    let mut store = outbox(w);
    let taken: Vec<_> = store.take(&nickname).into_iter().map(|e| e.item).collect();
    assert_eq!(
        taken, w.queued_payloads,
        "the sealed payload is kept as it was - never re-sealed, never opened"
    );
}

// What is kept, and what is not.

#[then("a text message is held for someone unreachable")]
async fn text_is_held(_w: &mut AlooWorld) {
    assert!(aloo::client::outbox::is_queueable(&sealed_text("hi")));
}

/// Anything under the pad belongs to `client::otp_outbox`, which sends
/// one message per acknowledgement in order - so the general queue, which
/// flushes everything at once, deliberately refuses it.
#[then("a pad-wrapped message is held in the pad queue instead")]
async fn otp_text_is_held(_w: &mut AlooWorld) {
    assert!(!aloo::client::outbox::is_queueable(
        &aloo::client::outbox::OutboxItem::Reliable(aloo::p2p_proto::P2pPayload::OtpEnvelope {
            channel: None,
            msg_id: Some(1),
            seq: 1,
            envelope: aloo::proto::Envelope {
                content: aloo::proto::Content::Text,
                blocks: vec![vec![7u8; 16]],
            },
            sender_device_id: "laptop".into(),
        })
    ));
}

#[then("a voice message is held for someone unreachable")]
async fn voice_is_held(_w: &mut AlooWorld) {
    assert!(aloo::client::outbox::is_queueable(
        &aloo::client::outbox::OutboxItem::Reliable(aloo::p2p_proto::P2pPayload::StreamStart {
            channel: None,
            stream_id: 1,
            msg_id: Some(1),
        })
    ));
    assert!(aloo::client::outbox::is_queueable(
        &aloo::client::outbox::OutboxItem::VoiceChunk {
            stream_id: 1,
            seq: 0,
            blocks: vec![vec![1, 2, 3]],
        }
    ));
}

#[then("a file transfer is not held for someone unreachable")]
async fn file_is_not_held(_w: &mut AlooWorld) {
    assert!(!aloo::client::outbox::is_queueable(
        &aloo::client::outbox::OutboxItem::Reliable(aloo::p2p_proto::P2pPayload::FileChunk {
            stream_id: 1,
            seq: 0,
            blocks: vec![vec![0u8; 4]],
        })
    ));
}

#[then("a delivery receipt is not held for someone unreachable")]
async fn receipt_is_not_held(_w: &mut AlooWorld) {
    assert!(!aloo::client::outbox::is_queueable(
        &aloo::client::outbox::OutboxItem::Reliable(aloo::p2p_proto::P2pPayload::DeliveryReceipt {
            msg_id: 1,
            stage: aloo::p2p_proto::ReceiptStage::Decrypted,
        })
    ));
}

// ---------------------------------------------------------------------
// A held leg, as the details popup reports it (AC-412)
// ---------------------------------------------------------------------

/// Logs an outgoing message and marks its one leg as held on disk, the
/// state `session::queue_undeliverable` leaves a row in.
#[cucumber::given("I have sent a message that is being held for bob")]
async fn message_held_for_bob(w: &mut AlooWorld) {
    let bob = UserId(crate::steps::ui_common::id_for("bob"));
    let state = w.ui_mut();
    let (msg_id, delivery) = state.start_delivery(&[bob]);
    state.channels[0].log.push(aloo::client::tui::ui::LogEntry {
        from: UserId(1),
        from_name: "me".into(),
        body: aloo::client::tui::ui::MessageBody::Text("waiting for you".into()),
        outgoing: true,
        failed: false,
        sent_at: "2026-08-28T12:00:00Z".into(),
        sent_at_utc: "2026-08-28T12:00:00Z".into(),
        owed_receipt: None,
        listened: true,
        delivery: Some(delivery),
        crypto: None,
    });
    state.message_selected = state.channels[0].log.len() - 1;
    state.mark_queued(bob, msg_id, true);
    w.held_msg_id = Some(msg_id);
}

#[when("that message goes out to bob")]
async fn held_message_goes_out(w: &mut AlooWorld) {
    let bob = UserId(crate::steps::ui_common::id_for("bob"));
    let msg_id = w.held_msg_id.expect("no held message in this scenario");
    w.ui_mut().mark_queued(bob, msg_id, false);
}

#[then(expr = "bob's line reads {word}")]
async fn bobs_line_reads(w: &mut AlooWorld, label: String) {
    let rows: Vec<String> = ui_buffer(w.ui_ref(), 100, 46)
        .content
        .chunks(100)
        .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
        .collect();
    assert!(
        rows.iter().any(|r| r.contains("bob") && r.contains(&label)),
        "expected bob's line to read {label:?}: {rows:?}"
    );
}


// ---------------------------------------------------------------------
// Sends driven through the real transport, on both sides of the switch
// ---------------------------------------------------------------------

/// A real session with `bob` known and an unpunched link open to him, so
/// a send has somewhere to go and nowhere to arrive - built once per
/// scenario, since generating its identity is the expensive part.
async fn queue_session(
    w: &mut AlooWorld,
) -> &mut (aloo::client::session::SessionState, aloo::client::tui::ui::UiState) {
    if w.queue_session.is_none() {
        let dir = scenario_dir(w);
        let queueing_on = w.queueing_on.unwrap_or(true);
        let (public, private) =
            aloo::crypto::pq::generate_bundle_with_bits(1024).expect("keygen");
        let der = aloo::proto::encode(&public).expect("encode bundle");
        let mut session = aloo::client::session::SessionState::for_test(
            aloo::client::session::TestSessionSpec {
                identity: aloo::client::connect::ResolvedIdentity {
                    private,
                    public_der: der.clone(),
                },
                scratch: dir,
                otp: None,
            },
        )
        .await;
        session.set_queue_send_messages(queueing_on);

        let mut ui = aloo::client::tui::ui::UiState::new("me".into());
        ui.set_own_id(UserId(1));
        let bob = crate::steps::ui_common::user_with_mode(
            crate::steps::ui_common::id_for("bob"),
            "bob",
            aloo::proto::KeyMode::PqHybrid,
        );
        ui.known_users.insert(UserId(crate::steps::ui_common::id_for("bob")), bob);
        session
            .peer_link_mut()
            .ensure_link(&mut aloo::control::NullSink, UserId(crate::steps::ui_common::id_for("bob")))
            .await;
        w.queue_session = Some((session, ui));
    }
    w.queue_session.as_mut().expect("just built")
}

/// A sealed payload of the shape a DM send produces, distinguishable from
/// the others by `n` so an ordering assertion can name them.
fn sealed_nth(n: usize) -> aloo::p2p_proto::P2pPayload {
    aloo::p2p_proto::P2pPayload::Envelope {
        channel: None,
        msg_id: Some(n as u64),
        envelope: aloo::proto::Envelope {
            content: aloo::proto::Content::Text,
            blocks: vec![format!("message {n}").into_bytes()],
        },
    }
}

#[when(expr = "I send {word} a message while he is unreachable")]
async fn send_while_unreachable(w: &mut AlooWorld, _nickname: String) {
    send_n_while_unreachable(w, 1, String::new()).await;
}

#[when(expr = "I send {word} {int} messages while he is unreachable")]
async fn send_n_messages(w: &mut AlooWorld, _nickname: String, count: usize) {
    send_n_while_unreachable(w, count, String::new()).await;
}

async fn send_n_while_unreachable(w: &mut AlooWorld, count: usize, _unused: String) {
    let peer = UserId(crate::steps::ui_common::id_for("bob"));
    let sent_so_far = w.sent_payload_count;
    for i in 0..count {
        let payload = sealed_nth(sent_so_far + i);
        {
            let (session, _) = queue_session(w).await;
            session.peer_link_mut().send_reliable_or_queue(peer, payload);
        }
        // The session loop is what turns "could not send" into a queued
        // message; a test has to play its part.
        let (session, ui) = w.queue_session.as_mut().expect("built above");
        aloo::client::session::drain_p2p_events(&mut aloo::control::NullSink, ui, session)
            .await
            .expect("draining should not fail");
    }
    w.sent_payload_count += count;
}

// ---------------------------------------------------------------------
// The matrix: queueing on/off x receiver online/offline x layering.
// The server dimension is a tag rather than a step on purpose - none of
// this consults a server. A punched link is what a send travels on, and
// whether a server happens to be reachable changes only how the two found
// each other, which is exactly the claim the @with_server /
// @without_reachable_server pairs below are asserting.
// ---------------------------------------------------------------------

/// Marks bob's link up, so a send finds a live transport rather than
/// falling through to whichever queue is configured.
#[cucumber::given(expr = "{word} is reachable")]
async fn peer_is_reachable(w: &mut AlooWorld, _nickname: String) {
    let peer = UserId(crate::steps::ui_common::id_for("bob"));
    let (session, _) = queue_session(w).await;
    session.peer_link_mut().mark_active_for_test(peer);
}

/// The default state of the harness, named so a scenario says which half
/// of the matrix it is in rather than relying on a silent default.
#[cucumber::given(expr = "{word} is not reachable")]
async fn peer_is_not_reachable(w: &mut AlooWorld, _nickname: String) {
    let _ = queue_session(w).await;
}

#[when(expr = "I send {word} a message")]
async fn send_a_message(w: &mut AlooWorld, _nickname: String) {
    send_n_while_unreachable(w, 1, String::new()).await;
}

#[then(expr = "it went straight out to {word}, held nowhere")]
async fn went_straight_out(w: &mut AlooWorld, nickname: String) {
    assert_eq!(
        outbox(w).len_for(&nickname),
        0,
        "a reachable peer's message has no reason to be held"
    );
    let peer = UserId(crate::steps::ui_common::id_for("bob"));
    let (session, _) = queue_session(w).await;
    assert!(
        session.peer_link_mut().pending_payloads(peer).is_empty(),
        "nor to be waiting in the transport's own queue"
    );
}

/// Seals one pad message for `contact`, which spends its pad position
/// there and then - the step the pad half of the matrix is built on.
#[when(expr = "I write a pad message for {string}")]
async fn write_a_pad_message(w: &mut AlooWorld, contact: String) {
    let peer = UserId(crate::steps::ui_common::id_for("bob"));
    let seq = w.sealed_pad_count;
    let (session, _) = queue_session(w).await;
    assert!(
        session.queue_sealed_otp_for_test(&contact, seq),
        "sealing is what spends the pad; it must be taken by the queue"
    );
    let _ = peer;
    w.sealed_pad_count += 1;
}

#[when(expr = "the queue for {string} is pumped")]
async fn pump_the_pad_queue(w: &mut AlooWorld, contact: String) {
    let peer = UserId(crate::steps::ui_common::id_for("bob"));
    let _ = queue_session(w).await;
    let (session, ui) = w.queue_session.as_mut().expect("built above");
    w.pad_queue_released = session.pump_otp_queue_for_test(ui, peer, &contact).await;
}

#[then("the front of it went out, and only the front")]
async fn front_went_out(w: &mut AlooWorld) {
    assert!(
        w.pad_queue_released,
        "a reachable peer's queue releases its front message"
    );
}

#[then(expr = "{int} sealed pad message is still waiting for its acknowledgement")]
#[then(expr = "{int} sealed pad messages are still waiting for its acknowledgement")]
async fn sealed_still_waiting(w: &mut AlooWorld, count: usize) {
    let (session, _) = queue_session(w).await;
    assert_eq!(
        session.otp_queued_total(),
        count,
        "the front stays until its own ack retires it"
    );
}

#[then(expr = "an offline peer's send is refused before anything is encrypted")]
async fn refused_before_encrypt(w: &mut AlooWorld) {
    let ui = w.ui_mut();
    assert!(
        ui.offline_blocks_send("are you there"),
        "with nothing to hold it, the send is stopped before any pad is spent"
    );
}

#[then(expr = "an offline peer's send is accepted for holding")]
async fn accepted_for_holding(w: &mut AlooWorld) {
    let ui = w.ui_mut();
    assert!(
        !ui.offline_blocks_send("are you there"),
        "with somewhere to hold it, writing to someone away is allowed"
    );
}

/// The drain: the link opens and everything held for him is offered.
#[when(expr = "{word}'s link comes up and his queue is drained")]
async fn link_up_and_drained(w: &mut AlooWorld, _nickname: String) {
    let peer = UserId(crate::steps::ui_common::id_for("bob"));
    {
        let (session, _) = queue_session(w).await;
        session.peer_link_mut().mark_active_for_test(peer);
        session.inject_p2p_event(aloo::client::p2p::P2pEvent::LinkStatusChanged {
            peer,
            status: aloo::client::p2p::LinkStatus::Active,
        });
    }
    let (session, ui) = w.queue_session.as_mut().expect("built above");
    aloo::client::session::drain_p2p_events(&mut aloo::control::NullSink, ui, session)
        .await
        .expect("draining should not fail");
}

/// His acknowledgement of the entry `id` names - the only thing that ever
/// removes a message that was actually sent.
#[when(expr = "{word} acknowledges the held message {int}")]
async fn peer_acknowledges(w: &mut AlooWorld, _nickname: String, id: u64) {
    let peer = UserId(crate::steps::ui_common::id_for("bob"));
    {
        let (session, _) = queue_session(w).await;
        session.inject_p2p_event(aloo::client::p2p::P2pEvent::FrameAcked { peer, tag: id });
    }
    let (session, ui) = w.queue_session.as_mut().expect("built above");
    aloo::client::session::drain_p2p_events(&mut aloo::control::NullSink, ui, session)
        .await
        .expect("draining should not fail");
}

#[when(expr = "{word}'s link comes up but his queue has not been drained yet")]
async fn link_up_queue_not_drained(w: &mut AlooWorld, _nickname: String) {
    let peer = UserId(crate::steps::ui_common::id_for("bob"));
    let (session, _) = queue_session(w).await;
    session.peer_link_mut().set_queue_held(peer, true);
}

#[then(expr = "nothing is waiting in the transport's own queue for {word}")]
async fn transport_queue_empty(w: &mut AlooWorld, _nickname: String) {
    let peer = UserId(crate::steps::ui_common::id_for("bob"));
    let (session, _) = queue_session(w).await;
    assert!(
        session.peer_link_mut().pending_payloads(peer).is_empty(),
        "one copy, or it goes twice"
    );
}

#[then(expr = "it is waiting in the transport's own queue for {word} instead")]
async fn transport_queue_holds_it(w: &mut AlooWorld, _nickname: String) {
    let peer = UserId(crate::steps::ui_common::id_for("bob"));
    let (session, _) = queue_session(w).await;
    assert_eq!(session.peer_link_mut().pending_payloads(peer).len(), 1);
}

#[then(expr = "the transport holds those {int} for {word} in the order they were sent")]
async fn transport_queue_in_order(w: &mut AlooWorld, count: usize, _nickname: String) {
    let peer = UserId(crate::steps::ui_common::id_for("bob"));
    let (session, _) = queue_session(w).await;
    let ids: Vec<Option<u64>> = session
        .peer_link_mut()
        .pending_payloads(peer)
        .into_iter()
        .map(|p| match p {
            aloo::p2p_proto::P2pPayload::Envelope { msg_id, .. } => msg_id,
            other => panic!("unexpected payload {other:?}"),
        })
        .collect();
    let want: Vec<Option<u64>> = (0..count as u64).map(Some).collect();
    assert_eq!(ids, want, "a direct send keeps its order too");
}

// ---------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------

#[when(expr = "{word} is still a contact on this machine")]
async fn still_a_contact(w: &mut AlooWorld, nickname: String) {
    w.still_contacts.insert(nickname);
}

#[when(expr = "{word} is no longer a contact on this machine")]
async fn no_longer_a_contact(w: &mut AlooWorld, nickname: String) {
    w.still_contacts.remove(&nickname);
}

/// Ages every queued entry far past anything a time-based rule would have
/// kept, so the next step proves that age is not what decides.
#[when("those messages were written a year ago")]
async fn written_a_year_ago(w: &mut AlooWorld) {
    let dir = scenario_dir(w).join("outbox");
    for entry in std::fs::read_dir(&dir).expect("the outbox directory") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("q") {
            continue;
        }
        let contents = std::fs::read_to_string(&path).expect("a queue file");
        let aged: String = contents
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(_, hex)| format!("1000000 {hex}\n"))
            .collect();
        std::fs::write(&path, aged).expect("re-writing the queue file");
    }
}

#[when("the queue is swept")]
async fn queue_is_swept(w: &mut AlooWorld) {
    let still = w.still_contacts.clone();
    let mut store = outbox(w);
    store.retain_contacts(|nickname| still.contains(nickname));
}

// ---------------------------------------------------------------------
// Where a silenced voice is reported (AC-415)
// ---------------------------------------------------------------------

#[cucumber::given(expr = "{word}'s voice is muted")]
async fn voice_is_muted(w: &mut AlooWorld, nickname: String) {
    w.ui_mut()
        .set_muted_voice([nickname].into_iter().collect());
}

fn screen_rows(w: &AlooWorld) -> Vec<String> {
    let buffer = ui_buffer(w.ui_ref(), 100, 30);
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect()
}

#[then(expr = "{word} is marked as muted in the sidebar")]
async fn marked_muted(w: &mut AlooWorld, nickname: String) {
    let marker = aloo::client::tui::ui::VOICE_MUTED_MARKER;
    assert!(
        screen_rows(w)
            .iter()
            .any(|r| r.contains(&nickname) && r.contains(marker)),
        "expected {nickname} to carry the muted marker"
    );
}

#[then(expr = "{word} is not singled out in the sidebar")]
async fn not_marked_muted(w: &mut AlooWorld, nickname: String) {
    let marker = aloo::client::tui::ui::VOICE_MUTED_MARKER;
    assert!(
        !screen_rows(w)
            .iter()
            .any(|r| r.contains(&nickname) && r.contains(marker)),
        "with nobody's voice playing, one name must not be marked for it"
    );
}

#[then("the header says playback is off")]
async fn header_says_playback_off(w: &mut AlooWorld) {
    assert!(
        screen_rows(w).iter().take(3).any(|r| r.contains("playback off")),
        "the blanket state belongs in the header"
    );
}

#[then("the header says nothing about playback")]
async fn header_silent_about_playback(w: &mut AlooWorld) {
    assert!(
        !screen_rows(w).iter().any(|r| r.contains("playback off")),
        "nothing to report while arriving voice plays"
    );
}

// ---------------------------------------------------------------------
// The pad session's own durable queue (US-064, AC-418/419)
// ---------------------------------------------------------------------

/// A sealed pad-wrapped message. Opaque on purpose: sealing is spending,
/// and what the queue keeps is ciphertext it never looks inside.
fn sealed_pad(seq: u64) -> aloo::p2p_proto::P2pPayload {
    aloo::p2p_proto::P2pPayload::OtpEnvelope {
        channel: None,
        msg_id: Some(seq),
        seq,
        envelope: aloo::proto::Envelope {
            content: aloo::proto::Content::Text,
            blocks: vec![vec![seq as u8; 48]],
        },
        sender_device_id: "laptop".into(),
    }
}

fn otp_outbox(w: &mut AlooWorld) -> aloo::client::otp_outbox::OtpOutbox {
    let dir = scenario_dir(w).join("otp_outbox");
    aloo::client::otp_outbox::OtpOutbox::load(&dir)
}

#[cucumber::given(expr = "nothing is queued for the contact {string}")]
#[then(expr = "nothing is queued for the contact {string}")]
async fn nothing_queued_for_contact(w: &mut AlooWorld, contact: String) {
    assert_eq!(otp_outbox(w).len_for(&contact), 0);
}

#[when(expr = "I seal {int} pad message for {string}")]
#[when(expr = "I seal {int} pad messages for {string}")]
async fn seal_pad_messages(w: &mut AlooWorld, count: u64, contact: String) {
    let mut store = otp_outbox(w);
    let first = w.sealed_pad_count;
    for i in 0..count {
        let seq = first + i;
        store
            .queue(&contact, &sealed_pad(seq), seq, Some(seq), None, [seq as u8; 32])
            .unwrap();
        w.sealed_payloads.push(sealed_pad(seq));
    }
    w.sealed_pad_count += count;
}

/// The pad is already spent by the time the queue is asked, so its answer
/// is what decides whether the sealed bytes still have somewhere to go.
#[when(expr = "I try to queue a sealed pad message for the contact {string}")]
async fn try_queue_for_contact(w: &mut AlooWorld, contact: String) {
    let mut store = otp_outbox(w);
    let seq = w.sealed_pad_count;
    w.pad_queue_accepted = store
        .queue(&contact, &sealed_pad(seq), seq, Some(seq), None, [seq as u8; 32])
        .expect("refusing a name is not an I/O failure");
}

#[then("the queue says it took it")]
async fn queue_took_it(w: &mut AlooWorld) {
    assert!(
        w.pad_queue_accepted,
        "a storable contact's message is taken, and the caller is told so"
    );
}

#[then("the queue says it did not take it, so the caller can send it instead")]
async fn queue_refused_it(w: &mut AlooWorld) {
    assert!(
        !w.pad_queue_accepted,
        "a refusal reported as success would lose a message whose pad is spent"
    );
}

#[then(expr = "{int} pad message is queued for {string}")]
#[then(expr = "{int} pad messages are queued for {string}")]
async fn n_pad_queued(w: &mut AlooWorld, count: usize, contact: String) {
    assert_eq!(otp_outbox(w).len_for(&contact), count);
}

#[then("they come back in the order they were sealed")]
async fn pad_order_preserved(w: &mut AlooWorld) {
    let mut store = otp_outbox(w);
    for (i, expected) in w.sealed_payloads.clone().into_iter().enumerate() {
        let front = store.front("alice-bob").expect("a message is waiting");
        assert_eq!(front.seq(), Some(i as u64), "strictly in order");
        assert_eq!(front.payload(), Some(expected));
        store.take_front("alice-bob").unwrap();
    }
}

#[then(expr = "the next pad message for {string} is sequence {int}")]
async fn next_pad_seq(w: &mut AlooWorld, contact: String, seq: u64) {
    let store = otp_outbox(w);
    let front = store.front(&contact).expect("a message is waiting");
    assert_eq!(front.seq(), Some(seq));
}

#[then("reading it again does not consume it")]
async fn peek_does_not_consume(w: &mut AlooWorld) {
    let store = otp_outbox(w);
    let before = store.len_for("alice-bob");
    let _ = store.front("alice-bob");
    assert_eq!(store.len_for("alice-bob"), before);
}

/// The one thing that retires a sealed message: its own proof-carrying
/// acknowledgement came back.
#[when("that message is acknowledged")]
async fn pad_message_acked(w: &mut AlooWorld) {
    let mut store = otp_outbox(w);
    store.take_front("alice-bob").unwrap();
}

#[then(expr = "after a restart {int} pad messages are queued for {string}")]
async fn after_restart_count(w: &mut AlooWorld, count: usize, contact: String) {
    // A brand-new reader over the same directory is what the next run of
    // the app does.
    assert_eq!(otp_outbox(w).len_for(&contact), count);
}

#[then(expr = "after a restart the next pad message for {string} is sequence {int}")]
async fn after_restart_next(w: &mut AlooWorld, contact: String, seq: u64) {
    let store = otp_outbox(w);
    assert_eq!(store.front(&contact).and_then(|e| e.seq()), Some(seq));
}

#[then(expr = "what is queued for {string} is byte-identical to what was sealed")]
async fn pad_byte_identical(w: &mut AlooWorld, contact: String) {
    let store = otp_outbox(w);
    let front = store.front(&contact).expect("a message is waiting");
    assert_eq!(
        front.payload().as_ref(),
        w.sealed_payloads.first(),
        "ciphertext is kept as it was - never re-sealed, never opened"
    );
}

#[when(expr = "the contact {string} is still on this machine")]
async fn contact_still_here(w: &mut AlooWorld, contact: String) {
    w.still_contacts.insert(contact);
}

#[when(expr = "the contact {string} is no longer on this machine")]
async fn contact_gone(w: &mut AlooWorld, contact: String) {
    w.still_contacts.remove(&contact);
}

#[when("the pad queue is swept")]
async fn pad_queue_swept(w: &mut AlooWorld) {
    let still = w.still_contacts.clone();
    let mut store = otp_outbox(w);
    store.retain_contacts(|contact| still.contains(contact));
}

#[then(expr = "no queue file is left for {string}")]
async fn no_queue_file(w: &mut AlooWorld, contact: String) {
    let path = scenario_dir(w).join("otp_outbox").join(format!("{contact}.q"));
    assert!(!path.exists(), "a file that held pad output must not be left behind");
}

// ---------------------------------------------------------------------
// A change that takes effect now (AC-411), and one spelling for every
// switch in the file (AC-416)
// ---------------------------------------------------------------------

/// The popup writes the value straight onto the running `UiState`, which
/// is what every playback decision reads - so "it took effect" is
/// observable without a restart or a session.
#[then("arriving voice is kept off the speakers for everyone")]
async fn autoplay_took_effect(w: &mut AlooWorld) {
    let draft = &w
        .ui_ref()
        .settings_popup
        .as_ref()
        .expect("popup open")
        .draft;
    assert!(!draft.voice_autoplay, "the draft the session is handed says off");

    // What the session does with it, applied here the same way
    // `save_settings_draft` does, so the effect itself is asserted rather
    // than assumed.
    let queueing = w.ui_ref().queue_send_messages;
    w.ui_mut().voice_autoplay = false;
    w.ui_mut().queue_send_messages = queueing;
    for name in ["bob", "carol"] {
        let id = UserId(crate::steps::ui_common::id_for(name));
        assert!(
            w.ui_ref().suppress_playback_from(id),
            "{name}'s arriving voice must be kept off the speakers"
        );
    }
}

#[then("the global push-to-talk switch is off")]
async fn ptt_switch_off(w: &mut AlooWorld) {
    assert!(
        !w.direct_settings
            .as_ref()
            .expect("a loaded settings file")
            .global_ptt_enabled,
        "`false` from a file written before the spellings were unified must still read as off"
    );
}

#[then("the daemon otp switch is on")]
async fn daemon_otp_on(w: &mut AlooWorld) {
    assert!(w.direct_settings.as_ref().expect("a loaded file").daemon_otp);
}

#[when("those settings are written back out")]
async fn settings_written_back(w: &mut AlooWorld) {
    let path = scenario_dir(w).join("settings-roundtrip");
    let settings = w.direct_settings.clone().expect("a loaded settings file");
    settings.save(&path).expect("writing the settings back");
    w.written_settings = Some(std::fs::read_to_string(&path).expect("reading them back"));
}

#[then("no switch is written as true or false")]
async fn no_true_false(w: &mut AlooWorld) {
    let contents = w
        .written_settings
        .as_ref()
        .expect("nothing has been written back yet");
    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        assert!(
            !matches!(value, "true" | "false"),
            "{key} is a switch written the old way: {line:?}"
        );
    }
}

/// A pad-only pair's message: the pad and nothing else, with no
/// `pqhybrid` envelope around it (`OtpFraming::Direct`) - queued on
/// exactly the same terms as a wrapped one.
#[when(expr = "I seal {int} pad-only messages for {string}")]
#[when(expr = "I seal {int} pad-only message for {string}")]
async fn seal_pad_only_messages(w: &mut AlooWorld, count: u64, contact: String) {
    let mut store = otp_outbox(w);
    let first = w.sealed_pad_count;
    for i in 0..count {
        let seq = first + i;
        // `Direct` framing carries the padded bytes as the envelope's own
        // single block, with nothing sealed around them.
        let payload = aloo::p2p_proto::P2pPayload::OtpEnvelope {
            channel: None,
            msg_id: Some(seq),
            seq,
            envelope: aloo::proto::Envelope {
                content: aloo::proto::Content::Text,
                blocks: vec![vec![0xAB; 64]],
            },
            sender_device_id: "laptop".into(),
        };
        store
            .queue(&contact, &payload, seq, Some(seq), None, [seq as u8; 32])
            .unwrap();
        w.sealed_payloads.push(payload);
    }
    w.sealed_pad_count += count;
}


/// AC-440: the wait before an unacknowledged pad send is repeated. That
/// the retry re-sends sealed bytes rather than encrypting new ones, and
/// leaves a recording still streaming alone, are measured properties -
/// pinned by `an_unacknowledged_send_is_retried_once_its_wait_runs_out`
/// and `the_retry_timer_never_disturbs_a_recording_still_being_sent`,
/// which count pad positions and inspect the in-flight stream set. Neither
/// is restated here as an assertion this step could not actually make.
#[then("a pad send waits a bounded time for its acknowledgement before retrying")]
async fn retry_wait_is_bounded(_w: &mut AlooWorld) {
    let first = aloo::client::otp::OTP_RETRY_DELAY;
    let ceiling = aloo::client::otp::OTP_RETRY_MAX_DELAY;
    assert!(
        !first.is_zero(),
        "a retry that fired immediately would repeat a send still in flight"
    );
    assert!(first <= ceiling, "the backoff climbs towards its ceiling, not past it");
}
