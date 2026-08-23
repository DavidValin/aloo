//! Delivery acknowledgment steps (US-041): the per-message indicator and
//! the details popup behind `i`.
//!
//! Reading the indicator goes through `LogEntry::delivery_status` rather
//! than the rendered dot, and reading the popup goes through the rendered
//! rows - the popup's whole contract is what it puts on screen, while the
//! dot's is which of three states a row is in (`render_messages` paints
//! whichever that is).

use cucumber::{given, then, when};

use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

use aloo::client::connect::ResolvedIdentity;
use aloo::client::delivery::PendingReceipts;
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::{
    DELIVERED_LABEL, DELIVERY_ARROW, DeliveryProof, DeliveryStatus, ENCRYPTION_LABEL, Focus,
    KEY_FILE_LABEL, KEY_LABEL, KEY_OFFSET_LABEL, KEY_SEQ_LABEL, LISTENED_LABEL, LogEntry,
    MessageBody, NO_CRYPTO_INFO, SAVED_LABEL, SENT_AT_LABEL, UNDELIVERED_LABEL, UiAction, UiState,
    strike_through,
};
use aloo::crypto::pq::PqPublicBundle;
use aloo::p2p_proto::ReceiptStage;
use aloo::proto::UserId;
use aloo::proto::{ChannelInfo, ChannelKind, KeyMode, UserInfo};

use super::ui_common::id_for;
use crate::world::{AlooWorld, pq_bundle_for};

/// The delivery tag of the send the scenario most recently made - the same
/// id the row carries, which is the whole point of it (7.2.1).
fn last_msg_id(w: &AlooWorld) -> u64 {
    match w.last_action.as_ref().expect("no send was made") {
        UiAction::SendChannelText { msg_id, .. } | UiAction::SendDirectText { msg_id, .. } => {
            *msg_id
        }
        other => panic!("the last action was not a text send: {other:?}"),
    }
}

fn last_in_channel<'a>(w: &'a AlooWorld, channel: &str) -> &'a LogEntry {
    w.ui_ref()
        .channels
        .iter()
        .find(|c| c.name == channel)
        .unwrap_or_else(|| panic!("no channel {channel:?}"))
        .log
        .last()
        .expect("that channel's log is empty")
}

fn last_in_room<'a>(w: &'a AlooWorld, peer: &str) -> &'a LogEntry {
    w.ui_ref().private_rooms[&UserId(id_for(peer))]
        .log
        .last()
        .expect("that room's log is empty")
}

fn assert_status(entry: &LogEntry, want: DeliveryStatus) {
    assert_eq!(
        entry.delivery_status(),
        Some(want),
        "the row's delivery indicator is not the expected one"
    );
}

// ---------------------------------------------------------------------
// When
// ---------------------------------------------------------------------

#[when(expr = "{word} acknowledges my last message")]
async fn peer_acknowledges(w: &mut AlooWorld, name: String) {
    let msg_id = last_msg_id(w);
    w.ui_mut().mark_delivered(
        UserId(id_for(&name)),
        msg_id,
        ReceiptStage::Decrypted,
        DeliveryProof::Receipt,
    );
}

// ---------------------------------------------------------------------
// Then - the indicator
// ---------------------------------------------------------------------

#[then(expr = "my last message in {string} is undelivered")]
async fn channel_undelivered(w: &mut AlooWorld, channel: String) {
    assert_status(last_in_channel(w, &channel), DeliveryStatus::None);
}

#[then(expr = "my last message in {string} is partly delivered")]
async fn channel_partly(w: &mut AlooWorld, channel: String) {
    assert_status(last_in_channel(w, &channel), DeliveryStatus::Some);
}

#[then(expr = "my last message in {string} is delivered")]
async fn channel_delivered(w: &mut AlooWorld, channel: String) {
    assert_status(last_in_channel(w, &channel), DeliveryStatus::All);
}

#[then(expr = "my last message in the room with {word} is undelivered")]
async fn dm_undelivered(w: &mut AlooWorld, name: String) {
    assert_status(last_in_room(w, &name), DeliveryStatus::None);
}

#[then(expr = "my last message in the room with {word} is delivered")]
async fn dm_delivered(w: &mut AlooWorld, name: String) {
    assert_status(last_in_room(w, &name), DeliveryStatus::All);
}

#[then(expr = "{word}'s message in the room with {word} carries no delivery indicator")]
async fn incoming_has_no_indicator(w: &mut AlooWorld, sender: String, room: String) {
    let entry = last_in_room(w, &room);
    assert!(
        !entry.outgoing,
        "the scenario meant a message that arrived here, not one this client sent"
    );
    assert_eq!(entry.from_name, sender);
    assert_eq!(
        entry.delivery_status(),
        None,
        "a message that arrived here has no delivery of its own to report"
    );
}

// ---------------------------------------------------------------------
// Then - the details popup
// ---------------------------------------------------------------------

/// The popup's rows, as rendered - it exists only on screen, so this is
/// the only honest place to read it from.
fn popup_rows(w: &AlooWorld) -> Vec<String> {
    crate::support::rows_of(&crate::support::ui_buffer(w.ui_ref(), 100, 30))
}

fn assert_popup_row_pairs(w: &AlooWorld, name: &str, label: &str) {
    let rows = popup_rows(w);
    assert!(
        rows.iter().any(|r| r.contains(name) && r.contains(label)),
        "no popup row names {name:?} as {label}; rendered:\n{}",
        rows.join("\n")
    );
}

#[then(expr = "the message details name {string} as DELIVERED")]
async fn details_delivered(w: &mut AlooWorld, name: String) {
    assert_popup_row_pairs(w, &name, DELIVERED_LABEL);
}

#[then(expr = "the message details name {string} as UNDELIVERED")]
async fn details_undelivered(w: &mut AlooWorld, name: String) {
    assert_popup_row_pairs(w, &name, UNDELIVERED_LABEL);
}

#[then("the message details show when it was sent")]
async fn details_show_time(w: &mut AlooWorld) {
    let rows = popup_rows(w);
    assert!(
        rows.iter().any(|r| r.contains(SENT_AT_LABEL)),
        "the popup must open with the time the message was sent; rendered:\n{}",
        rows.join("\n")
    );
}

#[then("the message details say there is no delivery information")]
async fn details_say_nothing_to_show(w: &mut AlooWorld) {
    let rows = popup_rows(w);
    assert!(
        rows.iter()
            .any(|r| r.contains(aloo::client::tui::ui::NO_DELIVERY_INFO)),
        "a row that tracks no delivery must say so rather than showing an empty list; rendered:\n{}",
        rows.join("\n")
    );
}

#[then("the message details are still open")]
async fn details_still_open(w: &mut AlooWorld) {
    let rows = popup_rows(w);
    assert!(
        rows.iter().any(|r| r.contains("Message details")),
        "a key the popup does not handle must be absorbed, not close it; rendered:\n{}",
        rows.join("\n")
    );
}

#[then("the message details are closed")]
async fn details_closed(w: &mut AlooWorld) {
    let rows = popup_rows(w);
    assert!(
        !rows.iter().any(|r| r.contains("Message details")),
        "Escape must close the popup; rendered:\n{}",
        rows.join("\n")
    );
}

// ---------------------------------------------------------------------
// Then - a message that reached nobody
// ---------------------------------------------------------------------

/// The strike is drawn, not styled, so the only place to read it is the
/// rendered row - a combining mark occupies no cell of its own, so it
/// arrives attached to the character it follows.
fn message_rows_are_struck(w: &AlooWorld, text: &str) -> bool {
    popup_rows(w)
        .iter()
        .any(|r| r.contains(&strike_through(text)))
}

#[then(expr = "my last message in {string} is struck through")]
async fn channel_struck(w: &mut AlooWorld, channel: String) {
    let entry = last_in_channel(w, &channel);
    assert!(
        entry.reached_nobody(),
        "only a message that reached nobody is struck through"
    );
    let text = match &entry.body {
        MessageBody::Text(text) => text.clone(),
        other => panic!("expected a text message, got {other:?}"),
    };
    assert!(
        message_rows_are_struck(w, &text),
        "the row must be drawn struck through; rendered:\n{}",
        popup_rows(w).join("\n")
    );
}

#[then(expr = "my last message in {string} is not struck through")]
async fn channel_not_struck(w: &mut AlooWorld, channel: String) {
    let entry = last_in_channel(w, &channel);
    assert!(
        !entry.reached_nobody(),
        "a message that did reach somebody is never struck through"
    );
    let text = match &entry.body {
        MessageBody::Text(text) => text.clone(),
        other => panic!("expected a text message, got {other:?}"),
    };
    assert!(
        !message_rows_are_struck(w, &text),
        "the row must be drawn plainly; rendered:\n{}",
        popup_rows(w).join("\n")
    );
}

// ---------------------------------------------------------------------
// Then - the arrow itself, as drawn
// ---------------------------------------------------------------------

/// The arrow is the indicator, so both what it reads and what colour it is
/// have to be read off the rendered buffer rather than off the state.
fn arrow_color(w: &AlooWorld) -> ratatui::style::Color {
    let buffer = crate::support::ui_buffer(w.ui_ref(), 100, 30);
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width.saturating_sub(1) {
            let pair: String = (0..DELIVERY_ARROW.len() as u16)
                .map(|i| buffer[(x + i, y)].symbol())
                .collect();
            // Only the message log draws the arrow with a space on each
            // side of it, so this cannot pick up the popup or the help
            // text by accident.
            let preceded_by_space = x > 0 && buffer[(x - 1, y)].symbol() == " ";
            if pair == DELIVERY_ARROW && preceded_by_space {
                return buffer[(x, y)].fg;
            }
        }
    }
    panic!(
        "no delivery arrow was drawn; rendered:\n{}",
        popup_rows(w).join("\n")
    );
}

#[then(expr = "my message reads {string}")]
#[then(expr = "bob's message reads {string}")]
async fn row_reads(w: &mut AlooWorld, text: String) {
    let rows = popup_rows(w);
    assert!(
        rows.iter().any(|r| r.contains(&text)),
        "no row reads {text:?}; rendered:\n{}",
        rows.join("\n")
    );
}

#[then(expr = "its arrow is {word}")]
async fn arrow_is(w: &mut AlooWorld, colour: String) {
    let want = match colour.as_str() {
        "grey" | "gray" => DeliveryStatus::None,
        "orange" => DeliveryStatus::Some,
        "green" => DeliveryStatus::All,
        other => panic!("unknown arrow colour {other:?}"),
    };
    assert_eq!(
        arrow_color(w),
        want.color(),
        "the arrow's colour is what says how far the message has got"
    );
}

// ---------------------------------------------------------------------
// Voice messages and file transfers (AC-230, AC-235)
// ---------------------------------------------------------------------

/// Both are logged the way their real send paths log them: a row created
/// up front, carrying the delivery id the wire payload will name.
#[when("I record a voice message to the channel")]
async fn record_voice(w: &mut AlooWorld) {
    let bob = UserId(id_for("bob"));
    let state = w.ui_mut();
    let (_, delivery) = state.start_delivery(&[bob]);
    state.log_own_voice_stream_start_channel("general", 7, Some(delivery));
}

#[when("I offer bob a file")]
async fn offer_file(w: &mut AlooWorld) {
    let bob = UserId(id_for("bob"));
    let state = w.ui_mut();
    let (_, delivery) = state.start_delivery(&[bob]);
    state.log_own_file_offer_channel("general", 8, "notes.txt".into(), 10, Some(delivery));
}

#[then("both of those rows carry a delivery arrow")]
async fn both_rows_carry_arrow(w: &mut AlooWorld) {
    let log = &w.ui_ref().channels[0].log;
    assert_eq!(log.len(), 2, "one voice row and one file row");
    assert!(
        log.iter().all(|e| e.delivery_status().is_some()),
        "a voice message and a file transfer are messages too"
    );
    let rows = popup_rows(w);
    assert_eq!(
        rows.iter()
            .filter(|r| r.contains(&format!("me {DELIVERY_ARROW} ")))
            .count(),
        2,
        "both are drawn with the arrow rather than the plain separator; rendered:\n{}",
        rows.join("\n")
    );
}

#[then("both are undelivered")]
async fn both_undelivered(w: &mut AlooWorld) {
    let log = &w.ui_ref().channels[0].log;
    assert!(
        log.iter()
            .all(|e| e.delivery_status() == Some(DeliveryStatus::None)),
        "nothing has been decrypted on the far side yet"
    );
}

const OFFER_STREAM_ID: u64 = 8;
const OFFER_MSG_ID: u64 = 4242;

#[given("bob has been offered a file that names one of my messages")]
async fn bob_offered_file(w: &mut AlooWorld) {
    let mut pending = PendingReceipts::new();
    pending.remember(UserId(id_for("bob")), OFFER_STREAM_ID, Some(OFFER_MSG_ID));
    w.pending_receipts = Some(pending);
    w.receipted = None;
}

#[then("nothing further is owed merely because the offer arrived")]
async fn nothing_on_arrival(w: &mut AlooWorld) {
    assert!(
        w.receipted.is_none(),
        "an offer is not a delivery - nothing has been decrypted yet"
    );
    assert_eq!(
        w.pending_receipts.as_ref().expect("no offer").len(),
        1,
        "it is owed, not paid"
    );
}

#[when("the whole file arrives and is decrypted on his side")]
async fn file_completes(w: &mut AlooWorld) {
    let pending = w.pending_receipts.as_mut().expect("no offer");
    w.receipted = pending.settle(UserId(id_for("bob")), OFFER_STREAM_ID, true);
}

#[when("his side fails part way through")]
async fn file_fails(w: &mut AlooWorld) {
    let pending = w.pending_receipts.as_mut().expect("no offer");
    w.receipted = pending.settle(UserId(id_for("bob")), OFFER_STREAM_ID, false);
}

#[then("my message is acknowledged")]
async fn message_acknowledged(w: &mut AlooWorld) {
    assert_eq!(
        w.receipted,
        Some(OFFER_MSG_ID),
        "the receipt names the message the offer named"
    );
}

#[then("nothing is acknowledged")]
async fn nothing_acknowledged(w: &mut AlooWorld) {
    assert_eq!(
        w.receipted, None,
        "a transfer that failed leaves the sender's row undelivered, which is the truth"
    );
    assert!(
        w.pending_receipts.as_ref().expect("no offer").is_empty(),
        "and it is forgotten rather than left to be settled later"
    );
}

// ---------------------------------------------------------------------
// The extra states a voice message and a file can reach (AC-236)
// ---------------------------------------------------------------------

/// Opens the details popup on the last row, so the assertions below read
/// the same thing a user pressing `i` would. Idempotent, because `i` is a
/// toggle and several steps in a row may want it open.
fn open_details_on_last_row(w: &mut AlooWorld) {
    if popup_rows(w).iter().any(|r| r.contains("Message details")) {
        return;
    }
    let state = w.ui_mut();
    let len = state.channels[0].log.len();
    state.focus = Focus::Messages;
    state.message_selected = len.saturating_sub(1);
    state.handle_key(KeyCode::Char('i'), KeyModifiers::NONE, KeyEventKind::Press);
}

fn last_msg_id_in_general(w: &AlooWorld) -> u64 {
    w.ui_ref().channels[0]
        .log
        .last()
        .and_then(|e| e.delivery.as_ref())
        .map(|d| d.msg_id)
        .expect("the last row tracks a delivery")
}

#[when(expr = "bob reports he decrypted it")]
async fn bob_decrypted(w: &mut AlooWorld) {
    let msg_id = last_msg_id_in_general(w);
    w.ui_mut().mark_delivered(
        UserId(id_for("bob")),
        msg_id,
        ReceiptStage::Decrypted,
        DeliveryProof::Receipt,
    );
    open_details_on_last_row(w);
}

#[when(expr = "bob reports he played it")]
#[when(expr = "bob reports he saved it")]
async fn bob_consumed(w: &mut AlooWorld) {
    let msg_id = last_msg_id_in_general(w);
    w.ui_mut().mark_delivered(
        UserId(id_for("bob")),
        msg_id,
        ReceiptStage::Consumed,
        DeliveryProof::Receipt,
    );
    open_details_on_last_row(w);
}

#[then(expr = "the message details name {string} as DELIVERED+LISTENED")]
async fn details_listened(w: &mut AlooWorld, name: String) {
    assert_popup_row_pairs(w, &name, LISTENED_LABEL);
}

#[then(expr = "the message details name {string} as DELIVERED+SAVED")]
async fn details_saved(w: &mut AlooWorld, name: String) {
    assert_popup_row_pairs(w, &name, SAVED_LABEL);
}

#[then("the message details show no extra state")]
async fn details_no_extra_state(w: &mut AlooWorld) {
    let rows = popup_rows(w);
    assert!(
        !rows
            .iter()
            .any(|r| r.contains(LISTENED_LABEL) || r.contains(SAVED_LABEL)),
        "there is no such thing as listening to, or saving, a text message; rendered:\n{}",
        rows.join("\n")
    );
}

// ---------------------------------------------------------------------
// A receipt is earned by being readable, not by arriving (AC-233)
// ---------------------------------------------------------------------

const PEER: UserId = UserId(2);

#[given("a session that can read messages sent to it")]
async fn a_readable_session(w: &mut AlooWorld) {
    let (my_public, my_private) = pq_bundle_for("receipt-me");
    let my_der = aloo::proto::encode(&my_public).expect("encode bundle");
    let scratch = std::env::temp_dir().join(format!(
        "aloo-bdd-receipt-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&scratch).unwrap();
    let mut session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity {
            private: my_private,
            public_der: my_der,
        },
        scratch,
        otp: None,
    })
    .await;

    let mut ui = UiState::new("me".into());
    ui.set_own_id(UserId(1));
    ui.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
    ui.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    let (peer_public, _) = pq_bundle_for("receipt-bob");
    let peer = UserInfo {
        id: PEER,
        name: "bob".into(),
        public_key_der: aloo::proto::encode(&peer_public).expect("encode bundle"),
        key_mode: KeyMode::PqHybrid,
    };
    ui.seed_member("general", peer.clone());
    ui.known_users.insert(PEER, peer);
    // Never punched, so whatever the session decides to send stays where a
    // step below can read it.
    session
        .peer_link_mut()
        .ensure_link(&mut aloo::control::NullSink, PEER)
        .await;

    w.ui = Some(ui);
    w.receipt_session = Some(session);
    w.receipt_own_bundle = Some(my_public);
}

/// Bob really seals a message - to `sealed_to`'s keys, which a step
/// chooses to be ours or a stranger's. `msg_id` doubles as the send id, so
/// two messages in one scenario never collide in the `ReplayGuard`.
async fn peer_sends(w: &mut AlooWorld, sealed_to: &PqPublicBundle, msg_id: u64) {
    let (_, bob_private) = pq_bundle_for("receipt-bob");
    let blob = aloo::crypto::pq::seal_send(
        &bob_private,
        sealed_to.bootstrap_encap(),
        aloo::crypto::pq::bundle_fingerprint(sealed_to).expect("fingerprint"),
        Some("general".to_string()),
        msg_id,
        b"a message",
    )
    .expect("sealing should succeed");
    let envelope = aloo::proto::Envelope {
        content: aloo::proto::Content::Text,
        blocks: vec![blob],
    };
    let mut session = w.receipt_session.take().expect("no session");
    let ui = w.ui.as_mut().expect("no ui");
    aloo::client::channel::on_message(
        ui,
        &mut session,
        "general".into(),
        PEER,
        "bob".into(),
        Some(msg_id),
        envelope,
    );
    w.receipt_session = Some(session);
}

fn receipts_sent(w: &mut AlooWorld) -> Vec<(u64, ReceiptStage)> {
    w.receipt_session
        .as_mut()
        .expect("no session")
        .peer_link_mut()
        .pending_payloads(PEER)
        .into_iter()
        .filter_map(|p| match p {
            aloo::p2p_proto::P2pPayload::DeliveryReceipt { msg_id, stage } => Some((msg_id, stage)),
            _ => None,
        })
        .collect()
}

#[when("a peer sends me a message they sealed to my key")]
async fn peer_sends_readable(w: &mut AlooWorld) {
    let bundle = w.receipt_own_bundle.take().expect("no bundle");
    peer_sends(w, &bundle, 1).await;
    w.receipt_own_bundle = Some(bundle);
}

#[when("a peer sends me a message sealed to somebody else's key")]
async fn peer_sends_unreadable(w: &mut AlooWorld) {
    let (stranger, _) = pq_bundle_for("receipt-stranger");
    peer_sends(w, &stranger, 2).await;
}

#[then("that message is acknowledged as decrypted")]
async fn acknowledged_as_decrypted(w: &mut AlooWorld) {
    assert_eq!(
        receipts_sent(w),
        vec![(1, ReceiptStage::Decrypted)],
        "one receipt, naming the message that opened"
    );
}

#[then("nothing more is acknowledged")]
async fn nothing_more_acknowledged(w: &mut AlooWorld) {
    assert_eq!(
        receipts_sent(w),
        vec![(1, ReceiptStage::Decrypted)],
        "the unreadable one added nothing - the sender's row stays undelivered"
    );
}

// ---------------------------------------------------------------------
// How the message was encrypted (AC-242), and under a pad (AC-243)
// ---------------------------------------------------------------------

#[when("I open the details of my last message")]
async fn open_details_of_last_message(w: &mut AlooWorld) {
    let state = w.ui_mut();
    let len = match state.active_private_room {
        Some(peer) => state.private_rooms[&peer].log.len(),
        None => state.channels[0].log.len(),
    };
    state.focus = Focus::Messages;
    state.message_selected = len.saturating_sub(1);
    state.handle_key(KeyCode::Char('i'), KeyModifiers::NONE, KeyEventKind::Press);
}

/// Read wide: the popup sizes itself to its own longest line, and the
/// scheme's name is the longest thing in it.
fn details_rows(w: &AlooWorld) -> Vec<String> {
    crate::support::rows_of(&crate::support::ui_buffer(w.ui_ref(), 160, 30))
}

fn assert_details_line(w: &AlooWorld, label: &str, value: &str) {
    let rows = details_rows(w);
    assert!(
        rows.iter().any(|r| r.contains(label) && r.contains(value)),
        "no details line reads {label:?} {value:?}; rendered:\n{}",
        rows.join("\n")
    );
}

#[then("the details name the encryption scheme by its mechanism")]
async fn details_name_the_scheme(w: &mut AlooWorld) {
    // The cipher, not the `my_key` tag the sidebar shows - that one is
    // about identity, and says nothing about how a message was encrypted.
    assert_details_line(w, ENCRYPTION_LABEL, "ML-KEM-1024");
}

#[then("the details name the key it was sealed to")]
async fn details_name_the_key(w: &mut AlooWorld) {
    let key_id = {
        let state = w.ui_ref();
        let peer = state.active_private_room.expect("a room is open");
        aloo::crypto::short_fingerprint_der(&state.known_users[&peer].public_key_der)
    };
    assert_details_line(w, KEY_LABEL, &key_id);
}

#[then("the details report no encryption at all")]
async fn details_report_no_encryption(w: &mut AlooWorld) {
    assert_details_line(w, ENCRYPTION_LABEL, NO_CRYPTO_INFO);
}

#[then(expr = "the details name pad sequence {int} at offset {int}")]
async fn details_name_pad_position(w: &mut AlooWorld, seq: u64, offset: u64) {
    assert_details_line(w, KEY_SEQ_LABEL, &seq.to_string());
    assert_details_line(w, KEY_OFFSET_LABEL, &offset.to_string());
}

#[then(expr = "the details name the key file ending {string}")]
async fn details_name_key_file(w: &mut AlooWorld, tail: String) {
    assert_details_line(w, KEY_FILE_LABEL, &tail);
}
