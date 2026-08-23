//! OTP mail steps (US-035, docs/PROTOCOL.md §17): the `/mail`//`/mailbox`
//! surface driven through `UiState` exactly like the other UI features,
//! the mail server exercised over real loopback TCP (the storage under a
//! scenario temp dir), the client's re-padded received-mail store, and
//! the pad-safety gates - the same split the OTP-layer steps (`otp.rs`)
//! use between UI, live-socket and pure-function coverage.

use std::path::PathBuf;
use std::time::Duration;

use cucumber::{given, then, when};
use crossterm::event::KeyCode;
use tokio::net::{TcpListener, TcpStream};

use aloo::client::otp_cli::{self, OtpCliOutcome, RecoverDirection};
use aloo::client::otp_mail::{MailGate, RecipientCheck, mail_gate};
use aloo::client::otp_mail_store::{OtpMailStore, ReceivedMailRef, SentMailRef, SentMailStatus};
use aloo::client::tui::otp_mail::{MailboxRow, MailFocus};
use aloo::client::tui::ui::UiAction;
use aloo::control::ControlEndpoint;
use aloo::crypto::otp::{OtpMailSealed, mail_id_is_valid, new_mail_id, repad};
use aloo::crypto::pq::{bundle_fingerprint, sign_mail, verify_mail};
use aloo::proto::{ClientMessage, KeyMode, ServerMessage};
use aloo::server::ServerOptions;
use aloo::server::mail::{MailStore, StoredMail};
use aloo::server::users_registry::UsersRegistry;

use crate::world::{AlooWorld, pq_bundle_for};

const MAIL_CONTACT: &str = "aabb-ccdd";

/// Polls `cond` for up to a second - disk effects of a message we sent
/// happen on the server's own task, an instant after the send returns.
async fn eventually(mut cond: impl FnMut() -> bool, what: &str) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn compose_of(w: &AlooWorld) -> &aloo::client::tui::otp_mail::ComposeState {
    &w.ui_ref()
        .otp_mail
        .as_ref()
        .expect("the mail view should be open")
        .compose
}

fn rendered_rows(w: &AlooWorld) -> Vec<String> {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| aloo::client::tui::ui::render(f, w.ui_ref()))
        .unwrap();
    let buffer = terminal.backend().buffer().clone();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect()
}

// ---------------------------------------------------------------------
// Compose view (AC-154..AC-159) - UiState-driven
// ---------------------------------------------------------------------

#[then("the mail compose view is open")]
async fn compose_open(w: &mut AlooWorld) {
    assert!(w.ui_ref().otp_mail.is_some());
}

#[then("the mail compose view is not open")]
async fn compose_not_open(w: &mut AlooWorld) {
    assert!(w.ui_ref().otp_mail.is_none());
}

#[then("the mail's To, Subtext and Content fields are all empty")]
async fn fields_empty(w: &mut AlooWorld) {
    let compose = compose_of(w);
    assert!(compose.to.is_empty());
    assert!(compose.subtext.is_empty());
    assert!(compose.content.is_empty());
    assert!(compose.attachments.is_empty());
}

#[then(expr = "a recipient check was requested for {string}")]
async fn check_requested(w: &mut AlooWorld, nickname: String) {
    assert_eq!(
        w.last_action,
        Some(UiAction::CheckOtpMailRecipient { nickname })
    );
}

#[when(expr = "the recipient check answers that {string} is not pinned")]
async fn check_not_pinned(w: &mut AlooWorld, nickname: String) {
    w.ui_mut()
        .otp_mail_set_check(&nickname, RecipientCheck::NotPinned);
}

#[when(expr = "the recipient check answers that {string} has a {int} MB key")]
#[given(expr = "the recipient check answers that {string} has a {int} MB key")]
async fn check_ok_mb(w: &mut AlooWorld, nickname: String, mb: u64) {
    w.ui_mut().otp_mail_set_check(
        &nickname,
        RecipientCheck::Ok {
            contact_name: MAIL_CONTACT.into(),
            enc_key_remaining: mb * 1024 * 1024,
        },
    );
}

#[when(expr = "the recipient check answers that {string} has a key with {int} spare bytes")]
async fn check_ok_spare(w: &mut AlooWorld, nickname: String, spare: u64) {
    // "Spare" over the compose view's own fixed overhead estimate, so the
    // scenario can speak in attachment-sized numbers.
    w.ui_mut().otp_mail_set_check(
        &nickname,
        RecipientCheck::Ok {
            contact_name: MAIL_CONTACT.into(),
            enc_key_remaining: aloo::client::otp_mail::MAIL_OVERHEAD_ESTIMATE + spare,
        },
    );
}

#[then("the To field renders invalid, red, with a cross")]
async fn to_renders_invalid(w: &mut AlooWorld) {
    assert!(!compose_of(w).valid_for_composing());
    let rows = rendered_rows(w);
    assert!(
        rows.iter().any(|r| r.contains('\u{274C}')),
        "a cross emoji marks the invalid recipient: {rows:?}"
    );
}

#[then("the To field renders valid, green, with a tick")]
async fn to_renders_valid(w: &mut AlooWorld) {
    assert!(compose_of(w).valid_for_composing());
    let rows = rendered_rows(w);
    assert!(
        rows.iter().any(|r| r.contains('\u{2705}')),
        "a tick emoji marks the valid recipient: {rows:?}"
    );
}

#[then("the remaining key is displayed in the top right, in MB")]
async fn key_left_displayed(w: &mut AlooWorld) {
    let rows = rendered_rows(w);
    let header = &rows[0];
    assert!(
        header.contains("Key left:") && header.contains("MB"),
        "{header:?}"
    );
    assert!(header.trim_end().ends_with("MB"), "right-aligned: {header:?}");
}

#[when("I note the remaining key")]
async fn note_key_left(w: &mut AlooWorld) {
    w.otp_mail_key_left = Some(
        compose_of(w)
            .key_left_after_mail()
            .expect("the recipient check should have passed"),
    );
}

#[when("I move to the mail content field")]
async fn focus_content(w: &mut AlooWorld) {
    w.ui_mut()
        .otp_mail
        .as_mut()
        .expect("mail view open")
        .compose
        .focus = MailFocus::Content;
}

#[when("I move to the mail attachments pane")]
async fn focus_attachments(w: &mut AlooWorld) {
    w.ui_mut()
        .otp_mail
        .as_mut()
        .expect("mail view open")
        .compose
        .focus = MailFocus::Attachments;
}

#[then(expr = "the remaining key shrank by {int} bytes")]
async fn key_left_shrank(w: &mut AlooWorld, by: u64) {
    let before = w.otp_mail_key_left.expect("noted earlier");
    let now = compose_of(w).key_left_after_mail().expect("still valid");
    assert_eq!(before - now, by);
}

#[when(expr = "a {int} byte voice recording finishes for the mail")]
#[given(expr = "a {int} byte voice recording finishes for the mail")]
async fn voice_finishes(w: &mut AlooWorld, bytes: usize) {
    // The same entry point `session.rs` uses when the accumulate worker
    // reports - returning false is the cancelled case.
    w.ui_mut().otp_mail_add_voice(500, vec![0u8; bytes]);
}

#[then("the recording was cancelled, not attached")]
async fn recording_cancelled(w: &mut AlooWorld) {
    assert!(compose_of(w).attachments.is_empty());
}

#[then(expr = "the mail has {int} attachment")]
#[then(expr = "the mail has {int} attachments")]
async fn attachment_count(w: &mut AlooWorld, n: usize) {
    assert_eq!(compose_of(w).attachments.len(), n);
}

#[then("a removal confirmation is open")]
async fn removal_confirm_open(w: &mut AlooWorld) {
    assert!(compose_of(w).delete_confirm.is_some());
    let rows = rendered_rows(w);
    assert!(
        rows.iter().any(|r| r.contains("Remove attachment")),
        "{rows:?}"
    );
}

#[then("a send confirmation is open")]
async fn send_confirm_open(w: &mut AlooWorld) {
    assert!(compose_of(w).send_confirm);
    let rows = rendered_rows(w);
    assert!(rows.iter().any(|r| r.contains("Send this mail to")), "{rows:?}");
}

#[then("no send was produced and the compose view is still open")]
async fn no_send_produced(w: &mut AlooWorld) {
    assert!(w.action_was_none, "Enter on the Cancel default sends nothing");
    assert!(w.ui_ref().otp_mail.is_some());
    assert!(!compose_of(w).send_confirm, "the confirm closed");
}

#[then("the send action was produced")]
async fn send_produced(w: &mut AlooWorld) {
    assert_eq!(w.last_action, Some(UiAction::SendOtpMail));
}

// ---------------------------------------------------------------------
// Retry ciphertext recovery (AC-159/TB-193) - real `otp` CLI
// ---------------------------------------------------------------------

#[when(expr = "{word} seals an otp mail for {word}")]
async fn seal_mail(w: &mut AlooWorld, from: String, _to: String) {
    let contact = w.otp_contact_name.clone().expect("a provisioned contact");
    let cfg = w.otp_cfgs.get(&from).expect("sender cfg").clone();
    // A real sealed shape: payload + identity signature, exactly what the
    // send path pipes through `otp --encrypt`.
    let (_, private) = pq_bundle_for(&from);
    let payload = b"subtext and content and attachments, encoded".to_vec();
    let signature = sign_mail(&private, &payload).expect("sign");
    let sealed = aloo::proto::encode(&OtpMailSealed { payload, signature }).unwrap();
    let Ok(OtpCliOutcome::Ok(ciphertext)) =
        otp_cli::encrypt_retrying(&cfg, &contact, &sealed, true).await
    else {
        panic!("mail encrypt should succeed");
    };
    w.otp_mail_sealed = sealed;
    w.otp_mail_ciphertext = ciphertext;
}

#[then("the keychain's last-sent copy replays the very same ciphertext")]
async fn last_sent_replays(w: &mut AlooWorld) {
    let contact = w.otp_contact_name.clone().unwrap();
    let cfg = w.otp_cfgs.get("alice").expect("the sealing side's cfg").clone();
    let recovered = otp_cli::recover_last(&cfg, &contact, RecoverDirection::Sent)
        .await
        .expect("recover runs")
        .expect("a safety copy exists while unconfirmed");
    assert_eq!(recovered, w.otp_mail_ciphertext);
}

#[then(expr = "{word} decrypts it back to the sealed bytes")]
async fn recipient_decrypts(w: &mut AlooWorld, to: String) {
    let contact = w.otp_contact_name.clone().unwrap();
    let cfg = w.otp_cfgs.get(&to).expect("recipient cfg").clone();
    let Ok(OtpCliOutcome::Ok(bytes)) =
        otp_cli::decrypt_retrying(&cfg, &contact, &w.otp_mail_ciphertext, true).await
    else {
        panic!("mail decrypt should succeed");
    };
    assert_eq!(bytes, w.otp_mail_sealed);
}

// ---------------------------------------------------------------------
// The live mail server (AC-160, AC-161) - loopback TCP + scenario disk
// ---------------------------------------------------------------------

#[given("a server with otp mail storage")]
async fn mail_server(w: &mut AlooWorld) {
    let mail_dir = w.temp_path("mail-server");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let users = UsersRegistry::open_with_iterations(w.temp_path("mail-server-users"), 100).unwrap();
    let options = ServerOptions::new(users.clone()).with_mail_dir(mail_dir.clone());
    tokio::spawn(async move {
        let _ = aloo::server::serve(listener, options).await;
    });
    w.addr = Some(addr);
    w.server_users = Some(users);
    w.otp_mail_dir = Some(mail_dir);
}

fn mail_dir(w: &AlooWorld) -> PathBuf {
    w.otp_mail_dir.clone().expect("a mail server is running")
}

async fn recv_from(w: &mut AlooWorld, who: &str) -> ServerMessage {
    let stream = w
        .client_mut(who)
        .stream
        .as_mut()
        .expect("client stream");
    tokio::time::timeout(Duration::from_secs(2), stream.recv::<ServerMessage>())
        .await
        .unwrap_or_else(|_| panic!("{who} timed out waiting for a server message"))
        .expect("recv")
        .expect("server closed the connection")
}

async fn send_from(w: &mut AlooWorld, who: &str, msg: &ClientMessage) {
    let stream = w
        .client_mut(who)
        .stream
        .as_mut()
        .expect("client stream");
    stream.send(msg).await.expect("send");
}

#[when(expr = "{word} uploads an otp mail addressed to {word}")]
async fn upload_mail(w: &mut AlooWorld, from: String, to: String) {
    // Real ciphertext is opaque to the server - what these scenarios prove
    // is storage/routing, so representative bytes stand in for a pad seal.
    let mail_id = new_mail_id();
    let ciphertext = format!("sealed-for-{to}").into_bytes();
    w.otp_mail_id = Some(mail_id.clone());
    w.otp_mail_ciphertext = ciphertext.clone();
    send_from(
        w,
        &from,
        &ClientMessage::OtpMailSend {
            mail_id,
            to,
            contact_name: MAIL_CONTACT.into(),
            seq: 0,
            sent_at_utc: 1_766_000_000,
            ciphertext,
        },
    )
    .await;
}

#[then("the server acknowledges the mail as stored")]
async fn server_acknowledges(w: &mut AlooWorld) {
    let expected = w.otp_mail_id.clone().unwrap();
    let msg = recv_from(w, "alice").await;
    let ServerMessage::OtpMailResult { mail_id, ok, reason } = msg else {
        panic!("expected OtpMailResult, got {msg:?}");
    };
    assert_eq!(mail_id, expected);
    assert!(ok, "storage should succeed: {reason:?}");
}

#[then("the mail's ciphertext waits on the server's disk")]
async fn ciphertext_on_disk(w: &mut AlooWorld) {
    let path = mail_dir(w)
        .join("pending")
        .join(w.otp_mail_id.clone().unwrap());
    eventually(|| path.is_file(), "the pending mail file to appear").await;
    let stored: StoredMail = aloo::proto::decode(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(stored.ciphertext, w.otp_mail_ciphertext);
    assert_eq!(stored.from, "alice", "from is the registered nickname");
    assert_eq!(stored.to, "bob");
}

#[when(expr = "{word} fetches his otp mail")]
#[when(expr = "{word} fetches her otp mail")]
async fn fetch_mail(w: &mut AlooWorld, who: String) {
    send_from(w, &who, &ClientMessage::OtpMailFetch).await;
}

#[then("bob is handed the stored mail intact")]
async fn bob_handed_mail(w: &mut AlooWorld) {
    let expected_id = w.otp_mail_id.clone().unwrap();
    let msg = recv_from(w, "bob").await;
    let ServerMessage::OtpMailDeliver {
        mail_id,
        from,
        contact_name,
        seq,
        ciphertext,
        ..
    } = msg
    else {
        panic!("expected OtpMailDeliver, got {msg:?}");
    };
    assert_eq!(mail_id, expected_id);
    assert_eq!(from, "alice");
    assert_eq!(contact_name, MAIL_CONTACT);
    assert_eq!(seq, 0);
    assert_eq!(ciphertext, w.otp_mail_ciphertext, "byte-identical");
}

#[when("bob acknowledges the mail")]
async fn bob_acknowledges(w: &mut AlooWorld) {
    let mail_id = w.otp_mail_id.clone().unwrap();
    send_from(w, "bob", &ClientMessage::OtpMailAck { mail_id }).await;
}

#[then("the mail's ciphertext is gone from the server's disk")]
async fn ciphertext_gone(w: &mut AlooWorld) {
    let path = mail_dir(w)
        .join("pending")
        .join(w.otp_mail_id.clone().unwrap());
    eventually(|| !path.exists(), "the pending mail file to be deleted").await;
}

#[when(expr = "{word} disconnects")]
async fn client_disconnects(w: &mut AlooWorld, who: String) {
    // Dropping the endpoint closes the TCP stream; the server unregisters
    // on EOF, freeing the nickname for the later reconnect.
    w.clients.remove(&who);
}

#[when(expr = "{word} reconnects and fetches her otp mail")]
async fn reconnect_and_fetch(w: &mut AlooWorld, who: String) {
    let addr = w.addr.expect("server running");
    // The nickname frees asynchronously with the server noticing the
    // close - retry the whole handshake until it is granted again.
    let password = w
        .server_users
        .as_ref()
        .expect("server running")
        .is_registered(&who)
        .then(|| format!("pw-{who}"))
        .expect("who should already be registered from connecting earlier");
    let mut granted = None;
    for _ in 0..100 {
        let mut stream = ControlEndpoint::new(TcpStream::connect(addr).await.unwrap());
        let _registration_open = stream
            .client_handshake()
            .await
            .unwrap()
            .expect("server closed during handshake");
        stream
            .send(&ClientMessage::Auth {
                nickname: who.clone(),
                password: password.clone(),
            })
            .await
            .unwrap();
        let ServerMessage::AuthResult { ok: true, .. } =
            stream.recv().await.unwrap().unwrap()
        else {
            panic!("auth should succeed");
        };
        stream
            .send(&ClientMessage::Identify {
                public_key_der: vec![],
                key_mode: KeyMode::PqHybrid,
            })
            .await
            .unwrap();
        match stream.recv::<ServerMessage>().await.unwrap().unwrap() {
            ServerMessage::IdentifyResult { ok: true, .. } => {
                // ChannelList follows immediately; consume it so the next
                // recv is the fetch's answer.
                let list: ServerMessage = stream.recv().await.unwrap().unwrap();
                assert!(matches!(list, ServerMessage::ChannelList(_)));
                granted = Some(stream);
                break;
            }
            ServerMessage::IdentifyResult { ok: false, .. } => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
    let stream = granted.expect("the nickname should free after the disconnect");
    w.clients.insert(
        who.clone(),
        crate::world::ClientState {
            stream: Some(stream),
            received: Vec::new(),
            ..Default::default()
        },
    );
    send_from(w, &who, &ClientMessage::OtpMailFetch).await;
}

#[then("alice is told the mail was delivered")]
async fn alice_told_delivered(w: &mut AlooWorld) {
    let expected = w.otp_mail_id.clone().unwrap();
    let msg = recv_from(w, "alice").await;
    let ServerMessage::OtpMailDelivered { mail_id } = msg else {
        panic!("expected OtpMailDelivered, got {msg:?}");
    };
    assert_eq!(mail_id, expected);
}

#[when("alice confirms the delivery receipt")]
async fn alice_confirms_receipt(w: &mut AlooWorld) {
    let mail_id = w.otp_mail_id.clone().unwrap();
    send_from(w, "alice", &ClientMessage::OtpMailDeliveredAck { mail_id }).await;
}

#[then("the server forgets the delivery receipt")]
async fn receipt_forgotten(w: &mut AlooWorld) {
    let path = mail_dir(w)
        .join("delivered")
        .join(w.otp_mail_id.clone().unwrap());
    eventually(|| !path.exists(), "the delivery receipt to be removed").await;
}

// ---------------------------------------------------------------------
// The mailbox popup (AC-162)
// ---------------------------------------------------------------------

#[then("the mailbox was requested")]
async fn mailbox_requested(w: &mut AlooWorld) {
    assert_eq!(w.last_action, Some(UiAction::OpenOtpMailbox));
    assert!(
        w.ui_ref().otp_mail.is_some(),
        "/mailbox opens the mail view as the popup's backdrop"
    );
}

#[when("the mailbox holds a delivered mail to bob and a received mail from alice")]
async fn mailbox_rows(w: &mut AlooWorld) {
    w.ui_mut().otp_mail_set_mailbox_rows(vec![
        MailboxRow::Sent(SentMailRef {
            mail_id: "aa".repeat(16),
            to: "bob".into(),
            contact_name: MAIL_CONTACT.into(),
            seq: 0,
            sent_at_utc: 1_766_000_000,
            status: SentMailStatus::Delivered,
        }),
        MailboxRow::Received(ReceivedMailRef {
            mail_id: "bb".repeat(16),
            from: "alice".into(),
            sent_at_utc: 1_766_000_100,
            received_at_utc: 1_766_000_200,
            size: 42,
        }),
    ]);
}

#[then("the mailbox lists the mail to bob as delivered, without its content")]
async fn mailbox_lists(w: &mut AlooWorld) {
    assert!(w.ui_ref().otp_mailbox_open());
    let rows = rendered_rows(w);
    assert!(
        rows.iter().any(|r| r.contains("to bob") && r.contains("delivered")),
        "{rows:?}"
    );
    assert!(rows.iter().any(|r| r.contains("from alice")), "{rows:?}");
}

#[when("I select the received mail and press Enter")]
async fn select_received(w: &mut AlooWorld) {
    let index = {
        let mail = w.ui_ref().otp_mail.as_ref().expect("mail view");
        let mb = mail.mailbox.as_ref().expect("mailbox open");
        mb.rows
            .iter()
            .position(|r| matches!(r, MailboxRow::Received(_)))
            .expect("a received row")
    };
    w.ui_mut()
        .otp_mail
        .as_mut()
        .unwrap()
        .mailbox
        .as_mut()
        .unwrap()
        .selected = index;
    crate::steps::ui_common::press_key(
        w,
        KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    );
}

#[then("a read of the received mail was requested")]
async fn read_requested(w: &mut AlooWorld) {
    assert_eq!(
        w.last_action,
        Some(UiAction::ReadOtpMail {
            mail_id: "bb".repeat(16)
        })
    );
}

// ---------------------------------------------------------------------
// The client's received-mail store (AC-163)
// ---------------------------------------------------------------------

#[given("a fresh client mail store")]
async fn fresh_client_store(w: &mut AlooWorld) {
    let dir = w.temp_path("mail-client");
    w.otp_mail_dir = Some(dir.clone());
    w.otp_mail_client_store = Some(OtpMailStore::new_empty(dir));
}

#[when("a decrypted mail payload is stored re-padded")]
async fn store_repadded(w: &mut AlooWorld) {
    let payload = b"From: alice - the whole decoded mail".to_vec();
    let (ct, pad) = repad(&payload);
    w.otp_mail_payload = payload;
    w.otp_mail_id = Some("cd".repeat(16));
    let store = w.otp_mail_client_store.as_mut().unwrap();
    store
        .store_received_payload(
            ReceivedMailRef {
                mail_id: "cd".repeat(16),
                from: "alice".into(),
                sent_at_utc: 1,
                received_at_utc: 2,
                size: w.otp_mail_payload.len() as u64,
            },
            &ct,
            &pad,
        )
        .expect("store blobs");
}

fn blob_paths(w: &AlooWorld) -> (PathBuf, PathBuf) {
    let dir = w.otp_mail_dir.clone().unwrap();
    let id = w.otp_mail_id.clone().unwrap();
    (dir.join(format!("{id}.ct")), dir.join(format!("{id}.pad")))
}

#[then("the store holds a ciphertext file and a pad file for it")]
async fn blob_pair_exists(w: &mut AlooWorld) {
    let (ct, pad) = blob_paths(w);
    assert!(ct.is_file());
    assert!(pad.is_file());
}

#[then("neither file alone contains the payload")]
async fn neither_is_plaintext(w: &mut AlooWorld) {
    let (ct, pad) = blob_paths(w);
    assert_ne!(std::fs::read(ct).unwrap(), w.otp_mail_payload);
    assert_ne!(std::fs::read(pad).unwrap(), w.otp_mail_payload);
}

#[then("reading the mail decrypts it in memory")]
async fn reading_decrypts(w: &mut AlooWorld) {
    let store = w.otp_mail_client_store.as_ref().unwrap();
    assert_eq!(
        store.read_received_payload(&w.otp_mail_id.clone().unwrap()),
        Some(w.otp_mail_payload.clone())
    );
}

#[when("the mail is removed")]
async fn mail_removed(w: &mut AlooWorld) {
    let id = w.otp_mail_id.clone().unwrap();
    assert!(w.otp_mail_client_store.as_mut().unwrap().remove_received(&id));
}

#[then("both files are destroyed and the mail is unreadable")]
async fn blobs_destroyed(w: &mut AlooWorld) {
    let (ct, pad) = blob_paths(w);
    assert!(!ct.exists());
    assert!(!pad.exists());
    let store = w.otp_mail_client_store.as_ref().unwrap();
    assert_eq!(
        store.read_received_payload(&w.otp_mail_id.clone().unwrap()),
        None
    );
}

// ---------------------------------------------------------------------
// The pre-decrypt gate (TB-194)
// ---------------------------------------------------------------------

#[given(expr = "my pad contact for the claimed sender is {string} expecting sequence {int}")]
async fn gate_given(w: &mut AlooWorld, contact: String, next: u64) {
    w.otp_mail_expected_contact = Some(contact);
    w.otp_mail_next_expected = next;
}

#[when(expr = "a mail sealed under contact {string} arrives at sequence {int}")]
async fn gate_arrives(w: &mut AlooWorld, carried: String, seq: u64) {
    w.otp_mail_gate = Some(mail_gate(
        w.otp_mail_expected_contact.as_deref(),
        &carried,
        w.otp_mail_next_expected,
        seq,
    ));
}

#[then("the mail is refused before the pad is touched")]
async fn gate_refused(w: &mut AlooWorld) {
    assert_eq!(w.otp_mail_gate, Some(MailGate::RefuseContact));
}

#[then("the mail is admitted to the one genuine decrypt")]
async fn gate_admitted(w: &mut AlooWorld) {
    assert_eq!(w.otp_mail_gate, Some(MailGate::Decrypt));
}

#[then("the mail is only re-acknowledged")]
async fn gate_ack_only(w: &mut AlooWorld) {
    assert_eq!(w.otp_mail_gate, Some(MailGate::AckOnly));
}

#[then("the mail waits for the earlier spend")]
async fn gate_waits(w: &mut AlooWorld) {
    assert_eq!(w.otp_mail_gate, Some(MailGate::Wait));
}

// ---------------------------------------------------------------------
// The identity signature (TB-195)
// ---------------------------------------------------------------------

#[when("alice signs a mail payload")]
async fn alice_signs(w: &mut AlooWorld) {
    let (_, private) = pq_bundle_for("alice");
    w.otp_mail_payload = b"the sealed mail payload".to_vec();
    w.otp_mail_signature = sign_mail(&private, &w.otp_mail_payload).expect("sign");
}

#[then("the signature verifies against alice's pinned identity")]
async fn signature_verifies(w: &mut AlooWorld) {
    let (public, _) = pq_bundle_for("alice");
    assert!(verify_mail(&public, &w.otp_mail_payload, &w.otp_mail_signature));
}

#[then("a single flipped payload bit no longer verifies")]
async fn flipped_bit_fails(w: &mut AlooWorld) {
    let (public, _) = pq_bundle_for("alice");
    let mut tampered = w.otp_mail_payload.clone();
    tampered[0] ^= 0x01;
    assert!(!verify_mail(&public, &tampered, &w.otp_mail_signature));
}

#[then("bob's identity does not verify it either")]
async fn other_identity_fails(w: &mut AlooWorld) {
    let (bob_public, _) = pq_bundle_for("bob");
    // Sanity: the identities are genuinely distinct.
    let (alice_public, _) = pq_bundle_for("alice");
    assert_ne!(
        bundle_fingerprint(&alice_public).unwrap(),
        bundle_fingerprint(&bob_public).unwrap()
    );
    assert!(!verify_mail(&bob_public, &w.otp_mail_payload, &w.otp_mail_signature));
}

// ---------------------------------------------------------------------
// Mail id validation (TB-196)
// ---------------------------------------------------------------------

#[given("a server mail store in a scenario directory")]
async fn server_store_direct(w: &mut AlooWorld) {
    let dir = w.temp_path("mail-ids");
    w.otp_mail_server_store = Some(MailStore::open(dir).expect("open"));
}

#[then("freshly generated mail ids are 32 lowercase hex characters")]
async fn ids_are_hex(w: &mut AlooWorld) {
    let _ = w;
    for _ in 0..8 {
        let id = new_mail_id();
        assert_eq!(id.len(), 32);
        assert!(mail_id_is_valid(&id));
        assert!(id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }
}

#[then("a mail with a path-shaped id is refused by the store")]
async fn path_id_refused(w: &mut AlooWorld) {
    let store = w.otp_mail_server_store.as_ref().unwrap();
    let mail = StoredMail {
        mail_id: "../../../../etc/passwd0000000000".into(),
        from: "alice".into(),
        to: "bob".into(),
        contact_name: MAIL_CONTACT.into(),
        seq: 0,
        sent_at_utc: 0,
        ciphertext: vec![1, 2, 3],
    };
    assert!(!mail_id_is_valid(&mail.mail_id));
    assert!(store.store(&mail).is_err());
    assert!(store.pending_for("bob").is_empty());
}
