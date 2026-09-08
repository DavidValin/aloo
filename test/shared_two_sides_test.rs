//! Cancel and resume across *both* ends of one shared-folder transfer
//! (US-066): two real sessions, each with its own identity and its own
//! record of what is passing between them, with the sealed payloads one
//! side decides to send handed to the other exactly as the link would.
//!
//! The single-session tests (`shared_session_test.rs`) pin what each side
//! does in isolation. What they cannot show is the pair agreeing - that a
//! cancel on one screen becomes a cancelled row on the other, and that a
//! resume carries on the same transfer rather than opening a second one
//! on either side. That is what this file is for.

use std::path::{Path, PathBuf};

use aloo::client::connect::ResolvedIdentity;
use aloo::client::session::shared;
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::transfer_log::{TransferDirection, TransferStatus};
use aloo::client::tui::ui::UiState;
use aloo::control::NullSink;
use aloo::crypto::pq::{PqPrivateBundle, PqPublicBundle, generate_bundle_with_bits};
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{self, ChannelInfo, ChannelKind, KeyMode, UserId, UserInfo};
use aloo::settings::SharedFolder;

const TEST_KEY_BITS: usize = 1024;
/// What each side calls the other. Both sessions are `UserId(2)` to the
/// other, which is fine and realistic: ids are per-connection.
const THEM: UserId = UserId(2);

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-two-sides-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

struct Identity {
    public: PqPublicBundle,
    private: PqPrivateBundle,
    der: Vec<u8>,
}

fn identity() -> Identity {
    let (public, private) = generate_bundle_with_bits(TEST_KEY_BITS).expect("keygen");
    let der = proto::encode(&public).expect("encode bundle");
    Identity {
        public,
        private,
        der,
    }
}

/// One end of the pair: its session, its screen, and how much of what it
/// has decided to send has already been carried to the other side.
struct Side {
    session: SessionState,
    ui: UiState,
    delivered: usize,
}

impl Side {
    async fn new(label: &str, me: &Identity, them: &Identity, them_name: &str) -> Self {
        let session = SessionState::for_test(TestSessionSpec {
            identity: ResolvedIdentity {
                private: me.private.clone(),
                public_der: me.der.clone(),
            },
            scratch: scratch(label),
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
        let info = UserInfo {
            id: THEM,
            name: them_name.into(),
            public_key_der: them.der.clone(),
            key_mode: KeyMode::PqHybrid,
        };
        ui.seed_member("general", info.clone());
        ui.known_users.insert(THEM, info);
        let _ = &them.public;
        Self {
            session,
            ui,
            delivered: 0,
        }
    }

    /// A link this side believes it can reach, recording what goes out so
    /// it can be handed to the other end.
    async fn open(&mut self) {
        self.session
            .peer_link_mut()
            .ensure_link(&mut NullSink, THEM)
            .await;
        self.session
            .peer_link_mut()
            .record_sent_payloads_for_test();
        self.session.peer_link_mut().mark_active_for_test(THEM);
    }

    fn sent(&mut self) -> Vec<P2pPayload> {
        self.session.peer_link_mut().sent_payloads_for_test(THEM)
    }

    fn uploads(&self) -> Vec<&aloo::client::transfer_log::TransferRecord> {
        self.ui
            .transfers
            .records()
            .iter()
            .filter(|r| r.direction == TransferDirection::Upload)
            .collect()
    }

    fn downloads(&self) -> Vec<&aloo::client::transfer_log::TransferRecord> {
        self.ui
            .transfers
            .records()
            .iter()
            .filter(|r| r.direction == TransferDirection::Download)
            .collect()
    }
}

/// Carries everything `from` has decided to send since the last call
/// into `to`, the way the link would - the envelopes are already sealed
/// to the other side, so nothing is re-encrypted here.
async fn deliver(from: &mut Side, to: &mut Side) {
    let all = from.sent();
    let fresh: Vec<P2pPayload> = all.into_iter().skip(from.delivered).collect();
    from.delivered += fresh.len();
    for payload in fresh {
        let envelope = match payload {
            P2pPayload::SharedFolders { envelope }
            | P2pPayload::SharedListRequest { envelope }
            | P2pPayload::SharedListResponse { envelope }
            | P2pPayload::SharedDownloadRequest { envelope }
            | P2pPayload::SharedFileTag { envelope }
            | P2pPayload::SharedDownloadPlan { envelope }
            | P2pPayload::SharedDownloadCancel { envelope }
            | P2pPayload::SharedDownloadDone { envelope } => envelope,
            _ => continue,
        };
        // Through the session's own event loop, not by calling the
        // handler directly: that is the path a real link takes, and the
        // only one that proves the arm is wired up at all.
        to.session
            .inject_p2p_event(aloo::client::p2p::P2pEvent::SharedFolderMessage {
                from: THEM,
                envelope,
            });
        aloo::client::session::drain_p2p_events(&mut NullSink, &mut to.ui, &mut to.session)
            .await
            .expect("the other side handles it");
    }
}

/// An owner sharing a folder of `files`, and a requester who may see it.
async fn pair(label: &str, files: usize) -> (Side, Side, PathBuf) {
    let owner_id = identity();
    let requester_id = identity();
    // The owner knows the requester as "bob"; the requester knows the
    // owner as "alice". Each share line names the other by that name.
    let mut owner = Side::new(&format!("{label}-owner"), &owner_id, &requester_id, "bob").await;
    let mut requester =
        Side::new(&format!("{label}-req"), &requester_id, &owner_id, "alice").await;

    let dir = scratch(&format!("{label}-share"));
    let photos = dir.join("Photos");
    for i in 0..files {
        write(&photos.join(format!("f{i}.txt")), "content");
    }
    shared::set_shares(
        &mut owner.session,
        vec![SharedFolder::parse(&format!("{},bob", photos.display())).unwrap()],
    );
    owner.open().await;
    requester.open().await;
    (owner, requester, dir)
}

/// Asks for the whole share and lets the owner answer, returning the
/// request id both sides now know it by.
async fn start_download(owner: &mut Side, requester: &mut Side) -> u64 {
    shared::request_shared_download(
        &mut NullSink,
        &mut requester.ui,
        &mut requester.session,
        THEM,
        "Photos".into(),
        String::new(),
    )
    .await
    .unwrap();
    deliver(requester, owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap(),
        "the owner walks the folder"
    );
    deliver(owner, requester).await;
    requester.downloads()[0].request_id
}

/// @requirement AC-469
#[tokio::test]
async fn a_cancel_from_the_receiver_shows_as_cancelled_on_the_sender() {
    let (mut owner, mut requester, dir) = pair("recv-cancel", 8).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    // Both sides agree it is under way.
    assert_eq!(requester.downloads()[0].status, TransferStatus::Running);
    assert_eq!(owner.uploads().len(), 1, "the sender has one row for it");
    assert!(owner.uploads()[0].status.is_active());
    let (queued_before, sending_before) = shared::queued_for(&owner.session, THEM);
    assert!(queued_before > 0 && sending_before, "and files under way");

    shared::cancel_shared_download(
        &mut NullSink,
        &mut requester.ui,
        &mut requester.session,
        request_id,
    )
    .await
    .unwrap();
    deliver(&mut requester, &mut owner).await;

    assert_eq!(
        requester.downloads()[0].status,
        TransferStatus::Cancelled,
        "the receiver's own row says so"
    );
    assert_eq!(
        owner.uploads()[0].status,
        TransferStatus::Cancelled,
        "and so does the sender's - it is not still 'sending files'"
    );
    let (queued_after, _) = shared::queued_for(&owner.session, THEM);
    assert_eq!(queued_after, 0, "nothing more of it is queued to send");
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-469
#[tokio::test]
async fn a_cancel_from_the_sender_shows_as_stopped_on_the_receiver() {
    let (mut owner, mut requester, dir) = pair("send-cancel", 8).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    shared::cancel_upload(
        &mut NullSink,
        &mut owner.ui,
        &mut owner.session,
        "bob".to_string(),
        request_id,
    )
    .await
    .unwrap();
    deliver(&mut owner, &mut requester).await;

    assert_eq!(owner.uploads()[0].status, TransferStatus::Cancelled);
    match &requester.downloads()[0].status {
        TransferStatus::Failed(why) => assert!(
            why.contains("stopped by the other side"),
            "the receiver is told who stopped it: {why}"
        ),
        other => panic!("expected the receiver's row to stop, got {other:?}"),
    }
    let (queued_after, _) = shared::queued_for(&owner.session, THEM);
    assert_eq!(queued_after, 0);
    std::fs::remove_dir_all(&dir).ok();
}

/// The whole cycle the user actually performs: cancel, resume, cancel
/// again - with one row on each screen throughout, and both screens
/// agreeing at every step.
/// @requirement AC-464, AC-469
#[tokio::test]
async fn cancel_resume_and_cancel_again_keep_one_row_agreeing_on_both_sides() {
    let (mut owner, mut requester, dir) = pair("cycle", 8).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    // 1. Cancelled from the receiver.
    shared::cancel_shared_download(
        &mut NullSink,
        &mut requester.ui,
        &mut requester.session,
        request_id,
    )
    .await
    .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert_eq!(requester.downloads()[0].status, TransferStatus::Cancelled);
    assert_eq!(owner.uploads()[0].status, TransferStatus::Cancelled);

    // 2. Resumed - the same transfer, on both screens.
    shared::resume_shared_download(
        &mut NullSink,
        &mut requester.ui,
        &mut requester.session,
        request_id,
    )
    .await
    .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    deliver(&mut owner, &mut requester).await;

    assert_eq!(
        requester.downloads().len(),
        1,
        "the receiver still has one row for this download"
    );
    assert_eq!(
        owner.uploads().len(),
        1,
        "and the sender one row, not a second item"
    );
    assert_eq!(requester.downloads()[0].request_id, request_id);
    assert_eq!(owner.uploads()[0].request_id, request_id);
    assert_eq!(
        requester.downloads()[0].status,
        TransferStatus::Running,
        "the receiver is past 'asking...'"
    );
    assert!(owner.uploads()[0].status.is_active(), "and the sender is sending again");

    // 3. Cancelled again - and it sticks on both sides.
    shared::cancel_shared_download(
        &mut NullSink,
        &mut requester.ui,
        &mut requester.session,
        request_id,
    )
    .await
    .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert_eq!(requester.downloads()[0].status, TransferStatus::Cancelled);
    assert_eq!(
        owner.uploads()[0].status,
        TransferStatus::Cancelled,
        "the sender stops showing it as sending, the second time too"
    );
    assert_eq!(shared::queued_for(&owner.session, THEM).0, 0);
    assert_eq!(requester.downloads().len(), 1, "still one row each");
    assert_eq!(owner.uploads().len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// Files keep completing on the owner while the user cancels, resumes
/// and cancels again. A round's in-flight files must stop being credited
/// to the request once it is cancelled: crediting them to the *resumed*
/// round drove its job to "every file sent" after only a handful of real
/// ones, which finished the requester's row early - and a finished row
/// cannot be cancelled, so the second cancel sent nothing and the sender
/// went on transferring for good.
/// @requirement AC-464, AC-469
#[tokio::test]
async fn completions_from_a_cancelled_round_do_not_finish_the_resumed_one() {
    const FILES: usize = 8;
    let (mut owner, mut requester, dir) = pair("interleaved", FILES).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    /// Every file offer the owner has put on the wire so far.
    fn offers(owner: &mut Side) -> Vec<u64> {
        owner
            .sent()
            .into_iter()
            .filter_map(|p| match p {
                P2pPayload::FileOffer { stream_id, .. } => Some(stream_id),
                _ => None,
            })
            .collect()
    }
    let first_round = offers(&mut owner);
    assert!(!first_round.is_empty(), "the first round is under way");

    // 1. Cancelled while those files are still going.
    shared::cancel_shared_download(
        &mut NullSink,
        &mut requester.ui,
        &mut requester.session,
        request_id,
    )
    .await
    .unwrap();
    deliver(&mut requester, &mut owner).await;

    // 2. Resumed.
    shared::resume_shared_download(
        &mut NullSink,
        &mut requester.ui,
        &mut requester.session,
        request_id,
    )
    .await
    .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    deliver(&mut owner, &mut requester).await;

    // 3. Now everything completes: the abandoned round's files first,
    //    then the resumed round's, as the owner releases them.
    let mut finished: Vec<u64> = Vec::new();
    for _ in 0..40 {
        let outstanding: Vec<u64> = offers(&mut owner)
            .into_iter()
            .filter(|s| !finished.contains(s))
            .collect();
        if outstanding.is_empty() {
            break;
        }
        for stream_id in outstanding {
            finished.push(stream_id);
            shared::on_shared_stream_finished(
                &mut NullSink,
                &mut owner.ui,
                &mut owner.session,
                stream_id,
            )
            .await
            .unwrap();
        }
        deliver(&mut owner, &mut requester).await;

        // The moment either side calls it finished, the resumed round
        // must genuinely have offered every file - not been credited
        // with the abandoned round's.
        if !requester.downloads()[0].status.is_active() {
            let second_round = offers(&mut owner).len() - first_round.len();
            assert!(
                second_round >= FILES,
                "the download was called finished after only {second_round} files of \
                 the resumed round - the cancelled round's completions were credited to it"
            );
            break;
        }
    }

    let second_round = offers(&mut owner).len() - first_round.len();
    assert_eq!(
        second_round, FILES,
        "the resumed round offers the whole folder again"
    );
    assert_eq!(requester.downloads().len(), 1, "one row each, throughout");
    assert_eq!(owner.uploads().len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// Every update to the sender's own row used to look the peer up in
/// `known_users` again. A requester who goes offline, or comes back
/// under a new id, resolves to no name at all - the record is then never
/// found, and the row sits at "transferring" with nothing left that
/// could ever close it. The name is remembered with the job instead.
/// @requirement AC-469
#[tokio::test]
async fn the_senders_row_still_closes_when_the_peer_is_no_longer_known() {
    let (mut owner, mut requester, dir) = pair("peer-gone", 4).await;
    let request_id = start_download(&mut owner, &mut requester).await;
    assert!(owner.uploads()[0].status.is_active());

    // They drop off this side's roster entirely - offline, or back under
    // a fresh id.
    owner.ui.known_users.remove(&THEM);

    let in_flight: Vec<u64> = owner
        .sent()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::FileOffer { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .collect();
    for stream_id in in_flight {
        shared::on_shared_stream_finished(
            &mut NullSink,
            &mut owner.ui,
            &mut owner.session,
            stream_id,
        )
        .await
        .unwrap();
    }

    assert_eq!(owner.uploads().len(), 1, "still one row");
    assert_eq!(
        owner.uploads()[0].files_done, 4,
        "its progress is still counted against it"
    );
    assert!(
        !owner.uploads()[0].status.is_active(),
        "and it closes rather than sitting at 'transferring' for good"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A file that was already in flight when the cancel arrived finishes on
/// the wire - it cannot be unsent - but it must not push the cancelled
/// row's counters along as though it were still going.
/// @requirement AC-469
#[tokio::test]
async fn a_file_finishing_after_a_cancel_does_not_revive_the_row() {
    let (mut owner, mut requester, dir) = pair("late-file", 8).await;
    let request_id = start_download(&mut owner, &mut requester).await;
    let in_flight: Vec<u64> = owner
        .sent()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::FileOffer { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .collect();
    assert!(!in_flight.is_empty(), "some files are on the wire");

    shared::cancel_shared_download(
        &mut NullSink,
        &mut requester.ui,
        &mut requester.session,
        request_id,
    )
    .await
    .unwrap();
    deliver(&mut requester, &mut owner).await;
    let done_before = owner.uploads()[0].files_done;

    for stream_id in in_flight {
        shared::on_shared_stream_finished(
            &mut NullSink,
            &mut owner.ui,
            &mut owner.session,
            stream_id,
        )
        .await
        .unwrap();
    }

    assert_eq!(
        owner.uploads()[0].status,
        TransferStatus::Cancelled,
        "it stays cancelled"
    );
    assert_eq!(
        owner.uploads()[0].files_done,
        done_before,
        "and its counts stop where the cancel left them"
    );
    std::fs::remove_dir_all(&dir).ok();
}
