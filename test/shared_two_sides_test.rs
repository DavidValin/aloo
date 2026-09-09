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
/// The owner is `UserId(1)` and the requester `UserId(2)`, on both sides
/// alike - the way a server hands out one id per connection that every
/// party sees the same way. It has to be consistent: a key rotation is
/// signed to the recipient's id, and a receiver checks that it is the
/// one named.
const OWNER: UserId = UserId(1);
const REQUESTER: UserId = UserId(2);
/// How the owner refers to the requester - the older name most of this
/// file uses from the owner's side.
const THEM: UserId = REQUESTER;

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
    /// The id this side knows the other by.
    them: UserId,
    /// When set, this side's key rotations are dropped on the way over
    /// rather than carried - what a relay path that lags the link, or
    /// loses them, looks like from the other end.
    withhold_rotations: bool,
}

impl Side {
    async fn new(
        label: &str,
        me: &Identity,
        them: &Identity,
        them_name: &str,
        own_id: UserId,
        them_id: UserId,
    ) -> Self {
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
        ui.set_own_id(own_id);
        ui.on_channel_list(vec![ChannelInfo {
            name: "general".into(),
            kind: ChannelKind::Public,
        }]);
        ui.on_joined(ChannelInfo {
            name: "general".into(),
            kind: ChannelKind::Public,
        });
        let info = UserInfo {
            id: them_id,
            name: them_name.into(),
            public_key_der: them.der.clone(),
            key_mode: KeyMode::PqHybrid,
        };
        ui.seed_member("general", info.clone());
        ui.known_users.insert(them_id, info);
        let mut session = session;
        // What a server's `UserJoined` seeds: the peer's bootstrap
        // encryption keys and identity fingerprint. Without it no rotation
        // ever happens on either side, and this harness spent a long time
        // passing while the real pair rotated on every send.
        let fingerprint = aloo::crypto::pq::bundle_fingerprint(&them.public).expect("fingerprint");
        session.pq_peer_keys_mut().bootstrap(
            them_id,
            them.public.bootstrap_encap().clone(),
            fingerprint,
        );
        Self {
            session,
            ui,
            delivered: 0,
            them: them_id,
            withhold_rotations: false,
        }
    }

    /// A link this side believes it can reach, recording what goes out so
    /// it can be handed to the other end.
    async fn open(&mut self) {
        let them = self.them;
        self.session
            .peer_link_mut()
            .ensure_link(&mut NullSink, them)
            .await;
        self.session
            .peer_link_mut()
            .record_sent_payloads_for_test();
        self.session.peer_link_mut().mark_active_for_test(them);
    }

    fn sent(&mut self) -> Vec<P2pPayload> {
        let them = self.them;
        self.session.peer_link_mut().sent_payloads_for_test(them)
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
async fn deliver(from: &mut Side, to: &mut Side) -> usize {
    let all = from.sent();
    let fresh: Vec<P2pPayload> = all.into_iter().skip(from.delivered).collect();
    from.delivered += fresh.len();
    let carried = fresh.len();
    let from_id = to.them;
    let withhold = from.withhold_rotations;
    for payload in fresh {
        // The file-transfer traffic a download actually produces is
        // carried too, not just the shared-folder control messages: it is
        // the accepts and rejects coming back that drive the owner's own
        // accounting, and leaving them out hid a whole class of
        // disagreement between the two sides.
        let envelope = match payload {
            P2pPayload::SharedFolders { envelope }
            | P2pPayload::SharedListRequest { envelope }
            | P2pPayload::SharedListResponse { envelope }
            | P2pPayload::SharedDownloadRequest { envelope }
            | P2pPayload::SharedFileTag { envelope }
            | P2pPayload::SharedDownloadPlan { envelope }
            | P2pPayload::SharedDownloadCancel { envelope }
            | P2pPayload::SharedDownloadDone { envelope } => envelope,
            P2pPayload::FileOffer {
                channel,
                stream_id,
                msg_id,
                envelope,
            } => {
                to.session
                    .inject_p2p_event(aloo::client::p2p::P2pEvent::FileOffer {
                        channel,
                        from: from_id,
                        stream_id,
                        msg_id,
                        envelope,
                    });
                aloo::client::session::drain_p2p_events(&mut NullSink, &mut to.ui, &mut to.session)
                    .await
                    .expect("the offer is handled");
                continue;
            }
            // Key rotations travel in wire order with everything else -
            // which is the whole point: a receiver must never be further
            // behind the sender's keys than the messages between them.
            P2pPayload::KeyRotation { .. } if withhold => continue,
            P2pPayload::KeyRotation {
                rotation,
                signature,
            } => {
                to.session
                    .inject_p2p_event(aloo::client::p2p::P2pEvent::KeyRotation {
                        from: from_id,
                        rotation,
                        signature,
                    });
                aloo::client::session::drain_p2p_events(&mut NullSink, &mut to.ui, &mut to.session)
                    .await
                    .expect("the rotation is handled");
                continue;
            }
            P2pPayload::FileAccept { stream_id } => {
                to.session
                    .inject_p2p_event(aloo::client::p2p::P2pEvent::FileAccepted { stream_id });
                aloo::client::session::drain_p2p_events(&mut NullSink, &mut to.ui, &mut to.session)
                    .await
                    .expect("the accept is handled");
                continue;
            }
            P2pPayload::FileReject { stream_id } => {
                to.session
                    .inject_p2p_event(aloo::client::p2p::P2pEvent::FileRejected { stream_id });
                aloo::client::session::drain_p2p_events(&mut NullSink, &mut to.ui, &mut to.session)
                    .await
                    .expect("the reject is handled");
                continue;
            }
            _ => continue,
        };
        // Through the session's own event loop, not by calling the
        // handler directly: that is the path a real link takes, and the
        // only one that proves the arm is wired up at all.
        to.session
            .inject_p2p_event(aloo::client::p2p::P2pEvent::SharedFolderMessage {
                from: from_id,
                envelope,
            });
        aloo::client::session::drain_p2p_events(&mut NullSink, &mut to.ui, &mut to.session)
            .await
            .expect("the other side handles it");
    }
    carried
}

/// Carries traffic both ways until a whole round trip moves nothing.
/// The owner may offer one file per key rotation the requester sends
/// back - a rotation is what refreshes the permit each send consumes
/// (`RemoteKeys`), and the requester rotates as each tag arrives - so a
/// burst that a single `deliver` used to carry whole now takes as many
/// round trips as it has files. This is that exchange run to rest.
async fn settle(owner: &mut Side, requester: &mut Side) {
    for _ in 0..64 {
        let a = deliver(owner, requester).await;
        let b = deliver(requester, owner).await;
        if a == 0 && b == 0 {
            return;
        }
    }
    panic!("the two sides never came to rest");
}

/// An owner sharing a folder of `files`, and a requester who may see it.
async fn pair(label: &str, files: usize) -> (Side, Side, PathBuf) {
    let owner_id = identity();
    let requester_id = identity();
    // The owner knows the requester as "bob"; the requester knows the
    // owner as "alice". Each share line names the other by that name.
    let mut owner = Side::new(
        &format!("{label}-owner"),
        &owner_id,
        &requester_id,
        "bob",
        OWNER,
        REQUESTER,
    )
    .await;
    let mut requester = Side::new(
        &format!("{label}-req"),
        &requester_id,
        &owner_id,
        "alice",
        REQUESTER,
        OWNER,
    )
    .await;

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
        OWNER,
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
    let before_resume = offers(&mut owner).len();
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
                true,
            )
            .await
            .unwrap();
        }
        deliver(&mut owner, &mut requester).await;
        deliver(&mut requester, &mut owner).await;

        // The moment either side calls it finished, the resumed round
        // must genuinely have offered every file - not been credited
        // with the abandoned round's.
        if !requester.downloads()[0].status.is_active() {
            let second_round = offers(&mut owner).len() - before_resume;
            assert!(
                second_round >= FILES,
                "the download was called finished after only {second_round} files of \
                 the resumed round - the cancelled round's completions were credited to it"
            );
            break;
        }
    }

    let second_round = offers(&mut owner).len() - before_resume;
    assert_eq!(
        second_round, FILES,
        "the resumed round offers the whole folder again"
    );
    assert_eq!(requester.downloads().len(), 1, "one row each, throughout");
    assert_eq!(owner.uploads().len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// The user's exact sequence, with the transfer genuinely running
/// between the steps: files complete and are accepted on both sides
/// after the resume, and only then is it cancelled a second time. The
/// earlier cycle test cancelled the resumed round the instant it
/// started, before a single file of it had been answered - which is not
/// what a person does, and skipped whatever the round leaves behind.
/// @requirement AC-469, TB-303
#[tokio::test]
async fn a_second_cancel_after_the_resume_has_run_still_stops_the_sender() {
    const FILES: usize = 8;
    let (mut owner, mut requester, dir) = pair("second-cancel", FILES).await;
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

    // A couple of the first round's files land before the user gives up
    // on it.
    let mut finished: Vec<u64> = Vec::new();
    for stream_id in offers(&mut owner).into_iter().take(2) {
        finished.push(stream_id);
        shared::on_shared_stream_finished(
            &mut NullSink,
            &mut owner.ui,
            &mut owner.session,
            stream_id,
            true,
        )
            .await
            .unwrap();
    }
    deliver(&mut owner, &mut requester).await;
    deliver(&mut requester, &mut owner).await;

    // 1. Cancelled.
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert_eq!(requester.downloads()[0].status, TransferStatus::Cancelled);
    assert_eq!(owner.uploads()[0].status, TransferStatus::Cancelled);

    // 2. Resumed.
    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    deliver(&mut owner, &mut requester).await;
    deliver(&mut requester, &mut owner).await;
    assert!(owner.uploads()[0].status.is_active(), "the sender is going again");

    // 3. It runs for a while: files of the resumed round complete and
    //    are answered, both sides moving, exactly as they would on
    //    screen.
    for _ in 0..3 {
        let outstanding: Vec<u64> = offers(&mut owner)
            .into_iter()
            .filter(|s| !finished.contains(s))
            .take(2)
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
                true,
            )
            .await
            .unwrap();
        }
        deliver(&mut owner, &mut requester).await;
        deliver(&mut requester, &mut owner).await;
    }
    assert!(
        requester.downloads()[0].status.is_active(),
        "the resumed download is still going when the user reaches for cancel: {:?}",
        requester.downloads()[0].status
    );

    // 4. Cancelled again - and the sender must stop, not go on
    //    "transferring" for good.
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;

    assert_eq!(requester.downloads()[0].status, TransferStatus::Cancelled);
    assert_eq!(
        owner.uploads()[0].status,
        TransferStatus::Cancelled,
        "the sender stops showing it as sending after the second cancel too"
    );
    assert_eq!(shared::queued_for(&owner.session, THEM).0, 0);
    assert_eq!(requester.downloads().len(), 1, "one row each, throughout");
    assert_eq!(owner.uploads().len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// The owner walks the folder off its event loop, and only starts
/// sending when that walk lands. A cancel that arrives while it is
/// still walking - which is exactly what a big folder and an impatient
/// second cancel produce - must stop the round the walk is about to
/// start. Otherwise the receiver shows "cancelled" while the sender
/// begins transferring the whole folder with nothing left that could
/// ever stop it.
/// @requirement TB-303
#[tokio::test]
async fn a_cancel_arriving_while_the_owner_is_still_walking_stops_that_round() {
    let (mut owner, mut requester, dir) = pair("cancel-mid-walk", 8).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    // Cancelled, resumed - and cancelled again straight away, before
    // the owner's walk of the resumed ask has come back.
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;

    // Now the walk lands, after the cancel.
    shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
        .await
        .unwrap();
    deliver(&mut owner, &mut requester).await;

    assert_eq!(requester.downloads()[0].status, TransferStatus::Cancelled);
    assert_eq!(
        owner.uploads()[0].status,
        TransferStatus::Cancelled,
        "the walk that landed after the cancel must not start the round again"
    );
    assert_eq!(
        shared::queued_for(&owner.session, THEM),
        (0, false),
        "and nothing of it is queued or on the wire"
    );
    assert_eq!(owner.uploads().len(), 1, "one row each, throughout");
    assert_eq!(requester.downloads().len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// What "resume" is supposed to mean: the files already on disk are
/// refused as they are offered, so only what is missing actually moves.
/// The ask itself is the same one again - the owner re-walks the folder
/// and offers every file - so the skipping is the whole of it, and
/// nothing else here proves it happens end to end.
/// @requirement AC-464
#[tokio::test]
async fn resuming_skips_the_files_already_on_disk() {
    const FILES: usize = 4;
    let (mut owner, mut requester, dir) = pair("resume-skip", FILES).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    // The stopped round's stragglers - files the owner had already put
    // on the wire when the cancel reached it - are refused and answered
    // now, so that what follows counts the resumed round alone.
    settle(&mut owner, &mut requester).await;
    let rejects_before = requester
        .sent()
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::FileReject { .. }))
        .count();

    // Two of them are already here, whole, from the round that was
    // stopped - the owner knows them as "alice".
    let landed = shared::download_dir(&requester.session)
        .join("alice")
        .join("Photos");
    for i in 0..2 {
        write(&landed.join(format!("f{i}.txt")), "content");
    }

    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    settle(&mut owner, &mut requester).await;

    assert_eq!(
        requester.downloads()[0].files_skipped, 2,
        "the two already here are refused rather than fetched again"
    );
    // And the owner is told so: those streams come back refused, which
    // is what lets it move on to the rest.
    let rejects = requester
        .sent()
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::FileReject { .. }))
        .count();
    assert_eq!(
        rejects - rejects_before,
        2,
        "and the sender is told not to send them"
    );

    // The sender's own row says the same, rather than counting bytes it
    // never put on the wire as sent.
    deliver(&mut requester, &mut owner).await;
    assert_eq!(
        owner.uploads()[0].files_skipped, 2,
        "the sender records them as already had, not as sent"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Cancel and resume must hold up whichever side stops it and in
/// whatever order, so every combination is walked here rather than the
/// one or two a person happened to try. Each round genuinely runs -
/// files complete and are answered - before the next step.
async fn cancel_resume_cancel(label: &str, first_by_owner: bool, second_by_owner: bool) {
    const FILES: usize = 8;
    let (mut owner, mut requester, dir) = pair(label, FILES).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    async fn stop(
        owner: &mut Side,
        requester: &mut Side,
        request_id: u64,
        by_owner: bool,
    ) {
        if by_owner {
            shared::cancel_upload(
                &mut NullSink,
                &mut owner.ui,
                &mut owner.session,
                "bob".to_string(),
                request_id,
            )
            .await
            .unwrap();
            deliver(owner, requester).await;
        } else {
            shared::cancel_shared_download(
                &mut NullSink,
                &mut requester.ui,
                &mut requester.session,
                request_id,
            )
            .await
            .unwrap();
            deliver(requester, owner).await;
        }
    }

    /// Lets a couple of the files under way actually complete.
    async fn run_a_little(owner: &mut Side, requester: &mut Side, finished: &mut Vec<u64>) {
        let outstanding: Vec<u64> = owner
            .sent()
            .into_iter()
            .filter_map(|p| match p {
                P2pPayload::FileOffer { stream_id, .. } => Some(stream_id),
                _ => None,
            })
            .filter(|s| !finished.contains(s))
            .take(2)
            .collect();
        for stream_id in outstanding {
            finished.push(stream_id);
            shared::on_shared_stream_finished(
                &mut NullSink,
                &mut owner.ui,
                &mut owner.session,
                stream_id,
                true,
            )
            .await
            .unwrap();
        }
        deliver(owner, requester).await;
        deliver(requester, owner).await;
    }

    let mut finished: Vec<u64> = Vec::new();
    run_a_little(&mut owner, &mut requester, &mut finished).await;

    // 1. Stopped by one side.
    stop(&mut owner, &mut requester, request_id, first_by_owner).await;
    assert!(
        !requester.downloads()[0].status.is_active(),
        "the receiver's row stops ({label})"
    );
    assert!(
        !owner.uploads()[0].status.is_active(),
        "and so does the sender's ({label}): {:?}",
        owner.uploads()[0].status
    );

    // 2. Resumed from the receiver, which is the only side that can.
    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    deliver(&mut owner, &mut requester).await;
    deliver(&mut requester, &mut owner).await;
    assert!(
        owner.uploads()[0].status.is_active(),
        "the sender picks it up again ({label})"
    );
    assert!(
        requester.downloads()[0].status.is_active(),
        "and the receiver shows it running ({label})"
    );
    run_a_little(&mut owner, &mut requester, &mut finished).await;

    // 3. Stopped again, by whichever side this case is about.
    stop(&mut owner, &mut requester, request_id, second_by_owner).await;
    assert!(
        !requester.downloads()[0].status.is_active(),
        "the receiver stops ({label})"
    );
    assert!(
        !owner.uploads()[0].status.is_active(),
        "and the sender stops showing it as transferring ({label}): {:?}",
        owner.uploads()[0].status
    );
    assert_eq!(
        shared::queued_for(&owner.session, THEM).0,
        0,
        "nothing of it is left queued ({label})"
    );
    assert_eq!(requester.downloads().len(), 1, "one row each ({label})");
    assert_eq!(owner.uploads().len(), 1, "one row each ({label})");
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-469
#[tokio::test]
async fn stopping_twice_from_the_receiver_holds_on_both_sides() {
    cancel_resume_cancel("rr", false, false).await;
}

/// @requirement AC-469
#[tokio::test]
async fn stopping_from_the_sender_then_from_the_receiver_holds_on_both_sides() {
    cancel_resume_cancel("sr", true, false).await;
}

/// @requirement AC-469
#[tokio::test]
async fn stopping_twice_from_the_sender_holds_on_both_sides() {
    cancel_resume_cancel("ss", true, true).await;
}

/// @requirement AC-469
#[tokio::test]
async fn stopping_from_the_receiver_then_from_the_sender_holds_on_both_sides() {
    cancel_resume_cancel("rs", false, true).await;
}

/// The sender-side twin of `completions_from_a_cancelled_round_do_not_finish_the_resumed_one`.
/// When the *owner* stops an upload, the files it already had on the
/// wire have to stop being attributed to that request too - exactly as
/// they do when the requester stops it. Left attached they are credited
/// to whatever job next carries the id, which is the resume of the very
/// same transfer, and they also go on holding the parallel-send budget
/// so nothing new can go out at all.
/// @requirement AC-469
#[tokio::test]
async fn a_senders_cancel_detaches_its_files_the_way_a_receivers_does() {
    const FILES: usize = 8;
    let (mut owner, mut requester, dir) = pair("send-cancel-detach", FILES).await;
    let request_id = start_download(&mut owner, &mut requester).await;

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
    assert!(!first_round.is_empty(), "files are on the wire");

    // 1. The sender stops it, with those files still going.
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
    assert_eq!(
        shared::in_flight_for(&owner.session, THEM),
        0,
        "the stopped request's files stop counting against the send budget"
    );

    // 2. The receiver asks again.
    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    deliver(&mut owner, &mut requester).await;
    let second_round: Vec<u64> = offers(&mut owner)
        .into_iter()
        .filter(|s| !first_round.contains(s))
        .collect();
    assert!(
        !second_round.is_empty(),
        "the resumed round gets to send at all - the stopped round's files \
         are not still holding every slot"
    );

    // 3. Now the abandoned round's files finish, as they must: they were
    //    already on the wire and cannot be unsent.
    for stream_id in first_round {
        shared::on_shared_stream_finished(
            &mut NullSink,
            &mut owner.ui,
            &mut owner.session,
            stream_id,
            true,
        )
            .await
            .unwrap();
    }
    deliver(&mut owner, &mut requester).await;
    assert!(
        requester.downloads()[0].status.is_active(),
        "the resumed download is not called finished on the strength of \
         the abandoned round's files: {:?}",
        requester.downloads()[0].status
    );

    // 4. And the receiver can still stop it, on both screens.
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert_eq!(requester.downloads()[0].status, TransferStatus::Cancelled);
    assert_eq!(
        owner.uploads()[0].status,
        TransferStatus::Cancelled,
        "the sender stops showing it as transferring"
    );
    assert_eq!(requester.downloads().len(), 1, "one row each, throughout");
    assert_eq!(owner.uploads().len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// A file the user went and fetched never asks them to accept it - the
/// Accept popup belongs to `/file` sends alone (§7.8). The way it turned
/// up on a folder download was a chain: a stopped round's files were
/// still credited to the resumed one, which drove the owner's job to
/// "every file sent" while half its own files were still queued; the
/// owner declared the download done; the requester forgot the request on
/// hearing that; and the files the owner then went on to send arrived
/// with tags naming a request nobody remembered, so each one asked to be
/// accepted.
/// @requirement AC-455, AC-469
#[tokio::test]
async fn a_download_never_asks_to_be_accepted_however_it_was_stopped() {
    const FILES: usize = 8;
    let (mut owner, mut requester, dir) = pair("no-popup", FILES).await;
    let request_id = start_download(&mut owner, &mut requester).await;

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

    // The sender stops it, the receiver asks again, and then everything
    // finishes - the abandoned round's files among them.
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
    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    deliver(&mut owner, &mut requester).await;

    let mut finished: Vec<u64> = Vec::new();
    for round in 0..40 {
        // The abandoned round's files land first, exactly as they would.
        let outstanding: Vec<u64> = if round == 0 {
            first_round.clone()
        } else {
            offers(&mut owner)
                .into_iter()
                .filter(|s| !finished.contains(s) && !first_round.contains(s))
                .collect()
        };
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
                true,
            )
            .await
            .unwrap();
        }
        deliver(&mut owner, &mut requester).await;
        deliver(&mut requester, &mut owner).await;
        assert!(
            requester.ui.file_offer_open().is_none(),
            "a file this side asked for was put to the user to accept"
        );
    }
    assert!(
        requester.ui.file_offer_open().is_none(),
        "a file this side asked for was put to the user to accept"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A link that drops mid-transfer closes the row on *both* screens.
/// The requester's side was closed all along; the sender's was not, and
/// dropping the job is precisely what leaves nothing able to close it -
/// so that row sat at "transferring" for the rest of the session with
/// nothing in flight behind it, which is why neither header showed a
/// speed. A later cancel could not rescue it either: the requester's own
/// state for the transfer went with the link, so its cancel was never
/// sent.
/// @requirement AC-469
#[tokio::test]
async fn a_lost_link_closes_the_row_on_both_sides() {
    let (mut owner, mut requester, dir) = pair("link-lost", 8).await;
    let request_id = start_download(&mut owner, &mut requester).await;
    assert!(owner.uploads()[0].status.is_active());
    assert!(requester.downloads()[0].status.is_active());

    shared::on_peer_link_lost(&mut owner.session, &mut owner.ui, THEM);
    shared::on_peer_link_lost(&mut requester.session, &mut requester.ui, OWNER);

    assert!(
        !owner.uploads()[0].status.is_active(),
        "the sender's row closes rather than sitting at 'transferring' \
         with nothing behind it: {:?}",
        owner.uploads()[0].status
    );
    assert!(
        !requester.downloads()[0].status.is_active(),
        "and so does the receiver's"
    );
    let _ = request_id;
    std::fs::remove_dir_all(&dir).ok();
}

/// Resuming after a real round, rather than after files were planted on
/// disk: the files that genuinely arrived are finished through the very
/// destination the accept computed, and the resumed round must refuse
/// exactly those. This is the whole chain - the path the tag implies,
/// the path the accept writes to, the path the finished file is renamed
/// to, and the path the next round tests - and it only resumes if all
/// four agree.
/// @requirement AC-464
#[tokio::test]
async fn a_resume_refuses_the_files_the_previous_round_actually_delivered() {
    const FILES: usize = 8;
    let (mut owner, mut requester, dir) = pair("resume-real", FILES).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    // The files of the first round arrive, exactly as a transfer would
    // leave them: written to the partial the accept chose, then finished.
    let arriving = shared::receiving_from_for_test(&requester.session, OWNER);
    assert!(!arriving.is_empty(), "files are arriving");
    let delivered = arriving.len() as u32;
    for (stream_id, partial, _dest) in arriving {
        write(&partial, "content");
        assert!(
            shared::finish_shared_receive(
                &mut requester.session,
                &mut requester.ui,
                OWNER,
                stream_id,
                true,
            ),
            "the arriving file is finished"
        );
    }

    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;

    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
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
        requester.downloads()[0].files_skipped, delivered,
        "every file the first round delivered is refused rather than \
         fetched again - the resume moves only what is missing"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A link that goes away mid-transfer is not the end of the transfer:
/// both sides show what actually happened, and once the peer is back the
/// download picks up from there rather than starting over. What arrived
/// before the link went is kept and refused when it is offered again, so
/// only the rest moves.
/// @requirement AC-464, AC-469
#[tokio::test]
async fn a_transfer_cut_off_by_a_lost_link_resumes_from_where_it_got_to() {
    const FILES: usize = 8;
    let (mut owner, mut requester, dir) = pair("link-resume", FILES).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    // Some of it genuinely arrives first.
    let arriving = shared::receiving_from_for_test(&requester.session, OWNER);
    let delivered = arriving.len() as u32;
    assert!(delivered > 0, "some files are arriving");
    for (stream_id, partial, _) in arriving {
        write(&partial, "content");
        shared::finish_shared_receive(
            &mut requester.session,
            &mut requester.ui,
            OWNER,
            stream_id,
            true,
        );
    }

    // Then the link goes.
    shared::on_peer_link_lost(&mut owner.session, &mut owner.ui, THEM);
    shared::on_peer_link_lost(&mut requester.session, &mut requester.ui, OWNER);
    assert!(!owner.uploads()[0].status.is_active(), "the sender says so");
    assert!(
        !requester.downloads()[0].status.is_active(),
        "and so does the receiver"
    );

    // They come back - the harness's own link is still standing, which
    // is what a peer returning amounts to here - and the user resumes.
    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
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
        requester.downloads()[0].files_skipped, delivered,
        "what arrived before the link went is kept, not fetched again"
    );
    assert!(
        requester.downloads()[0].status.is_active(),
        "and the rest of it is moving again"
    );
    assert_eq!(requester.downloads().len(), 1, "still one row each");
    assert_eq!(owner.uploads().len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// A cancel whose send does not make it must not leave the two sides
/// disagreeing for good. It used to: the cancel went out exactly once
/// and its result was discarded, so a moment where the peer could not be
/// sealed to - a key not yet rotated in, a link already gone - left this
/// side showing "cancelled" and the owner still showing the upload, and
/// cancelling again did nothing at all because from this side's point of
/// view it already had. The owner answers every cancel, and the ask
/// repeats until that answer comes.
/// @requirement AC-469
#[tokio::test]
async fn a_cancel_that_does_not_get_through_is_asked_again_until_it_does() {
    let (mut owner, mut requester, dir) = pair("cancel-lost", 8).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    // The cancel is made, but nothing of it reaches the owner - the
    // send is simply dropped on the floor here.
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    let _lost = requester.sent();
    requester.delivered = requester_sent_count(&mut requester);
    assert_eq!(
        requester.downloads()[0].status,
        TransferStatus::Cancelled,
        "this side has given up on it"
    );
    assert!(
        owner.uploads()[0].status.is_active(),
        "and the owner has not heard, so the two disagree for now"
    );

    // The ticker comes round. The cancel goes again, and this time it
    // lands.
    tokio::time::sleep(shared::CANCEL_RETRY_EVERY).await;
    shared::retry_pending_cancels(&mut NullSink, &mut requester.ui, &mut requester.session)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;

    assert_eq!(
        owner.uploads()[0].status,
        TransferStatus::Cancelled,
        "the owner is told after all, rather than transferring for good"
    );

    // And the owner's answer stops the asking.
    deliver(&mut owner, &mut requester).await;
    assert!(
        !shared::has_pending_request(&requester.session, request_id),
        "the answer closes the request, so nothing is re-sent for ever"
    );
    assert_eq!(requester.downloads()[0].status, TransferStatus::Cancelled);
    assert_eq!(requester.downloads().len(), 1, "one row each, throughout");
    assert_eq!(owner.uploads().len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// How much this side has put on the wire so far, so a test can decide
/// that some of it never arrived.
fn requester_sent_count(side: &mut Side) -> usize {
    let them = side.them;
    side.session
        .peer_link_mut()
        .sent_payloads_for_test(them)
        .len()
}

/// The answer to a cancel can arrive after the user has already
/// resumed - the cancel is re-asked until it is answered, so the answer
/// is exactly the message most likely to be late. It must close the
/// round it names and not the one that replaced it. Every ask carries
/// its own number for that reason.
/// @requirement AC-469, TB-303
#[tokio::test]
async fn the_answer_to_a_cancel_does_not_close_the_round_that_replaced_it() {
    let (mut owner, mut requester, dir) = pair("late-ack", 8).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    // Cancelled, and the owner answers - but that answer is held up.
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    let held = owner.sent();
    owner.delivered += held.len();
    assert_eq!(owner.uploads()[0].status, TransferStatus::Cancelled);

    // Meanwhile the user resumes, and the resumed round gets going.
    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    deliver(&mut owner, &mut requester).await;
    assert!(
        requester.downloads()[0].status.is_active(),
        "the resumed download is running"
    );

    // Only now does the answer to the cancel land.
    for payload in held {
        if let P2pPayload::SharedDownloadDone { envelope } = payload {
            requester
                .session
                .inject_p2p_event(aloo::client::p2p::P2pEvent::SharedFolderMessage {
                    from: OWNER,
                    envelope,
                });
            aloo::client::session::drain_p2p_events(
                &mut NullSink,
                &mut requester.ui,
                &mut requester.session,
            )
            .await
            .expect("the late answer is handled");
        }
    }

    assert!(
        requester.downloads()[0].status.is_active(),
        "the resumed download is untouched by the previous round's answer: {:?}",
        requester.downloads()[0].status
    );
    assert!(
        owner.uploads()[0].status.is_active(),
        "and the sender is still sending it"
    );
    assert_eq!(requester.downloads().len(), 1, "one row each");
    assert_eq!(owner.uploads().len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// The sender's own view of which round is live can fall behind the
/// requester's: it is dropped with the link, and the ask that would
/// advance it can go missing. A cancel must still stop the transfer
/// then. Requiring the two views to agree exactly made the disagreement
/// permanent - with nothing remembered the sender reads attempt 1, so
/// the *first* cancel of a download matched and worked while every later
/// one was quietly acknowledged and ignored, and the upload ran on for
/// good. That is why cancelling worked once and never again.
/// @requirement AC-469, TB-303
#[tokio::test]
async fn a_cancel_still_stops_the_sender_when_its_view_of_the_round_is_behind() {
    let (mut owner, mut requester, dir) = pair("attempt-behind", 8).await;
    let request_id = start_download(&mut owner, &mut requester).await;

    // One cancel and resume, so the requester is on its second ask.
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    deliver(&mut owner, &mut requester).await;
    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    deliver(&mut owner, &mut requester).await;
    assert!(owner.uploads()[0].status.is_active(), "it is running again");

    // The sender forgets which round that was - what a lost link does to
    // it - while the transfer itself carries on.
    shared::forget_round_for_test(&mut owner.session, THEM, request_id);

    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;

    assert_eq!(requester.downloads()[0].status, TransferStatus::Cancelled);
    assert_eq!(
        owner.uploads()[0].status,
        TransferStatus::Cancelled,
        "the sender stops, rather than acknowledging the cancel and \
         transferring on"
    );
    assert_eq!(shared::queued_for(&owner.session, THEM).0, 0);
    assert_eq!(requester.downloads().len(), 1, "one row each");
    assert_eq!(owner.uploads().len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// A file still arriving from a round the user has moved past is not a
/// file nobody asked for. It has to be recognised as belonging to that
/// download - or the ordinary Accept popup goes up for it, which belongs
/// to `/file` sends alone - and then refused, so nothing of an abandoned
/// round is written.
/// @requirement AC-455, TB-303
#[tokio::test]
async fn a_file_from_a_round_the_user_moved_past_is_refused_not_offered() {
    let (mut owner, mut requester, dir) = pair("old-round-file", 8).await;

    // The first round runs, but its tags and offers are held back rather
    // than delivered - they are still on their way when everything else
    // happens.
    shared::request_shared_download(
        &mut NullSink,
        &mut requester.ui,
        &mut requester.session,
        OWNER,
        "Photos".into(),
        String::new(),
    )
    .await
    .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    let held = owner.sent();
    owner.delivered += held.len();
    let request_id = requester.downloads()[0].request_id;

    // The user gives up on it and asks again.
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    deliver(&mut owner, &mut requester).await;
    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    deliver(&mut owner, &mut requester).await;

    // Only now do the first round's tags and offers turn up.
    let mut tagged = 0;
    for payload in held {
        match payload {
            P2pPayload::SharedFileTag { envelope } => {
                tagged += 1;
                requester
                    .session
                    .inject_p2p_event(aloo::client::p2p::P2pEvent::SharedFolderMessage {
                        from: OWNER,
                        envelope,
                    });
            }
            P2pPayload::FileOffer {
                channel,
                stream_id,
                msg_id,
                envelope,
            } => {
                requester
                    .session
                    .inject_p2p_event(aloo::client::p2p::P2pEvent::FileOffer {
                        channel,
                        from: OWNER,
                        stream_id,
                        msg_id,
                        envelope,
                    });
            }
            _ => continue,
        }
        aloo::client::session::drain_p2p_events(
            &mut NullSink,
            &mut requester.ui,
            &mut requester.session,
        )
        .await
        .expect("the straggler is handled");
    }
    assert!(tagged > 0, "the first round did tag some files");

    assert!(
        requester.ui.file_offer_open().is_none(),
        "a file of an abandoned round is refused, not put to the user to accept"
    );
    assert!(
        requester.downloads()[0].status.is_active(),
        "and the round they are actually on is untouched"
    );
    assert_eq!(requester.downloads().len(), 1, "one row throughout");
    std::fs::remove_dir_all(&dir).ok();
}

/// What was actually happening on the user's machines. The owner rotates
/// its encryption key after every sealed send and keeps only the last
/// eight; a folder download sends its plan, four tags and four offers in
/// one go. The rotations those nine sends triggered used to reach the
/// requester only after all nine, so a cancel sealed in between was nine
/// keys behind, could not be opened, and was dropped - and every retry
/// sealed to the same stale key. Meanwhile the requester refused each
/// file the owner went on offering, and every refusal ticked the owner's
/// progress bar without a byte moving: "the sender keeps transferring,
/// the bar moves, and neither header shows a speed".
/// @requirement AC-469, TB-225
#[tokio::test]
async fn a_cancel_is_never_sealed_to_a_key_the_owner_has_already_retired() {
    let (mut owner, mut requester, dir) = pair("key-lag", 8).await;
    let request_id = start_download(&mut owner, &mut requester).await;
    assert!(
        owner
            .sent()
            .iter()
            .any(|p| matches!(p, P2pPayload::KeyRotation { .. })),
        "the owner genuinely rotates in this harness now"
    );

    // Cancelled, and asked again - the resumed round is the burst.
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    deliver(&mut owner, &mut requester).await;
    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    deliver(&mut owner, &mut requester).await;

    // Cancelled again, right after that burst - sealed to whatever key
    // of the owner's the requester knows at this moment.
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    let bytes_before = owner.uploads()[0].bytes_done;
    deliver(&mut requester, &mut owner).await;

    assert_eq!(
        owner.uploads()[0].status,
        TransferStatus::Cancelled,
        "the owner could open the cancel and stopped"
    );

    // And the refusal loop never starts: nothing more is offered, so the
    // owner's bar does not creep along on files the requester refused.
    for _ in 0..4 {
        deliver(&mut owner, &mut requester).await;
        deliver(&mut requester, &mut owner).await;
    }
    assert_eq!(
        owner.uploads()[0].bytes_done, bytes_before,
        "the sender's progress does not move after the cancel"
    );
    assert_eq!(shared::queued_for(&owner.session, THEM).0, 0);
    std::fs::remove_dir_all(&dir).ok();
}

/// The owner's rotations may not reach the requester in time, or at all:
/// a relayed rotation lags a link that carries everything else, and a
/// relay can drop one. The requester then seals to the newest key it
/// *has*, which grows older with every send the owner makes. The owner
/// must not rotate itself out of that key's reach: it stops rotating
/// once it is `PQ_KEY_RETENTION - 1` generations ahead of the last key
/// the requester was seen using, so the cancel still opens.
/// @requirement TB-164, AC-469
#[tokio::test]
async fn a_cancel_still_opens_when_the_owners_rotations_stop_reaching_the_requester() {
    let (mut owner, mut requester, dir) = pair("rotation-lost", 8).await;
    let request_id = start_download(&mut owner, &mut requester).await;
    settle(&mut owner, &mut requester).await;

    // From here on nothing the owner rotates reaches the requester.
    owner.withhold_rotations = true;

    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    settle(&mut owner, &mut requester).await;
    assert_eq!(owner.uploads()[0].status, TransferStatus::Cancelled);

    // The resumed round: a burst of tags and offers, each rotating the
    // owner's key, none of which the requester hears about - and the
    // requester refusing each file it already has, which makes the
    // owner offer the next.
    shared::resume_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;
    assert!(
        shared::await_shared_event(&mut NullSink, &mut owner.ui, &mut owner.session)
            .await
            .unwrap()
    );
    settle(&mut owner, &mut requester).await;
    assert!(owner.uploads()[0].status.is_active(), "the sender is sending again");

    // Cancelled again, sealed to the newest key the requester knows -
    // which is now many of the owner's rotations old.
    shared::cancel_shared_download(&mut NullSink, &mut requester.ui, &mut requester.session, request_id)
        .await
        .unwrap();
    deliver(&mut requester, &mut owner).await;

    assert_eq!(
        owner.uploads()[0].status,
        TransferStatus::Cancelled,
        "the owner can still open a cancel sealed to the last key the requester heard of"
    );
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
    let _request_id = start_download(&mut owner, &mut requester).await;
    settle(&mut owner, &mut requester).await;
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
            true,
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
            true,
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
