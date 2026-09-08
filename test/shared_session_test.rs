//! The shared-folder exchange over a real `SessionState` (US-066,
//! `docs/PROTOCOL.md` §7.8): what a link coming up announces and to whom,
//! how a listing and a download request are answered from the share, that
//! files go out one at a time, and - the point of the whole tag mechanism
//! - that only a file this side asked for is accepted without a popup.
//!
//! Driven through the real functions over `SessionState::for_test`, the
//! same trade `session_receipt_test.rs` makes: the link to the peer is
//! only ever opened, never punched, so whatever the session decides to
//! send is still queued where the assertions can read it
//! (`sent_or_queued_payloads`).

use std::path::{Path, PathBuf};

use aloo::client::connect::ResolvedIdentity;
use aloo::client::session::shared;
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::shared_folders::{
    SharedDownloadDone, SharedDownloadPlan, SharedDownloadRequest, SharedError, SharedFileTag,
    SharedFolderSummary, SharedListRequest, SharedListResponse,
};
use aloo::client::tui::ui::UiState;
use aloo::control::NullSink;
use aloo::crypto::pq::{
    PqPrivateBundle, PqPublicBundle, bundle_fingerprint, generate_bundle_with_bits, open_send,
    seal_send,
};
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{self, ChannelInfo, ChannelKind, Content, Envelope, KeyMode, UserId, UserInfo};
use aloo::settings::SharedFolder;

/// Small enough to keep the suite quick - key size is not what any of
/// these assert (`session_receipt_test.rs` makes the same trade).
const TEST_KEY_BITS: usize = 1024;

const ALICE: UserId = UserId(2);
const BOB: UserId = UserId(3);

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-shared-session-{label}-{}-{}",
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

/// Everything one test needs: a session that is *us*, the two peers'
/// identities, and the scratch directory shares are made in.
struct World {
    session: SessionState,
    ui: UiState,
    me: Identity,
    alice: Identity,
    bob: Identity,
    dir: PathBuf,
}

async fn world(label: &str) -> World {
    let me = identity();
    let alice = identity();
    let bob = identity();
    let dir = scratch(label);
    let session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity {
            private: me.private.clone(),
            public_der: me.der.clone(),
        },
        scratch: dir.join("session"),
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
    for (id, name, der) in [
        (ALICE, "alice", alice.der.clone()),
        (BOB, "bob", bob.der.clone()),
    ] {
        let info = UserInfo {
            id,
            name: name.into(),
            public_key_der: der,
            key_mode: KeyMode::PqHybrid,
        };
        ui.seed_member("general", info.clone());
        ui.known_users.insert(id, info);
    }
    World {
        session,
        ui,
        me,
        alice,
        bob,
        dir,
    }
}

impl World {
    /// Opens (never punches) the link, so anything sent to `peer` queues
    /// where a test can read it back.
    async fn open_link(&mut self, peer: UserId) {
        self.session
            .peer_link_mut()
            .ensure_link(&mut NullSink, peer)
            .await;
    }

    /// A link this side believes it can reach - what starting a shared
    /// send at all turns on. Once it is `Active` a payload goes straight
    /// into the reliable layer rather than the pending queue, so the
    /// recorder is what `queued` can still read it back from.
    async fn active_link(&mut self, peer: UserId) {
        self.open_link(peer).await;
        self.session.peer_link_mut().record_sent_payloads_for_test();
        self.session.peer_link_mut().mark_active_for_test(peer);
    }

    /// Everything this side decided to send `peer`, whether it is
    /// waiting for a link or already handed to the reliable layer.
    fn queued(&mut self, peer: UserId) -> Vec<P2pPayload> {
        let mut out = self.session.peer_link_mut().sent_payloads_for_test(peer);
        if out.is_empty() {
            out = self.session.sent_or_queued_payloads(peer);
        }
        out
    }

    /// One envelope `peer` really did seal to us, as their client would.
    fn sealed_from(&self, peer: &Identity, send_id: u64, content: Content, plaintext: &[u8]) -> Envelope {
        let blob = seal_send(
            &peer.private,
            self.me.public.bootstrap_encap(),
            bundle_fingerprint(&self.me.public).expect("fingerprint"),
            None,
            send_id,
            plaintext,
        )
        .expect("sealing should succeed");
        Envelope {
            content,
            blocks: vec![blob],
        }
    }

    /// Opens an envelope we sealed to `peer`, as their client would.
    fn open_as(&self, peer: &Identity, envelope: &Envelope) -> Vec<u8> {
        let fp = bundle_fingerprint(&peer.public).expect("fingerprint");
        let decaps = [peer.private.bootstrap_decap().clone()];
        open_send(&decaps, &fp, &self.me.public, &envelope.blocks[0])
            .map(|(_, plaintext)| plaintext)
            .expect("the peer must be able to open what was sealed to them")
    }

    fn cleanup(self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

/// Every payload of one shared-folder kind queued for `peer`, with its
/// envelope opened as that peer and decoded.
fn shared_payloads<T: serde::de::DeserializeOwned>(
    w: &mut World,
    peer: UserId,
    peer_identity_is_alice: bool,
    want: Content,
) -> Vec<T> {
    let payloads = w.queued(peer);
    let mut out = Vec::new();
    for payload in payloads {
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
        if envelope.content != want {
            continue;
        }
        let identity = if peer_identity_is_alice {
            &w.alice
        } else {
            &w.bob
        };
        let plaintext = w.open_as(identity, &envelope);
        out.push(proto::decode::<T>(&plaintext).expect("the payload decodes"));
    }
    out
}

/// A share of `dir`, visible to `access` (`"all"` or a nickname list).
fn share(dir: &Path, access: &str) -> SharedFolder {
    SharedFolder::parse(&format!("{},{access}", dir.display())).expect("a valid share line")
}

// ---------------------------------------------------------------------
// Announcing
// ---------------------------------------------------------------------

/// @requirement AC-450
#[tokio::test]
async fn a_link_coming_up_announces_only_what_the_peer_may_see() {
    let mut w = world("announce").await;
    let public = w.dir.join("Public");
    let photos = w.dir.join("Photos");
    std::fs::create_dir_all(&public).unwrap();
    std::fs::create_dir_all(&photos).unwrap();
    shared::set_shares(
        &mut w.session,
        vec![share(&public, "all"), share(&photos, "alice")],
    );
    w.open_link(ALICE).await;
    w.open_link(BOB).await;

    shared::send_shared_folders(&mut w.session, &w.ui, ALICE, false);
    shared::send_shared_folders(&mut w.session, &w.ui, BOB, false);

    let to_alice: Vec<Vec<SharedFolderSummary>> =
        shared_payloads(&mut w, ALICE, true, Content::SharedFolders);
    assert_eq!(to_alice.len(), 1, "alice is told once");
    let names: Vec<&str> = to_alice[0].iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["Public", "Photos"]);

    let to_bob: Vec<Vec<SharedFolderSummary>> =
        shared_payloads(&mut w, BOB, false, Content::SharedFolders);
    assert_eq!(to_bob.len(), 1);
    let names: Vec<&str> = to_bob[0].iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["Public"], "the folder shared with alice is not bob's business");
    w.cleanup();
}

/// @requirement AC-450
#[tokio::test]
async fn a_peer_who_may_see_nothing_hears_nothing_at_link_up() {
    let mut w = world("announce-nothing").await;
    let photos = w.dir.join("Photos");
    std::fs::create_dir_all(&photos).unwrap();
    shared::set_shares(&mut w.session, vec![share(&photos, "alice")]);
    w.open_link(BOB).await;

    shared::send_shared_folders(&mut w.session, &w.ui, BOB, false);
    let to_bob: Vec<Vec<SharedFolderSummary>> =
        shared_payloads(&mut w, BOB, false, Content::SharedFolders);
    assert!(to_bob.is_empty(), "nothing to say, so nothing is said");

    // A withdrawal is different: it must be said, or their side would go
    // on offering what it last heard.
    shared::send_shared_folders(&mut w.session, &w.ui, BOB, true);
    let to_bob: Vec<Vec<SharedFolderSummary>> =
        shared_payloads(&mut w, BOB, false, Content::SharedFolders);
    assert_eq!(to_bob.len(), 1);
    assert!(to_bob[0].is_empty(), "an empty list withdraws everything");
    w.cleanup();
}

/// @requirement AC-448, AC-450
#[tokio::test]
async fn saving_the_share_list_announces_it_to_every_live_link() {
    let mut w = world("announce-on-save").await;
    let public = w.dir.join("Public");
    std::fs::create_dir_all(&public).unwrap();
    w.active_link(ALICE).await;
    w.active_link(BOB).await;

    shared::apply_share_settings(&mut w.session, &mut w.ui, vec![share(&public, "all")]);

    for (peer, is_alice) in [(ALICE, true), (BOB, false)] {
        let announced: Vec<Vec<SharedFolderSummary>> =
            shared_payloads(&mut w, peer, is_alice, Content::SharedFolders);
        assert_eq!(announced.len(), 1, "every live link is told");
        assert_eq!(announced[0][0].name, "Public");
    }
    w.cleanup();
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

/// @requirement AC-451, TB-301
#[tokio::test]
async fn a_listing_request_is_answered_from_the_share() {
    let mut w = world("listing").await;
    let photos = w.dir.join("Photos");
    write(&photos.join("beach.jpg"), "12345");
    std::fs::create_dir_all(photos.join("trip")).unwrap();
    shared::set_shares(&mut w.session, vec![share(&photos, "alice")]);
    w.open_link(ALICE).await;

    let request = SharedListRequest {
        request_id: 9,
        share: "Photos".into(),
        rel_path: String::new(),
    };
    let envelope = w.sealed_from(
        &w.alice,
        1,
        Content::SharedListRequest,
        &proto::encode(&request).unwrap(),
    );
    shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
        .await
        .unwrap();
    // The read runs off the loop; applying its result is what sends the
    // answer.
    assert!(
        shared::await_shared_event(&mut NullSink, &mut w.ui, &mut w.session)
            .await
            .unwrap()
    );

    let answers: Vec<SharedListResponse> =
        shared_payloads(&mut w, ALICE, true, Content::SharedListResponse);
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].request_id, 9, "the requester's own token comes back");
    assert!(answers[0].error.is_none());
    let names: Vec<&str> = answers[0].entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["trip", "beach.jpg"], "folders first, then files");
    assert!(answers[0].entries[0].is_dir);
    assert_eq!(answers[0].entries[1].size, 5);
    w.cleanup();
}

/// @requirement TB-300
#[tokio::test]
async fn a_request_for_a_share_not_granted_is_refused() {
    let mut w = world("listing-refused").await;
    let photos = w.dir.join("Photos");
    write(&photos.join("beach.jpg"), "x");
    // Shared with bob only - alice may not see it, and must not learn
    // anything about it beyond that.
    shared::set_shares(&mut w.session, vec![share(&photos, "bob")]);
    w.open_link(ALICE).await;

    for (share_name, want) in [
        ("Photos", SharedError::NoSuchShare),
        ("Videos", SharedError::NoSuchShare),
    ] {
        let request = SharedListRequest {
            request_id: 1,
            share: share_name.into(),
            rel_path: String::new(),
        };
        let envelope = w.sealed_from(
            &w.alice,
            if share_name == "Photos" { 1 } else { 2 },
            Content::SharedListRequest,
            &proto::encode(&request).unwrap(),
        );
        shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
            .await
            .unwrap();
        // A refusal is decided without touching the disk, but still comes
        // back through the same channel a real listing does.
        assert!(
            shared::await_shared_event(&mut NullSink, &mut w.ui, &mut w.session)
                .await
                .unwrap()
        );
        let answers: Vec<SharedListResponse> =
            shared_payloads(&mut w, ALICE, true, Content::SharedListResponse);
        let answer = answers.last().expect("an answer, even a refusal");
        assert_eq!(answer.error, Some(want), "share {share_name:?}");
        assert!(answer.entries.is_empty());
    }
    w.cleanup();
}

// ---------------------------------------------------------------------
// Downloading
// ---------------------------------------------------------------------

/// The owner offers several files at once, up to the parallel budget,
/// and releases the next as each finishes - so a folder of small files
/// is not one round trip per file, and a peer's screen is not filled
/// with every file at once either.
/// @requirement AC-452, AC-456, AC-460, TB-302
#[tokio::test]
async fn a_folder_download_is_offered_up_to_the_parallel_budget() {
    let mut w = world("download").await;
    let photos = w.dir.join("Photos");
    let file_count = shared::MAX_PARALLEL_SHARED_SENDS + 2;
    for i in 0..file_count {
        write(&photos.join(format!("f{i}.txt")), "content");
    }
    shared::set_shares(&mut w.session, vec![share(&photos, "alice")]);
    w.active_link(ALICE).await;

    let request = SharedDownloadRequest {
        request_id: 4,
        share: "Photos".into(),
        rel_path: String::new(),
    };
    let envelope = w.sealed_from(
        &w.alice,
        1,
        Content::SharedDownloadRequest,
        &proto::encode(&request).unwrap(),
    );
    shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
        .await
        .unwrap();
    assert!(
        shared::await_shared_event(&mut NullSink, &mut w.ui, &mut w.session)
            .await
            .unwrap()
    );

    // The plan goes out before any file, so the requester can show real
    // progress from the start.
    let plans: Vec<SharedDownloadPlan> =
        shared_payloads(&mut w, ALICE, true, Content::SharedDownloadPlan);
    assert_eq!(plans.len(), 1, "the plan is sent once, up front");
    assert_eq!(plans[0].files, file_count as u32);
    assert!(plans[0].bytes > 0);

    assert_eq!(
        shared::in_flight_for(&w.session, ALICE),
        shared::MAX_PARALLEL_SHARED_SENDS,
        "as many as the budget allows, no more"
    );
    let (queued, _) = shared::queued_for(&w.session, ALICE);
    assert_eq!(queued, 2, "the rest wait their turn");

    // Pumping again while the budget is full adds nothing: it is
    // finishing, not asking, that releases the next.
    shared::pump_shared_sends(&mut NullSink, &mut w.ui, &mut w.session, ALICE)
        .await
        .unwrap();
    assert_eq!(
        shared::in_flight_for(&w.session, ALICE),
        shared::MAX_PARALLEL_SHARED_SENDS
    );

    // Every tag names the very stream the offer that follows it carries,
    // which is the whole mechanism - and there is one of each per file
    // in flight.
    let tags: Vec<SharedFileTag> = shared_payloads(&mut w, ALICE, true, Content::SharedFileTag);
    assert_eq!(tags.len(), shared::MAX_PARALLEL_SHARED_SENDS);
    let offer_streams: Vec<u64> = w
        .queued(ALICE)
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::FileOffer { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .collect();
    assert_eq!(offer_streams.len(), shared::MAX_PARALLEL_SHARED_SENDS);
    for tag in &tags {
        assert!(
            offer_streams.contains(&tag.stream_id),
            "tag {tag:?} names no offer that went out"
        );
        assert_eq!(tag.request_id, 4);
    }
    // A shared send carries no message id: it makes no row in either
    // side's conversation (§7.8).
    let logged = w.queued(ALICE).into_iter().any(
        |p| matches!(p, P2pPayload::FileOffer { msg_id: Some(_), .. }),
    );
    assert!(!logged, "a shared send is not a message in the chat");

    // Finishing one releases exactly one more.
    shared::on_shared_stream_finished(&mut NullSink, &mut w.ui, &mut w.session, offer_streams[0])
        .await
        .unwrap();
    assert_eq!(
        shared::in_flight_for(&w.session, ALICE),
        shared::MAX_PARALLEL_SHARED_SENDS
    );
    let (queued, _) = shared::queued_for(&w.session, ALICE);
    assert_eq!(queued, 1);

    // And when every one is over, the request is closed out once.
    let mut done_streams = vec![offer_streams[0]];
    while shared::in_flight_for(&w.session, ALICE) > 0 {
        let next: Vec<u64> = w
            .queued(ALICE)
            .into_iter()
            .filter_map(|p| match p {
                P2pPayload::FileOffer { stream_id, .. } => Some(stream_id),
                _ => None,
            })
            .filter(|s| !done_streams.contains(s))
            .collect();
        if next.is_empty() {
            break;
        }
        for stream_id in next {
            done_streams.push(stream_id);
            shared::on_shared_stream_finished(&mut NullSink, &mut w.ui, &mut w.session, stream_id)
                .await
                .unwrap();
        }
    }
    let done: Vec<SharedDownloadDone> =
        shared_payloads(&mut w, ALICE, true, Content::SharedDownloadDone);
    assert_eq!(done.len(), 1, "the request is closed exactly once");
    assert_eq!(done[0].files, file_count as u32);
    assert!(done[0].error.is_none());
    w.cleanup();
}

/// @requirement AC-452
#[tokio::test]
async fn a_download_of_something_not_shared_is_answered_with_the_reason() {
    let mut w = world("download-refused").await;
    let photos = w.dir.join("Photos");
    write(&photos.join("one.txt"), "1");
    shared::set_shares(&mut w.session, vec![share(&photos, "bob")]);
    w.active_link(ALICE).await;

    let request = SharedDownloadRequest {
        request_id: 5,
        share: "Photos".into(),
        rel_path: String::new(),
    };
    let envelope = w.sealed_from(
        &w.alice,
        1,
        Content::SharedDownloadRequest,
        &proto::encode(&request).unwrap(),
    );
    shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
        .await
        .unwrap();
    assert!(
        shared::await_shared_event(&mut NullSink, &mut w.ui, &mut w.session)
            .await
            .unwrap()
    );

    let done: Vec<SharedDownloadDone> =
        shared_payloads(&mut w, ALICE, true, Content::SharedDownloadDone);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].files, 0);
    assert_eq!(done[0].error, Some(SharedError::NoSuchShare));
    let (queued, sending) = shared::queued_for(&w.session, ALICE);
    assert_eq!((queued, sending), (0, false), "nothing was queued to send");
    w.cleanup();
}

// ---------------------------------------------------------------------
// The requester's side: only what was asked for skips the popup
// ---------------------------------------------------------------------

/// Drives the requester's half: this side asks alice for a download, she
/// tags a stream, and the offer for it arrives.
async fn ask_and_tag(w: &mut World, tag_stream: u64, tag_request_id: Option<u64>) -> u64 {
    w.open_link(ALICE).await;
    shared::request_shared_download(
        &mut NullSink,
        &mut w.ui,
        &mut w.session,
        ALICE,
        "Photos".into(),
        "trip".into(),
    )
    .await
    .unwrap();
    let asked: Vec<SharedDownloadRequest> =
        shared_payloads(w, ALICE, true, Content::SharedDownloadRequest);
    assert_eq!(asked.len(), 1, "the ask went out");
    let request_id = asked[0].request_id;

    let tag = SharedFileTag {
        request_id: tag_request_id.unwrap_or(request_id),
        stream_id: tag_stream,
        rel_path: "trip/beach.jpg".into(),
    };
    let envelope = w.sealed_from(
        &w.alice,
        41,
        Content::SharedFileTag,
        &proto::encode(&tag).unwrap(),
    );
    shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
        .await
        .unwrap();
    request_id
}

/// @requirement AC-455
#[tokio::test]
async fn a_tagged_offer_is_accepted_without_a_popup() {
    let mut w = world("auto-accept").await;
    let stream_id = 77;
    ask_and_tag(&mut w, stream_id, None).await;
    assert!(
        shared::expects_offer(&w.session, ALICE, stream_id),
        "the tag registered the offer to come"
    );

    // The offer alice sends next, through the ordinary receive path.
    let offer = aloo::client::file_transfer::FileOfferPayload {
        filename: "beach.jpg".into(),
        size: 5,
    };
    let envelope = w.sealed_from(
        &w.alice,
        42,
        Content::FileOffer,
        &proto::encode(&offer).unwrap(),
    );
    aloo::client::session::drain_p2p_events(&mut NullSink, &mut w.ui, &mut w.session)
        .await
        .unwrap();
    w.session
        .inject_p2p_event(aloo::client::p2p::P2pEvent::FileOffer {
            channel: None,
            from: ALICE,
            stream_id,
            msg_id: Some(1),
            envelope,
        });
    aloo::client::session::drain_p2p_events(&mut NullSink, &mut w.ui, &mut w.session)
        .await
        .unwrap();

    assert!(
        w.ui.file_offer_open().is_none(),
        "a file this side asked for is never put to the user again"
    );
    let accepted = w
        .queued(ALICE)
        .into_iter()
        .any(|p| matches!(p, P2pPayload::FileAccept { stream_id: s } if s == stream_id));
    assert!(accepted, "it was accepted straight away");
    assert!(
        !shared::expects_offer(&w.session, ALICE, stream_id),
        "the tag is consumed by the offer it named"
    );
    w.cleanup();
}

/// A tag for a request this side never made is worth nothing - otherwise
/// anyone could drop a file on someone's disk by dressing it as a share.
/// @requirement AC-455
#[tokio::test]
async fn an_unrequested_tag_still_gets_the_popup() {
    let mut w = world("unrequested-tag").await;
    let stream_id = 78;
    // A tag naming a request id nobody issued.
    ask_and_tag(&mut w, stream_id, Some(999_999)).await;
    assert!(
        !shared::expects_offer(&w.session, ALICE, stream_id),
        "an unrequested tag registers nothing"
    );

    let offer = aloo::client::file_transfer::FileOfferPayload {
        filename: "surprise.bin".into(),
        size: 5,
    };
    let envelope = w.sealed_from(
        &w.alice,
        42,
        Content::FileOffer,
        &proto::encode(&offer).unwrap(),
    );
    w.session
        .inject_p2p_event(aloo::client::p2p::P2pEvent::FileOffer {
            channel: None,
            from: ALICE,
            stream_id,
            msg_id: Some(1),
            envelope,
        });
    aloo::client::session::drain_p2p_events(&mut NullSink, &mut w.ui, &mut w.session)
        .await
        .unwrap();

    let shown = w.ui.file_offer_open().expect("the ordinary popup");
    assert_eq!(shown.filename, "surprise.bin");
    assert!(shown.auto_dest.is_none());
    let accepted = w
        .queued(ALICE)
        .into_iter()
        .any(|p| matches!(p, P2pPayload::FileAccept { .. }));
    assert!(!accepted, "nothing is accepted before the user says so");
    w.cleanup();
}

/// @requirement AC-455
#[tokio::test]
async fn an_untagged_offer_still_gets_the_popup() {
    let mut w = world("untagged").await;
    w.open_link(ALICE).await;
    let offer = aloo::client::file_transfer::FileOfferPayload {
        filename: "hello.bin".into(),
        size: 3,
    };
    let envelope = w.sealed_from(
        &w.alice,
        7,
        Content::FileOffer,
        &proto::encode(&offer).unwrap(),
    );
    w.session
        .inject_p2p_event(aloo::client::p2p::P2pEvent::FileOffer {
            channel: None,
            from: ALICE,
            stream_id: 12,
            msg_id: Some(1),
            envelope,
        });
    aloo::client::session::drain_p2p_events(&mut NullSink, &mut w.ui, &mut w.session)
        .await
        .unwrap();

    assert_eq!(
        w.ui.file_offer_open().map(|o| o.filename.clone()),
        Some("hello.bin".to_string()),
        "an ordinary send is still consent-gated"
    );
    w.cleanup();
}

/// A peer still under identity review may not browse or pull anything,
/// and is told nothing about what exists - the same gate every other
/// content path applies (§12.4).
/// @requirement AC-455, TB-300
#[tokio::test]
async fn a_peer_under_identity_review_is_served_nothing() {
    let mut w = world("trust-gated").await;
    let photos = w.dir.join("Photos");
    write(&photos.join("one.txt"), "1");
    shared::set_shares(&mut w.session, vec![share(&photos, "alice")]);
    w.open_link(ALICE).await;
    w.ui.push_identity_review(
        ALICE,
        "alice".into(),
        "their key changed".into(),
        aloo::client::tui::ui::IdentityCase::StaticMismatch {
            new_public_key_der: vec![9; 4],
            previous_public_key_der: vec![8; 4],
        },
    );
    assert!(w.ui.is_trust_gated(ALICE), "she is under review");

    // Nothing is announced to her at all.
    shared::send_shared_folders(&mut w.session, &w.ui, ALICE, false);
    let announced: Vec<Vec<SharedFolderSummary>> =
        shared_payloads(&mut w, ALICE, true, Content::SharedFolders);
    assert!(announced.is_empty(), "a peer under review is told nothing");

    // And a request from her is not served, either way.
    let request = SharedListRequest {
        request_id: 1,
        share: "Photos".into(),
        rel_path: String::new(),
    };
    let envelope = w.sealed_from(
        &w.alice,
        1,
        Content::SharedListRequest,
        &proto::encode(&request).unwrap(),
    );
    shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
        .await
        .unwrap();
    let answers: Vec<SharedListResponse> =
        shared_payloads(&mut w, ALICE, true, Content::SharedListResponse);
    assert!(
        answers.is_empty(),
        "not even a refusal, which would itself confirm the link is answering"
    );
    w.cleanup();
}

/// Cancelling stops the owner offering what is still queued, throws
/// away only what was half-written, and leaves every completed file
/// alone.
/// @requirement AC-464, AC-462
#[tokio::test]
async fn cancelling_keeps_what_arrived_and_drops_only_the_half_written() {
    let mut w = world("cancel").await;
    w.open_link(ALICE).await;
    shared::request_shared_download(
        &mut NullSink,
        &mut w.ui,
        &mut w.session,
        ALICE,
        "Photos".into(),
        String::new(),
    )
    .await
    .unwrap();
    let asked: Vec<SharedDownloadRequest> =
        shared_payloads(&mut w, ALICE, true, Content::SharedDownloadRequest);
    let request_id = asked[0].request_id;
    assert!(
        w.ui.shared_download(request_id).is_some(),
        "the ask opens a row on the Downloads tab, not in the chat"
    );

    // One file already finished, one still arriving.
    let done = w.dir.join("downloads/done.txt");
    let arriving = w.dir.join("downloads/arriving.txt");
    write(&done, "kept");
    let partial = aloo::client::shared_folders::partial_path(&arriving);
    write(&partial, "half");
    shared::note_receiving_for_test(
        &mut w.session,
        ALICE,
        55,
        aloo::client::session::shared::SharedReceiving {
            request_id,
            dest: arriving.clone(),
            partial: partial.clone(),
            size: 100,
            written: 4,
        },
    );

    shared::cancel_shared_download(&mut NullSink, &mut w.ui, &mut w.session, request_id)
        .await
        .unwrap();

    assert_eq!(
        w.ui.shared_download(request_id).map(|d| d.status.label()),
        Some("cancelled".to_string())
    );
    assert!(done.exists(), "a file that had already arrived is kept");
    assert!(!partial.exists(), "the half-written one is not");
    assert!(!arriving.exists(), "and it never appears under the real name");

    // The owner is told, so it stops offering the rest.
    let cancels: Vec<aloo::client::shared_folders::SharedDownloadCancel> =
        shared_payloads(&mut w, ALICE, true, Content::SharedDownloadCancel);
    assert_eq!(cancels.len(), 1);
    assert_eq!(cancels[0].request_id, request_id);
    w.cleanup();
}

/// The owner honours a cancel by dropping what is still queued for that
/// request, and nothing else.
/// @requirement AC-464
#[tokio::test]
async fn an_owner_told_to_stop_drops_the_rest_of_that_request() {
    let mut w = world("cancel-owner").await;
    let photos = w.dir.join("Photos");
    for i in 0..shared::MAX_PARALLEL_SHARED_SENDS + 3 {
        write(&photos.join(format!("f{i}.txt")), "content");
    }
    shared::set_shares(&mut w.session, vec![share(&photos, "alice")]);
    w.active_link(ALICE).await;

    let request = SharedDownloadRequest {
        request_id: 12,
        share: "Photos".into(),
        rel_path: String::new(),
    };
    let envelope = w.sealed_from(
        &w.alice,
        1,
        Content::SharedDownloadRequest,
        &proto::encode(&request).unwrap(),
    );
    shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
        .await
        .unwrap();
    assert!(
        shared::await_shared_event(&mut NullSink, &mut w.ui, &mut w.session)
            .await
            .unwrap()
    );
    let (queued_before, _) = shared::queued_for(&w.session, ALICE);
    assert!(queued_before > 0, "some are still waiting their turn");

    let cancel = aloo::client::shared_folders::SharedDownloadCancel { request_id: 12 };
    let envelope = w.sealed_from(
        &w.alice,
        2,
        Content::SharedDownloadCancel,
        &proto::encode(&cancel).unwrap(),
    );
    shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
        .await
        .unwrap();

    let (queued_after, _) = shared::queued_for(&w.session, ALICE);
    assert_eq!(queued_after, 0, "nothing more of that request is offered");
    w.cleanup();
}

/// Permission is decided again for every file as it is offered, not
/// carried over from the walk that queued it - so revoking access part
/// way through a folder download actually stops it.
/// @requirement AC-461
#[tokio::test]
async fn revoking_access_mid_download_stops_the_files_still_queued() {
    let mut w = world("revoke-mid").await;
    let photos = w.dir.join("Photos");
    let file_count = shared::MAX_PARALLEL_SHARED_SENDS + 3;
    for i in 0..file_count {
        write(&photos.join(format!("f{i}.txt")), "content");
    }
    shared::set_shares(&mut w.session, vec![share(&photos, "alice")]);
    w.active_link(ALICE).await;

    let request = SharedDownloadRequest {
        request_id: 21,
        share: "Photos".into(),
        rel_path: String::new(),
    };
    let envelope = w.sealed_from(
        &w.alice,
        1,
        Content::SharedDownloadRequest,
        &proto::encode(&request).unwrap(),
    );
    shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
        .await
        .unwrap();
    assert!(
        shared::await_shared_event(&mut NullSink, &mut w.ui, &mut w.session)
            .await
            .unwrap()
    );
    let offered_before = shared_payloads::<SharedFileTag>(&mut w, ALICE, true, Content::SharedFileTag).len();
    assert_eq!(offered_before, shared::MAX_PARALLEL_SHARED_SENDS);
    let (queued, _) = shared::queued_for(&w.session, ALICE);
    assert!(queued > 0, "some are still waiting their turn");

    // Alice is taken off the share while the rest are queued.
    shared::set_shares(&mut w.session, vec![share(&photos, "bob")]);

    // Finishing the ones in flight would ordinarily release the rest.
    let streams: Vec<u64> = w
        .queued(ALICE)
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::FileOffer { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .collect();
    for stream_id in streams {
        shared::on_shared_stream_finished(&mut NullSink, &mut w.ui, &mut w.session, stream_id)
            .await
            .unwrap();
    }

    let offered_after = shared_payloads::<SharedFileTag>(&mut w, ALICE, true, Content::SharedFileTag).len();
    assert_eq!(
        offered_after, offered_before,
        "not one more file is offered once the share is no longer hers"
    );
    let (queued, in_flight) = shared::queued_for(&w.session, ALICE);
    assert_eq!((queued, in_flight), (0, false), "the queue is drained, not sent");
    // The request is still closed out, so her side is not left waiting.
    let done: Vec<SharedDownloadDone> =
        shared_payloads(&mut w, ALICE, true, Content::SharedDownloadDone);
    assert_eq!(done.len(), 1);
    w.cleanup();
}

/// The same holds for a narrower share appearing over part of a wider
/// one mid-download: the most restrictive rule applies to every file as
/// it is offered.
/// @requirement AC-461
#[tokio::test]
async fn a_narrower_share_added_mid_download_hides_what_it_covers() {
    let mut w = world("narrow-mid").await;
    let work = w.dir.join("work");
    write(&work.join("notes.txt"), "1");
    for i in 0..shared::MAX_PARALLEL_SHARED_SENDS + 2 {
        write(&work.join(format!("payroll/p{i}.csv")), "secret");
    }
    shared::set_shares(&mut w.session, vec![share(&work, "alice")]);
    w.active_link(ALICE).await;

    let request = SharedDownloadRequest {
        request_id: 22,
        share: "work".into(),
        rel_path: String::new(),
    };
    let envelope = w.sealed_from(
        &w.alice,
        1,
        Content::SharedDownloadRequest,
        &proto::encode(&request).unwrap(),
    );
    shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
        .await
        .unwrap();
    assert!(
        shared::await_shared_event(&mut NullSink, &mut w.ui, &mut w.session)
            .await
            .unwrap()
    );

    // Whatever was already offered before the change is legitimately on
    // its way; what matters is that nothing new follows it.
    let before: Vec<String> = shared_payloads::<SharedFileTag>(&mut w, ALICE, true, Content::SharedFileTag)
        .into_iter()
        .map(|t| t.rel_path)
        .collect();

    // `payroll` becomes a share of its own that alice is not on.
    shared::set_shares(
        &mut w.session,
        vec![share(&work, "alice"), share(&work.join("payroll"), "bob")],
    );

    let streams: Vec<u64> = w
        .queued(ALICE)
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::FileOffer { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .collect();
    for stream_id in streams {
        shared::on_shared_stream_finished(&mut NullSink, &mut w.ui, &mut w.session, stream_id)
            .await
            .unwrap();
    }

    let after: Vec<String> = shared_payloads::<SharedFileTag>(&mut w, ALICE, true, Content::SharedFileTag)
        .into_iter()
        .map(|t| t.rel_path)
        .collect();
    let newly_offered: Vec<&String> = after.iter().skip(before.len()).collect();
    assert!(
        newly_offered.iter().all(|rel| !rel.starts_with("payroll/")),
        "nothing more from the newly narrowed folder is offered: {newly_offered:?}"
    );
    assert!(
        before.iter().any(|rel| rel.starts_with("payroll/")),
        "the test is only meaningful if payroll files were being sent before the change"
    );
    w.cleanup();
}

/// A peer does not have to use the browser. These are requests put on
/// the wire by hand, naming shares and paths that were never offered -
/// the listing must answer nothing, and the download must queue nothing
/// and offer no file.
/// @requirement AC-461, TB-300
#[tokio::test]
async fn an_injected_path_lists_nothing_and_downloads_nothing() {
    let mut w = world("injection").await;
    // What alice may see, what she may not, and what is not hers at all.
    let public = w.dir.join("Public");
    write(&public.join("ok.txt"), "fine");
    write(&public.join("payroll/secret.csv"), "secret");
    let private = w.dir.join("Private");
    write(&private.join("keys.txt"), "not hers");
    write(&w.dir.join("outside.txt"), "not shared at all");
    #[cfg(unix)]
    std::os::unix::fs::symlink(w.dir.join("outside.txt"), public.join("escape.txt")).unwrap();

    shared::set_shares(
        &mut w.session,
        vec![
            share(&public, "alice"),
            share(&private, "bob"),
            share(&public.join("payroll"), "bob"),
        ],
    );
    w.active_link(ALICE).await;

    // Every one of these is a request a hand-rolled client could send.
    let attempts: Vec<(&str, &str)> = vec![
        ("Private", ""),                    // a share that is not hers
        ("Nonexistent", ""),                // a share that does not exist
        ("payroll", ""),                    // a nested share she is not on
        ("Public", "payroll"),              // ...reached through the one she is on
        ("Public", "payroll/secret.csv"),   // ...and by naming the file itself
        ("Public", ".."),                   // straight out of the share
        ("Public", "../outside.txt"),
        ("Public", "sub/../../outside.txt"),
        ("Public", "/etc/passwd"),          // an absolute path
        ("Public", "./ok.txt"),             // a dot component
        ("Public", "escape.txt"),           // a symlink pointing out of it
    ];

    let mut send_id = 100;
    for (share_name, rel_path) in &attempts {
        send_id += 1;
        let req = SharedListRequest {
            request_id: send_id,
            share: (*share_name).to_string(),
            rel_path: (*rel_path).to_string(),
        };
        let envelope = w.sealed_from(
            &w.alice,
            send_id,
            Content::SharedListRequest,
            &proto::encode(&req).unwrap(),
        );
        shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
            .await
            .unwrap();
        shared::await_shared_event(&mut NullSink, &mut w.ui, &mut w.session)
            .await
            .unwrap();

        let answer = shared_payloads::<SharedListResponse>(&mut w, ALICE, true, Content::SharedListResponse)
            .into_iter()
            .find(|r| r.request_id == send_id)
            .unwrap_or_else(|| panic!("no answer for {share_name}/{rel_path}"));
        assert!(
            answer.error.is_some(),
            "{share_name}/{rel_path} was answered rather than refused"
        );
        assert!(
            answer.entries.is_empty(),
            "{share_name}/{rel_path} listed {:?}",
            answer.entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>()
        );
    }

    // And the same paths as downloads: nothing queued, nothing offered.
    for (share_name, rel_path) in &attempts {
        send_id += 1;
        let req = SharedDownloadRequest {
            request_id: send_id,
            share: (*share_name).to_string(),
            rel_path: (*rel_path).to_string(),
        };
        let envelope = w.sealed_from(
            &w.alice,
            send_id,
            Content::SharedDownloadRequest,
            &proto::encode(&req).unwrap(),
        );
        shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
            .await
            .unwrap();
        shared::await_shared_event(&mut NullSink, &mut w.ui, &mut w.session)
            .await
            .unwrap();
        assert_eq!(
            shared::queued_for(&w.session, ALICE),
            (0, false),
            "{share_name}/{rel_path} queued something to send"
        );
    }

    // Not one file offer went out across every attempt above.
    let offers = w
        .queued(ALICE)
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::FileOffer { .. }))
        .count();
    assert_eq!(offers, 0, "an injected path produced a file offer");
    let tags: Vec<SharedFileTag> = shared_payloads(&mut w, ALICE, true, Content::SharedFileTag);
    assert!(tags.is_empty(), "an injected path produced a tag: {tags:?}");

    // The share she *is* on still works, so the refusals above are the
    // rules biting rather than everything being broken.
    let req = SharedListRequest {
        request_id: 999,
        share: "Public".into(),
        rel_path: String::new(),
    };
    let envelope = w.sealed_from(
        &w.alice,
        999,
        Content::SharedListRequest,
        &proto::encode(&req).unwrap(),
    );
    shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
        .await
        .unwrap();
    shared::await_shared_event(&mut NullSink, &mut w.ui, &mut w.session)
        .await
        .unwrap();
    let answer = shared_payloads::<SharedListResponse>(&mut w, ALICE, true, Content::SharedListResponse)
        .into_iter()
        .find(|r| r.request_id == 999)
        .expect("her own share answers");
    assert!(answer.error.is_none());
    let names: Vec<&str> = answer.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["ok.txt"],
        "only what she may see - not payroll, not the symlink out"
    );
    w.cleanup();
}

/// @requirement TB-302
#[tokio::test]
async fn a_lost_link_drops_what_was_queued_for_that_peer() {
    let mut w = world("link-lost").await;
    let photos = w.dir.join("Photos");
    write(&photos.join("one.txt"), "1");
    write(&photos.join("two.txt"), "22");
    shared::set_shares(&mut w.session, vec![share(&photos, "alice")]);
    w.active_link(ALICE).await;
    w.ui.set_peer_shares(ALICE, vec!["Theirs".into()]);

    let request = SharedDownloadRequest {
        request_id: 6,
        share: "Photos".into(),
        rel_path: String::new(),
    };
    let envelope = w.sealed_from(
        &w.alice,
        1,
        Content::SharedDownloadRequest,
        &proto::encode(&request).unwrap(),
    );
    shared::on_shared_folder_message(&mut w.ui, &mut w.session, ALICE, envelope)
        .await
        .unwrap();
    assert!(
        shared::await_shared_event(&mut NullSink, &mut w.ui, &mut w.session)
            .await
            .unwrap()
    );
    let (queued, sending) = shared::queued_for(&w.session, ALICE);
    assert!(queued > 0 || sending, "something was under way");

    shared::on_peer_link_lost(&mut w.session, &mut w.ui, ALICE);
    assert_eq!(
        shared::queued_for(&w.session, ALICE),
        (0, false),
        "nothing is held for a peer who is gone"
    );
    assert!(
        w.ui.peer_shares.get(&ALICE).is_none(),
        "and what they shared is no longer offered to browse"
    );
    // But they have not withdrawn it: when they come back and say so
    // again, the DM is not told all over again.
    w.ui.set_peer_shares(ALICE, vec!["Theirs".into()]);
    let repeats = w
        .ui
        .private_rooms
        .get(&ALICE)
        .map(|room| room.log.len())
        .unwrap_or(0);
    assert_eq!(repeats, 0, "a link flap is not news to announce twice");
    w.cleanup();
}
