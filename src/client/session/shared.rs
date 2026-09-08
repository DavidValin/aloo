//! The shared-folder exchange over the direct link (`docs/PROTOCOL.md`
//! §7.8): announcing what this side shares, answering a peer's listing
//! and download requests, and - as the requester - asking, matching
//! each arriving offer to the download it answers, and accepting it
//! without a popup.
//!
//! Every message here is an ordinary sealed envelope on the reliable
//! link, exactly like `ChannelPresence`. The file bytes themselves are
//! never handled here: a download request turns into one ordinary
//! `direct_message::handle_send_file` per file, one at a time per peer,
//! each preceded by a `SharedFileTag` naming the request - so the whole
//! existing transfer path (offer, accept, chunks, receipts, and under a
//! live pad session the OTP offer/content spends) is reused as is, with
//! only the requester's accept step short-circuited
//! (`tag_incoming_offer`/`drain_auto_accepts`).
//!
//! Filesystem work is done off the select loop (`serve_listing`,
//! `serve_download` hand it to `spawn_blocking`) and comes back as a
//! `SharedEvent`, the same way a direct-punch DNS lookup does.

use std::time::{Duration, Instant};

use serde::Serialize;

use crate::client::shared_folders::{
    self, DownloadFile, SharedDownloadCancel, SharedDownloadDone, SharedDownloadPlan,
    SharedDownloadRequest, SharedError, SharedFileTag, SharedFolderSummary, SharedListRequest,
    SharedListResponse,
};
use crate::client::direct_message::SendFileRow;
use crate::client::tui::ui::{PendingFileOffer, UiState};
use crate::p2p_proto::P2pPayload;
use crate::proto::{self, Content, Envelope, UserId};
use crate::settings::SharedFolder;

use super::SessionState;

/// How long an offered shared file may sit unanswered before the owner
/// gives up on it and moves on to the next queued one - an offer held
/// behind the requester's own identity review, or simply never
/// accepted, must not stall every file behind it forever. Only an
/// *unanswered* offer times out; one that is streaming is left to the
/// transfer itself.
pub const SHARED_OFFER_TIMEOUT: Duration = Duration::from_secs(120);

/// One file waiting its turn in `SessionState::shared_send_queue`.
///
/// The share it came from is carried with it, because permission is
/// re-checked at the moment the file is offered rather than trusted from
/// the walk that queued it (`pump_shared_sends`).
pub struct QueuedSharedFile {
    pub request_id: u64,
    pub share: String,
    pub file: DownloadFile,
}

/// The owner's book-keeping for one download request: how many files it
/// resolved to, how many have finished (sent, failed, or refused), and
/// the error to report at the end if the walk was cut short.
pub struct SharedJob {
    pub total: u32,
    pub finished: u32,
    pub error: Option<SharedError>,
}

/// How many of a requester's files the owner offers at once. More than
/// one, because a folder of small files spent most of its time waiting
/// out a round trip per file; bounded, because every one in flight is a
/// row on their screen and a share of the same upload budget
/// (`shared_folders::SharePacer`), and because the reliable layer's own
/// window is what actually moves the bytes.
pub const MAX_PARALLEL_SHARED_SENDS: usize = 4;

/// One file the owner currently has in flight to a requester.
pub struct SharedSending {
    pub request_id: u64,
    /// The file's size, credited to the upload's own progress once it is
    /// over - the sender has no receive events to count from.
    pub size: u64,
    pub since: Instant,
}

/// One shared file currently arriving on the requester's side: where it
/// is being written while it arrives, and where it belongs once it is
/// whole.
///
/// It is written under `shared_folders::partial_path` throughout, so a
/// transfer that is cancelled, fails, or dies with the process never
/// leaves something that looks like the finished file - only a `.part`
/// nobody will mistake for it, which is then removed.
pub struct SharedReceiving {
    pub request_id: u64,
    pub dest: std::path::PathBuf,
    pub partial: std::path::PathBuf,
    pub size: u64,
    /// Bytes reported so far, so each progress event contributes only
    /// what is new to the download's own total.
    pub written: u64,
}

pub enum SharedRequestKind {
    List,
    Download,
}

/// A request this side has sent and not yet seen answered.
pub struct PendingSharedRequest {
    pub peer: UserId,
    pub share: String,
    pub rel_path: String,
    pub kind: SharedRequestKind,
}

/// An offer this side is expecting, from the `SharedFileTag` that
/// preceded it - what turns the offer's popup into an automatic accept.
pub struct ExpectedSharedOffer {
    pub request_id: u64,
    pub share: String,
    pub rel_path: String,
}

/// Filesystem results coming back to the select loop.
pub enum SharedEvent {
    ListReady {
        peer: UserId,
        response: SharedListResponse,
    },
    DownloadReady {
        peer: UserId,
        request_id: u64,
        /// The share the walk was of - carried so each file can be
        /// re-checked against it when its turn comes.
        share: String,
        /// What inside it was asked for, so the sender's own record of
        /// this upload is labelled the way the requester's is.
        rel_path: String,
        files: Vec<DownloadFile>,
        error: Option<SharedError>,
    },
}

// ---------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------

/// Seals `payload` to `peer` under `content` and queues it on their link -
/// the same construction `send_device_id_announce` uses. `false` if the
/// peer cannot currently be addressed (unknown, or no key to seal to).
fn send_sealed<T: Serialize>(
    session: &mut SessionState,
    ui_state: &UiState,
    peer: UserId,
    content: Content,
    payload: &T,
    wrap: fn(Envelope) -> P2pPayload,
) -> bool {
    let Some(user) = ui_state.known_users.get(&peer) else {
        return false;
    };
    let Ok(plaintext) = proto::encode(payload) else {
        return false;
    };
    let pubkey_der = user.public_key_der.clone();
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
    let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
        &session.own_pq_private,
        session.pq_peer_keys.encap_for(peer),
        &pubkey_der,
        None,
        send_id,
        &plaintext,
        content,
    ) else {
        return false;
    };
    session.peer_link.send_reliable_or_queue(peer, wrap(envelope));
    super::request_rotation(session, peer);
    true
}

// ---------------------------------------------------------------------
// Owner side
// ---------------------------------------------------------------------

/// Tells `peer` which folders they may see. `even_if_empty` sends the
/// empty list too - what a withdrawal needs, since the peer reconciles
/// against whatever they last heard; a link merely coming up sends
/// nothing when there is nothing to say.
pub fn send_shared_folders(
    session: &mut SessionState,
    ui_state: &UiState,
    peer: UserId,
    even_if_empty: bool,
) {
    // Access is decided by nickname, and a peer under identity review
    // (§12.4) is precisely someone whose claim to one is in question -
    // so they are told nothing until the user has accepted them, the
    // same gate every other content path applies.
    if ui_state.is_trust_gated(peer) {
        return;
    }
    let Some(user) = ui_state.known_users.get(&peer) else {
        return;
    };
    let names = shared_folders::visible_share_names(&session.shares, &user.name);
    if names.is_empty() && !even_if_empty {
        return;
    }
    let list: Vec<SharedFolderSummary> =
        names.into_iter().map(|name| SharedFolderSummary { name }).collect();
    send_sealed(session, ui_state, peer, Content::SharedFolders, &list, |envelope| {
        P2pPayload::SharedFolders { envelope }
    });
}

/// Reports every configured share that cannot actually be served, in the
/// status line as well as the log - a share whose folder is missing
/// otherwise fails silently here and shows up only as an error on
/// whoever tried to browse it.
pub fn report_unusable_shares(session: &SessionState, ui_state: &mut UiState) {
    for folder in &session.shares {
        if let Some(problem) = shared_folders::share_root_problem(folder) {
            crate::log_warn!("share {:?} cannot be served: {problem}", folder.name());
            ui_state.push_status_notice(
                format!("shared folder {:?}: {problem}", folder.name()),
                false,
            );
        }
    }
}

/// Re-announces to every peer with a live link - after the share list
/// changes, so a folder withdrawn here disappears on their side at once.
pub fn broadcast_shared_folders(session: &mut SessionState, ui_state: &UiState) {
    for peer in session.peer_link.active_peers() {
        send_shared_folders(session, ui_state, peer, true);
    }
}

/// The settings popup saved a new share list: applied to this session
/// and announced.
pub fn apply_share_settings(
    session: &mut SessionState,
    ui_state: &mut UiState,
    shares: Vec<SharedFolder>,
) {
    session.shares = shares;
    report_unusable_shares(session, ui_state);
    broadcast_shared_folders(session, ui_state);
}

fn serve_listing(session: &mut SessionState, nickname: &str, peer: UserId, req: SharedListRequest) {
    let tx = session.shared_events_tx.clone();
    let request_id = req.request_id;
    let failed = move |error: SharedError| SharedListResponse {
        request_id,
        entries: Vec::new(),
        truncated: false,
        error: Some(error),
    };
    match shared_folders::find_visible_share(&session.shares, nickname, &req.share) {
        Err(error) => {
            let _ = tx.send(SharedEvent::ListReady {
                peer,
                response: failed(error),
            });
        }
        Ok(share) => {
            let root = share.root();
            // Resolved before the read is handed off, from the same
            // share list this request was checked against: what a
            // narrower, stricter share hides stays hidden however this
            // folder is reached (§7.8).
            let forbidden = shared_folders::forbidden_roots(&session.shares, nickname);
            tokio::task::spawn_blocking(move || {
                let response = match shared_folders::list_directory(&root, &req.rel_path, &forbidden)
                {
                    Ok((entries, truncated)) => SharedListResponse {
                        request_id,
                        entries,
                        truncated,
                        error: None,
                    },
                    Err(error) => failed(error),
                };
                let _ = tx.send(SharedEvent::ListReady { peer, response });
            });
        }
    }
}

fn serve_download(
    session: &mut SessionState,
    nickname: &str,
    peer: UserId,
    req: SharedDownloadRequest,
) {
    let tx = session.shared_events_tx.clone();
    let request_id = req.request_id;
    match shared_folders::find_visible_share(&session.shares, nickname, &req.share) {
        Err(error) => {
            let _ = tx.send(SharedEvent::DownloadReady {
                peer,
                request_id,
                share: req.share.clone(),
                rel_path: req.rel_path.clone(),
                files: Vec::new(),
                error: Some(error),
            });
        }
        Ok(share) => {
            let root = share.root();
            let forbidden = shared_folders::forbidden_roots(&session.shares, nickname);
            let name = req.share.clone();
            let rel = req.rel_path.clone();
            tokio::task::spawn_blocking(move || {
                let (files, error) =
                    shared_folders::collect_download(&root, &req.rel_path, &forbidden);
                let _ = tx.send(SharedEvent::DownloadReady {
                    peer,
                    request_id,
                    share: name,
                    rel_path: rel,
                    files,
                    error,
                });
            });
        }
    }
}

fn send_download_done(
    session: &mut SessionState,
    ui_state: &UiState,
    peer: UserId,
    request_id: u64,
    files: u32,
    error: Option<SharedError>,
) {
    let done = SharedDownloadDone {
        request_id,
        files,
        error,
    };
    send_sealed(session, ui_state, peer, Content::SharedDownloadDone, &done, |envelope| {
        P2pPayload::SharedDownloadDone { envelope }
    });
}

/// A filesystem result is back: answer the listing, or queue the files
/// and start sending.
pub async fn on_shared_event(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    event: SharedEvent,
) -> proto::Result<()> {
    match event {
        SharedEvent::ListReady { peer, response } => {
            if response.error == Some(SharedError::ShareUnavailable) {
                // The requester is told "not readable on their machine",
                // which only this side can act on - so this side is told
                // too, with the reason.
                report_unusable_shares(session, ui_state);
            }
            send_sealed(session, ui_state, peer, Content::SharedListResponse, &response, |envelope| {
                P2pPayload::SharedListResponse { envelope }
            });
        }
        SharedEvent::DownloadReady {
            peer,
            request_id,
            share,
            rel_path,
            files,
            error,
        } => {
            if files.is_empty() {
                if error == Some(SharedError::ShareUnavailable) {
                    report_unusable_shares(session, ui_state);
                }
                send_download_done(session, ui_state, peer, request_id, 0, error);
                return Ok(());
            }
            // The sender's own record of this transfer, so it shows in
            // the global transfers popup and can be cancelled from there
            // (§7.8) - one per request, per requester.
            let peer_name = ui_state
                .known_users
                .get(&peer)
                .map(|u| u.name.clone())
                .unwrap_or_default();
            ui_state.start_transfer(
                crate::client::transfer_log::TransferDirection::Upload,
                request_id,
                peer_name,
                share.clone(),
                rel_path,
            );
            ui_state.set_transfer_plan(
                crate::client::transfer_log::TransferDirection::Upload,
                request_id,
                files.len() as u32,
                files.iter().map(|f| f.size).sum(),
            );
            ui_state.transfers.save_or_warn();
            // What this actually covers, before a byte of it moves, so
            // the requester's own progress counts against something real
            // from the start (§7.8).
            let plan = SharedDownloadPlan {
                request_id,
                files: files.len() as u32,
                bytes: files.iter().map(|f| f.size).sum(),
            };
            send_sealed(session, ui_state, peer, Content::SharedDownloadPlan, &plan, |envelope| {
                P2pPayload::SharedDownloadPlan { envelope }
            });
            session.shared_jobs.insert(
                (peer, request_id),
                SharedJob {
                    total: files.len() as u32,
                    finished: 0,
                    error,
                },
            );
            let queue = session.shared_send_queue.entry(peer).or_default();
            for file in files {
                queue.push_back(QueuedSharedFile {
                    request_id,
                    share: share.clone(),
                    file,
                });
            }
            pump_shared_sends(wr, ui_state, session, peer).await?;
        }
    }
    Ok(())
}

/// Offers `peer` as many queued files as the parallel budget allows -
/// `MAX_PARALLEL_SHARED_SENDS` at once, the next going out as each
/// finishes (`on_shared_stream_finished`).
///
/// Waits, rather than skipping the file, on the two gates a send can
/// hit: no live link, and no fresh rotating key yet
/// (`RemoteKeys::can_use`). Both clear on their own - the link coming
/// back, the peer's next rotation landing - and each of those arms pumps
/// again; the ticker's `pump_all_shared_sends` covers anything else.
pub async fn pump_shared_sends(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
) -> proto::Result<()> {
    // Offers nobody answered: given up on so the queue moves. The row
    // each made stays, marked failed, like any other send that never
    // happened.
    let stale: Vec<u64> = session
        .shared_sending
        .iter()
        .filter(|((to, stream_id), sending)| {
            *to == peer
                && sending.since.elapsed() >= SHARED_OFFER_TIMEOUT
                && session.own_file_targets.contains_key(stream_id)
        })
        .map(|((_, stream_id), _)| *stream_id)
        .collect();
    for stream_id in stale {
        session.own_file_targets.remove(&stream_id);
        let me = ui_state.own_id.unwrap_or(UserId(0));
        ui_state.set_file_failed(me, stream_id);
        note_shared_stream_finished(session, ui_state, stream_id);
    }

    while in_flight_to(session, peer) < MAX_PARALLEL_SHARED_SENDS {
        if !session.peer_link.is_active(peer) || !session.remote_keys.can_use(peer) {
            return Ok(());
        }
        let Some(user) = ui_state.known_users.get(&peer).cloned() else {
            return Ok(());
        };
        let Some(next) = session
            .shared_send_queue
            .get_mut(&peer)
            .and_then(|q| q.pop_front())
        else {
            return Ok(());
        };
        // Permission is decided again here, not carried over from the
        // walk that queued this file. A folder download is offered over
        // seconds or minutes, and in that time the owner may have taken
        // the peer off the share's list, deleted the share, or added a
        // narrower one over part of it - none of which would stop
        // anything already queued if the queue were trusted. The path is
        // re-resolved too, so what is opened is what the share holds
        // now (§7.8's "checked afresh on every request" applied to every
        // *file*, not only to the request that asked for it).
        let still_allowed = shared_folders::find_visible_share(
            &session.shares,
            &user.name,
            &next.share,
        )
        .ok()
        .and_then(|share| {
            let forbidden = shared_folders::forbidden_roots(&session.shares, &user.name);
            shared_folders::resolve_shared_path(&share.root(), &next.file.rel_path, &forbidden).ok()
        });
        let Some(path) = still_allowed else {
            // Revoked, moved or hidden since the walk: not sent, and
            // counted as finished so the request still completes rather
            // than hanging on a file that is no longer theirs.
            finish_job_file(session, ui_state, peer, next.request_id, None);
            continue;
        };

        // The tag has to name the stream the offer *after* it will use,
        // and that offer is built by `handle_send_file`, which takes its
        // id off the same counter this tag's own envelope is about to
        // consume one from - so the offer's is the one after the tag's.
        // Predicted here because the tag must go out first (ordering on
        // the reliable link is what lets the requester match them), and
        // then checked against the id the send actually claimed rather
        // than trusted.
        let stream_id = session.next_stream_id + 1;
        let before: Vec<u64> = session.own_file_targets.keys().copied().collect();
        let tag = SharedFileTag {
            request_id: next.request_id,
            stream_id,
            rel_path: next.file.rel_path.clone(),
        };
        if !send_sealed(session, ui_state, peer, Content::SharedFileTag, &tag, |envelope| {
            P2pPayload::SharedFileTag { envelope }
        }) {
            finish_job_file(session, ui_state, peer, next.request_id, None);
            continue;
        }
        let filename = crate::client::file_transfer::truncate_filename(
            &crate::client::file_transfer::display_filename(&path),
        );
        crate::client::direct_message::handle_send_file(
            wr,
            ui_state,
            session,
            peer,
            path,
            filename,
            next.file.size,
            user.public_key_der,
            SendFileRow::Silent,
        )
        .await?;
        let claimed = session
            .own_file_targets
            .keys()
            .copied()
            .find(|id| !before.contains(id));
        let Some(claimed) = claimed else {
            // Refused before it claimed an id at all (the pad gate, a key
            // that would not seal): counted as finished so the request
            // still completes, and the next file is tried.
            //
            // The tag for it is already on its way, and the requester
            // will hold that expectation until the link drops - so the id
            // it named is burned here rather than left for the next send
            // to take. Without this the very next offer to that peer, an
            // ordinary `/file` send of something else included, would
            // land on the stale expectation and be written to disk
            // unasked (§7.8's "only what was asked for skips the popup").
            if session.next_stream_id <= stream_id {
                session.next_stream_id = stream_id + 1;
            }
            finish_job_file(session, ui_state, peer, next.request_id, None);
            continue;
        };
        if claimed != stream_id {
            crate::log_warn!(
                "shared send claimed stream {claimed}, not the {stream_id} its tag named"
            );
        }
        let stream_id = claimed;
        if let Some(target) = session.own_file_targets.get_mut(&stream_id) {
            target.pacer = Some(session.share_pacer.clone());
        }
        session.shared_sending.insert(
            (peer, stream_id),
            SharedSending {
                request_id: next.request_id,
                size: next.file.size,
                since: Instant::now(),
            },
        );
        session
            .shared_request_of_stream
            .insert(stream_id, (peer, next.request_id));
    }
    Ok(())
}

/// How many of `peer`'s files are in flight right now.
fn in_flight_to(session: &SessionState, peer: UserId) -> usize {
    session
        .shared_sending
        .keys()
        .filter(|(to, _)| *to == peer)
        .count()
}

/// Counts one of `request_id`'s files as over, and sends
/// `SharedDownloadDone` once every one of them is.
fn finish_job_file(
    session: &mut SessionState,
    ui_state: &mut UiState,
    peer: UserId,
    request_id: u64,
    sent: Option<u64>,
) {
    use crate::client::transfer_log::TransferDirection::Upload;
    if let Some(size) = sent {
        ui_state.on_upload_file_done(request_id, size);
    }
    let Some(job) = session.shared_jobs.get_mut(&(peer, request_id)) else {
        return;
    };
    job.finished += 1;
    if job.finished >= job.total {
        let job = session
            .shared_jobs
            .remove(&(peer, request_id))
            .expect("just found");
        ui_state.finish_transfer(
            Upload,
            request_id,
            job.error.map(|e| e.describe().to_string()),
        );
        ui_state.transfers.save_or_warn();
        send_download_done(session, ui_state, peer, request_id, job.total, job.error);
    }
}

/// The book-keeping half of `on_shared_stream_finished`, without the
/// pump - so a give-up inside the pump itself can use it.
fn note_shared_stream_finished(
    session: &mut SessionState,
    ui_state: &mut UiState,
    stream_id: u64,
) -> Option<UserId> {
    let (peer, request_id) = session.shared_request_of_stream.remove(&stream_id)?;
    let sent = session
        .shared_sending
        .remove(&(peer, stream_id))
        .map(|s| s.size);
    finish_job_file(session, ui_state, peer, request_id, sent);
    Some(peer)
}

/// A send this side made for a download request is over - done, failed,
/// or refused (`FileEvent::SendDone`/`SendFailed`, `P2pEvent::FileRejected`):
/// the next queued file for that peer goes out. A stream that was not a
/// shared send is ignored.
pub async fn on_shared_stream_finished(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    stream_id: u64,
) -> proto::Result<()> {
    if let Some(peer) = note_shared_stream_finished(session, ui_state, stream_id) {
        pump_shared_sends(wr, ui_state, session, peer).await?;
    }
    Ok(())
}

/// The ticker's pass: every peer with something queued, or an offer to
/// give up on, is pumped. Idempotent - a peer with a send in flight and
/// nothing to time out is left alone.
pub async fn pump_all_shared_sends(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
) -> proto::Result<()> {
    let peers: std::collections::BTreeSet<UserId> = session
        .shared_send_queue
        .iter()
        .filter(|(_, q)| !q.is_empty())
        .map(|(p, _)| *p)
        .chain(session.shared_sending.keys().map(|(peer, _)| *peer))
        .collect();
    for peer in peers {
        pump_shared_sends(wr, ui_state, session, peer).await?;
    }
    Ok(())
}

/// The link to `peer` is gone: whatever was queued for them cannot be
/// sent, and whatever they were expecting will not arrive. Both sides'
/// state for that peer is dropped rather than left waiting on a link
/// that may never return under the same id.
pub fn on_peer_link_lost(session: &mut SessionState, ui_state: &mut UiState, peer: UserId) {
    session.shared_send_queue.remove(&peer);
    let dropped: Vec<u64> = session
        .shared_sending
        .keys()
        .filter(|(to, _)| *to == peer)
        .map(|(_, stream_id)| *stream_id)
        .collect();
    for stream_id in dropped {
        session.shared_sending.remove(&(peer, stream_id));
        session.shared_request_of_stream.remove(&stream_id);
    }
    session.shared_jobs.retain(|(p, _), _| *p != peer);
    // Whatever this side was pulling from them cannot continue, and its
    // half-written files go rather than being left looking finished.
    let ours: Vec<u64> = session
        .shared_requests
        .iter()
        .filter(|(_, r)| r.peer == peer)
        .map(|(id, _)| *id)
        .collect();
    for request_id in ours {
        abandon_receiving(session, request_id);
        ui_state.finish_shared_download(request_id, Some("the link went away".to_string()));
    }
    session.shared_requests.retain(|_, r| r.peer != peer);
    session.expected_shared_offers.retain(|(p, _), _| *p != peer);
    // Not a withdrawal - they will announce again when they are back, and
    // the notice must not be printed afresh on every flap.
    ui_state.forget_peer_shares_until_they_return(peer);
}

// ---------------------------------------------------------------------
// Both sides: an arriving shared-folder message
// ---------------------------------------------------------------------

/// Opens `envelope` and acts on whichever of the six payloads it is.
/// Access is checked afresh on every request (`find_visible_share`),
/// never trusted from the announce.
pub async fn on_shared_folder_message(
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    envelope: Envelope,
) -> proto::Result<()> {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return Ok(());
    };
    let content = envelope.content.clone();
    let Some(plaintext) = super::decrypt_own_envelope(&envelope, from, &sender, None, session) else {
        return Ok(());
    };
    super::request_rotation(session, from);
    match content {
        Content::SharedFolders => {
            let Ok(list) = proto::decode::<Vec<SharedFolderSummary>>(&plaintext) else {
                return Ok(());
            };
            let mut names: Vec<String> = Vec::new();
            for summary in list {
                if !summary.name.is_empty() && !names.contains(&summary.name) {
                    names.push(summary.name);
                }
            }
            ui_state.set_peer_shares(from, names);
        }
        Content::SharedListRequest => {
            let Ok(req) = proto::decode::<SharedListRequest>(&plaintext) else {
                return Ok(());
            };
            if ui_state.is_trust_gated(from) {
                return Ok(());
            }
            serve_listing(session, &sender.name, from, req);
        }
        Content::SharedListResponse => {
            let Ok(response) = proto::decode::<SharedListResponse>(&plaintext) else {
                return Ok(());
            };
            let matches = session
                .shared_requests
                .get(&response.request_id)
                .is_some_and(|r| r.peer == from && matches!(r.kind, SharedRequestKind::List));
            if !matches {
                return Ok(());
            }
            let pending = session
                .shared_requests
                .remove(&response.request_id)
                .expect("just checked");
            ui_state.set_shared_listing(
                from,
                &pending.share,
                &pending.rel_path,
                response.entries,
                response.truncated,
                response.error,
            );
        }
        Content::SharedDownloadRequest => {
            let Ok(req) = proto::decode::<SharedDownloadRequest>(&plaintext) else {
                return Ok(());
            };
            if ui_state.is_trust_gated(from) {
                return Ok(());
            }
            serve_download(session, &sender.name, from, req);
        }
        Content::SharedDownloadCancel => {
            let Ok(cancel) = proto::decode::<SharedDownloadCancel>(&plaintext) else {
                return Ok(());
            };
            // Only what is still queued: a file already in flight cannot
            // be unsent, and the requester discards it either way.
            if let Some(queue) = session.shared_send_queue.get_mut(&from) {
                queue.retain(|q| q.request_id != cancel.request_id);
            }
            session.shared_jobs.remove(&(from, cancel.request_id));
        }
        Content::SharedDownloadPlan => {
            let Ok(plan) = proto::decode::<SharedDownloadPlan>(&plaintext) else {
                return Ok(());
            };
            let ours = session
                .shared_requests
                .get(&plan.request_id)
                .is_some_and(|r| r.peer == from && matches!(r.kind, SharedRequestKind::Download));
            if ours {
                ui_state.set_shared_download_plan(plan.request_id, plan.files, plan.bytes);
            }
        }
        Content::SharedFileTag => {
            let Ok(tag) = proto::decode::<SharedFileTag>(&plaintext) else {
                return Ok(());
            };
            // Only a request this side made, to this peer, is honoured -
            // anyone else's tag is dropped and the offer behind it gets
            // the ordinary popup.
            let Some(pending) = session.shared_requests.get(&tag.request_id) else {
                return Ok(());
            };
            if pending.peer != from || !matches!(pending.kind, SharedRequestKind::Download) {
                return Ok(());
            }
            session.expected_shared_offers.insert(
                (from, tag.stream_id),
                ExpectedSharedOffer {
                    request_id: tag.request_id,
                    share: pending.share.clone(),
                    rel_path: tag.rel_path,
                },
            );
        }
        Content::SharedDownloadDone => {
            let Ok(done) = proto::decode::<SharedDownloadDone>(&plaintext) else {
                return Ok(());
            };
            let ours = session
                .shared_requests
                .get(&done.request_id)
                .is_some_and(|r| r.peer == from && matches!(r.kind, SharedRequestKind::Download));
            if !ours {
                return Ok(());
            }
            let pending = session
                .shared_requests
                .remove(&done.request_id)
                .expect("just checked");
            let _ = &pending;
            // The Downloads tab is where a download's outcome lives
            // (§7.8) - the conversation is for what people send each
            // other, not for what this side went and fetched.
            ui_state.finish_shared_download(
                done.request_id,
                done.error.map(|e| e.describe().to_string()),
            );
            ui_state.transfers.save_or_warn();
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Requester side
// ---------------------------------------------------------------------

fn fresh_request_id(session: &mut SessionState) -> u64 {
    let id = session.next_shared_request_id;
    session.next_shared_request_id += 1;
    id
}

/// `UiAction::RequestSharedListing`: asks `peer` what is in
/// `share`/`rel_path`. The browser is told at once if the ask itself
/// could not be sent.
pub async fn request_shared_listing(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
    share: String,
    rel_path: String,
) -> proto::Result<()> {
    let request_id = fresh_request_id(session);
    let req = SharedListRequest {
        request_id,
        share: share.clone(),
        rel_path: rel_path.clone(),
    };
    session.shared_requests.insert(
        request_id,
        PendingSharedRequest {
            peer,
            share: share.clone(),
            rel_path: rel_path.clone(),
            kind: SharedRequestKind::List,
        },
    );
    session.peer_link.ensure_link(wr, peer).await;
    if !send_sealed(session, ui_state, peer, Content::SharedListRequest, &req, |envelope| {
        P2pPayload::SharedListRequest { envelope }
    }) {
        session.shared_requests.remove(&request_id);
        ui_state.set_shared_listing(peer, &share, &rel_path, Vec::new(), false, Some(SharedError::Io));
    }
    Ok(())
}

/// `UiAction::DownloadShared`: asks `peer` for `share`/`rel_path` - a
/// file, or every file under a folder. What arrives is accepted without
/// a popup (`tag_incoming_offer`), into
/// `<downloads>/<peer>/<share>/<rel_path>`.
pub async fn request_shared_download(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
    share: String,
    rel_path: String,
) -> proto::Result<()> {
    let request_id = fresh_request_id(session);
    let req = SharedDownloadRequest {
        request_id,
        share: share.clone(),
        rel_path: rel_path.clone(),
    };
    session.shared_requests.insert(
        request_id,
        PendingSharedRequest {
            peer,
            share: share.clone(),
            rel_path: rel_path.clone(),
            kind: SharedRequestKind::Download,
        },
    );
    session.peer_link.ensure_link(wr, peer).await;
    let peer_name = ui_state
        .known_users
        .get(&peer)
        .map(|u| u.name.clone())
        .unwrap_or_default();
    let what = shared_folders::join_rel(&share, &rel_path);
    if send_sealed(session, ui_state, peer, Content::SharedDownloadRequest, &req, |envelope| {
        P2pPayload::SharedDownloadRequest { envelope }
    }) {
        // The row this download lives on from now on - the Downloads tab,
        // not the conversation (§7.8).
        ui_state.start_shared_download(request_id, peer, peer_name, share, rel_path);
        ui_state.transfers.save_or_warn();
    } else {
        session.shared_requests.remove(&request_id);
        ui_state.push_status_notice(format!("could not ask {peer_name} for {what}"), false);
    }
    Ok(())
}

/// Removes everything a download was part-way through writing, keeping
/// every file that had already finished - what cancelling, a lost link,
/// or a failure leaves behind (`docs/PROTOCOL.md` §7.8).
///
/// Only `.part` files are removed, and only this request's: a completed
/// file has already been moved into place under its own name and is not
/// this function's business.
pub(crate) fn abandon_receiving(session: &mut SessionState, request_id: u64) {
    let mine: Vec<(UserId, u64)> = session
        .shared_receiving
        .iter()
        .filter(|(_, r)| r.request_id == request_id)
        .map(|(key, _)| *key)
        .collect();
    for key in mine {
        if let Some(receiving) = session.shared_receiving.remove(&key) {
            let _ = std::fs::remove_file(&receiving.partial);
        }
        // The worker is dropped with its entry, so no further chunk is
        // written; anything still arriving for it is ignored.
        session.active_file_transfers.remove(&key);
        session.expected_shared_offers.remove(&key);
    }
}

/// `UiAction::CancelSharedDownload`: stops a download this side asked
/// for. The owner is told so it stops offering what is still queued, the
/// half-written files go, and everything already complete stays.
pub async fn cancel_shared_download(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    request_id: u64,
) -> proto::Result<()> {
    if !ui_state.cancel_shared_download(request_id) {
        return Ok(());
    }
    abandon_receiving(session, request_id);
    let pending = session.shared_requests.remove(&request_id);
    if let Some(pending) = pending {
        let cancel = SharedDownloadCancel { request_id };
        session.peer_link.ensure_link(wr, pending.peer).await;
        send_sealed(
            session,
            ui_state,
            pending.peer,
            Content::SharedDownloadCancel,
            &cancel,
            |envelope| P2pPayload::SharedDownloadCancel { envelope },
        );
    }
    Ok(())
}

/// The sender's own cancel: stops offering the rest of an upload and
/// tells the requester, who is otherwise left waiting for files that
/// will never come. What is already on the wire finishes, as with every
/// other cancel here - the transport cannot unsend it.
pub async fn cancel_upload(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    request_id: u64,
) -> proto::Result<()> {
    use crate::client::transfer_log::TransferDirection::Upload;
    let Some(record) = ui_state.transfers.get(Upload, request_id) else {
        return Ok(());
    };
    if !record.status.is_active() {
        return Ok(());
    }
    let peer_name = record.peer_name.clone();
    ui_state.cancel_transfer(Upload, request_id);
    let Some(peer) = peer_by_name(ui_state, &peer_name) else {
        // Gone already: nothing to tell, and nothing left queued for a
        // link that is down (`on_peer_link_lost`).
        return Ok(());
    };
    let sent = session
        .shared_jobs
        .get(&(peer, request_id))
        .map(|job| job.finished)
        .unwrap_or(0);
    if let Some(queue) = session.shared_send_queue.get_mut(&peer) {
        queue.retain(|q| q.request_id != request_id);
    }
    session.shared_jobs.remove(&(peer, request_id));
    session.peer_link.ensure_link(wr, peer).await;
    send_download_done(
        session,
        ui_state,
        peer,
        request_id,
        sent,
        Some(SharedError::Cancelled),
    );
    Ok(())
}

/// `UiAction::ResumeSharedDownload`: asks for the same folder again.
/// Nothing tracks what a stopped download had got through, so the ask is
/// the same one - what makes it a resume rather than a restart is that
/// every file already on disk at its full size is refused as it is
/// offered (`already_have`), so only what is genuinely missing moves.
pub async fn resume_shared_download(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    request_id: u64,
) -> proto::Result<()> {
    let Some(item) = ui_state.shared_download(request_id) else {
        return Ok(());
    };
    if item.status.is_active() {
        return Ok(());
    }
    let (peer_name, share, rel_path) =
        (item.peer_name.clone(), item.share.clone(), item.rel_path.clone());
    // The record names them by nickname, which is what survives a
    // restart - so a resume looks them up among who is here now rather
    // than relying on a `UserId` that may be long gone (§3).
    let Some(peer) = peer_by_name(ui_state, &peer_name) else {
        ui_state.push_status_notice(
            format!("{peer_name} is not here - the download cannot resume yet"),
            false,
        );
        return Ok(());
    };
    ui_state.clear_shared_download(request_id);
    request_shared_download(wr, ui_state, session, peer, share, rel_path).await
}

/// Whoever is currently connected under `nickname`, if anyone.
fn peer_by_name(ui_state: &UiState, nickname: &str) -> Option<UserId> {
    ui_state
        .known_users
        .iter()
        .find(|(_, user)| user.name == nickname)
        .map(|(id, _)| *id)
}

/// Whether `dest` is already the file being offered, whole - the test a
/// resumed download skips on. Size alone, deliberately: the owner sends
/// no digest, and re-fetching every byte to check one would defeat the
/// point of resuming at all.
fn already_have(dest: &std::path::Path, size: u64) -> bool {
    std::fs::metadata(dest).is_ok_and(|meta| meta.is_file() && meta.len() == size)
}

/// Run on every arriving file offer, before it is queued: an offer whose
/// `(from, stream_id)` a `SharedFileTag` announced is given its
/// destination, which is what makes `UiState::push_file_offer` park it
/// for `drain_auto_accepts` instead of showing the popup. Every other
/// offer is left exactly as it was.
pub fn tag_incoming_offer(session: &mut SessionState, offer: &mut PendingFileOffer) {
    let Some(expected) = session
        .expected_shared_offers
        .remove(&(offer.from, offer.stream_id))
    else {
        return;
    };
    offer.auto_dest = Some(shared_folders::download_dest(
        &session.shared_download_dir,
        &offer.from_name,
        &expected.share,
        &expected.rel_path,
    ));
    offer.shared_request_id = Some(expected.request_id);
}

/// Accepts every offer `push_file_offer` parked - called right after an
/// offer arrives (either path), and after an identity review releases
/// what it held.
///
/// A file already on disk at exactly the size being offered is refused
/// rather than fetched again: that is what makes resuming a download
/// move only what is missing, and what stops a folder being re-fetched
/// whole when one file of it failed.
pub async fn drain_auto_accepts(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
) -> proto::Result<()> {
    for (from, stream_id) in ui_state.take_auto_accepts() {
        let Some(offer) = ui_state.file_offer_for(from, stream_id).cloned() else {
            continue;
        };
        let (Some(dest), Some(request_id)) = (offer.auto_dest.clone(), offer.shared_request_id)
        else {
            continue;
        };
        if already_have(&dest, offer.size) {
            ui_state.take_file_offer(from, stream_id);
            session
                .peer_link
                .send_reliable_or_queue(from, P2pPayload::FileReject { stream_id });
            ui_state.on_shared_download_file_done(request_id, offer.size, true);
            continue;
        }
        session.shared_receiving.insert(
            (from, stream_id),
            SharedReceiving {
                request_id,
                dest: dest.clone(),
                partial: shared_folders::partial_path(&dest),
                size: offer.size,
                written: 0,
            },
        );
        super::ui_action::accept_file_offer(wr, ui_state, session, from, stream_id).await?;
    }
    Ok(())
}

/// One shared file's bytes have landed - the download's own total gains
/// only what is new, and the header's speed window with it.
pub fn on_shared_receive_progress(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    stream_id: u64,
    written: u64,
) {
    let Some(receiving) = session.shared_receiving.get_mut(&(from, stream_id)) else {
        return;
    };
    let delta = written.saturating_sub(receiving.written);
    receiving.written = written;
    let request_id = receiving.request_id;
    ui_state.on_shared_download_progress(request_id, delta, Instant::now());
}

/// One shared file has arrived whole: moved from its `.part` into the
/// name it was always going to have. Only here does a downloaded file
/// appear under its own name (§7.8).
pub fn finish_shared_receive(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    stream_id: u64,
    ok: bool,
) -> bool {
    let Some(receiving) = session.shared_receiving.remove(&(from, stream_id)) else {
        return false;
    };
    if !ok {
        let _ = std::fs::remove_file(&receiving.partial);
        return true;
    }
    if let Some(parent) = receiving.dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if std::fs::rename(&receiving.partial, &receiving.dest).is_err() {
        // The two are in one directory, so this is only reachable if the
        // destination cannot be written at all - the partial goes rather
        // than being left behind looking like a download.
        let _ = std::fs::remove_file(&receiving.partial);
        return true;
    }
    ui_state.on_shared_download_file_done(receiving.request_id, receiving.size, false);
    true
}

/// What this side currently shares - set from `~/.aloo/settings` at
/// session start and by the settings popup. Exposed so a test can share
/// a scratch directory without writing a settings file.
pub fn shares(session: &SessionState) -> &[SharedFolder] {
    &session.shares
}

/// Replaces what this side shares, announcing nothing - `apply_share_settings`
/// is the path that also tells every peer.
pub fn set_shares(session: &mut SessionState, shares: Vec<SharedFolder>) {
    session.shares = shares;
}

/// Registers a file as arriving, for a test that needs one part-way
/// through without a real transfer behind it.
pub fn note_receiving_for_test(
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
    receiving: SharedReceiving,
) {
    session.shared_receiving.insert((from, stream_id), receiving);
}

/// The one upload budget every shared send debits (§7.8).
pub fn share_pacer(session: &SessionState) -> &std::sync::Arc<shared_folders::SharePacer> {
    &session.share_pacer
}

/// How many files are still queued for `peer`, and whether one is in
/// flight to them - what a test asks to see "one at a time" hold.
pub fn queued_for(session: &SessionState, peer: UserId) -> (usize, bool) {
    (
        session
            .shared_send_queue
            .get(&peer)
            .map(|q| q.len())
            .unwrap_or(0),
        in_flight_to(session, peer) > 0,
    )
}

/// How many of `peer`'s files are in flight right now - what a test asks
/// to see the parallel budget hold.
pub fn in_flight_for(session: &SessionState, peer: UserId) -> usize {
    in_flight_to(session, peer)
}

/// Whether an offer from `peer` under `stream_id` would be accepted
/// without a popup right now - a tag for it has arrived and not yet been
/// consumed.
pub fn expects_offer(session: &SessionState, peer: UserId, stream_id: u64) -> bool {
    session
        .expected_shared_offers
        .contains_key(&(peer, stream_id))
}

/// Test hook: waits for the next filesystem result and applies it, so a
/// test that asked for a listing or a download can see the answer
/// without racing the blocking pool.
pub async fn await_shared_event(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
) -> proto::Result<bool> {
    let event = match session.test_shared_events.as_mut() {
        Some(rx) => rx.recv().await,
        None => None,
    };
    match event {
        Some(event) => {
            on_shared_event(wr, ui_state, session, event).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

