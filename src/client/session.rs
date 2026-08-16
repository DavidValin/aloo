//! The live, connected session: the event loop, session-wide state, and
//! the rsa_per_msg key-rotation / identity-pinning bookkeeping that isn't
//! specific to a channel or a DM. Per-conversation-type send/receive
//! handling lives in `crate::client::channel` and `crate::client::direct_message`; the
//! generic live-voice-streaming plumbing they both share lives in
//! `crate::client::voice_stream`.

use std::collections::HashMap;
use std::io::Stdout;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::net::TcpStream;

use crate::BoxError;
use crate::client::connect::ResolvedIdentity;
use crate::crypto;
use crate::client::file_transfer;
use crate::client::idstore;
use crate::client::netstats;
use crate::client::own_next_keys;
use crate::client::p2p::{self, P2pEvent, P2pOutbound, PeerLinkManager};
use crate::control::ControlSink;
use crate::p2p_proto::P2pPayload;
use crate::proto::{
    self, ClientMessage, Content, Envelope, KeyMode, ServerMessage, UserId, UserInfo,
};
use crate::client::rekey;
use crate::client::sysstats;
use crate::client::tui::ui::{self, IdentityCase, PendingFileOffer, UiAction, UiState, VoiceTarget};
use crate::client::voice;
use crate::client::voice_stream;

/// How long an incoming stream can go without a chunk/end before it's
/// treated as abandoned - see `voice_stream::STREAM_IDLE_TIMEOUT`.
use voice_stream::STREAM_IDLE_TIMEOUT;

/// Every piece of state and every channel handle the voice-streaming
/// machinery needs, threaded through both `handle_ui_action` (outgoing)
/// and `handle_server_message` (incoming) so neither function needs a
/// long, error-prone parameter list.
pub(crate) struct SessionState {
    /// Set while we're recording; sending on it tells the record-stream
    /// worker to flush and stop.
    pub(crate) active_recording: Option<std::sync::mpsc::Sender<()>>,
    /// Per-connection counter for our own outgoing streams. Only unique
    /// per-sender by design - every consumer must key by `(from,
    /// stream_id)`, never `stream_id` alone.
    pub(crate) next_stream_id: u64,
    /// Counter for local mixer source ids (`voice::MixerCmd`), a purely
    /// local concept with no wire meaning - shared by history replay and
    /// every incoming stream's decrypt worker.
    pub(crate) next_mixer_id: u64,
    pub(crate) own_stream_targets: HashMap<u64, voice_stream::OwnStreamTarget>,
    pub(crate) active_streams: HashMap<(UserId, u64), voice_stream::ActiveStream>,
    /// File-transfer counterparts of the two maps above - see
    /// `file_transfer::OwnFileTarget`/`ActiveFileTransfer`. Keyed the same
    /// way: `own_file_targets` by our own `stream_id` alone (it's always
    /// our stream), `active_file_transfers` by `(from, stream_id)`.
    pub(crate) own_file_targets: HashMap<u64, file_transfer::OwnFileTarget>,
    pub(crate) active_file_transfers: HashMap<(UserId, u64), file_transfer::ActiveFileTransfer>,
    /// Where a file-transfer worker thread (`file_transfer::spawn_send_file_worker`/
    /// `spawn_receive_file_worker`) reports progress/completion/failure,
    /// polled by `run_connected_session`'s select loop (`handle_file_event`).
    pub(crate) file_events_tx: tokio::sync::mpsc::UnboundedSender<file_transfer::FileEvent>,
    /// Outgoing voice/file-chunk traffic from a background thread (the
    /// recorder, the file sender) - drained by `run_connected_session`'s
    /// select loop into `peer_link.dispatch_outbound`. Direct-transport
    /// counterpart of what used to be a raw `ClientMessage` written
    /// straight to the TCP socket.
    pub(crate) record_out_tx: tokio::sync::mpsc::UnboundedSender<P2pOutbound>,
    pub(crate) own_stream_done_tx: tokio::sync::mpsc::UnboundedSender<(u64, u32, Vec<u8>)>,
    pub(crate) mixer_tx: tokio::sync::mpsc::UnboundedSender<voice::MixerCmd>,
    pub(crate) stream_finished_tx: tokio::sync::mpsc::UnboundedSender<(UserId, u64, u32, Vec<u8>)>,
    pub(crate) audio_err_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Whether *this* client's own `my_key` is `rsa_per_msg` - gates
    /// whether `request_rotation` ever actually does
    /// anything.
    pub(crate) own_key_mode: KeyMode,
    /// This client's own rotating per-peer keypairs (`rekey::OwnKeys`).
    /// Built for every `KeyMode` except `PqHybrid` (under a
    /// non-`PerMessage` mode it simply never rotates), so the decrypt path
    /// branches on our own mode once instead of scattering RSA logic.
    /// `None` for `PqHybrid` - see `own_pq_private`. Shared with
    /// `spawn_rotation_worker`'s thread (`Arc<Mutex<_>>`); the lock is
    /// only held for brief operations, never for RSA-4096 keygen itself.
    pub(crate) own_keys: Option<Arc<Mutex<rekey::OwnKeys>>>,
    /// This client's own PQ-hybrid private keybundle (`crypto::pq`,
    /// `docs/PROTOCOL.md` §13) - `Some` only when `own_key_mode ==
    /// KeyMode::PqHybrid`, the mirror image of `own_keys` above. `PqHybrid`
    /// is a static identity (no rotation), so unlike `own_keys` this is
    /// never wrapped for a background rotation worker to touch.
    pub(crate) own_pq_private: Option<crate::crypto::pq::PqPrivateBundle>,
    /// Our own PQ-hybrid identity fingerprint - what an incoming send's
    /// binding must name as its recipient for us to accept it at all
    /// (`crypto::pq::open_setup`). `Some` exactly when `own_pq_private` is.
    pub(crate) own_pq_fp: Option<[u8; 32]>,
    /// Our rotating `pq_hybrid` decryption keys, one set per peer
    /// (`docs/PROTOCOL.md` §13.10). `Some` exactly when `own_pq_private`
    /// is. Unlike `own_keys` this needs no `Arc<Mutex<_>>`: ML-KEM/X25519
    /// keygen is fast enough to run inline, so no background worker shares
    /// it.
    pub(crate) own_pq_keys: Option<crate::client::pq_rekey::PqOwnKeys>,
    /// Which `pq_hybrid` encryption keys each peer currently wants us to
    /// use, and how far along their rotation counter we have seen.
    pub(crate) pq_peer_keys: crate::client::pq_rekey::PqPeerKeys,
    /// Where a rotation to send is queued for the main loop to write.
    /// Shared with `spawn_rotation_worker`, which uses it for the
    /// `rsa_per_msg` rotations it produces off-thread.
    pub(crate) rotate_out_tx: tokio::sync::mpsc::UnboundedSender<ClientMessage>,
    /// Refuses a send that already arrived once - see `replay::ReplayGuard`.
    pub(crate) replay: crate::client::replay::ReplayGuard,
    /// Freshness/queueing for peers who use `rsa_per_msg`, independent of
    /// our own `key_mode` (PROTOCOL.md §11.5).
    pub(crate) remote_keys: rekey::RemoteKeys,
    /// Where `request_rotation` sends "please rotate for
    /// this peer" requests - consumed one at a time by
    /// `spawn_rotation_worker`'s dedicated thread, which is what actually
    /// keeps rotations off the event-loop task.
    pub(crate) rotate_request_tx: tokio::sync::mpsc::UnboundedSender<UserId>,
    /// Rotation requests handed to `spawn_rotation_worker` but not yet
    /// finished; > 0 drives `UiState::tick_spinner`, so the spinner
    /// animates exactly while a key is being regenerated. An
    /// `Arc<AtomicUsize>` rather than a channel: the UI only needs the
    /// current count at redraw time.
    pub(crate) rotation_pending: Arc<AtomicUsize>,
    /// Local nickname -> full-public-key pinning store (`docs/PROTOCOL.md`
    /// §12), checked whenever a peer's identity is first learned
    /// (`check_identity`) so a nickname reconnecting under a different key
    /// can be flagged instead of silently trusted. Doubles as the
    /// *verification* half of the `rsa_per_msg` continuity mechanism
    /// (§12.6, `handle_key_rotated`) - a peer's rolling key gets pinned
    /// here too, checked via signature rather than byte comparison.
    pub(crate) id_store: idstore::IdStore,
    /// This client's own per-peer `rsa_per_msg` continuity private keys
    /// (`docs/PROTOCOL.md` §12.6, `own_next_keys::OwnNextKeys`) - the
    /// *sending* half: what lets this client resume-prove "it's still me"
    /// to a peer right after reconnecting. `None` unless this session's own
    /// `key_mode` is `PerMessage` - only that mode has anything to persist
    /// or resume here.
    pub(crate) own_next_keys: Option<own_next_keys::OwnNextKeys>,
    /// Feeds the header's `Conn:<quality>` indicator (`docs/SPEC.md`
    /// "Connected UI") - every protocol message actually sent or received
    /// records an event here (`netstats::ConnStats::record_event`), and
    /// `run_connected_session`'s ticker reads `.quality()` off it once a
    /// second into `UiState::conn_quality`.
    pub(crate) conn_stats: netstats::ConnStats,
    /// Where `voice_stream::spawn_record_stream_worker` reports that a
    /// recording stopped itself on reaching `voice::MAX_RECORDING_SAMPLES`,
    /// polled by `run_connected_session`'s `auto_stop_rx` select arm.
    pub(crate) auto_stop_tx: tokio::sync::mpsc::UnboundedSender<()>,
    /// The mixer id of the voice message currently being replayed (Enter on
    /// a finished `MessageBody::Voice` entry), if any - set by
    /// `handle_ui_action`'s `ReplayVoice` arm, read (and cleared) by
    /// `StopPlayback` (Escape) and by the mixer's `on_finished` callback
    /// once that source actually drains on its own. `None` whenever nothing
    /// is being replayed.
    pub(crate) active_replay_id: Option<u64>,
    /// The session's one direct client<->client UDP transport - see
    /// `crate::client::p2p`. Every text/voice/file send that used to go to the
    /// server now goes through this instead; the server keeps handling
    /// only auth/identify/channel-membership/presence and the initial
    /// candidate exchange this relies on.
    pub(crate) peer_link: PeerLinkManager,
}

/// Runs on one dedicated thread for the whole session, processing
/// `rsa_per_msg` rotation requests (§11.3) one at a time - keeping
/// RSA-4096 keygen (100ms to low seconds) off the async event-loop task,
/// which would otherwise stall UI redraw and network processing on every
/// message sent or received.
///
/// Deliberately a *single* worker: two rotations for the same peer racing
/// would each sign against whatever "current" key they read first, and
/// the receiver validates against the one key it still trusts (§11.4) -
/// the loser's `RotateKey` would be silently dropped. Strict one-at-a-time
/// processing makes that race structurally impossible, at the acceptable
/// cost of different peers' rotations queueing.
///
/// The `own_keys` lock is held only for `current_private_for` and
/// `install_rotated_key`; the keygen itself runs with no lock held.
/// `pending` is decremented once a request is handled (success or
/// failure), pairing with the increment in
/// `request_rotation` to drive the UI spinner.
fn spawn_rotation_worker(
    own_keys: Arc<Mutex<rekey::OwnKeys>>,
    out_tx: tokio::sync::mpsc::UnboundedSender<ClientMessage>,
    pending: Arc<AtomicUsize>,
) -> tokio::sync::mpsc::UnboundedSender<UserId> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<UserId>();
    std::thread::spawn(move || {
        while let Some(peer) = rx.blocking_recv() {
            let old_private = own_keys.lock().unwrap().current_private_for(peer);
            match rekey::generate_and_sign_rotation(&old_private, peer) {
                Ok((new_public_key_der, signature, new_private)) => {
                    own_keys.lock().unwrap().install_rotated_key(
                        peer,
                        new_private,
                        new_public_key_der.clone(),
                    );
                    let _ = out_tx.send(ClientMessage::RotateKey {
                        to: peer,
                        new_public_key_der,
                        signature,
                    });
                }
                Err(e) => eprintln!("aloo: rsa_per_msg key rotation for {peer:?} failed: {e}"),
            }
            pending.fetch_sub(1, Ordering::SeqCst);
        }
    });
    tx
}

// `key_mode` (added for rsa_per_msg) pushed this past clippy's default
// 7-argument threshold; grouping the handshake outputs into a struct would
// be a larger, unrelated refactor of an already-established call site.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_connected_session(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    mut rd: crate::control::ControlReader<tokio::io::ReadHalf<TcpStream>>,
    mut wr: crate::control::ControlWriter<tokio::io::WriteHalf<TcpStream>>,
    display_name: String,
    you: UserId,
    my_identity: ResolvedIdentity,
    key_mode: KeyMode,
    keyboard_release_reporting: bool,
    id_store: idstore::IdStore,
    own_next_keys: Option<own_next_keys::OwnNextKeys>,
    mut hotkey_rx: Option<tokio::sync::mpsc::UnboundedReceiver<crate::client::global_ptt::GlobalPttEvent>>,
    server_addr: SocketAddr,
) -> Result<(), BoxError> {
    let mut input_rx = crate::client::tui::terminal::spawn_input_thread();

    let (net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
    tokio::spawn(async move {
        loop {
            match rd.recv::<ServerMessage>().await {
                Ok(Some(msg)) => {
                    if net_tx.send(msg).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    });

    let (audio_err_tx, mut audio_err_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    // One persistent mixer thread for the whole session - per-message
    // stream opens against the same device are a common way to make
    // ALSA/dmix fail with "unable to open slave", and the one mixer sums
    // simultaneous sources instead of queuing them (see
    // `voice::spawn_mixer`).
    let mixer_err_tx = audio_err_tx.clone();
    let (mixer_finished_tx, mut mixer_finished_rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
    let mixer_tx = voice::spawn_mixer(
        move |e| {
            let _ = mixer_err_tx.send(e);
        },
        move |id| {
            let _ = mixer_finished_tx.send(id);
        },
    );

    let (record_out_tx, mut record_out_rx) = tokio::sync::mpsc::unbounded_channel::<P2pOutbound>();
    let (own_stream_done_tx, mut own_stream_done_rx) =
        tokio::sync::mpsc::unbounded_channel::<(u64, u32, Vec<u8>)>();
    let (stream_finished_tx, mut stream_finished_rx) =
        tokio::sync::mpsc::unbounded_channel::<(UserId, u64, u32, Vec<u8>)>();
    let (file_events_tx, mut file_events_rx) =
        tokio::sync::mpsc::unbounded_channel::<file_transfer::FileEvent>();
    let (auto_stop_tx, mut auto_stop_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    // The session's one direct client<->client UDP transport (`crate::client::p2p`).
    // Bound on the same address family as the server so the reflexive-
    // address probe below can actually reach it; the port is ephemeral
    // (`:0`) since only the server needs a fixed, well-known port.
    let bind_addr: SocketAddr = if server_addr.is_ipv6() {
        SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0)
    };
    let (p2p_events_tx, mut p2p_events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (peer_link, p2p_socket) = PeerLinkManager::bind(bind_addr, server_addr, p2p_events_tx)
        .await
        .map_err(|e| format!("failed to open the direct-link UDP socket: {e}"))?;
    let (p2p_raw_tx, mut p2p_raw_rx) =
        tokio::sync::mpsc::unbounded_channel::<(SocketAddr, crate::p2p_proto::PunchDatagram)>();
    p2p::spawn_receive_loop(p2p_socket, p2p_raw_tx);

    // `PqHybrid` has no single RSA key to seed `rekey::OwnKeys` with and
    // never rotates (it's a static identity, like `Rsa`/`Password`/`None`
    // but with its own separate key material) - see `SessionState::own_keys`/
    // `own_pq_private`.
    let (own_keys, own_pq_private, own_pq_fp, own_pq_keys) = match my_identity {
        ResolvedIdentity::Rsa(kp) => (
            Some(Arc::new(Mutex::new(rekey::OwnKeys::new(kp.private)))),
            None,
            None,
            None,
        ),
        ResolvedIdentity::Pq {
            private,
            public_der,
        } => {
            let rotating =
                crate::client::pq_rekey::PqOwnKeys::new(private.bootstrap_decap().clone());
            (
                None,
                Some(private),
                crate::crypto::pq::fingerprint_of_encoded(&public_der),
                Some(rotating),
            )
        }
    };
    let (rotate_out_tx, mut rotate_out_rx) =
        tokio::sync::mpsc::unbounded_channel::<ClientMessage>();
    let rotation_pending = Arc::new(AtomicUsize::new(0));
    let rotate_request_tx = match &own_keys {
        Some(own_keys) => {
            spawn_rotation_worker(own_keys.clone(), rotate_out_tx.clone(), rotation_pending.clone())
        }
        // No worker needed: `request_rotation` only ever
        // sends on this channel when `own_key_mode == PerMessage`, which
        // always has `own_keys: Some(_)` above - so for `PqHybrid` (the
        // only case reaching here) nothing is ever sent, and a dropped
        // receiver is already handled gracefully there as "worker gone".
        None => tokio::sync::mpsc::unbounded_channel::<UserId>().0,
    };

    let mut session = SessionState {
        active_recording: None,
        next_stream_id: 1,
        next_mixer_id: 1,
        own_stream_targets: HashMap::new(),
        active_streams: HashMap::new(),
        own_file_targets: HashMap::new(),
        active_file_transfers: HashMap::new(),
        file_events_tx,
        record_out_tx,
        own_stream_done_tx,
        mixer_tx,
        stream_finished_tx,
        audio_err_tx,
        own_key_mode: key_mode,
        own_keys,
        own_pq_private,
        own_pq_fp,
        own_pq_keys,
        pq_peer_keys: crate::client::pq_rekey::PqPeerKeys::new(),
        rotate_out_tx: rotate_out_tx.clone(),
        replay: crate::client::replay::ReplayGuard::new(),
        remote_keys: rekey::RemoteKeys::new(),
        rotate_request_tx,
        rotation_pending,
        id_store,
        own_next_keys,
        conn_stats: netstats::ConnStats::new(),
        auto_stop_tx,
        active_replay_id: None,
        peer_link,
    };

    let mut ui_state = UiState::new(display_name);
    ui_state.set_own_id(you);
    ui_state.set_keyboard_release_reporting(keyboard_release_reporting);
    // Ticks fast enough that `tick_recording_timeout` can detect a
    // released Space key within one `RECORD_HOLD_TIMEOUT` window without
    // adding much latency; also drives the idle-stream sweep below.
    let mut ticker = tokio::time::interval(Duration::from_millis(150));
    let mut tick_count: u32 = 0;
    let mut cpu_monitor = sysstats::CpuMonitor::new();
    let mut last_cpu_sample = Instant::now();
    let mut last_conn_sample = Instant::now();

    terminal.draw(|f| ui::render(f, &ui_state))?;

    loop {
        tokio::select! {
            ev = input_rx.recv() => {
                let Some(ev) = ev else { break };
                if let Event::Key(key) = ev {
                    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                        break;
                    }
                    if let Some(action) = ui_state.handle_key(key.code, key.modifiers, key.kind) {
                        handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                    }
                }
            }
            msg = net_rx.recv() => {
                let Some(msg) = msg else { break };
                if let Some(action) = handle_server_message(msg, &mut ui_state, you, &mut wr, &mut session).await? {
                    handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                }
            }
            msg = record_out_rx.recv() => {
                let Some(msg) = msg else { break };
                session.peer_link.dispatch_outbound(msg);
            }
            dgram = p2p_raw_rx.recv() => {
                let Some((addr, dgram)) = dgram else { break };
                session.peer_link.on_datagram(addr, dgram);
            }
            event = p2p_events_rx.recv() => {
                let Some(event) = event else { break };
                handle_p2p_event(event, &mut ui_state, &mut session);
            }
            msg = rotate_out_rx.recv() => {
                let Some(msg) = msg else { break };
                wr.send_control(&msg).await?;
                session.conn_stats.record_event(Instant::now());
                if let ClientMessage::RotateKey { to, .. } = &msg
                    && let Some(nickname) = ui_state.known_users.get(to).map(|u| u.name.clone())
                {
                    persist_own_continuity_key(&mut session, &nickname, *to);
                }
            }
            done = own_stream_done_rx.recv() => {
                let Some((stream_id, duration_ms, pcm)) = done else { break };
                if let Some(target) = session.own_stream_targets.remove(&stream_id) {
                    match target {
                        voice_stream::OwnStreamTarget::Channel { channel, recipients } => {
                            crate::client::channel::on_own_stream_finished(&mut ui_state, &mut session, you, channel, recipients, stream_id, duration_ms, pcm);
                        }
                        voice_stream::OwnStreamTarget::Direct(to) => {
                            crate::client::direct_message::on_own_stream_finished(&mut ui_state, &mut session, you, to, stream_id, duration_ms, pcm);
                        }
                    }
                }
            }
            finished = stream_finished_rx.recv() => {
                let Some((from, stream_id, duration_ms, pcm)) = finished else { break };
                if let Some(active) = session.active_streams.remove(&(from, stream_id)) {
                    // Best-effort re-check of the trust state
                    // `on_stream_start` snapshotted - skips the "message
                    // ended" chime for a sender who was never heard. Not
                    // threaded through `ActiveStream`, so a mismatch newly
                    // detected mid-stream (rare) could still chime for
                    // suppressed audio - a harmless UX quirk, not a
                    // correctness issue.
                    let was_heard = !ui_state.is_trust_gated(from);
                    match active.channel {
                        Some(channel) => crate::client::channel::on_stream_finished(&mut ui_state, &channel, from, stream_id, duration_ms, pcm),
                        None => crate::client::direct_message::on_stream_finished(&mut ui_state, from, stream_id, duration_ms, pcm),
                    }
                    if was_heard {
                        voice_stream::play_end_chime(&mut session);
                    }
                    request_rotation(&mut session, from);
                }
            }
            event = file_events_rx.recv() => {
                let Some(event) = event else { break };
                handle_file_event(&mut ui_state, &mut session, event);
            }
            stopped = auto_stop_rx.recv() => {
                let Some(()) = stopped else { break };
                if let Some(action) = ui_state.force_stop_recording() {
                    handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                }
            }
            finished_id = mixer_finished_rx.recv() => {
                let Some(finished_id) = finished_id else { break };
                if session.active_replay_id == Some(finished_id) {
                    session.active_replay_id = None;
                    ui_state.replaying = false;
                }
            }
            err = audio_err_rx.recv() => {
                let Some(err) = err else { break };
                ui_state.playback_failed(err);
            }
            // `hotkey_rx` being `None` (feature disabled, unsupported, or
            // registration failed) parks this branch forever via
            // `pending()`. Unlike `input_rx`/`net_rx`, the sender dying is
            // *not* fatal to the session - this arm just sets `hotkey_rx`
            // to `None` itself so the branch parks from then on.
            hotkey_ev = async {
                match hotkey_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(hotkey_ev) = hotkey_ev else {
                    hotkey_rx = None;
                    continue;
                };
                match hotkey_ev {
                    crate::client::global_ptt::GlobalPttEvent::Pressed => {
                        if let Some(action @ UiAction::VoiceRecordStart(_)) = ui_state.global_record_start() {
                            handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                        }
                    }
                    crate::client::global_ptt::GlobalPttEvent::Released => {
                        if let Some(action) = ui_state.global_record_stop() {
                            handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                        }
                    }
                }
            }
            _ = ticker.tick() => {
                tick_count = tick_count.wrapping_add(1);
                if tick_count % 4 == 0 {
                    ui_state.toggle_blink();
                }
                let now = Instant::now();
                // CPU:<pct>% refreshes roughly every 300ms (docs/SPEC.md
                // "Connected UI") - driven off elapsed wall time rather
                // than a fixed tick-count multiple so it can't drift from
                // the documented cadence if `ticker`'s own interval ever
                // changes.
                if now.duration_since(last_cpu_sample) >= Duration::from_millis(300) {
                    ui_state.set_cpu_usage(cpu_monitor.refresh());
                    last_cpu_sample = now;
                }
                // Conn:<quality> refreshes once a second, same reasoning.
                if now.duration_since(last_conn_sample) >= Duration::from_secs(1) {
                    ui_state.set_conn_quality(session.conn_stats.quality());
                    last_conn_sample = now;
                }
                ui_state.tick_spinner(session.rotation_pending.load(Ordering::SeqCst) > 0);
                if let Some(action) = ui_state.tick_dwell(Instant::now()) {
                    handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                }
                if let Some(action) = ui_state.tick_recording_timeout(Instant::now()) {
                    handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                }
                let cutoff = Instant::now() - STREAM_IDLE_TIMEOUT;
                for stream in session.active_streams.values().filter(|s| s.last_seen < cutoff) {
                    let _ = stream.job_tx.send(voice_stream::DecryptJob::End);
                }
                session.peer_link.tick();
            }
        }
        terminal.draw(|f| ui::render(f, &ui_state))?;
    }

    Ok(())
}

async fn handle_ui_action(
    action: UiAction,
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
) -> proto::Result<()> {
    match action {
        UiAction::JoinChannel {
            name,
            kind,
            password,
        } => {
            crate::client::channel::handle_join(wr, session, name, kind, password).await?;
        }
        UiAction::LeaveChannel { name } => {
            crate::client::channel::handle_leave(wr, ui_state, session, name).await?;
        }
        UiAction::SendChannelText {
            channel,
            plaintext,
            recipients,
        } => {
            crate::client::channel::handle_send_text(wr, session, channel, plaintext, recipients).await?;
        }
        UiAction::SendDirectText {
            to,
            plaintext,
            recipient_key_mode,
            recipient_pubkey_der,
        } => {
            crate::client::direct_message::handle_send_text(
                wr,
                session,
                to,
                plaintext,
                recipient_key_mode,
                recipient_pubkey_der,
            )
            .await?;
        }
        UiAction::SendFileChannel {
            channel,
            path,
            filename,
            size,
            recipients,
        } => {
            crate::client::channel::handle_send_file(
                wr, ui_state, session, channel, path, filename, size, recipients,
            )
            .await?;
        }
        UiAction::SendFileDirect {
            to,
            path,
            filename,
            size,
            recipient_key_mode,
            recipient_pubkey_der,
        } => {
            crate::client::direct_message::handle_send_file(
                wr,
                ui_state,
                session,
                to,
                path,
                filename,
                size,
                recipient_key_mode,
                recipient_pubkey_der,
            )
            .await?;
        }
        UiAction::VoiceRecordStart(target) => {
            let err_tx = session.audio_err_tx.clone();
            let on_stream_error = move |e: String| {
                let _ = err_tx.send(e);
            };
            match voice::Recorder::start(on_stream_error) {
                Ok(recorder) => {
                    let stream_id = session.next_stream_id;
                    session.next_stream_id += 1;
                    match target {
                        VoiceTarget::Channel {
                            channel,
                            recipients,
                        } => {
                            crate::client::channel::handle_voice_record_start(
                                wr, ui_state, session, recorder, stream_id, channel, recipients,
                            )
                            .await?;
                        }
                        VoiceTarget::Direct {
                            to,
                            recipient_key_mode,
                            recipient_pubkey_der,
                        } => {
                            crate::client::direct_message::handle_voice_record_start(
                                wr,
                                ui_state,
                                session,
                                recorder,
                                stream_id,
                                to,
                                recipient_key_mode,
                                recipient_pubkey_der,
                            )
                            .await?;
                        }
                    }
                }
                Err(e) => {
                    // Without this, a failed device open (no mic, permissions,
                    // ...) was only ever visible on stderr - invisible once the
                    // TUI has taken over the terminal via the alternate screen.
                    ui_state.recording_failed(e.to_string());
                }
            }
        }
        UiAction::VoiceRecordStop => {
            if let Some(stop_tx) = session.active_recording.take() {
                let _ = stop_tx.send(());
                voice_stream::play_end_chime(session);
            }
        }
        UiAction::ReplayVoice { pcm, .. } => {
            let samples = voice::pcm_from_bytes(&pcm);
            if !samples.is_empty() {
                let id = session.next_mixer_id;
                session.next_mixer_id += 1;
                session.active_replay_id = Some(id);
                let _ = session.mixer_tx.send(voice::MixerCmd::Push { id, samples });
                let _ = session.mixer_tx.send(voice::MixerCmd::Finish { id });
            }
        }
        UiAction::StopPlayback => {
            if let Some(id) = session.active_replay_id.take() {
                let _ = session.mixer_tx.send(voice::MixerCmd::Stop { id });
            }
        }
        UiAction::AcceptIdentity(peer) => {
            if let Some(review) = ui_state.identity_reviews.get(&peer).cloned() {
                match review.case {
                    // A static key just needs pinning - `known_users` (and
                    // hence what future sends encrypt with) already holds
                    // this exact key, set unconditionally by `on_user_joined`
                    // when the peer joined (docs/PROTOCOL.md §12.4); nothing
                    // else was withheld from it, only the local pin.
                    IdentityCase::StaticMismatch {
                        new_public_key_der, ..
                    } => {
                        session
                            .id_store
                            .check_and_pin(&review.nickname, &new_public_key_der);
                        if let Err(e) = session.id_store.save() {
                            eprintln!("aloo: failed to save id_store: {e}");
                        }
                    }
                    // A rolling key never installed anywhere - gated on
                    // sight, a `Live`-only rotation while gated, or a
                    // failed resume signature. Accepting it needs the same
                    // install+persist+flush sequence an ordinary rotation
                    // gets, for whichever key was most recently offered.
                    IdentityCase::ResumeFailed { new_public_key_der } => {
                        install_trusted_rotation(
                            ui_state,
                            wr,
                            session,
                            peer,
                            &review.nickname,
                            new_public_key_der,
                        )
                        .await?;
                    }
                }
            }
            if ui_state.resolve_identity_accept(peer) {
                voice_stream::play_bell_chime(session);
            }
        }
        UiAction::RejectIdentity(peer) => {
            // No `id_store`/`rekey` writes at all - the previous pin (if
            // any) is left exactly as it was, so this is never persisted
            // (docs/PROTOCOL.md §12).
            ui_state.resolve_identity_reject(peer);
        }
        UiAction::AcceptFileOffer { from, stream_id } => {
            accept_file_offer(wr, ui_state, session, from, stream_id).await?;
        }
        UiAction::RejectFileOffer { from, stream_id } => {
            ui_state.take_file_offer(from, stream_id);
            session.peer_link.ensure_link(wr, from).await;
            session
                .peer_link
                .send_reliable_or_queue(from, P2pPayload::FileReject { stream_id });
        }
    }
    Ok(())
}

/// Carries out an `AcceptFileOffer` decision: resolves which key to decrypt
/// incoming chunks with (same `voice_stream::resolve_incoming_key` a voice
/// stream uses), spawns the receiving worker, creates the log row, and
/// tells the sender to start streaming.
async fn accept_file_offer(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
) -> proto::Result<()> {
    let Some(offer) = ui_state.take_file_offer(from, stream_id) else {
        return Ok(());
    };
    let sender_public_key_der = ui_state
        .known_users
        .get(&from)
        .map(|u| u.public_key_der.clone())
        .unwrap_or_default();
    let key = voice_stream::resolve_incoming_key(session, from, &sender_public_key_der);
    let dest_name = crate::client::file_transfer::safe_filename(&crate::client::file_transfer::truncate_filename(
        &offer.filename,
    ));
    let dest_path = crate::client::file_transfer::default_download_dir().join(dest_name);
    let job_tx = file_transfer::spawn_receive_file_worker(
        key,
        dest_path,
        from,
        stream_id,
        session.file_events_tx.clone(),
    );
    session.active_file_transfers.insert(
        (from, stream_id),
        file_transfer::ActiveFileTransfer {
            job_tx,
            last_seen: Instant::now(),
        },
    );
    match &offer.channel {
        Some(channel) => {
            ui_state.on_channel_file_offer_accepted(
                channel,
                from,
                offer.from_name.clone(),
                stream_id,
                offer.filename.clone(),
                offer.size,
            );
        }
        None => {
            ui_state.on_direct_file_offer_accepted(
                from,
                offer.from_name.clone(),
                stream_id,
                offer.filename.clone(),
                offer.size,
            );
        }
    }
    session.peer_link.ensure_link(wr, from).await;
    session
        .peer_link
        .send_reliable_or_queue(from, P2pPayload::FileAccept { stream_id });
    Ok(())
}

/// Applies one incoming server message to `ui_state`. Returns an action
/// the caller must carry out over the network - only used so the very
/// first channel list triggers an immediate join of the auto-selected
/// first tab ("selected" implies joined); later tab switches join via the
/// dwell timer (`UiState::tick_dwell`). Async (and given `wr`) because
/// two `rsa_per_msg` side effects write to the network right here: our
/// own rotation after receiving a text (§11.3), and validating+flushing a
/// peer's `KeyRotated` (§11.4/§11.5).
async fn handle_server_message(
    msg: ServerMessage,
    ui_state: &mut UiState,
    you: UserId,
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
) -> proto::Result<Option<UiAction>> {
    // Feeds the header's Conn:<quality> indicator (docs/SPEC.md "Connected
    // UI") - every incoming protocol message counts, at this single choke
    // point every variant already passes through.
    session.conn_stats.record_event(Instant::now());
    match msg {
        ServerMessage::Hello { .. }
        | ServerMessage::AuthResult { .. }
        | ServerMessage::IdentifyResult { .. } => {
            // only expected during the handshake in connect::connect_and_handshake
        }
        ServerMessage::ChannelList(list) => {
            if let Some(action) = crate::client::channel::on_list(ui_state, list) {
                return Ok(Some(action));
            }
        }
        ServerMessage::Joined { channel } => crate::client::channel::on_joined(ui_state, channel),
        // Reuses the plain, dedup-safe appender directly - unlike
        // `crate::client::channel::on_list` (only for the connect-time snapshot
        // above), this must never auto-join anything.
        ServerMessage::ChannelCreated { channel } => ui_state.on_channel_list(vec![channel]),
        ServerMessage::ChannelJoinFailed { name, reason } => {
            crate::client::channel::on_join_failed(name, reason)
        }
        ServerMessage::ChannelJoinRejected { name, kind } => {
            crate::client::channel::on_join_rejected(ui_state, name, kind)
        }
        ServerMessage::UserJoined { channel, user } => {
            // rsa_per_msg peers need freshness/queue tracking from the
            // moment we learn about them (§11.5), whether that's this
            // join snapshot or a later arrival.
            if user.key_mode == KeyMode::PerMessage {
                session.remote_keys.track(user.id);
            }
            // A pq_hybrid peer's bundle carries only their *bootstrap*
            // encryption keys (§13.10) - what to encrypt to until the
            // relationship rotates. Recorded here, superseded by the first
            // `KeyRotated` they send us.
            if user.key_mode == KeyMode::PqHybrid
                && let Ok(bundle) =
                    proto::decode::<crate::crypto::pq::PqPublicBundle>(&user.public_key_der)
                && let Ok(fingerprint) = crate::crypto::pq::bundle_fingerprint(&bundle)
            {
                session
                    .pq_peer_keys
                    .bootstrap(user.id, bundle.bootstrap_encap().clone(), fingerprint);
            }
            // Pin/check identity exactly once per connection - the first
            // time we ever see this UserId, before `on_user_joined` below
            // records it in `known_users` (which is what gates this
            // check on every subsequent UserJoined for the same
            // already-connected peer, e.g. from joining a second shared
            // channel with them).
            if !ui_state.known_users.contains_key(&user.id) {
                check_identity(session, ui_state, &user);
                // If *we* use rsa_per_msg and have a persisted continuity
                // key for this nickname (docs/PROTOCOL.md §12.6), prove
                // "it's still me" the moment we see them again - before
                // any application message is exchanged, not waiting for
                // one. A no-op otherwise (own key_mode isn't PerMessage,
                // or nothing persisted for this nickname yet).
                if session.own_key_mode == KeyMode::PerMessage {
                    send_resume_rotation_if_available(session, wr, user.id, &user.name).await?;
                }
                // Start punching a direct link the moment we learn this
                // peer exists rather than at first send (§7.1): voice is
                // never queued, so a link still `Punching` when someone
                // starts recording excludes that recipient outright. The
                // gap between learning about a channel-mate and pressing
                // Space is normally far longer than the handshake needs.
                // Harmless unconditionally: `ensure_link` is a no-op on an
                // existing link, and failure stays silent until something
                // is actually queued against this peer.
                session.peer_link.ensure_link(wr, user.id).await;
            }
            ui_state.on_user_joined(&channel, user);
        }
        ServerMessage::UserLeft { channel, user_id } => {
            ui_state.on_user_left(&channel, user_id);
            // Unlike `UserOffline` below, a `UserLeft` peer may still share
            // another channel with us or have an open DM - only forget the
            // link once neither is true anymore (docs/PROTOCOL.md §7.1.3).
            if !ui_state.has_reason_to_keep_link(user_id) {
                session.peer_link.forget(user_id);
            }
        }
        ServerMessage::UserOffline { user_id } => {
            ui_state.on_user_offline(user_id);
            // A full disconnect is always the end of any relationship with
            // them - unlike `UserLeft` (one channel, possibly still shared
            // elsewhere or via an open DM), so this is the one case safe to
            // forget the link unconditionally.
            session.peer_link.forget(user_id);
            // Their rotating encryption keys, and ours for them, end with
            // the connection: a later one is a different `UserId` starting
            // its rotation counter over (§13.10), and the keys we held are
            // of no further use to anyone - including us.
            session.pq_peer_keys.forget(user_id);
            if let Some(own) = session.own_pq_keys.as_mut() {
                own.forget(user_id);
            }
            session.replay.forget(user_id);
        }
        ServerMessage::KeyRotated {
            from,
            new_public_key_der,
            signature,
        } => {
            handle_key_rotated(
                ui_state,
                you,
                wr,
                session,
                from,
                new_public_key_der,
                signature,
            )
            .await?;
        }
        ServerMessage::PeerCandidates {
            from,
            candidates,
            link_nonce,
        } => {
            // Trust boundary (docs/PROTOCOL.md §7.1.2): the server's relay
            // performs no relationship checking of its own - any registered
            // client can name any other UserId as `peer`. Only respond to a
            // request from someone we currently share a joined channel
            // with; a stranger's request is dropped before any PeerLink
            // state is touched at all.
            if ui_state.shares_a_joined_channel(from) {
                session
                    .peer_link
                    .on_peer_candidates(wr, from, candidates, link_nonce)
                    .await;
            }
        }
        ServerMessage::Error { message } => eprintln!("aloo: server error: {message}"),
    }
    Ok(None)
}

/// Applies one incoming direct-link event (`crate::client::p2p::P2pEvent`) - the
/// direct-transport counterpart of `handle_server_message`'s old content
/// arms (`ChannelMessage`/`DirectMessage`/`Stream*`/`File*`). `from_name` is
/// resolved locally from `ui_state.known_users` rather than carried on the
/// wire: the server used to attach it from its own registry, but a peer we
/// have a link to is necessarily one whose `UserInfo` (learned via
/// `UserJoined`) we already hold.
fn handle_p2p_event(event: P2pEvent, ui_state: &mut UiState, session: &mut SessionState) {
    let name_of = |ui_state: &UiState, id: UserId| {
        ui_state
            .known_users
            .get(&id)
            .map(|u| u.name.clone())
            .unwrap_or_default()
    };
    match event {
        P2pEvent::Message {
            channel: Some(channel),
            from,
            envelope,
        } => {
            let from_name = name_of(ui_state, from);
            crate::client::channel::on_message(ui_state, session, channel, from, from_name, envelope);
        }
        P2pEvent::Message {
            channel: None,
            from,
            envelope,
        } => {
            let from_name = name_of(ui_state, from);
            crate::client::direct_message::on_message(ui_state, session, from, from_name, envelope);
        }
        P2pEvent::StreamStart {
            channel: Some(channel),
            from,
            stream_id,
        } => {
            let from_name = name_of(ui_state, from);
            crate::client::channel::on_stream_start(ui_state, session, channel, from, from_name, stream_id);
        }
        P2pEvent::StreamStart {
            channel: None,
            from,
            stream_id,
        } => {
            let from_name = name_of(ui_state, from);
            crate::client::direct_message::on_stream_start(ui_state, session, from, from_name, stream_id);
        }
        P2pEvent::StreamKeySetup {
            from,
            stream_id,
            setup,
        } => {
            voice_stream::forward_key_setup(session, from, stream_id, setup);
        }
        P2pEvent::StreamChunk {
            from,
            stream_id,
            seq,
            blocks,
        } => {
            voice_stream::forward_chunk(session, from, stream_id, seq, blocks);
        }
        P2pEvent::StreamEnd { from, stream_id } => {
            voice_stream::end_incoming_stream(session, from, stream_id);
        }
        P2pEvent::FileOffer {
            channel,
            from,
            stream_id,
            envelope,
        } => {
            let from_name = name_of(ui_state, from);
            handle_incoming_file_offer(
                ui_state, session, from, from_name, stream_id, channel, envelope,
            );
        }
        P2pEvent::FileAccepted { stream_id } => {
            if let Some(target) = session.own_file_targets.remove(&stream_id) {
                let me = ui_state.own_id.unwrap_or(UserId(0));
                ui_state.set_file_progress(me, stream_id, 0);
                // A pq_hybrid transfer's setup goes out before its first
                // chunk, exactly as a voice stream's does after
                // `StreamStart` - the chunks themselves are ciphertext only.
                if let voice_stream::DirectStreamKey::Pq(pq) = &target.key {
                    for (id, setup) in pq.setups() {
                        session
                            .peer_link
                            .send_reliable_or_queue(id, P2pPayload::StreamKeySetup { stream_id, setup });
                    }
                }
                file_transfer::spawn_send_file_worker(
                    target.path,
                    target.key,
                    target.to,
                    stream_id,
                    session.record_out_tx.clone(),
                    session.file_events_tx.clone(),
                );
            }
        }
        P2pEvent::FileRejected { stream_id } => {
            session.own_file_targets.remove(&stream_id);
            let me = ui_state.own_id.unwrap_or(UserId(0));
            ui_state.set_file_rejected(me, stream_id);
        }
        P2pEvent::FileChunk {
            from,
            stream_id,
            seq,
            blocks,
        } => {
            file_transfer::forward_chunk(
                &mut session.active_file_transfers,
                from,
                stream_id,
                seq,
                blocks,
            );
        }
        P2pEvent::FileEnd { from, stream_id } => {
            file_transfer::end_incoming_transfer(&mut session.active_file_transfers, from, stream_id);
        }
        P2pEvent::LinkFailed { peer, reason } => {
            let name = name_of(ui_state, peer);
            let peer_name = if name.is_empty() {
                format!("{peer:?}")
            } else {
                name
            };
            ui_state.p2p_link_failed(&peer_name, &reason);
        }
    }
}

/// Checks a newly-learned peer's announced identity against the local
/// pinning store (§12), opening a blocking Accept/Reject review if their
/// nickname was previously pinned to a key this connection hasn't proven
/// itself a continuation of. `KeyMode::None` is skipped - no continuity
/// mechanism by design (§12.2). Two different checks, branched by
/// `key_mode`:
///
/// - `Rsa`/`Password`: their key is stable by construction, so a byte
///   comparison against the pin is definitive (`StaticMismatch` arm).
/// - `PerMessage`: the bootstrap key is fresh every connect and never
///   itself compared - but a nickname with a §12.6 continuity pin is
///   gated the instant it's seen again, *before* any resume or rotation
///   attempt. `handle_key_rotated`'s `Live` check only proves
///   self-consistency with this connection's own announced key (true of
///   anyone the first time a fresh `UserId` rotates), so silently
///   trusting would let a peer who never *tries* to prove continuity
///   sail through. Only a genuinely verified `Resumed` anchor clears the
///   gate silently.
///
/// Deliberately does **not** use `IdStore::check_and_pin` on a mismatch:
/// that always re-pins as a side effect, which would trust the new key
/// for next time regardless of what the user decides - a `Reject` must
/// leave the old pin untouched until `AcceptIdentity` explicitly re-pins.
/// `IdStore::get` reads without mutating, so the comparison is by hand.
/// Whether `user`'s newly announced identity carries a continuity
/// certificate (§12.7) signed by the one currently pinned for them - i.e.
/// whether this key change was deliberately made by whoever held the old
/// keys, rather than being an unexplained substitution.
///
/// Only `pq_hybrid` identities can prove this; the RSA modes have no
/// signing identity separable from the key being replaced, so for them a
/// changed key is always a question for the user.
fn continuity_proven(pinned_der: &[u8], user: &UserInfo) -> bool {
    if user.key_mode != KeyMode::PqHybrid {
        return false;
    }
    let (Ok(pinned), Ok(announced)) = (
        proto::decode::<crypto::pq::PqPublicBundle>(pinned_der),
        proto::decode::<crypto::pq::PqPublicBundle>(&user.public_key_der),
    ) else {
        return false;
    };
    crypto::pq::verify_continuity(&pinned, &announced)
}

/// A malformed `public_key_der` is silently skipped - this is a local
/// safety net, not protocol validation.
fn check_identity(session: &mut SessionState, ui_state: &mut UiState, user: &UserInfo) {
    // `public_key_der` holds different bytes depending on scheme (an RSA
    // SPKI DER blob for every mode except `PqHybrid`, a bincode-encoded
    // `crypto::pq::PqPublicBundle` for it) - parseability is checked with
    // the matching decoder rather than always assuming RSA, or a `PqHybrid`
    // peer would always fail this check and never get pinned at all.
    let parses = match user.key_mode {
        KeyMode::PqHybrid => {
            proto::decode::<crypto::pq::PqPublicBundle>(&user.public_key_der).is_ok()
        }
        _ => crypto::public_key_from_der(&user.public_key_der).is_ok(),
    };
    if !parses {
        return;
    }
    match user.key_mode {
        key_mode if crate::client::keymode_policy::uses_byte_comparison_pinning(key_mode) => {
            match session.id_store.get(&user.name) {
                None => {
                    // First-ever sighting: nothing to compare against, so this is
                    // never suspicious - pin it immediately, same as before.
                    session
                        .id_store
                        .check_and_pin(&user.name, &user.public_key_der);
                    if let Err(e) = session.id_store.save() {
                        eprintln!("aloo: failed to save id_store: {e}");
                    }
                }
                Some(previous) if previous == user.public_key_der.as_slice() => {}
                // A key change that proves itself is not an alarm. If this
                // peer's new bundle carries a certificate signed by the
                // identity we already pinned (§12.7), they deliberately
                // retired the old keys - move the pin across and say so on
                // the status line rather than opening a review. Reserving
                // the review for genuinely unexplained changes is what
                // keeps it meaningful; one that fires on every legitimate
                // rekey teaches people to dismiss it.
                Some(previous) if continuity_proven(previous, user) => {
                    let name = user.name.clone();
                    session
                        .id_store
                        .check_and_pin(&name, &user.public_key_der);
                    if let Err(e) = session.id_store.save() {
                        eprintln!("aloo: failed to save id_store: {e}");
                    }
                    ui_state.push_notice(format!(
                        "{name} moved to a new identity and proved it - pin updated"
                    ));
                }
                Some(previous) => {
                    let previous_public_key_der = previous.to_vec();
                    let message = format!(
                        "'{}' connected with a different key than last time (was {}, now {}) - possible impersonation. Accept their new key, or reject it.",
                        user.name,
                        short_fingerprint(&crypto::fingerprint_der(&previous_public_key_der)),
                        short_fingerprint(&crypto::fingerprint_der(&user.public_key_der)),
                    );
                    ui_state.push_identity_review(
                        user.id,
                        user.name.clone(),
                        message,
                        IdentityCase::StaticMismatch {
                            new_public_key_der: user.public_key_der.clone(),
                            previous_public_key_der,
                        },
                    );
                }
            }
        }
        KeyMode::PerMessage => {
            if session.id_store.get(&user.name).is_some() {
                push_unverified_resume_review(
                    ui_state,
                    user.id,
                    &user.name,
                    user.public_key_der.clone(),
                );
            }
        }
        // KeyMode::None, plus an unreachable fallback for the guard arm
        // above (rustc can't statically know `uses_byte_comparison_pinning`
        // covers exactly Rsa/Password/PqHybrid).
        _ => {}
    }
}

/// Opens (or refreshes, if one's already queued - `push_identity_review`
/// upserts) the review for an `rsa_per_msg` nickname that has a continuity
/// key pinned but hasn't - yet, or ever - proven this connection is a
/// continuation of it. Shared by `check_identity` (the instant such a
/// nickname is seen again, before any rotation attempt at all) and
/// `handle_key_rotated` (a `Live`-only rotation arriving for a peer who's
/// already gated for this same reason - self-consistency alone still isn't
/// proof, so the review stays open, just pointed at whichever key was most
/// recently offered).
fn push_unverified_resume_review(
    ui_state: &mut UiState,
    peer: UserId,
    nickname: &str,
    new_public_key_der: Vec<u8>,
) {
    let message = format!(
        "'{nickname}' is using rsa_per_msg under a nickname previously linked to a different session's key, and hasn't proven continuity with it - possible impersonation. Accept their new key, or reject it."
    );
    ui_state.push_identity_review(
        peer,
        nickname.to_string(),
        message,
        IdentityCase::ResumeFailed { new_public_key_der },
    );
}

/// Shortens a full SHA-256 hex fingerprint (`crypto::fingerprint`) to its
/// first 16 hex characters (8 bytes) for compact display in a UI warning -
/// still effectively unique for telling two specific keys apart at a
/// glance, without wrapping a 64-character hex string across the screen.
fn short_fingerprint(fp: &str) -> &str {
    fp.get(..16).unwrap_or(fp)
}

/// The sending half of `rsa_per_msg` continuity (§12.6): with a persisted
/// continuity key for `nickname`, proves "it's still me" to their
/// brand-new `UserId` right away by re-asserting that same key,
/// self-signed and bound to `peer`; a no-op if nothing is persisted yet.
/// Deliberately the *same* key rather than a fresh one: no keygen needed
/// (`crypto::sign` is fast), and ordinary rotation (§11.3) picks up again
/// on the next real message.
async fn send_resume_rotation_if_available(
    session: &mut SessionState,
    wr: &mut impl crate::control::ControlSink,
    peer: UserId,
    nickname: &str,
) -> proto::Result<()> {
    let Some(private) = session
        .own_next_keys
        .as_ref()
        .and_then(|s| s.get(nickname))
        .cloned()
    else {
        return Ok(());
    };
    let public_der = match crypto::public_key_to_der(&private.to_public_key()) {
        Ok(der) => der,
        Err(_) => return Ok(()),
    };
    let signature = match rekey::sign_rotation(&private, peer, &public_der) {
        Ok(sig) => sig,
        Err(_) => return Ok(()),
    };

    // Only reachable when `own_key_mode == PerMessage` (the caller already
    // gates on that), which always has `own_keys: Some(_)` - see
    // `SessionState::own_keys`.
    let Some(own_keys) = session.own_keys.as_ref() else {
        return Ok(());
    };
    own_keys
        .lock()
        .unwrap()
        .install_rotated_key(peer, private, public_der.clone());
    wr.send_control(&ClientMessage::RotateKey {
            to: peer,
            new_public_key_der: public_der,
            signature,
        },
    )
    .await?;
    session.conn_stats.record_event(Instant::now());
    persist_own_continuity_key(session, nickname, peer);
    Ok(())
}

/// Persists this client's current per-peer private key for `peer` into
/// `own_next_keys`, keyed by `nickname`, so the *next* reconnect has
/// something fresh to resume from. A no-op unless this session is
/// `PerMessage`. Called after *every* rotation - crash-safety over
/// write-frequency: if the process dies first, the next resume simply
/// won't verify (an ordinary first-sighting-shaped case), never a false
/// alarm.
fn persist_own_continuity_key(session: &mut SessionState, nickname: &str, peer: UserId) {
    let Some(own_next_keys) = session.own_next_keys.as_mut() else {
        return;
    };
    // Only reachable when `own_key_mode == PerMessage` (every caller of this
    // fn is itself only reached in that case), which always has `own_keys:
    // Some(_)` - see `SessionState::own_keys`.
    let Some(own_keys) = session.own_keys.as_ref() else {
        return;
    };
    let private = own_keys.lock().unwrap().current_private_for(peer);
    own_next_keys.set(nickname, private);
    if let Err(e) = own_next_keys.save() {
        eprintln!("aloo: failed to save own_next_keys: {e}");
    }
}

/// Requests rotation of our own per-peer key for `peer` - a no-op unless
/// this session is `PerMessage`, so callers can invoke it unconditionally
/// after any send/receive (§11.3). Does *not* rotate itself: it hands
/// `peer` to `spawn_rotation_worker` and returns immediately, keeping the
/// RSA-4096 keygen off this event-loop task. Increments
/// `session.rotation_pending` here rather than in the worker on dequeue,
/// so the spinner reflects the whole queued-plus-in-flight batch.
/// Rotates our `pq_hybrid` encryption keys for `peer` and offers them the
/// new ones - a no-op unless this session is `PqHybrid`, so callers invoke
/// it unconditionally after any send or receive, exactly like
/// `request_rotation` (§13.10).
///
/// Unlike that one, this rotates **inline**: ML-KEM-1024 and X25519 keygen
/// are microseconds, so there is nothing here worth handing to a background
/// worker, and no spinner to drive. The key it supersedes is dropped the
/// moment it falls out of the retention window, which is what forward
/// secrecy actually consists of here.
/// Installs a `pq_hybrid` peer's offer of fresh encryption keys (§13.10),
/// having verified it against the identity we already pinned for them.
///
/// Dropped silently on a bad signature, a rotation addressed to somebody
/// else, or a generation we have already moved past - the previously
/// trusted keys are left exactly as they were, so a forged or replayed
/// rotation cannot strand a relationship or drag it back onto an older key.
///
/// A successful install makes the peer *fresh* again, which releases
/// anything queued for them while they had no usable key.
fn handle_pq_key_rotated(
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
    rotation_bytes: Vec<u8>,
    signature: Vec<u8>,
) {
    let Some(you) = ui_state.own_id else { return };
    let Some(my_fp) = session.own_pq_fp else { return };
    let Some(sender_public) = ui_state
        .known_users
        .get(&peer)
        .and_then(|u| proto::decode::<crate::crypto::pq::PqPublicBundle>(&u.public_key_der).ok())
    else {
        return;
    };
    let Some(rotation) = crate::crypto::pq::verify_rotation(
        &sender_public,
        you,
        &my_fp,
        &rotation_bytes,
        &signature,
    ) else {
        return;
    };
    if session.pq_peer_keys.install(peer, rotation) {
        session.remote_keys.on_rotated(peer);
    }
}

pub(crate) fn request_rotation_if_pq_hybrid(session: &mut SessionState, peer: UserId) {
    if session.own_key_mode != KeyMode::PqHybrid {
        return;
    }
    let Some(signing) = session.own_pq_private.clone() else {
        return;
    };
    let Some(peer_fp) = session.pq_peer_keys.fingerprint_for(peer) else {
        return;
    };
    let Some(own) = session.own_pq_keys.as_mut() else {
        return;
    };
    let rotation = own.rotate_for(peer);
    let Ok((encoded, signature)) =
        crate::crypto::pq::sign_rotation(&signing, peer, &peer_fp, &rotation)
    else {
        return;
    };
    // Handed to the main loop to write, the same route the rsa_per_msg
    // worker's rotations take.
    let _ = session.rotate_out_tx.send(ClientMessage::RotateKey {
        to: peer,
        new_public_key_der: encoded,
        signature,
    });
}

/// Rotates our own key material for `peer`, whichever scheme this session
/// uses - the single trigger every send and receive path calls, so neither
/// `rsa_per_msg` nor `pq_hybrid` needs its own sprinkling of call sites.
/// A no-op for the static modes, which have nothing to rotate.
pub(crate) fn request_rotation(session: &mut SessionState, peer: UserId) {
    if session.own_key_mode == KeyMode::PqHybrid {
        request_rotation_if_pq_hybrid(session, peer);
        return;
    }
    if session.own_key_mode == KeyMode::PerMessage {
        session.rotation_pending.fetch_add(1, Ordering::SeqCst);
        if session.rotate_request_tx.send(peer).is_err() {
            // The worker thread is gone (should only happen during
            // shutdown) - undo the increment so a request that will never
            // be processed doesn't leave the spinner animating forever.
            session.rotation_pending.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Validates an incoming `KeyRotated` against the key we currently trust
/// for `peer` (§11.4), falling back to their persisted cross-session
/// continuity pin in `id_store` (§12.6) - the fallback is what makes a
/// legitimate reconnect (brand-new `UserId`, so the live check can never
/// pass) verifiable at all.
///
/// A verified `Resumed` is the *only* thing that silently installs a key
/// for a pinned nickname - an actual signature proving continuity. `Live`
/// alone only proves self-consistency with what this same connection
/// announced (true of anyone the first time a fresh `UserId` rotates), so
/// it is not cross-session evidence. For a gated peer this function only
/// ever *clears* the gate (genuine `Resumed`) or leaves it as-is - never
/// opens it; `check_identity` already did.
///
/// On `Resumed`: installs the key everywhere it's cached, refreshes the
/// continuity pin, flushes queued messages FIFO (each followed by our own
/// rotation if we're `PerMessage` - §11.3), and silently resolves any
/// outstanding review like an `Accept`, revealing held messages. `Live`
/// with *no* pin (the ordinary case) gets identical treatment - nothing
/// to prove. `Live` with a pin installs nothing and refreshes the open
/// review to point at this latest attempt. `Failed` installs nothing; if
/// there's a pin it opens/refreshes a review worded for an explicit
/// failed proof. An unknown sender, or a no-anchor signature with nothing
/// pinned, is silently dropped - never suspicious just because there was
/// nothing to check (§12.6.3).
async fn handle_key_rotated(
    ui_state: &mut UiState,
    you: UserId,
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    peer: UserId,
    new_public_key_der: Vec<u8>,
    signature: Vec<u8>,
) -> proto::Result<()> {
    // A pq_hybrid peer rotates encryption keys, not identity, and signs
    // each rotation with the identity we already pinned - so none of the
    // RSA path's chain-of-custody or §12.6 resume reasoning applies.
    if ui_state.known_users.get(&peer).map(|u| u.key_mode) == Some(KeyMode::PqHybrid) {
        handle_pq_key_rotated(ui_state, session, peer, new_public_key_der, signature);
        return Ok(());
    }
    let Some(nickname) = ui_state.known_users.get(&peer).map(|u| u.name.clone()) else {
        return Ok(());
    };
    let live_trusted = ui_state
        .known_users
        .get(&peer)
        .and_then(|u| crypto::public_key_from_der(&u.public_key_der).ok());
    let continuity_pinned = session.id_store.get(&nickname).map(|d| d.to_vec());
    let continuity_trusted = continuity_pinned
        .as_deref()
        .and_then(|d| crypto::public_key_from_der(d).ok());
    let was_gated = ui_state.is_trust_gated(peer);

    match rekey::verify_with_fallback(
        live_trusted.as_ref(),
        continuity_trusted.as_ref(),
        you,
        &new_public_key_der,
        &signature,
    ) {
        rekey::ResumeVerification::Resumed(_) => {
            // An actual proof of continuity - install it, and if
            // `check_identity` had this nickname gated, that proof is
            // exactly what clears it: resolve the review the same way an
            // `Accept` would (held messages included), just silently.
            install_trusted_rotation(ui_state, wr, session, peer, &nickname, new_public_key_der)
                .await?;
            if was_gated && ui_state.resolve_identity_accept(peer) {
                voice_stream::play_bell_chime(session);
            }
            Ok(())
        }
        rekey::ResumeVerification::Live(_) if !was_gated => {
            // Nothing was pinned for this nickname (or it was already
            // fully trusted this session) - an ordinary rotation, exactly
            // as trustworthy as it's ever been.
            install_trusted_rotation(ui_state, wr, session, peer, &nickname, new_public_key_der)
                .await
        }
        rekey::ResumeVerification::Live(_) => {
            // Gated already, and self-consistency alone doesn't clear
            // that - refresh the review to point at this latest key so
            // Accept, if it comes, installs something they can actually
            // still decrypt, but stay Pending.
            push_unverified_resume_review(ui_state, peer, &nickname, new_public_key_der);
            Ok(())
        }
        rekey::ResumeVerification::Failed => {
            if was_gated || continuity_pinned.is_some() {
                let message = format!(
                    "'{nickname}' reconnected but couldn't prove continuity with a previous session (invalid resume signature) - possible impersonation. Accept their new key, or reject it."
                );
                ui_state.push_identity_review(
                    peer,
                    nickname,
                    message,
                    IdentityCase::ResumeFailed { new_public_key_der },
                );
            }
            Ok(())
        }
    }
}

/// Installs a `rsa_per_msg` peer's newly-trusted rolling key wherever it's
/// cached, refreshes the `id_store` continuity pin, and flushes any
/// messages that were queued waiting for it (`docs/PROTOCOL.md` §11.5,
/// §12.6) - shared by `handle_key_rotated`'s ordinary `Live`/`Resumed`
/// success path and a manual `AcceptIdentity` for a previously-`Failed`
/// resume (`handle_ui_action`), since both end up doing exactly the same
/// thing once the new key is trusted, whichever anchor (or person) did the
/// trusting.
async fn install_trusted_rotation(
    ui_state: &mut UiState,
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    peer: UserId,
    nickname: &str,
    new_public_key_der: Vec<u8>,
) -> proto::Result<()> {
    ui_state.on_user_key_rotated(peer, new_public_key_der.clone());
    session
        .id_store
        .check_and_pin(nickname, &new_public_key_der);
    if let Err(e) = session.id_store.save() {
        eprintln!("aloo: failed to save id_store: {e}");
    }

    let batch = session.remote_keys.on_rotated(peer);
    let mut sent_any = false;
    for item in batch {
        let Some(der) = ui_state
            .known_users
            .get(&peer)
            .map(|u| u.public_key_der.clone())
        else {
            continue;
        };
        let (channel, plaintext) = match item {
            rekey::QueuedOutbound::Direct { plaintext } => (None, plaintext),
            rekey::QueuedOutbound::Channel { channel, plaintext } => (Some(channel), plaintext),
        };
        let Some(envelope) = crate::client::envelope::encrypt_for_one(&der, plaintext.as_bytes(), Content::Text) else {
            continue;
        };
        session.peer_link.ensure_link(wr, peer).await;
        session
            .peer_link
            .send_reliable_or_queue(peer, P2pPayload::Envelope { channel, envelope });
        sent_any = true;
        request_rotation(session, peer);
    }
    if sent_any {
        session.remote_keys.mark_used(peer);
    }
    Ok(())
}

/// Decrypts `envelope`, addressed to *us*, from `from` (`sender`'s
/// `UserInfo`, needed only for `PqHybrid`'s signature verification - see
/// below). Which decryption scheme to use is decided by **our own**
/// `session.own_key_mode`, not `sender`'s: a message addressed to us was
/// necessarily encrypted against whichever public key material *we*
/// announced, regardless of what `my_key` the sender themselves runs (see
/// `docs/PROTOCOL.md` §13's "who can send to a `PqHybrid` peer" note) -
/// `sender.key_mode` only matters here to know what shape their signing
/// public key is in.
pub(crate) fn decrypt_envelope_for(
    envelope: Envelope,
    from: UserId,
    sender: &UserInfo,
    channel: Option<&str>,
    session: &mut SessionState,
) -> Option<ui::MessageBody> {
    if envelope.content != Content::Text {
        return None;
    }
    let plaintext = decrypt_own_envelope(&envelope, from, sender, channel, session)?;
    Some(ui::MessageBody::Text(
        String::from_utf8_lossy(&plaintext).into_owned(),
    ))
}

/// Decrypts a `FileOffer` envelope addressed to us into its
/// `FileOfferPayload` - the offer counterpart of `decrypt_envelope_for`,
/// same RSA/PQ dispatch, different output shape (there's no `MessageBody`
/// for an unresolved offer, only for the row an `Accept` eventually
/// creates - see `handle_incoming_file_offer`).
fn decrypt_file_offer(
    envelope: &Envelope,
    from: UserId,
    sender: &UserInfo,
    channel: Option<&str>,
    session: &mut SessionState,
) -> Option<crate::client::file_transfer::FileOfferPayload> {
    if envelope.content != Content::FileOffer {
        return None;
    }
    let plaintext = decrypt_own_envelope(envelope, from, sender, channel, session)?;
    proto::decode(&plaintext).ok()
}

/// The RSA/PQ dispatch shared by `decrypt_envelope_for` and
/// `decrypt_file_offer` - decrypts `envelope.blocks` addressed to us,
/// regardless of `envelope.content` (callers check that themselves first).
///
/// The PQ path additionally enforces everything a signature alone can't:
/// that the send was sealed for *us*, that it arrived where it claims to
/// belong (`channel`), and that it isn't a replay of one already accepted
/// from this peer. Any of those failing is an ordinary decrypt failure -
/// the message is dropped, exactly like a bad AEAD tag.
fn decrypt_own_envelope(
    envelope: &Envelope,
    from: UserId,
    sender: &UserInfo,
    channel: Option<&str>,
    session: &mut SessionState,
) -> Option<Vec<u8>> {
    if session.own_key_mode == KeyMode::PqHybrid {
        let my_fp = session.own_pq_fp?;
        let candidates = session.own_pq_keys.as_ref()?.candidates_for(from);
        let sender_public: crypto::pq::PqPublicBundle =
            proto::decode(&sender.public_key_der).ok()?;
        let blob = envelope.blocks.first()?;
        let (binding, plaintext) =
            crypto::pq::open_send(&candidates, &my_fp, &sender_public, blob)?;
        if binding.channel.as_deref() != channel {
            return None;
        }
        if !session.replay.accept(from, binding.send_id) {
            return None;
        }
        Some(plaintext)
    } else {
        session
            .own_keys
            .as_ref()?
            .lock()
            .unwrap()
            .decrypt_from(from, &envelope.blocks)
    }
}


/// Applies an incoming `FileOffer`: decrypts it, and either holds it
/// (`Pending`/`Rejected` sender, `docs/PROTOCOL.md` §12 - same "held until
/// Accepted" precedent as a message/stream) or queues it for the
/// Accept/Reject popup, playing the bell if it's the one that ends up
/// shown right away.
fn handle_incoming_file_offer(
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    from_name: String,
    stream_id: u64,
    channel: Option<String>,
    envelope: Envelope,
) {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return;
    };
    let Some(payload) = decrypt_file_offer(&envelope, from, &sender, channel.as_deref(), session)
    else {
        return;
    };
    let filename = crate::client::file_transfer::truncate_filename(&payload.filename);
    let offer = PendingFileOffer {
        from,
        from_name,
        filename,
        size: payload.size,
        stream_id,
        channel,
    };
    if ui_state.is_trust_gated(from) {
        ui_state.hold_file_offer(offer);
        return;
    }
    if ui_state.push_file_offer(offer) {
        voice_stream::play_bell_chime(session);
    }
}

/// Dispatches one file-transfer progress/completion/failure event
/// (`file_transfer::FileEvent`) into the matching log row - see
/// `UiState::update_file_entry` for how a row is found from just
/// `(from, stream_id)`.
fn handle_file_event(
    ui_state: &mut UiState,
    session: &mut SessionState,
    event: file_transfer::FileEvent,
) {
    let me = ui_state.own_id.unwrap_or(UserId(0));
    match event {
        file_transfer::FileEvent::SendProgress { stream_id, bytes } => {
            ui_state.set_file_progress(me, stream_id, bytes)
        }
        file_transfer::FileEvent::SendDone { stream_id } => {
            ui_state.set_file_completed(me, stream_id)
        }
        file_transfer::FileEvent::SendFailed { stream_id } => ui_state.set_file_failed(me, stream_id),
        file_transfer::FileEvent::ReceiveProgress {
            from,
            stream_id,
            bytes,
        } => ui_state.set_file_progress(from, stream_id, bytes),
        file_transfer::FileEvent::ReceiveDone {
            from, stream_id, ..
        } => {
            session.active_file_transfers.remove(&(from, stream_id));
            ui_state.set_file_completed(from, stream_id);
        }
        file_transfer::FileEvent::ReceiveFailed { from, stream_id } => {
            session.active_file_transfers.remove(&(from, stream_id));
            ui_state.set_file_failed(from, stream_id);
        }
    }
}
