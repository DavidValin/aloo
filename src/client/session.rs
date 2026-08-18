//! The live, connected session: the event loop, session-wide state, and
//! the identity-pinning bookkeeping that isn't specific to a channel or a
//! DM. Per-conversation-type send/receive handling lives in
//! `crate::client::channel` and `crate::client::direct_message`; the
//! generic live-voice-streaming plumbing they both share lives in
//! `crate::client::voice_stream`.

use std::collections::HashMap;
use std::io::Stdout;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use rsa::RsaPrivateKey;
use tokio::net::TcpStream;

use crate::BoxError;
use crate::client::connect::ResolvedIdentity;
use crate::crypto;
use crate::client::file_transfer;
use crate::client::idstore;
use crate::client::netstats;
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
    /// One entry per currently-arriving OTP-protected transfer - see
    /// `file_transfer::OtpIncomingFileReceive`'s doc. Removed once
    /// `ReceiveDone`/`ReceiveFailed` finishes handling it.
    pub(crate) otp_incoming_file_receives: HashMap<(UserId, u64), file_transfer::OtpIncomingFileReceive>,
    /// The temp ciphertext path a sending OTP transfer is actually
    /// streaming from (`P2pEvent::FileAccepted`'s OTP branch), kept only
    /// long enough to delete it once the send finishes or fails
    /// (`FileEvent::SendDone`/`SendFailed`) - the *real* file the user
    /// picked is never touched or deleted.
    pub(crate) otp_send_temp_files: HashMap<u64, std::path::PathBuf>,
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
    /// Whether *this* client's own `my_key` is `pq_hybrid` - gates whether
    /// `request_rotation` ever actually does anything.
    pub(crate) own_key_mode: KeyMode,
    /// This client's own static RSA-family private key (`Password`/`None`
    /// - neither ever rotates), used to decrypt anything addressed to us.
    /// `None` for `PqHybrid` - see `own_pq_private`.
    pub(crate) own_keys: Option<RsaPrivateKey>,
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
    /// is. ML-KEM/X25519 keygen is fast enough to run inline on the
    /// event-loop task, so this needs no background worker.
    pub(crate) own_pq_keys: Option<crate::client::pq_rekey::PqOwnKeys>,
    /// Which `pq_hybrid` encryption keys each peer currently wants us to
    /// use, and how far along their rotation counter we have seen.
    pub(crate) pq_peer_keys: crate::client::pq_rekey::PqPeerKeys,
    /// Where a `pq_hybrid` rotation to send is queued for the main loop to
    /// write (`request_rotation_if_pq_hybrid`).
    pub(crate) rotate_out_tx: tokio::sync::mpsc::UnboundedSender<ClientMessage>,
    /// Refuses a send that already arrived once - see `replay::ReplayGuard`.
    pub(crate) replay: crate::client::replay::ReplayGuard,
    /// Freshness/queueing for peers whose key rotates during the session
    /// (currently `pq_hybrid` only), independent of our own `key_mode`.
    pub(crate) remote_keys: rekey::RemoteKeys,
    /// Local nickname -> full-public-key pinning store (`docs/PROTOCOL.md`
    /// §12), checked whenever a peer's identity is first learned
    /// (`check_identity`) so a nickname reconnecting under a different key
    /// can be flagged instead of silently trusted.
    pub(crate) id_store: idstore::IdStore,
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
    /// Where every `otp` CLI subprocess call this session makes is spawned
    /// from - one stable working directory, resolved once at connect time
    /// (`client::otp_cli::OtpCliConfig::resolve`).
    pub(crate) otp_cli_cfg: crate::client::otp_cli::OtpCliConfig,
    /// Per-contact OTP provisioning/ack-gate state, loaded from
    /// `~/.aloo/otp_store` alongside `id_store` and saved synchronously
    /// after every mutation - see `client::otp_store`'s module doc for why.
    pub(crate) otp_store: crate::client::otp_store::OtpStore,
    /// Outgoing OTP messages held back while their contact's previous
    /// message is still awaiting a network ack - in-memory only, unlike
    /// `otp_store` (`client::otp::OtpOutQueue`'s doc).
    pub(crate) otp_out_queue: crate::client::otp::OtpOutQueue,
    /// One entry per sender currently mid-way through sending us a fresh
    /// OTP pad, accumulated chunk by chunk
    /// (`crypto::otp::OtpKeySetupReassembly`'s doc). In-memory only, per
    /// connection: if the sender reconnects mid-transfer the whole
    /// handshake attempt has to restart anyway, same as any other
    /// in-flight state tied to a `UserId`.
    pub(crate) otp_incoming_setup: HashMap<UserId, crate::crypto::otp::OtpKeySetupReassembly>,
}

// `key_mode` pushed this past clippy's default 7-argument threshold;
// grouping the handshake outputs into a struct would be a larger,
// unrelated refactor of an already-established call site.
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
        tokio::sync::mpsc::unbounded_channel::<(SocketAddr, p2p::InboundDatagram)>();
    p2p::spawn_receive_loop(p2p_socket, server_addr, p2p_raw_tx);

    // `PqHybrid` has no single RSA key here and never rotates it (it's a
    // static identity, like `Password`/`None`, but with its own separate
    // key material) - see `SessionState::own_keys`/`own_pq_private`.
    let (own_keys, own_pq_private, own_pq_fp, own_pq_keys) = match my_identity {
        ResolvedIdentity::Rsa(kp) => (Some(kp.private), None, None, None),
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

    let mut session = SessionState {
        active_recording: None,
        next_stream_id: 1,
        next_mixer_id: 1,
        own_stream_targets: HashMap::new(),
        active_streams: HashMap::new(),
        own_file_targets: HashMap::new(),
        active_file_transfers: HashMap::new(),
        otp_incoming_file_receives: HashMap::new(),
        otp_send_temp_files: HashMap::new(),
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
        id_store,
        conn_stats: netstats::ConnStats::new(),
        auto_stop_tx,
        active_replay_id: None,
        peer_link,
        otp_cli_cfg: crate::client::otp_cli::OtpCliConfig::resolve(),
        otp_store: crate::client::otp_store::OtpStore::load(
            &crate::client::otp_store::OtpStore::default_path(),
        )
        .unwrap_or_else(|_| {
            crate::client::otp_store::OtpStore::new_empty(
                crate::client::otp_store::OtpStore::default_path(),
            )
        }),
        otp_out_queue: crate::client::otp::OtpOutQueue::new(),
        otp_incoming_setup: HashMap::new(),
    };

    let mut ui_state = UiState::new(display_name);
    ui_state.set_own_id(you);
    ui_state.set_keyboard_release_reporting(keyboard_release_reporting);
    // Ticks fast enough that `tick_recording_timeout` can detect a
    // released Space key within one `RECORD_HOLD_TIMEOUT` window without
    // adding much latency; also drives the idle-stream sweep below.
    let mut ticker = tokio::time::interval(Duration::from_millis(150));
    let mut tick_count: u32 = 0;
    // Keeps the server able to tell this session is still alive
    // (docs/PROTOCOL.md §4.1) even across a long stretch where the user
    // sends nothing - real chat/voice/file content never touches the
    // server at all (it's peer-to-peer), so without this an idle-but-happy
    // session would look identical to a dead one from the server's side.
    let mut heartbeat_ticker = tokio::time::interval(proto::HEARTBEAT_INTERVAL);
    let mut cpu_monitor = sysstats::CpuMonitor::new();
    let mut last_cpu_sample = Instant::now();
    let mut last_conn_sample = Instant::now();
    let mut last_otp_key_status_sample = Instant::now();

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
                if let Some(action) = handle_server_message(msg, &mut ui_state, &mut wr, &mut session).await? {
                    handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                }
            }
            msg = record_out_rx.recv() => {
                let Some(msg) = msg else { break };
                session.peer_link.dispatch_outbound(msg);
            }
            dgram = p2p_raw_rx.recv() => {
                let Some((addr, dgram)) = dgram else { break };
                session.peer_link.on_inbound(addr, dgram);
            }
            event = p2p_events_rx.recv() => {
                let Some(event) = event else { break };
                handle_p2p_event(event, &mut ui_state, &mut wr, &mut session).await?;
            }
            msg = rotate_out_rx.recv() => {
                let Some(msg) = msg else { break };
                wr.send_control(&msg).await?;
                session.conn_stats.record_event(Instant::now());
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
                        voice_stream::OwnStreamTarget::DirectOtp { to, contact_name, recipient_pubkey_der } => {
                            // Finalized locally the same way a live stream's
                            // own row is (we already hold the full plaintext
                            // regardless of how the send itself turns out,
                            // same as an optimistically-logged text send) -
                            // `send_voice_offer` handles the actual OTP
                            // encrypt-and-send, notifying on failure.
                            ui_state.on_direct_stream_finished(to, you, stream_id, duration_ms, pcm.clone());
                            crate::client::otp::send_voice_offer(
                                &mut wr, &mut session, &mut ui_state, to, &contact_name, &recipient_pubkey_der, pcm, duration_ms,
                            ).await?;
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
                handle_file_event(&mut ui_state, &mut session, event).await;
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
            _ = heartbeat_ticker.tick() => {
                wr.send_control(&ClientMessage::Heartbeat).await?;
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
                // The OTP session header's live Seq/Offset/remaining figures
                // (docs/PROTOCOL.md 16.5) refresh once a second too, and only
                // for whichever DM is actually open right now - see
                // `otp::poll_key_status`'s doc for why nothing else is
                // polled.
                if now.duration_since(last_otp_key_status_sample) >= Duration::from_secs(1) {
                    if let Some(peer) = ui_state.active_private_room {
                        crate::client::otp::poll_key_status(&session, &mut ui_state, peer).await;
                    }
                    last_otp_key_status_sample = now;
                }
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
            crate::client::channel::handle_send_text(wr, ui_state, session, channel, plaintext, recipients).await?;
        }
        UiAction::SendDirectText {
            to,
            plaintext,
            recipient_key_mode,
            recipient_pubkey_der,
            log_index,
        } => {
            crate::client::direct_message::handle_send_text(
                wr,
                ui_state,
                session,
                to,
                plaintext,
                recipient_key_mode,
                recipient_pubkey_der,
                log_index,
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
                // A static key just needs pinning - `known_users` (and
                // hence what future sends encrypt with) already holds this
                // exact key, set unconditionally by `on_user_joined` when
                // the peer joined (docs/PROTOCOL.md §12.4); nothing else
                // was withheld from it, only the local pin.
                let IdentityCase::StaticMismatch {
                    new_public_key_der, ..
                } = review.case;
                session
                    .id_store
                    .check_and_pin(&review.nickname, &new_public_key_der);
                if let Err(e) = session.id_store.save() {
                    eprintln!("aloo: failed to save id_store: {e}");
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
        UiAction::RequestOtpSession {
            peer,
            key_mode,
            pubkey_der,
        } => {
            crate::client::otp::handle_otp_command(wr, ui_state, session, peer, key_mode, pubkey_der)
                .await?;
        }
        UiAction::ConfirmOtpGenerate { size_mb } => {
            crate::client::otp::confirm_generate(wr, session, ui_state, size_mb).await?;
        }
        UiAction::CancelOtpGenerate => {
            crate::client::otp::cancel_generate(ui_state);
        }
        UiAction::AcceptOtpInvite => {
            crate::client::otp::accept_invite(wr, session, ui_state).await?;
        }
        UiAction::RejectOtpInvite => {
            crate::client::otp::reject_invite(wr, session, ui_state).await?;
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
    let final_path = crate::client::file_transfer::default_download_dir().join(dest_name);
    // An OTP-active offer's chunks are ordinary pq_hybrid ciphertext, same
    // as any other transfer (see `client::otp::send_file_offer`'s doc) -
    // only the destination differs: a temp file, decrypted whole into
    // `final_path` once `handle_file_event`'s `ReceiveDone` runs
    // `client::otp::finish_incoming_file`.
    // `seq` starts `None` here - the content phase's own pad slot isn't
    // reserved (or numbered) until the sender's `FileAccepted` handling
    // actually runs `otp --encrypt`, named separately once
    // `P2pEvent::OtpFileContentSeq` arrives (docs/PROTOCOL.md 16.2).
    let worker_dest = match &offer.otp_contact_name {
        Some(contact_name) => {
            let temp_path = crate::client::otp::temp_content_path(&session.otp_cli_cfg, "otp-recv");
            session.otp_incoming_file_receives.insert(
                (from, stream_id),
                file_transfer::OtpIncomingFileReceive {
                    contact_name: contact_name.clone(),
                    seq: None,
                    temp_path: temp_path.clone(),
                    kind: file_transfer::OtpIncomingKind::File {
                        final_path: final_path.clone(),
                    },
                },
            );
            temp_path
        }
        None => final_path,
    };
    let job_tx = file_transfer::spawn_receive_file_worker(
        key,
        worker_dest,
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
/// punching a direct link to a newly-learned peer writes to the network
/// right here.
async fn handle_server_message(
    msg: ServerMessage,
    ui_state: &mut UiState,
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
                ui_state.forget_link_status(user_id);
            }
        }
        ServerMessage::UserOffline { user_id } => {
            ui_state.on_user_offline(user_id);
            // A full disconnect is always the end of any relationship with
            // them - unlike `UserLeft` (one channel, possibly still shared
            // elsewhere or via an open DM), so this is the one case safe to
            // forget the link unconditionally.
            session.peer_link.forget(user_id);
            ui_state.forget_link_status(user_id);
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
            // Only `pq_hybrid` peers ever rotate, so this is always their
            // encryption-key offer (§13.10).
            handle_pq_key_rotated(ui_state, session, from, new_public_key_der, signature);
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
///
/// Async (and given `wr`) for the one event that has to reach the network:
/// `Signal`, the manager asking for a candidate list to be relayed. It
/// can't send that itself - `tick_at` has no control sink, deliberately,
/// so link state stays testable without one - so the round trip to the
/// server for an automatic re-punch lands here (docs/PROTOCOL.md §7.1).
async fn handle_p2p_event(
    event: P2pEvent,
    ui_state: &mut UiState,
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
) -> proto::Result<()> {
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
            crate::client::direct_message::on_message(ui_state, session, from, from_name, envelope)
                .await;
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
            // `target` stays in `own_file_targets` here -
            // `start_outgoing_file_content` may need to queue this stream
            // behind another pending OTP send, in which case the entry
            // (key included) must still be there whenever the queue
            // finally drains it (`client::otp::start_outgoing_file_content`'s
            // doc). It owns removal, and spawning the send worker, in
            // every case (immediate, queued, and the plain non-OTP path
            // alike).
            if let Some(target) = session.own_file_targets.get(&stream_id) {
                let me = ui_state.own_id.unwrap_or(UserId(0));
                ui_state.set_file_progress(me, stream_id, 0);
                // A pq_hybrid transfer's setup goes out before its first
                // chunk, exactly as a voice stream's does after
                // `StreamStart` - the chunks themselves are ciphertext only.
                let setups: Vec<(UserId, Vec<u8>)> = match &target.key {
                    voice_stream::DirectStreamKey::Pq(pq) => pq.setups(),
                    _ => Vec::new(),
                };
                for (id, setup) in setups {
                    session
                        .peer_link
                        .send_reliable_or_queue(id, P2pPayload::StreamKeySetup { stream_id, setup });
                }
                crate::client::otp::start_outgoing_file_content(session, ui_state, stream_id).await?;
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
        P2pEvent::Signal {
            peer,
            candidates,
            link_nonce,
        } => {
            wr.send_control(&ClientMessage::RequestPeerLink {
                peer,
                candidates,
                link_nonce,
            })
            .await?;
            session.conn_stats.record_event(Instant::now());
        }
        P2pEvent::LinkStatusChanged { peer, status } => {
            ui_state.set_link_status(peer, status);
            if status == p2p::LinkStatus::Active {
                // A send whose ciphertext already left the machine is
                // recovered via `otp --recover-last`, never re-encoded -
                // this is the one place that retry gets triggered, on every
                // genuine reachability transition (reconnect, link flap,
                // this app's own restart once the link comes back up).
                // Scans every OTP contact with something outstanding, not
                // just `peer` - cheap (a handful of contacts at most) and
                // opportunistically recovers anyone else reachable too.
                crate::client::otp::recover_and_resend(wr, session, ui_state).await?;
            }
        }
        P2pEvent::OtpMessage {
            channel,
            from,
            seq,
            envelope,
        } => {
            let from_name = name_of(ui_state, from);
            crate::client::otp::on_message(session, ui_state, channel, from, from_name, seq, envelope)
                .await;
        }
        P2pEvent::OtpFileOffer {
            channel,
            from,
            stream_id,
            seq,
            envelope,
        } => {
            let from_name = name_of(ui_state, from);
            crate::client::otp::on_file_offer(
                session, ui_state, channel, from, from_name, stream_id, seq, envelope,
            )
            .await;
        }
        P2pEvent::OtpDeliveryAck { from, seq } => {
            crate::client::otp::on_delivery_ack(wr, ui_state, session, from, seq).await?;
        }
        P2pEvent::OtpFileContentSeq { from, stream_id, seq } => {
            if let Some(pending) = session.otp_incoming_file_receives.get_mut(&(from, stream_id)) {
                pending.seq = Some(seq);
            }
        }
        P2pEvent::OtpVoiceOffer {
            from,
            stream_id,
            seq,
            envelope,
        } => {
            crate::client::otp::on_voice_offer(wr, session, ui_state, from, stream_id, seq, envelope).await;
        }
    }
    Ok(())
}

/// Checks a newly-learned peer's announced identity against the local
/// pinning store (§12), opening a blocking Accept/Reject review if their
/// nickname was previously pinned to a key this connection hasn't proven
/// itself a continuation of. `KeyMode::None` is skipped - no continuity
/// mechanism by design (§12.2). `Password`/`PqHybrid` keys are stable by
/// construction, so a byte comparison against the pin is definitive
/// (`StaticMismatch` arm).
///
/// Deliberately does **not** use `IdStore::check_and_pin` on a mismatch:
/// that always re-pins as a side effect, which would trust the new key
/// for next time regardless of what the user decides - a `Reject` must
/// leave the old pin untouched until `AcceptIdentity` explicitly re-pins.
/// `IdStore::get` reads without mutating, so the comparison is by hand.
/// Whether `user`'s newly announced identity carries a continuity
/// certificate (§12.6) signed by the one currently pinned for them - i.e.
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
                // identity we already pinned (§12.6), they deliberately
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
        // KeyMode::None, plus an unreachable fallback for the guard arm
        // above (rustc can't statically know `uses_byte_comparison_pinning`
        // covers exactly Password/PqHybrid).
        _ => {}
    }
}

/// Shortens a full SHA-256 hex fingerprint (`crypto::fingerprint`) to its
/// first 16 hex characters (8 bytes) for compact display in a UI warning -
/// still effectively unique for telling two specific keys apart at a
/// glance, without wrapping a 64-character hex string across the screen.
fn short_fingerprint(fp: &str) -> &str {
    fp.get(..16).unwrap_or(fp)
}

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

/// Rotates our `pq_hybrid` encryption keys for `peer` and offers them the
/// new ones - a no-op unless this session is `PqHybrid`, so callers invoke
/// it unconditionally after any send or receive, via `request_rotation`
/// (§13.10). Rotates **inline**: ML-KEM-1024 and X25519 keygen are
/// microseconds, so there is nothing here worth handing to a background
/// worker. The key it supersedes is dropped the moment it falls out of the
/// retention window, which is what forward secrecy actually consists of
/// here.
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
    // Handed to the main loop to write.
    let _ = session.rotate_out_tx.send(ClientMessage::RotateKey {
        to: peer,
        new_public_key_der: encoded,
        signature,
    });
}

/// Rotates our own key material for `peer` - the single trigger every send
/// and receive path calls, so `pq_hybrid` needs no sprinkling of call
/// sites of its own. A no-op for the static modes, which have nothing to
/// rotate.
pub(crate) fn request_rotation(session: &mut SessionState, peer: UserId) {
    if session.own_key_mode == KeyMode::PqHybrid {
        request_rotation_if_pq_hybrid(session, peer);
    }
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
pub(crate) fn decrypt_file_offer(
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

/// `decrypt_file_offer`'s voice counterpart, for `Content::VoiceOffer` -
/// always a DM (voice-under-OTP has no channel path), so no `channel`
/// parameter.
pub(crate) fn decrypt_voice_offer(
    envelope: &Envelope,
    from: UserId,
    sender: &UserInfo,
    session: &mut SessionState,
) -> Option<crate::client::file_transfer::VoiceOfferPayload> {
    if envelope.content != Content::VoiceOffer {
        return None;
    }
    let plaintext = decrypt_own_envelope(envelope, from, sender, None, session)?;
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
pub(crate) fn decrypt_own_envelope(
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
        crypto::decrypt_chunked(session.own_keys.as_ref()?, &envelope.blocks).ok()
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
        otp_contact_name: None,
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
async fn handle_file_event(
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
            if let Some(temp) = session.otp_send_temp_files.remove(&stream_id) {
                crate::client::otp::secure_remove_file(&temp);
            }
            ui_state.set_file_completed(me, stream_id)
        }
        file_transfer::FileEvent::SendFailed { stream_id } => {
            if let Some(temp) = session.otp_send_temp_files.remove(&stream_id) {
                crate::client::otp::secure_remove_file(&temp);
            }
            ui_state.set_file_failed(me, stream_id)
        }
        file_transfer::FileEvent::ReceiveProgress {
            from,
            stream_id,
            bytes,
        } => ui_state.set_file_progress(from, stream_id, bytes),
        file_transfer::FileEvent::ReceiveDone {
            from, stream_id, ..
        } => {
            session.active_file_transfers.remove(&(from, stream_id));
            match session.otp_incoming_file_receives.remove(&(from, stream_id)) {
                Some(pending) => {
                    crate::client::otp::finish_incoming_file(session, ui_state, from, stream_id, pending).await;
                }
                None => ui_state.set_file_completed(from, stream_id),
            }
        }
        file_transfer::FileEvent::ReceiveFailed { from, stream_id } => {
            session.active_file_transfers.remove(&(from, stream_id));
            if let Some(pending) = session.otp_incoming_file_receives.remove(&(from, stream_id)) {
                crate::client::otp::secure_remove_file(&pending.temp_path);
            }
            ui_state.set_file_failed(from, stream_id);
        }
    }
}
