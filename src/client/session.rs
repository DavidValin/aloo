//! The live, connected session: the event loop, session-wide state, and
//! the identity-pinning bookkeeping that isn't specific to a channel or a
//! DM. Per-conversation-type send/receive handling lives in
//! `crate::client::channel` and `crate::client::direct_message`; the
//! generic live-voice-streaming plumbing they both share lives in
//! `crate::client::voice_stream`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyModifiers};
use rsa::RsaPrivateKey;

use crate::BoxError;
use crate::client::connect::ResolvedIdentity;
use crate::crypto;
use crate::client::file_transfer;
use crate::client::idstore;
use crate::client::netstats;
use crate::client::p2p::{self, P2pEvent, P2pOutbound, PeerLinkManager};
use crate::p2p_proto::{P2pPayload, ReceiptStage};
use crate::proto::{
    self, ClientMessage, Content, Envelope, KeyMode, ServerMessage, UserId, UserInfo,
};
use crate::client::reconnect::{ServerEvent, ServerLinkState};
use crate::client::rekey;
use crate::client::sysstats;
use crate::client::tui::ui::{self, IdentityCase, PendingFileOffer, UiAction, UiState, VoiceTarget};
use crate::client::voice;
use crate::client::voice_call;
use crate::client::voice_stream;

use voice_stream::IdleStreamAction;

/// Everything that can arrive from "the person using this session",
/// whichever surface they are using it through
/// (`crate::client::tui::surface`).
///
/// A daemon's session has no terminal of its own, and gains one only when
/// someone attaches, so this covers more than a terminal event: one loop
/// serves both worlds, fed by the local stdin thread on a
/// terminal-attached run and by the IPC listener in a daemon.
#[derive(Debug)]
pub enum SessionInput {
    /// A key (or other terminal event) from whoever is driving right now.
    Key(Event),
    /// Someone attached a viewer of this size - start drawing to it.
    Attached {
        writer: crate::client::tui::surface::AttachWriter,
        size: crate::client::tui::surface::TerminalSize,
    },
    /// The attached viewer's terminal changed size.
    Resized(crate::client::tui::surface::TerminalSize),
    /// Stop drawing and keep running - `/daemon`, or the viewer's socket
    /// dropping. Never ends the session.
    Detach,
    /// End the session and return, as a clean quit does.
    Shutdown,
}

/// Every piece of state and every channel handle the voice-streaming
/// machinery needs, threaded through both `handle_ui_action` (outgoing)
/// and `handle_server_message` (incoming) so neither function needs a
/// long, error-prone parameter list.
/// Whether this session has a server behind it, and if so whether it can
/// be used right now.
///
/// The two "no" cases are deliberately distinct rather than one boolean:
/// `Absent` is how the client was started and will not change, so an
/// action needing a server should say so plainly and stop; `Unreachable`
/// is a condition that may well pass, so the same action is worth
/// describing as temporarily unavailable. Telling a user "this needs a
/// server" when one is merely reconnecting would be wrong, and telling
/// them "retrying" when there is no server at all would be a lie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Connected and usable.
    Connected,
    /// Configured, but not reachable at the moment.
    Unreachable,
    /// Started with no server at all (`--no-server`).
    Absent,
}

impl ServerState {
    /// Whether anything needing a server can happen right now.
    pub fn is_absent(self) -> bool {
        !matches!(self, Self::Connected)
    }

    /// Whether there is no server even in principle, as opposed to one
    /// that is merely away.
    pub fn is_serverless(self) -> bool {
        matches!(self, Self::Absent)
    }

    /// How to explain to a user that `what` cannot happen. Phrased for the
    /// status line, and different per state on purpose (see the type doc).
    pub fn refusal(self, what: &str) -> String {
        match self {
            Self::Connected => format!("{what} is not available"),
            Self::Unreachable => {
                format!("{what} needs the server, which is unreachable right now")
            }
            Self::Absent => format!("{what} needs a server - running without one"),
        }
    }
}

pub struct SessionState {
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
    /// select loop into `peer_link.dispatch_outbound`. This content never
    /// touches the control connection: it rides the direct link
    /// (`docs/PROTOCOL.md` §7.1) or waits for one.
    pub(crate) record_out_tx: tokio::sync::mpsc::UnboundedSender<P2pOutbound>,
    pub(crate) own_stream_done_tx: tokio::sync::mpsc::UnboundedSender<(u64, u32, Vec<u8>)>,
    /// Progress and completion reports from a pad generation running off
    /// the event loop (`client::otp::confirm_generate`) - drained by
    /// `run_connected_session`'s select loop, which moves the spinner and,
    /// on `Finished`, resumes the provisioning handshake. Generation is the
    /// one OTP step long enough (minutes, at the sizes now allowed) that
    /// running it inline would freeze every other thing this loop does.
    pub(crate) otp_keygen_tx: tokio::sync::mpsc::UnboundedSender<crate::client::otp::OtpKeygenEvent>,
    /// Completion reports from the pad send/receive workers
    /// (`client::otp_pad`) - drained by `run_connected_session`'s select
    /// loop, which is where the two-phase commit advances.
    pub(crate) otp_pad_tx: tokio::sync::mpsc::UnboundedSender<crate::client::otp_pad::PadEvent>,
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
    /// Which log row each outstanding OTP text send belongs to, keyed by
    /// `(contact_name, seq)` - what lets `client::otp::recover_and_resend_text`
    /// name the same message again (docs/PROTOCOL.md 7.2.1) when a stuck
    /// send is recovered rather than re-encoded. In-memory and
    /// session-scoped, like every other delivery id: a row from a previous
    /// run no longer exists to turn green.
    pub(crate) otp_text_msg_ids: std::collections::HashMap<(String, u64), u64>,
    /// Voice messages and file transfers that still owe their sender a
    /// delivery receipt (`client::delivery`, docs/PROTOCOL.md 7.2.1).
    pub(crate) pending_receipts: crate::client::delivery::PendingReceipts,
    /// One entry per sender currently mid-way through sending us a fresh
    /// OTP pad, accumulated chunk by chunk
    /// (`crypto::otp::OtpKeySetupReassembly`'s doc). In-memory only, per
    /// connection: if the sender reconnects mid-transfer the whole
    /// handshake attempt has to restart anyway, same as any other
    /// in-flight state tied to a `UserId`.
    pub(crate) otp_incoming_setup: HashMap<UserId, crate::crypto::otp::OtpKeySetupReassembly>,
    /// Pads currently streaming *in*, keyed by sender - see
    /// `client::otp_pad`. At most one per peer: a second `OtpPadStart` from
    /// the same sender supersedes the first, since a fresh `/otp` on their
    /// side is a fresh proposal and the old one can never be completed.
    pub(crate) otp_incoming_pads: HashMap<UserId, crate::client::otp_pad::IncomingPad>,
    /// Pads currently streaming *out*, keyed by recipient - the sending
    /// counterpart, and what `on_pad_verify` looks up to decide whether a
    /// verification it just received belongs to a live transfer.
    pub(crate) otp_outgoing_pads: HashMap<UserId, crate::client::otp_pad::OutgoingPad>,
    /// OTP mail references and received-mail blobs (docs/PROTOCOL.md §17),
    /// loaded from `~/.aloo/otp_mail/` alongside the other stores and
    /// saved synchronously after every mutation - see
    /// `client::otp_mail_store`'s module doc.
    pub(crate) otp_mail_store: crate::client::otp_mail_store::OtpMailStore,
    /// This machine's own `client::device_id` (`~/.aloo/d_id`) - sent,
    /// encrypted, to every peer once their link reaches `Active`
    /// (`send_device_id_announce`), purely so it can be shown in an
    /// impersonation review (docs/PROTOCOL.md §12.7).
    pub(crate) own_device_id: String,
    /// The device id each peer has announced, decrypted from their
    /// `Content::DeviceIdAnnounce` (`P2pEvent::DeviceIdAnnounce`). Never
    /// cleared - a peer's device id doesn't change mid-session just
    /// because their link flaps and re-punches.
    pub(crate) peer_device_ids: HashMap<UserId, String>,
    /// The live voice call (`crate::client::voice_call`) we're currently in,
    /// if any - distinct from push-to-talk's `active_recording`, and never
    /// set for more than one call at a time (`voice_call::is_busy`).
    pub(crate) active_call: Option<voice_call::ActiveCall>,
    /// Where a live call's audio threads report voice levels
    /// (`voice::level_from_pcm`) for the call modal's per-participant
    /// meters - our own capture worker under our own `UserId`, and each
    /// participant's decrypt worker under theirs. Drained by
    /// `run_connected_session`'s select loop into
    /// `UiState::set_call_level`.
    pub(crate) call_level_tx: tokio::sync::mpsc::UnboundedSender<(UserId, u8)>,
    /// What this session must do once connected, when it is running as a
    /// daemon (`crate::client::daemon::DaemonPlan`, docs/SPEC.md "Daemon
    /// mode"). `None` for every ordinary foreground client - and every
    /// hook that reads it is a no-op in that case, which is what keeps
    /// daemon mode from changing the behaviour of anything else.
    pub(crate) daemon_plan: Option<crate::client::daemon::DaemonPlan>,
    /// Whether a terminal is watching this session right now
    /// (`SessionInput::Attached` until `Detach`). Only meaningful in
    /// daemon mode; a foreground session is always being watched.
    ///
    /// What it gates is the join sound: it exists for when nobody is
    /// looking, so it must not fire at someone who is.
    pub(crate) viewer_attached: bool,
    /// Peers already announced as online, so "alice is here" is one sound
    /// however many shared channels her arrival arrives through
    /// (`UserJoined` is per channel). Cleared on `UserOffline`, so the
    /// next time she comes online is announced again.
    pub(crate) announced_online: std::collections::HashSet<UserId>,
    /// The peer a `--otp` daemon has proposed a session to and not yet
    /// heard the outcome for (docs/SPEC.md "Running in background mode").
    ///
    /// Only set when the *daemon* asked, never when a person typed
    /// `/otp` - someone at the keyboard already sees the outcome on
    /// screen, and does not need to be alerted to it.
    pub(crate) daemon_awaiting_otp: Option<UserId>,
    /// Whether a server is behind this session, and usable.
    pub(crate) server: ServerState,
    /// While the reconnect supervisor is waiting out its backoff
    /// (`crate::client::reconnect`): when the next attempt is due, and how
    /// many have already failed. The header's countdown is recomputed from
    /// this on every redraw rather than pushed a message per second.
    pub(crate) server_retry: Option<(Instant, u32)>,
    /// The password each private channel was joined with, so a reconnect
    /// can walk back into the same channels this session was in
    /// (`docs/PROTOCOL.md` §4.2). In memory for the life of the session
    /// only - it is never written anywhere, so a new session asks the user
    /// for it again.
    pub(crate) channel_passwords: HashMap<String, String>,
    /// Where a spawned `DirectResolve` lookup hands its answer back to the
    /// select loop (`docs/PROTOCOL.md` §7.1.5).
    pub(crate) direct_resolved_tx:
        tokio::sync::mpsc::UnboundedSender<(String, Option<SocketAddr>)>,
}

/// `run_connected_session` for a daemon: no terminal, a plan, and the
/// keyboard-release question answered by whoever attaches rather than by
/// this process.
///
/// `keyboard_release_reporting: false` is the deliberate choice, not a
/// placeholder. It is the safe default (`UiState`'s own doc): with it
/// unset, a held Space that never reports a release is still auto-stopped
/// on silence rather than recording forever. A daemon cannot ask - it has
/// no terminal - and the shortcut it actually exists for
/// (`global_ptt`) is exempt from that guess anyway, since a held OS hotkey
/// always delivers a real release.
#[allow(clippy::too_many_arguments)]
pub async fn run_daemon_session<W: crate::control::ControlSink>(
    surface: &mut crate::client::tui::surface::Surface,
    server_events: Option<tokio::sync::mpsc::UnboundedReceiver<ServerEvent>>,
    wr: W,
    display_name: String,
    you: UserId,
    my_identity: ResolvedIdentity,
    key_mode: KeyMode,
    id_store: idstore::IdStore,
    hotkey_rx: Option<tokio::sync::mpsc::UnboundedReceiver<crate::client::global_ptt::GlobalPttEvent>>,
    server_addr: Option<SocketAddr>,
    input_rx: tokio::sync::mpsc::UnboundedReceiver<SessionInput>,
    plan: crate::client::daemon::DaemonPlan,
) -> Result<(), BoxError> {
    run_connected_session(
        surface,
        server_events,
        wr,
        display_name,
        you,
        my_identity,
        key_mode,
        false,
        id_store,
        hotkey_rx,
        server_addr,
        input_rx,
        Some(plan),
    )
    .await
}

// `key_mode` pushed this past clippy's default 7-argument threshold;
// grouping the handshake outputs into a struct would be a larger,
// unrelated refactor of an already-established call site.
#[allow(clippy::too_many_arguments)]
pub async fn run_connected_session<W: crate::control::ControlSink>(
    surface: &mut crate::client::tui::surface::Surface,
    server_events: Option<tokio::sync::mpsc::UnboundedReceiver<ServerEvent>>,
    mut wr: W,
    display_name: String,
    you: UserId,
    my_identity: ResolvedIdentity,
    key_mode: KeyMode,
    keyboard_release_reporting: bool,
    id_store: idstore::IdStore,
    mut hotkey_rx: Option<tokio::sync::mpsc::UnboundedReceiver<crate::client::global_ptt::GlobalPttEvent>>,
    server_addr: Option<SocketAddr>,
    mut input_rx: tokio::sync::mpsc::UnboundedReceiver<SessionInput>,
    daemon_plan: Option<crate::client::daemon::DaemonPlan>,
) -> Result<(), BoxError> {
    // With no server there is nothing to hear from one: a channel is
    // created all the same, its sender parked here for the life of the
    // session so the branch simply never fires, and the select loop below
    // needs no serverless special case of its own.
    let server_state = match (&server_events, server_addr) {
        (Some(_), _) => ServerState::Connected,
        (None, _) => ServerState::Absent,
    };
    let (never_tx, never_rx) = tokio::sync::mpsc::unbounded_channel::<ServerEvent>();
    let mut server_events = server_events.unwrap_or(never_rx);
    let _server_events_kept_open = never_tx;

    let (audio_err_tx, mut audio_err_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (call_level_tx, mut call_level_rx) =
        tokio::sync::mpsc::unbounded_channel::<(UserId, u8)>();

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
    let (otp_keygen_tx, mut otp_keygen_rx) =
        tokio::sync::mpsc::unbounded_channel::<crate::client::otp::OtpKeygenEvent>();
    let (otp_pad_tx, mut otp_pad_rx) =
        tokio::sync::mpsc::unbounded_channel::<crate::client::otp_pad::PadEvent>();
    let (stream_finished_tx, mut stream_finished_rx) =
        tokio::sync::mpsc::unbounded_channel::<(UserId, u64, u32, Vec<u8>)>();
    let (file_events_tx, mut file_events_rx) =
        tokio::sync::mpsc::unbounded_channel::<file_transfer::FileEvent>();
    let (auto_stop_tx, mut auto_stop_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    // `~/.aloo/settings`, for the serverless direct-punch configuration
    // (`docs/PROTOCOL.md` §7.1.5) and `/mute-voice`'s persisted set
    // (docs/SPEC.md Functionality #15) alike. Read here rather than
    // threaded down from `main.rs`'s own load: the file may have been
    // edited by hand, or by another session, since this process started.
    // A read failure is not fatal for either consumer - nothing is muted
    // and direct punch stays off, the same way every other optional
    // subsystem in this loop degrades.
    let settings = crate::settings::Settings::load_or_create(&crate::settings::default_path())
        .unwrap_or_else(|e| {
            crate::log_warn!("could not read ~/.aloo/settings ({e}); direct punch stays off");
            crate::settings::Settings::default()
        });
    for (line, reason) in &settings.direct_punch_invalid {
        crate::log_warn!("ignoring direct_punch_to={line}: {reason}");
    }
    let (direct_resolved_tx, mut direct_resolved_rx) =
        tokio::sync::mpsc::unbounded_channel::<(String, Option<SocketAddr>)>();

    // The session's one direct client<->client UDP transport (`crate::client::p2p`).
    // Bound on the same address family as the server so the reflexive-
    // address probe below can actually reach it; the port is ephemeral
    // (`:0`) since only the server needs a fixed, well-known port.
    //
    // With `direct_punch=on` it is not ephemeral: a peer punching at us
    // with no server to relay a port has nothing to aim at but a port both
    // sides agreed on in advance, so the same socket binds
    // `direct_punch_port` (§7.1.5). A port already in use is not fatal -
    // the session falls back to an ephemeral one and says so, leaving
    // everything except direct punching working.
    // With no server to match families with, the socket follows whatever
    // the direct-punch targets need; IPv4 is the safe default there, since
    // that is what a settings file names in practice.
    let unspecified: std::net::IpAddr = if server_addr.is_some_and(|a| a.is_ipv6()) {
        std::net::Ipv6Addr::UNSPECIFIED.into()
    } else {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    };
    let bind_addr = SocketAddr::new(
        unspecified,
        if settings.direct_punch {
            settings.direct_punch_port
        } else {
            0
        },
    );
    // `~/.aloo/d_id` - generated once, on whichever session first needs it,
    // and reused for the machine's whole lifetime (`docs/PROTOCOL.md`
    // §12.7). A failure to load/create it is not fatal - the direct link
    // itself doesn't depend on it at all, it just leaves an impersonation
    // review with less to compare against - so this falls back to an
    // empty string (`display_device_id` renders that as "unknown") rather
    // than refusing to connect.
    let own_device_id = crate::client::device_id::load_or_create(&crate::client::device_id::default_path())
        .unwrap_or_else(|e| {
            crate::log_warn!("failed to load/create device id: {e} (continuing without one)");
            String::new()
        });
    let (p2p_events_tx, mut p2p_events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (mut peer_link, p2p_socket) =
        match PeerLinkManager::bind(bind_addr, server_addr, p2p_events_tx.clone()).await {
            Ok(ok) => ok,
            Err(e) if bind_addr.port() != 0 => {
                crate::log_warn!(
                    "could not bind the direct-punch port {} ({e});                      falling back to an ephemeral port - direct_punch_to peers                      will not be able to reach this client",
                    bind_addr.port()
                );
                PeerLinkManager::bind(
                    SocketAddr::new(unspecified, 0),
                    server_addr,
                    p2p_events_tx,
                )
                .await
                .map_err(|e| format!("failed to open the direct-link UDP socket: {e}"))?
            }
            Err(e) => return Err(format!("failed to open the direct-link UDP socket: {e}").into()),
        };
    if settings.direct_punch {
        peer_link.configure_direct_punch(
            display_name.clone(),
            settings.direct_punch_to.clone(),
            crate::client::p2p::utc_second_of_hour(),
        );
    }
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

    let is_daemon = daemon_plan.is_some();
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
        otp_keygen_tx,
        otp_pad_tx,
        mixer_tx,
        stream_finished_tx,
        audio_err_tx,
        call_level_tx,
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
        server: server_state,
        server_retry: None,
        channel_passwords: HashMap::new(),
        direct_resolved_tx,
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
        otp_text_msg_ids: std::collections::HashMap::new(),
        pending_receipts: crate::client::delivery::PendingReceipts::new(),
        otp_incoming_setup: HashMap::new(),
        otp_incoming_pads: HashMap::new(),
        otp_outgoing_pads: HashMap::new(),
        otp_mail_store: crate::client::otp_mail_store::OtpMailStore::load(
            crate::client::otp_mail_store::OtpMailStore::default_dir(),
        )
        .unwrap_or_else(|_| {
            crate::client::otp_mail_store::OtpMailStore::new_empty(
                crate::client::otp_mail_store::OtpMailStore::default_dir(),
            )
        }),
        own_device_id,
        peer_device_ids: HashMap::new(),
        active_call: None,
        daemon_plan,
        // A foreground session is always watched; a daemon starts with
        // nobody attached and learns otherwise from its IPC listener.
        viewer_attached: !is_daemon,
        announced_online: std::collections::HashSet::new(),
        daemon_awaiting_otp: None,
    };

    // Anything still in `~/.aloo/otp/.tmp/` is key material some earlier
    // run was still producing or still receiving when it stopped - a
    // superseded invitation, a dropped link, a kill, a power cut. It never
    // completed (completion is an atomic rename *out* of that directory),
    // so it is garbage by definition and is cleared here rather than left
    // to accumulate. See `client::otp_staging`'s module doc.
    crate::client::otp_staging::sweep(&session.otp_cli_cfg);

    let mut ui_state = UiState::new(display_name);
    // With no server there is nothing to join a channel *through*, so the
    // channels named in settings are simply the ones this client is in.
    // Seeded before the session starts so a `--focus channel:x` daemon
    // finds its channel already there, and so the first `ChannelPresence`
    // we send a peer is already correct.
    ui_state.serverless = server_state.is_serverless();
    // Fixed for the whole session: a `--no-server` start has no supervisor
    // and nothing it could ever reconnect to, so this is the one header
    // state that is never driven by an event.
    if server_state.is_serverless() {
        ui_state.set_server_link(ServerLinkState::NoServer);
        // The directory `/channels` and Ctrl+J browse: with no server the
        // configured channels are the only ones that exist, so they are
        // the whole of it.
        ui_state.known_channels = settings
            .direct_punch_channels
            .iter()
            .map(|name| proto::ChannelInfo {
                name: name.clone(),
                kind: proto::ChannelKind::Public,
            })
            .collect();
        for name in &settings.direct_punch_channels {
            crate::client::channel::on_joined(
                &mut ui_state,
                proto::ChannelInfo {
                    name: name.clone(),
                    kind: proto::ChannelKind::Public,
                },
            );
        }
    }
    ui_state.set_own_id(you);
    // What makes `/daemon` mean something: only a session with a
    // background to go back to can be handed back to it.
    ui_state.daemon_mode = is_daemon;
    ui_state.set_keyboard_release_reporting(keyboard_release_reporting);
    ui_state.set_muted_voice(settings.muted_voice.clone());
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

    // OTP mail (docs/PROTOCOL.md §17.3): a client with a local OTP
    // keychain immediately asks for everything the server holds for it -
    // pending mail addressed to this nickname, and delivery receipts for
    // mail it sent - then replays any upload whose storage acknowledgement
    // a previous session never saw. Skipped without the `otp` binary:
    // nothing could decrypt what a fetch would deliver.
    //
    // Also skipped with no server, since the server *is* the mailbox
    // (§7.1.5): the fetch would go nowhere and the resend would mark mail
    // as being uploaded to nothing, which is exactly the silent
    // half-finished state refusing at the point of intent exists to avoid.
    if !session.server.is_absent()
        && crate::client::otp_cli::binary_available(&session.otp_cli_cfg)
    {
        wr.send_control(&ClientMessage::OtpMailFetch).await?;
        session.conn_stats.record_event(Instant::now());
        crate::client::otp_mail::resend_pending(&mut wr, &mut session).await?;
    }

    // A serverless daemon never receives a `ChannelList` - nothing sends
    // one - so the joins its plan asks for have to be driven from here
    // instead, or `--channel` would be silently ignored on the one start
    // where nobody is watching to notice.
    if session.server.is_serverless() {
        request_daemon_joins(&mut wr, &mut ui_state, &mut session).await?;
    }

    surface.draw(|f| ui::render(f, &ui_state))?;

    loop {
        tokio::select! {
            input = input_rx.recv() => {
                let Some(input) = input else { break };
                match input {
                    SessionInput::Key(Event::Key(key)) => {
                        // Only ever reached from a terminal this process
                        // owns: the attach client answers Ctrl+C itself
                        // by detaching, so a viewer can never kill the
                        // daemon's session by quitting its own window.
                        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                            break;
                        }
                        if let Some(action) = ui_state.handle_key(key.code, key.modifiers, key.kind) {
                            // `Detach` acts on the surface, which this
                            // loop owns and `handle_ui_action` does not -
                            // so it is answered here rather than threaded
                            // down into a function about network sends.
                            if matches!(action, UiAction::Detach) {
                                session.viewer_attached = false;
                                surface.detach();
                            } else {
                                handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                            }
                        }
                    }
                    // The terminal this process owns changed size. Its
                    // attached counterpart is `SessionInput::Resized`
                    // below, and both land in the same place: the frame
                    // drawn at the bottom of this iteration repaints
                    // every cell for the new dimensions
                    // (`Surface::resize`).
                    SessionInput::Key(Event::Resize(cols, rows)) => {
                        surface.resize(crate::client::tui::surface::TerminalSize::new(cols, rows))?;
                    }
                    SessionInput::Key(_) => {}
                    SessionInput::Attached { writer, size } => {
                        session.viewer_attached = true;
                        surface.attach(writer, size)?;
                    }
                    SessionInput::Resized(size) => {
                        surface.resize(size)?;
                    }
                    SessionInput::Detach => {
                        session.viewer_attached = false;
                        surface.detach();
                    }
                    SessionInput::Shutdown => break,
                }
            }
            event = server_events.recv() => {
                // `None` means the supervisor task itself is gone, which
                // it only ever is once this session has dropped its own
                // sender - and a `--no-server` session holds that sender
                // open forever, so this branch never fires for one.
                let Some(event) = event else { break };
                handle_server_event(event, &mut ui_state, &mut wr, &mut session).await?;
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
                // A rotation for a peer the server has never named cannot
                // be relayed by it, and with no server at all none can.
                // The link is already authenticated and the rotation
                // carries its own signature, so it rides the link instead
                // - the alternative is forward secrecy silently stopping
                // (§13.10) for precisely the peers §7.1.5 exists for.
                if let ClientMessage::RotateKey {
                    to,
                    new_public_key_der,
                    signature,
                } = &msg
                    && (session.server.is_absent() || p2p::is_direct_peer_id(*to))
                {
                    session.peer_link.send_reliable_or_queue(
                        *to,
                        P2pPayload::KeyRotation {
                            rotation: new_public_key_der.clone(),
                            signature: signature.clone(),
                        },
                    );
                    continue;
                }
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
                        voice_stream::OwnStreamTarget::MailAttachment => {
                            // Nothing was sent anywhere - the finished
                            // recording either joins the mail being
                            // composed or, if it outgrew the remaining key
                            // meanwhile (or the compose view is gone), the
                            // operation is cancelled outright.
                            let compose_open = ui_state.otp_mail.is_some();
                            if !ui_state.otp_mail_add_voice(duration_ms, pcm) && compose_open {
                                ui_state.push_status_notice(
                                    "OTP mail: recording is larger than the remaining key - cancelled".to_string(),
                                    false,
                                );
                            }
                        }
                    }
                }
            }
            event = otp_pad_rx.recv() => {
                let Some(event) = event else { break };
                crate::client::otp::on_pad_event(&mut wr, &mut session, &mut ui_state, event).await?;
            }
            event = otp_keygen_rx.recv() => {
                let Some(event) = event else { break };
                crate::client::otp::on_keygen_event(&mut wr, &mut session, &mut ui_state, event).await?;
            }
            finished = stream_finished_rx.recv() => {
                let Some((from, stream_id, duration_ms, pcm)) = finished else { break };
                if let Some(active) = session.active_streams.remove(&(from, stream_id)) {
                    // Best-effort re-check of what `on_stream_start`
                    // snapshotted - skips the "message ended" chime for a
                    // sender who was never heard, whether that was the
                    // trust gate or a `/mute-voice` (a chime announcing
                    // audio that never played is just noise). Not threaded
                    // through `ActiveStream`, so a state newly changed
                    // mid-stream (rare) could still chime for suppressed
                    // audio - a harmless UX quirk, not a correctness issue.
                    let was_heard = !ui_state.suppress_playback_from(from);
                    // Decrypted audio, not merely a stream that ended: a
                    // stream whose every chunk failed to open accumulates
                    // nothing, and must not be receipted (7.2.1).
                    let decrypted = !pcm.is_empty();
                    let msg_id = session.pending_receipts.msg_id_of(from, stream_id);
                    // Recorded against the placeholder row while it can
                    // still be found by `stream_id` - finalizing below
                    // replaces that body with one that no longer carries
                    // it.
                    if decrypted && !was_heard {
                        ui_state.owe_replay_receipt(from, stream_id, msg_id);
                    }
                    match active.channel {
                        Some(channel) => crate::client::channel::on_stream_finished(&mut ui_state, &channel, from, stream_id, duration_ms, pcm),
                        None => crate::client::direct_message::on_stream_finished(&mut ui_state, from, stream_id, duration_ms, pcm),
                    }
                    if decrypted {
                        send_delivery_receipt(&mut session, from, msg_id, ReceiptStage::Decrypted);
                    }
                    // Heard on arrival is the common case and settles it
                    // here. A stream that decoded nothing is forgotten;
                    // one that decoded but was suppressed (muted, or a
                    // sender still under identity review) keeps its debt,
                    // to be paid if and when the user replays the row
                    // (`UiAction::ReplayVoice`).
                    if !decrypted || was_heard {
                        settle_delivery_id(&mut session, from, stream_id, decrypted && was_heard);
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
            level = call_level_rx.recv() => {
                let Some((peer, level)) = level else { break };
                ui_state.set_call_level(peer, level);
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
                // Liveness is a claim made *to a server* (§4.1). With none
                // there is nobody it could reassure.
                if !session.server.is_absent() {
                    wr.send_control(&ClientMessage::Heartbeat).await?;
                }
            }
            _ = ticker.tick() => {
                tick_count = tick_count.wrapping_add(1);
                if tick_count % 4 == 0 {
                    ui_state.toggle_blink();
                }
                // Independent of any progress report: a spinner that only
                // moved when bytes landed would stall exactly when the user
                // most needs to see the app is still alive (a slow disk, a
                // subprocess still starting up).
                ui_state.tick_otp_keygen_spinner();
                // Republish each in-flight pad transfer's link depth for
                // its worker thread to pace against - the worker cannot
                // reach into `peer_link` itself (`otp_pad::OutgoingPad`'s
                // `depth` doc).
                for (peer, pad) in &session.otp_outgoing_pads {
                    pad.depth.store(
                        session.peer_link.outbound_depth(*peer),
                        std::sync::atomic::Ordering::Relaxed,
                    );
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
                // The header's reconnect countdown, recomputed from the
                // supervisor's deadline on every redraw rather than pushed
                // up the event channel once a second - the number on screen
                // is then never a stale copy of one.
                if let Some((until, failed_attempts)) = session.server_retry {
                    ui_state.set_server_link(ServerLinkState::waiting(
                        failed_attempts,
                        crate::client::reconnect::seconds_left(now, until),
                    ));
                }
                // The call modal's duration readout (`docs/SPEC.md` "Live
                // voice calls") is refreshed on every tick rather than
                // once a second: the readout itself only changes at
                // one-second granularity, and refreshing at the redraw
                // cadence is what keeps it from lagging a whole second
                // behind the wall clock it is counting.
                ui_state.tick_call_duration(now);
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
                if let Some(action) = ui_state.tick_recording_timeout(Instant::now()) {
                    handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                }
                ui_state.tick_status_notice(Instant::now());
                ui_state.tick_selector_dropdown(Instant::now());
                sweep_idle_streams(&mut ui_state, &mut session, Instant::now());
                session.peer_link.tick_with_clock(crate::client::p2p::utc_second_of_hour());
            }
            Some((nickname, addr)) = direct_resolved_rx.recv() => {
                session.peer_link.on_direct_resolved(&nickname, addr);
            }
        }
        surface.draw(|f| ui::render(f, &ui_state))?;
    }

    Ok(())
}

/// Sends on the control channel only when there is a server able to
/// receive it, and reports success either way.
///
/// A session that has lost its server but kept its direct links alive
/// (`ServerState::Unreachable`) still reaches code that would write to it -
/// a re-signal, a channel departure. Writing to a dead socket errors, and
/// every one of those call sites propagates with `?`, so without this the
/// first such attempt would end the very session this is keeping alive.
pub(crate) async fn send_if_server(
    session: &SessionState,
    wr: &mut impl crate::control::ControlSink,
    msg: &ClientMessage,
) -> proto::Result<()> {
    if session.server.is_absent() {
        return Ok(());
    }
    wr.send_control(msg).await
}

async fn handle_ui_action(
    action: UiAction,
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
) -> proto::Result<()> {
    // Refused here, before anything acts on it, rather than left to vanish
    // into a control channel with no server behind it. A dropped message
    // is indistinguishable from the app ignoring you: the join popup would
    // close and no channel would ever appear, and a mail would sit
    // "sending" against a result that cannot arrive. One check, at the one
    // place every action passes through, so no call site can forget it.
    if let Some(what) = action.needs_server()
        && session.server.is_absent()
    {
        // Joining is the one refusal with a local answer: with no server a
        // channel is just a name both sides declare, so joining one that
        // *is* declared needs nobody's permission. Only a name nothing
        // configured is genuinely impossible.
        if let UiAction::JoinChannel { name, .. } = &action
            && session.server.is_serverless()
        {
            if ui_state.known_channels.iter().any(|c| c.name == *name) {
                crate::client::channel::on_joined(
                    ui_state,
                    proto::ChannelInfo {
                        name: name.clone(),
                        kind: proto::ChannelKind::Public,
                    },
                );
                broadcast_channel_presence(session, ui_state);
                return Ok(());
            }
            ui_state.push_status_notice(
                format!(
                    "{name:?} is not a direct_punch_channel - without a server,                      only channels named in ~/.aloo/settings exist"
                ),
                false,
            );
            return Ok(());
        }
        ui_state.push_status_notice(session.server.refusal(what), false);
        return Ok(());
    }
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
            msg_id,
        } => {
            crate::client::channel::handle_send_text(
                wr, ui_state, session, channel, plaintext, recipients, msg_id,
            )
            .await?;
        }
        UiAction::SendDirectText {
            to,
            plaintext,
            recipient_key_mode,
            recipient_pubkey_der,
            log_index,
            msg_id,
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
                msg_id,
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
                        VoiceTarget::MailAttachment => {
                            // Accumulate-only, addressed to nobody: the
                            // same worker an OTP DM recording uses, with
                            // the finished PCM routed to the compose form
                            // instead of any wire send.
                            let (stop_tx, stop_rx) = std::sync::mpsc::channel();
                            session.active_recording = Some(stop_tx);
                            session.own_stream_targets.insert(
                                stream_id,
                                voice_stream::OwnStreamTarget::MailAttachment,
                            );
                            voice_stream::spawn_record_accumulate_worker(
                                recorder,
                                stream_id,
                                session.own_stream_done_tx.clone(),
                                stop_rx,
                                session.auto_stop_tx.clone(),
                            );
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
        UiAction::ReplayVoice {
            pcm,
            from,
            owed_receipt,
            ..
        } => {
            let samples = voice::pcm_from_bytes(&pcm);
            if !samples.is_empty() {
                let id = session.next_mixer_id;
                session.next_mixer_id += 1;
                session.active_replay_id = Some(id);
                let _ = session.mixer_tx.send(voice::MixerCmd::Push { id, samples });
                let _ = session.mixer_tx.send(voice::MixerCmd::Finish { id });
                // A clip that was muted when it arrived is heard for the
                // first time now, and its sender is owed that news
                // (docs/PROTOCOL.md 7.2.1). `None` whenever nothing is
                // owed, which is the ordinary case.
                send_delivery_receipt(session, from, owed_receipt, ReceiptStage::Consumed);
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
                if let Some(key_mode) = ui_state.known_users.get(&peer).map(|u| u.key_mode) {
                    session.id_store.set_key_mode(&review.nickname, key_mode);
                }
                // The address/device id this connection was actually
                // reviewed under (docs/PROTOCOL.md §12.7) - known by now,
                // since the review was only ever revealed once punching
                // resolved (`reveal_pending_identity_review`). Recorded
                // against the freshly re-pinned key so the *next* mismatch
                // for this nickname has something other than "unknown" to
                // compare against.
                if let (Some(addr), Some(device_id)) = (
                    session.peer_link.active_addr(peer),
                    session.peer_device_ids.get(&peer).cloned(),
                ) {
                    session
                        .id_store
                        .set_last_seen(&review.nickname, addr, &device_id);
                }
                if let Err(e) = session.id_store.save() {
                    crate::log_warn!("failed to save id_store: {e}");
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
            // Snapshotted so a refusal raised by *this* call can be told
            // apart from a notice that was already on screen.
            let notice_before = ui_state.status_notice.clone();
            crate::client::otp::handle_otp_command(wr, ui_state, session, peer, key_mode, pubkey_der)
                .await?;
            // `handle_otp_command` refuses some proposals outright -
            // neither side `pq_hybrid`, no `otp` binary, an unreadable
            // peer identity - and those never reach the peer at all, so
            // no acknowledgement will ever arrive to resolve them. A new
            // failure notice is exactly that case; anything else is a
            // proposal genuinely in flight, resolved by
            // `on_key_setup_ack` when the peer answers.
            let refused = ui_state.status_notice != notice_before
                && matches!(&ui_state.status_notice, Some((_, false)));
            if refused && !ui_state.is_otp_active(peer) {
                let reason = ui_state
                    .status_notice
                    .as_ref()
                    .map(|(text, _)| text.clone())
                    .unwrap_or_default();
                daemon_otp_outcome(ui_state, session, peer, false, &reason);
            }
        }
        UiAction::ConfirmOtpGenerate { size_mb } => {
            crate::client::otp::confirm_generate(session, ui_state, size_mb).await?;
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
        UiAction::EndOtpSession {
            peer,
            key_mode,
            pubkey_der,
        } => {
            crate::client::otp::handle_end_otp_command(wr, ui_state, session, peer, key_mode, pubkey_der)
                .await?;
        }
        UiAction::CheckOtpMailRecipient { nickname } => {
            crate::client::otp_mail::handle_check_recipient(session, ui_state, nickname).await;
        }
        UiAction::OpenOtpMailbox => {
            crate::client::otp_mail::handle_open_mailbox(session, ui_state);
        }
        UiAction::SendOtpMail => {
            crate::client::otp_mail::handle_send(wr, session, ui_state).await?;
        }
        UiAction::ReadOtpMail { mail_id } => {
            crate::client::otp_mail::handle_read(session, ui_state, mail_id);
        }
        UiAction::DeleteOtpMail { mail_id } => {
            crate::client::otp_mail::handle_delete(session, ui_state, mail_id);
        }
        UiAction::SaveOtpMailAttachment { index } => {
            crate::client::otp_mail::handle_save_attachment(ui_state, index);
        }
        UiAction::StartCall(target) => match target {
            ui::CallTarget::Channel { channel } => {
                crate::client::channel::handle_start_call(wr, ui_state, session, channel).await?;
            }
            ui::CallTarget::Direct {
                to,
                recipient_key_mode,
                recipient_pubkey_der,
            } => {
                crate::client::direct_message::handle_start_call(
                    wr,
                    ui_state,
                    session,
                    to,
                    recipient_key_mode,
                    recipient_pubkey_der,
                )
                .await?;
            }
        },
        UiAction::AcceptCallInvite { call_id } => {
            voice_call::accept_invite(wr, session, ui_state, call_id).await?;
        }
        UiAction::RejectCallInvite { call_id } => {
            voice_call::reject_invite(wr, session, ui_state, call_id).await?;
        }
        UiAction::ToggleCallMute => {
            voice_call::toggle_mute(wr, session, ui_state).await?;
        }
        UiAction::EndCall => {
            voice_call::end_own_call(wr, session, ui_state).await?;
        }
        UiAction::InviteToCall { to } => {
            voice_call::invite_to_call(wr, session, ui_state, to).await?;
        }
        UiAction::HostMuteCallMember { peer, muted } => {
            voice_call::host_set_muted(wr, session, ui_state, peer, muted).await?;
        }
        UiAction::SetVoiceMuted { nickname, muted } => {
            set_voice_muted(ui_state, &nickname, muted);
        }
        UiAction::OpenContacts | UiAction::RefreshContacts => {
            crate::client::contacts::handle_open(session, ui_state).await;
        }
        UiAction::DeleteContact { nickname } => {
            crate::client::contacts::handle_delete(session, ui_state, nickname).await;
        }
        UiAction::InstallOtpKey {
            nickname,
            enc_path,
            dec_path,
        } => {
            crate::client::contacts::handle_install_otp_key(
                session, ui_state, nickname, enc_path, dec_path,
            )
            .await;
        }
        UiAction::Detach => {
            // Intercepted by `run_connected_session`'s input arm, which
            // owns the `Surface` this acts on. A no-op rather than an
            // `unreachable!` so a future call path that routes one through
            // here degrades to "nothing happened" instead of aborting a
            // live session over a UI command.
        }
    }
    Ok(())
}

/// Persists a `/mute-voice` / `/unmute-voice` decision to
/// `~/.aloo/settings` and mirrors back whatever actually landed there
/// (docs/SPEC.md Functionality #15).
///
/// Goes through `Settings::update_muted_voice`, never a plain `save` - see
/// that function's doc: this file is now written *during* a session, and
/// serializing this process's whole in-memory `Settings` would let a mute
/// silently revert server settings a concurrently started `aloo --server`
/// had just recorded.
///
/// A write failure leaves the in-memory set as `UiState` already applied
/// it (so the mute works for this session) and says so, rather than
/// refusing the mute over a preferences-file problem - the same policy
/// `load_id_store` applies to its own store.
fn set_voice_muted(ui_state: &mut UiState, nickname: &str, muted: bool) {
    let result = crate::settings::Settings::update_muted_voice(
        &crate::settings::default_path(),
        |set| {
            if muted {
                set.insert(nickname.to_string());
            } else {
                set.remove(nickname);
            }
        },
    );
    match result {
        Ok(stored) => ui_state.set_muted_voice(stored),
        Err(e) => ui_state.push_status_notice(
            format!("muted for this session only - could not write ~/.aloo/settings ({e})"),
            false,
        ),
    }
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
/// One event from the reconnect supervisor (`crate::client::reconnect`):
/// either a message the server sent, or a change in whether there is a
/// server to send one.
async fn handle_server_event(
    event: ServerEvent,
    ui_state: &mut UiState,
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
) -> proto::Result<()> {
    match event {
        ServerEvent::Message(msg) => {
            if let Some(action) = handle_server_message(*msg, ui_state, wr, session).await? {
                handle_ui_action(action, wr, ui_state, session).await?;
            }
        }
        // The server is gone, but the session is not: direct links are
        // punched peer-to-peer and neither know nor care that it went away,
        // so tearing the session down would disconnect the very peers it
        // did not affect. Anything needing a server is refused from here
        // on, described as temporary (`ServerState::Unreachable`) - which
        // it now genuinely is, because something is already retrying.
        ServerEvent::Lost => {
            session.server = ServerState::Unreachable;
            session.server_retry = None;
            ui_state.set_server_link(ServerLinkState::Reconnecting);
            ui_state.push_status_notice(
                "the server connection was lost - direct links are unaffected".to_string(),
                false,
            );
        }
        ServerEvent::Attempting => {
            session.server_retry = None;
            ui_state.set_server_link(ServerLinkState::Reconnecting);
        }
        ServerEvent::Waiting {
            until,
            failed_attempts,
            reason,
        } => {
            session.server_retry = Some((until, failed_attempts));
            ui_state.set_server_link(ServerLinkState::waiting(
                failed_attempts,
                crate::client::reconnect::seconds_left(Instant::now(), until),
            ));
            // Once, on the first failure. The header carries the state
            // from here on, and a notice per attempt would bury everything
            // else the log has to say for as long as the server is away.
            if failed_attempts == 1 {
                ui_state.push_status_notice(
                    format!("the server is not answering ({reason}) - still trying"),
                    false,
                );
            }
        }
        ServerEvent::Reconnected { you } => {
            on_server_reconnected(you, ui_state, wr, session).await?;
        }
    }
    Ok(())
}

/// Back on the server, as a brand-new `UserId` (TB-020).
///
/// Everything the old connection said about other people is dropped before
/// anything the new one says is applied: those `UserId`s were that
/// connection's to hand out, and a peer who reconnected in the meantime is
/// now a different one - as is anyone at all, if the server itself
/// restarted and began handing ids out from the start again. Nobody is
/// marked *offline* by this: they did not go anywhere, and this client
/// simply no longer knows who is there. Whoever is still around comes
/// straight back in the membership snapshot the re-joins below ask for, so
/// the cost of being thorough here is at most one re-punch of a link that
/// was already fine, and the cost of not being is a sidebar full of people
/// who are not there.
async fn on_server_reconnected(
    you: UserId,
    ui_state: &mut UiState,
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
) -> proto::Result<()> {
    session.server = ServerState::Connected;
    session.server_retry = None;
    ui_state.set_server_link(ServerLinkState::Connected);

    let stale: Vec<UserId> = ui_state
        .known_users
        .keys()
        .copied()
        // A direct peer is named by its own identity rather than by
        // anything the server handed out (§7.1.5), so no server coming or
        // going has any bearing on it.
        .filter(|id| !p2p::is_direct_peer_id(*id))
        .collect();
    for id in stale {
        drop_peer_state(ui_state, session, id);
    }
    ui_state.forget_server_presence();
    ui_state.set_own_id(you);

    // Walk back into the same channels. Without this a reconnect would be
    // silent in exactly the way that started all this: messages still
    // arriving over the direct links, and this client in nobody's member
    // list - including the member lists of people who connect later.
    let rejoin: Vec<(String, proto::ChannelKind)> = ui_state
        .channels
        .iter()
        .filter(|c| c.joined)
        .map(|c| (c.name.clone(), c.kind))
        .collect();
    for (name, kind) in rejoin {
        let password = session.channel_passwords.get(&name).cloned();
        crate::client::channel::handle_join(wr, session, name, kind, password).await?;
    }

    // The same mailbox catch-up a fresh connection does (§17.3) - a
    // reconnect is a fresh connection in every way that matters to the
    // server, including having missed whatever arrived while it was away.
    if crate::client::otp_cli::binary_available(&session.otp_cli_cfg) {
        wr.send_control(&ClientMessage::OtpMailFetch).await?;
        session.conn_stats.record_event(Instant::now());
        crate::client::otp_mail::resend_pending(wr, session).await?;
    }

    ui_state.push_status_notice("reconnected to the server".to_string(), true);
    Ok(())
}

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
            // A daemon joins exactly what it was configured to join, and
            // never `the-hall` unless that was one of them - the whole
            // point of the mode is to be where the user actually wants
            // their voice to land. `on_list`'s auto-join is skipped
            // entirely rather than joined-then-left, which would show up
            // to everyone in the hall as a connect/disconnect flicker.
            if session.daemon_plan.is_some() {
                ui_state.on_channel_list(list);
                request_daemon_joins(wr, ui_state, session).await?;
            } else if let Some(action) = crate::client::channel::on_list(ui_state, list) {
                return Ok(Some(action));
            }
        }
        ServerMessage::Joined { channel } => {
            let name = channel.name.clone();
            crate::client::channel::on_joined(ui_state, channel);
            apply_daemon_channel_focus(ui_state, session, &name);
            broadcast_channel_presence(session, ui_state);
        }
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
                // A peer who already has a provisioned OTP contact - an
                // active session from before they disconnected, or from an
                // earlier run of this app - reconnects under a fresh
                // `UserId`. Re-derive the UI-facing "active" flag for it
                // here, the same way `contact_name_if_active` already
                // re-derives the real send-path gate fresh from
                // `peer_pubkey_der` on every send. Without this, the
                // pad marker/header/call-blocking would wrongly show "inactive"
                // the moment a still-live session's peer reconnects, even
                // though nothing about the session itself ended - only
                // `/endotp` may do that (`docs/PROTOCOL.md` §16.6).
                if let Some(contact_name) =
                    crate::client::otp::contact_name_if_active(session, &user.public_key_der)
                {
                    ui_state.mark_otp_active(user.id);
                    crate::client::otp::refresh_otp_key_status(
                        &session.otp_cli_cfg,
                        ui_state,
                        user.id,
                        &contact_name,
                    )
                    .await;
                }
            }
            // Start punching a direct link the moment we learn this peer
            // exists rather than at first send (§7.1): voice is never
            // queued, so a link still `Punching` when someone starts
            // recording excludes that recipient outright. The gap between
            // learning about a channel-mate and pressing Space is normally
            // far longer than the handshake needs.
            //
            // Deliberately *outside* the `known_users` check above, unlike
            // the identity pin: `known_users` is never removed from, but
            // `UserOffline` does `peer_link.forget` them. Gating this on
            // "first time we've seen this UserId" therefore left a peer who
            // reconnected after any blip - including a heartbeat timeout on
            // a slow link (§4.1) - with no link and nothing to re-arm it,
            // showing as a permanently `Connecting` (yellow) name while
            // nothing was actually being punched. Harmless unconditionally:
            // `ensure_link` is a no-op on an existing link, and failure
            // stays silent until something is actually queued against them.
            // A `direct_punch_to` peer who is also on this server is one
            // person, and must end up with one link: filing their direct
            // target under the id the server just named is what makes the
            // two routes converge on a single `PeerLink` (§7.1.5 step 6)
            // instead of one per route.
            if let Some(stale) = session
                .peer_link
                .set_direct_peer_id(&user.name, Some(user.id))
            {
                // Their link was already up under the settings-file
                // identity and has just moved onto the one the server
                // named; the row it used to colour is nobody now.
                ui_state.forget_link_status(stale);
            }
            session.peer_link.ensure_link(wr, user.id).await;
            let joined_id = user.id;
            let joined_name = user.name.clone();
            ui_state.on_user_joined(&channel, user);
            if let Some(action) =
                on_daemon_peer_appeared(ui_state, session, joined_id, &joined_name, Some(&channel))
            {
                return Ok(Some(action));
            }
        }
        ServerMessage::UserLeft { channel, user_id } => {
            notify_daemon_presence(ui_state, session, user_id, Some(&channel), "left");
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
            forget_peer(ui_state, session, user_id);
        }
        ServerMessage::KeyRotated {
            from,
            new_public_key_der,
            signature,
        } => {
            // Only `pq_hybrid` peers ever rotate, so this is always their
            // encryption-key offer (§13.10).
            let (to_send, given_up) =
                handle_pq_key_rotated(ui_state, session, from, new_public_key_der, signature);
            flush_queued_outbound(wr, ui_state, session, from, to_send, given_up).await?;
        }
        ServerMessage::PeerCandidates {
            from,
            candidates,
            link_nonce,
        } => {
            // Trust boundary (docs/PROTOCOL.md §7.1.2): the server's relay
            // performs no relationship checking of its own - any registered
            // client can name any other UserId as `peer`. Only respond to a
            // request from someone we still have a reason to reach - a
            // shared joined channel, or DM history with them; a stranger's
            // request is dropped before any PeerLink state is touched at all.
            //
            // Deliberately the same bar §7.1.3 uses to decide whether to
            // *keep* a link, rather than the narrower shared-channel check:
            // the two must agree, or a DM that outlives every shared channel
            // ends up in a state both sides keep retrying forever while each
            // silently drops the other's candidate exchange. That survives
            // only on cached addresses - the moment either side's address
            // actually changes, which is exactly when signalling is what
            // recovers a link, the DM can never be re-punched again.
            if ui_state.has_reason_to_keep_link(from) {
                session
                    .peer_link
                    .on_peer_candidates(wr, from, candidates, link_nonce)
                    .await;
            } else {
            }
        }
        ServerMessage::Error { message } => crate::log_warn!("server error: {message}"),
        ServerMessage::OtpMailResult { mail_id, ok, reason } => {
            crate::client::otp_mail::on_mail_result(wr, session, ui_state, mail_id, ok, reason)
                .await?;
        }
        ServerMessage::OtpMailDeliver {
            mail_id,
            from,
            contact_name,
            seq,
            sent_at_utc: _,
            ciphertext,
        } => {
            // The wire-level sent_at is unauthenticated routing metadata;
            // the one the mail displays comes from inside the signed
            // payload (`client::otp_mail::on_mail_deliver`).
            crate::client::otp_mail::on_mail_deliver(
                wr, session, ui_state, mail_id, from, contact_name, seq, ciphertext,
            )
            .await?;
        }
        ServerMessage::OtpMailDelivered { mail_id } => {
            crate::client::otp_mail::on_mail_delivered(wr, session, ui_state, mail_id).await?;
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------
// Daemon plan hooks (docs/SPEC.md "Running in background mode")
//
// Every one of these is a no-op without a plan, which is what keeps
// daemon mode from changing what an ordinary client does.
// ---------------------------------------------------------------------

/// Sends one `JoinChannel` per configured channel, once, on the first
/// channel directory the server sends.
///
/// Once, not on every `ChannelList`: a client also receives one when a
/// channel is created later in the session, and re-requesting the joins
/// then would fight whatever the user has since done from an attached
/// terminal.
async fn request_daemon_joins(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
) -> proto::Result<()> {
    let Some(plan) = session.daemon_plan.as_mut() else {
        return Ok(());
    };
    if plan.joins_requested {
        return Ok(());
    }
    plan.joins_requested = true;
    let channels = plan.channels.clone();
    for channel in channels {
        // `Public` is the kind to *create* it with if it doesn't exist -
        // an existing channel keeps whatever kind it already has
        // (docs/PROTOCOL.md §6.1), so this never converts one. A private
        // channel joined by name with its password works identically.
        // Through the ordinary action path rather than straight into
        // `handle_join`: that is where the "can this happen at all" check
        // lives, and a daemon start is exactly when nobody is watching to
        // notice a join that quietly went nowhere. With no server it turns
        // into a local join for a configured channel, and a named refusal
        // for anything else.
        handle_ui_action(
            UiAction::JoinChannel {
                name: channel.name.clone(),
                kind: proto::ChannelKind::Public,
                password: channel.password.clone(),
            },
            wr,
            ui_state,
            session,
        )
        .await?;
    }
    Ok(())
}

/// Selects the focused channel's tab once its join is confirmed.
///
/// Only the first time. After that the focus belongs to whoever is
/// driving: someone who attached and moved to another tab must not have
/// it yanked back by a peer rejoining.
fn apply_daemon_channel_focus(ui_state: &mut UiState, session: &mut SessionState, joined: &str) {
    let Some(plan) = session.daemon_plan.as_mut() else {
        return;
    };
    if !plan.should_place_focus() || plan.focused_channel() != Some(joined) {
        return;
    }
    if let Some(index) = ui_state.channels.iter().position(|c| c.name == joined) {
        ui_state.selected_channel = index;
        // A daemon's focus is a channel, not a DM - so any private room
        // left open from a previous attach must not keep intercepting the
        // push-to-talk target (`current_voice_target` checks it first).
        ui_state.active_private_room = None;
        plan.focus_applied = true;
    }
}

/// Handles a peer appearing while a daemon plan is in effect: the focus
/// sound, the desktop notification, and - for a DM focus - opening the
/// room and, if asked, proposing an OTP session.
///
/// Returns the OTP request as an action rather than performing it, so the
/// caller drives it through the same `handle_ui_action` path `/otp` uses;
/// there is exactly one implementation of "propose an OTP session".
fn on_daemon_peer_appeared(
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
    nickname: &str,
    // `None` for a peer reached with no server and sharing no channel
    // (§7.1.5): there is no channel they can be said to have arrived in,
    // but they have still arrived, and a DM focus is about the person.
    channel: Option<&str>,
) -> Option<UiAction> {
    // Daemon mode at all, or there is nothing here to do.
    session.daemon_plan.as_ref()?;

    // The sound is decided against the *live* focus, so it is evaluated
    // before anything that gates on the plan's `--focus` - the two differ
    // exactly when someone has attached and moved, which is the case this
    // rule exists for. See `DaemonPlan::should_play_joined_chime`.
    let announce = crate::client::daemon::DaemonPlan::should_play_joined_chime(
        true,
        session.viewer_attached,
        &ui_state.current_focus(),
        peer,
        channel,
        session.announced_online.contains(&peer),
    );
    // Recorded whether or not it was announced: what makes "alice is
    // online" one event is her being online, not our having made a noise
    // about it (we may have been attached at the time, or pointed
    // elsewhere).
    session.announced_online.insert(peer);
    if announce {
        crate::client::voice_stream::play_joined_chime(session);
    }

    // Everything from here is about the focus the daemon was *started*
    // with: placing it the first time, and the OTP session that goes with
    // it. A peer who is not what this daemon was told to watch for is of
    // no further interest - the sound above has already had its say.
    let plan = session.daemon_plan.as_ref()?;
    if !plan.is_focus_event(nickname, channel) {
        return None;
    }
    let is_dm_focus = plan.focused_nickname() == Some(nickname);
    // Both decided before anything below mutates the plan - see
    // `DaemonPlan::should_place_focus` and `should_invite_otp`.
    let place_focus = is_dm_focus && plan.should_place_focus();
    let invite_otp = plan.should_invite_otp(nickname, ui_state.is_otp_active(peer));

    // Silent, so it keeps the broader rule on purpose: it costs nothing
    // to have seen later, and its siblings also cover leaving and
    // disconnecting, which the sound deliberately does not.
    crate::client::global_notification::notify(crate::client::global_notification::Notification::new(
        format!("{nickname} is here"),
        if is_dm_focus {
            "Hold the push-to-talk shortcut to talk to them.".to_string()
        } else {
            match channel {
                Some(channel) => format!("Joined {channel}."),
                None => "Reachable directly.".to_string(),
            }
        },
    ));

    if place_focus {
        // Open their room, so the global shortcut addresses them rather
        // than the channel they happened to be discovered in. Once only -
        // see `should_place_focus`: after this, where the focus sits
        // belongs to whoever is driving the session, not to the flag it
        // was started with.
        let Some(info) = ui_state.known_users.get(&peer).cloned() else {
            return None;
        };
        ui_state.open_private_room(info);
        if let Some(plan) = session.daemon_plan.as_mut() {
            plan.focus_applied = true;
        }
    }

    // The `UserJoined` arm above has already resumed any still-live
    // session (`mark_otp_active`), which is exactly what makes the
    // already-active case reachable here.
    if invite_otp {
        if let Some(plan) = session.daemon_plan.as_mut() {
            plan.otp_requested = true;
        }
        let info = ui_state.known_users.get(&peer)?.clone();
        // Marks this as the *daemon's* proposal, so its outcome is
        // announced out loud (`daemon_otp_outcome`). A `/otp` someone
        // typed is not marked, and stays silent - they can see it.
        session.daemon_awaiting_otp = Some(peer);
        return Some(UiAction::RequestOtpSession {
            peer,
            key_mode: info.key_mode,
            pubkey_der: info.public_key_der,
        });
    }
    None
}

/// Reports the outcome of an OTP session the *daemon* proposed
/// (docs/SPEC.md "Running in background mode").
///
/// A failure here is the one thing a `--otp` daemon cannot recover from
/// on its own: the peer is online, the focus is on them, and the shortcut
/// is ready - but what it would send is no longer pad-protected, which is
/// precisely what `--otp` was asked for. So it makes a noise. `bell.wav`,
/// the app's existing "something needs you" sound, rather than a new one:
/// this is the same class of event as an incoming file offer.
///
/// Success is silent. The daemon carrying on exactly as instructed is not
/// news.
pub(crate) fn daemon_otp_outcome(
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
    started: bool,
    reason: &str,
) {
    if session.daemon_awaiting_otp != Some(peer) {
        return;
    }
    session.daemon_awaiting_otp = None;
    if started {
        return;
    }
    crate::client::voice_stream::play_bell_chime(session);
    let name = ui_state
        .known_users
        .get(&peer)
        .map(|u| u.name.clone())
        .unwrap_or_default();
    crate::client::global_notification::notify(
        crate::client::global_notification::Notification::new(
            format!("No OTP session with {name}"),
            format!("{reason} Your voice would not be pad-protected."),
        ),
    );
}

/// Notifies that a focused peer has gone - left the focused channel, or
/// disconnected entirely.
///
/// Notification only, no sound: the spec asks for a sound when someone
/// *arrives* (that is the actionable event - you can talk to them now) and
/// for a notification either way.
fn notify_daemon_presence(
    ui_state: &UiState,
    session: &SessionState,
    peer: UserId,
    channel: Option<&str>,
    what: &str,
) {
    let Some(plan) = session.daemon_plan.as_ref() else {
        return;
    };
    let Some(info) = ui_state.known_users.get(&peer) else {
        return;
    };
    // `UserOffline` names no channel (docs/PROTOCOL.md §6.4) - it means
    // "this identity is gone", so for a channel focus it counts wherever
    // they were.
    let relevant = match channel {
        Some(channel) => plan.is_focus_event(&info.name, Some(channel)),
        None => plan.focused_nickname() == Some(info.name.as_str())
            || plan.focused_channel().is_some(),
    };
    if !relevant {
        return;
    }
    crate::client::global_notification::notify(crate::client::global_notification::Notification::new(
        format!("{} {what}", info.name),
        match channel {
            Some(channel) => format!("No longer in {channel}."),
            None => "They are offline.".to_string(),
        },
    ));
}

/// Everything that ends when one peer's connection does, in one place:
/// their presence, their direct link, their rotating keys, and any
/// half-arrived pad from them.
///
/// Called from `ServerMessage::UserOffline` for one peer, and from
/// `on_server_reconnected` for all of them at once - a reconnect makes
/// every `UserId` the previous connection handed out meaningless in
/// exactly the way one `UserOffline` makes a single one meaningless
/// (`docs/PROTOCOL.md` §4.2).
fn forget_peer(ui_state: &mut UiState, session: &mut SessionState, user_id: UserId) {
    // Read before `on_user_offline`, which is what would make the
    // nickname unresolvable if it ever stopped keeping them.
    notify_daemon_presence(ui_state, session, user_id, None, "disconnected");
    ui_state.on_user_offline(user_id);
    drop_peer_state(ui_state, session, user_id);
}

/// The half of `forget_peer` that is not about presence: the direct link,
/// the keys, and anything half-arrived from them.
///
/// Split out for a reconnect, which ends every relationship the previous
/// connection's `UserId`s named without any of them having *gone offline* -
/// nobody disconnected, this client did. Saying otherwise would log a
/// departure notice for each of them and, on a daemon, notify about it.
fn drop_peer_state(ui_state: &mut UiState, session: &mut SessionState, user_id: UserId) {
    // Their next arrival is a fresh "they are online" event.
    session.announced_online.remove(&user_id);
    // A full disconnect is always the end of any relationship with
    // them - unlike `UserLeft` (one channel, possibly still shared
    // elsewhere or via an open DM), so this is the one case safe to
    // forget the link unconditionally.
    // Released *before* the forget, not after: releasing moves a
    // live direct link back onto its settings-file identity, so
    // the forget below then finds nothing under `user_id` and
    // leaves it alone. The other order tore down a working direct
    // link every time its peer merely left the server.
    session.peer_link.release_direct_peer_id(user_id);
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
    // A half-received pad from this connection can never be
    // continued: the rest of it would arrive under the fresh
    // `UserId` they reconnect with, which starts its own
    // accumulation. Dropped here rather than left to linger for the
    // session, both because it is dead weight and because it is raw
    // pad material (zeroized on drop, so dropping it is what wipes
    // it).
    session.otp_incoming_setup.remove(&user_id);
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
            msg_id,
            envelope,
        } => {
            let from_name = name_of(ui_state, from);
            crate::client::channel::on_message(
                ui_state, session, channel, from, from_name, msg_id, envelope,
            );
        }
        P2pEvent::Message {
            channel: None,
            from,
            msg_id,
            envelope,
        } => {
            let from_name = name_of(ui_state, from);
            crate::client::direct_message::on_message(
                ui_state, session, from, from_name, msg_id, envelope,
            )
            .await;
        }
        P2pEvent::StreamStart {
            channel: Some(channel),
            from,
            stream_id,
            msg_id,
        } => {
            let from_name = name_of(ui_state, from);
            remember_delivery_id(session, from, stream_id, msg_id);
            crate::client::channel::on_stream_start(ui_state, session, channel, from, from_name, stream_id);
        }
        P2pEvent::StreamStart {
            channel: None,
            from,
            stream_id,
            msg_id,
        } => {
            let from_name = name_of(ui_state, from);
            remember_delivery_id(session, from, stream_id, msg_id);
            crate::client::direct_message::on_stream_start(ui_state, session, from, from_name, stream_id);
        }
        P2pEvent::StreamKeySetup {
            from,
            stream_id,
            setup,
        } => {
            // A pad transfer's setup shares this same generic event too -
            // claimed first, by the same `(from, stream_id)` test, since a
            // pad's stream is not an audio one and must not be handed to
            // the voice machinery.
            if crate::client::otp::route_pad_key_setup(session, from, stream_id, &setup) {
                return Ok(());
            }
            // A call's audio setup and a push-to-talk stream's share this
            // same generic event - `is_call_stream` tells them apart by
            // `(from, stream_id)` (see its doc for why that's unambiguous).
            if voice_call::is_call_stream(session, from, stream_id) {
                voice_call::forward_key_setup(session, from, stream_id, setup);
            } else {
                voice_stream::forward_key_setup(session, from, stream_id, setup);
            }
        }
        P2pEvent::StreamChunk {
            from,
            stream_id,
            seq,
            blocks,
        } => {
            if voice_call::is_call_stream(session, from, stream_id) {
                voice_call::forward_chunk(session, from, stream_id, seq, blocks);
            } else {
                voice_stream::forward_chunk(session, from, stream_id, seq, blocks);
            }
        }
        P2pEvent::StreamEnd { from, stream_id } => {
            voice_stream::end_incoming_stream(session, from, stream_id);
        }
        P2pEvent::FileOffer {
            channel,
            from,
            stream_id,
            msg_id,
            envelope,
        } => {
            let from_name = name_of(ui_state, from);
            remember_delivery_id(session, from, stream_id, msg_id);
            if handle_incoming_file_offer(
                ui_state, session, from, from_name, stream_id, channel, envelope,
            ) {
                // The offer itself opened - that is this message decrypted
                // (7.2.1). Whether the file is ever accepted and saved is
                // a separate answer, sent from `ReceiveDone` below.
                send_delivery_receipt(session, from, msg_id, ReceiptStage::Decrypted);
            }
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
        P2pEvent::OtpPadStart {
            from,
            stream_id,
            contact_name,
            keypair_size_mb,
            key_len,
            enc_digest,
            dec_digest,
        } => {
            crate::client::otp::on_pad_start(
                session,
                ui_state,
                from,
                stream_id,
                contact_name,
                keypair_size_mb,
                key_len,
                enc_digest,
                dec_digest,
            );
        }
        P2pEvent::OtpPadChunk {
            from,
            stream_id,
            seq,
            blocks,
        } => {
            crate::client::otp::on_pad_chunk(session, from, stream_id, seq, blocks);
        }
        P2pEvent::OtpPadEnd { from, stream_id } => {
            crate::client::otp::on_pad_end(session, from, stream_id);
        }
        P2pEvent::OtpPadVerify {
            from,
            contact_name,
            accepted,
            enc_digest,
            dec_digest,
        } => {
            crate::client::otp::on_pad_verify(
                session,
                ui_state,
                from,
                contact_name,
                accepted,
                enc_digest,
                dec_digest,
            )
            .await;
        }
        P2pEvent::OtpPadCommit { from, contact_name } => {
            crate::client::otp::on_pad_commit(session, ui_state, from, contact_name).await;
        }
        P2pEvent::OtpPadCommitAck { from, contact_name } => {
            crate::client::otp::on_pad_commit_ack(session, from, contact_name);
        }
        P2pEvent::Delivered {
            peer,
            msg_id,
            stage,
        } => {
            // The peer reports what it managed to do with this message
            // (docs/PROTOCOL.md 7.2.1) - the only thing that moves a row's
            // indicator off gray.
            ui_state.mark_delivered(peer, msg_id, stage);
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
            send_if_server(
                session,
                wr,
                &ClientMessage::RequestPeerLink {
                    peer,
                    candidates,
                    link_nonce,
                },
            )
            .await?;
            session.conn_stats.record_event(Instant::now());
        }
        P2pEvent::DirectResolve {
            nickname,
            host,
            port,
        } => {
            // Resolved off the select loop (a DNS lookup can block for
            // seconds) and handed back on the next pass through this
            // handler, exactly as `PeerLinkManager::direct_tick` expects.
            // An attempt whose answer never arrives simply times out at
            // `DIRECT_PUNCH_WINDOW` and resolves again at its next slot.
            let tx = session.direct_resolved_tx.clone();
            tokio::spawn(async move {
                let addr = tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .ok()
                    .and_then(|mut addrs| addrs.next());
                let _ = tx.send((nickname, addr));
            });
        }
        P2pEvent::LinkStatusChanged { peer, status } => {
            ui_state.set_link_status(peer, status);
            match status {
                p2p::LinkStatus::Active => {
                    // A send whose ciphertext already left the machine is
                    // recovered via `otp --recover-last`, never re-encoded -
                    // this is the one place that retry gets triggered, on every
                    // genuine reachability transition (reconnect, link flap,
                    // this app's own restart once the link comes back up).
                    // Scans every OTP contact with something outstanding, not
                    // just `peer` - cheap (a handful of contacts at most) and
                    // opportunistically recovers anyone else reachable too.
                    crate::client::otp::recover_and_resend(wr, session, ui_state).await?;
                    // Same trigger, same reasoning, for a pad still owed to
                    // this peer: an invitation whose delivery was never
                    // confirmed is re-offered rather than regenerated, so a
                    // peer who went offline mid-provisioning resumes instead
                    // of stranding both sides.
                    crate::client::otp::resend_pending_setups(wr, session, ui_state).await?;
                    // Same trigger again, for a `/endotp` notice this side
                    // still owes a peer who was unreachable when it ran (or
                    // whose acknowledgement never made it back) - see
                    // `docs/PROTOCOL.md` §16.6.
                    crate::client::otp::resend_pending_end_notices(wr, session, ui_state).await?;

                    // Tells `peer` our own device id, encrypted, every time
                    // the link reaches Active (idempotent - harmless on a
                    // reconnect/flap, and covers the case they somehow
                    // never got it the first time). Purely informational
                    // (docs/PROTOCOL.md §12.7); silently does nothing if we
                    // can't currently address them.
                    send_device_id_announce(session, ui_state, peer);
                    // A serverless peer has no server to learn our
                    // membership from, so a link opening is the moment to
                    // say it - and this envelope is also the thing that
                    // authenticates us to them (§7.1.5).
                    send_channel_presence(session, ui_state, peer);
                    maybe_resolve_p2p_identity_data(session, ui_state, peer);
                }
                p2p::LinkStatus::Lost => {
                    // Bounded by `PUNCH_TIMEOUT`/`SIGNAL_TIMEOUT` (`p2p.rs`'s
                    // `tick_at`), so a review withheld by
                    // `begin_identity_review` is never stuck open forever
                    // behind a link that never punches through - it's
                    // revealed here with "unknown" standing in for
                    // whatever never arrived.
                    if reveal_pending_identity_review(&session.id_store, ui_state, peer, None, None)
                    {
                        voice_stream::play_bell_chime(session);
                    }
                }
                p2p::LinkStatus::Connecting => {}
            }
        }
        P2pEvent::KeyRotation {
            from,
            rotation,
            signature,
        } => {
            // The same handler `ServerMessage::KeyRotated` uses: the
            // rotation verifies itself against the sender's pinned
            // identity, so which transport carried it changes nothing
            // about whether it is trusted (docs/PROTOCOL.md 13.10).
            let (to_send, given_up) =
                handle_pq_key_rotated(ui_state, session, from, rotation, signature);
            flush_queued_outbound(wr, ui_state, session, from, to_send, given_up).await?;
        }
        P2pEvent::ChannelPresence { from, envelope } => {
            // Registration can produce the daemon's own `--otp` proposal,
            // the same one `UserJoined` produces; driven through the
            // ordinary action path so there stays exactly one
            // implementation of it.
            if let Some(action) = on_channel_presence(session, ui_state, from, envelope) {
                handle_ui_action(action, wr, ui_state, session).await?;
            }
        }
        P2pEvent::DeviceIdAnnounce { from, envelope } => {
            on_device_id_announce(session, ui_state, from, envelope);
            maybe_resolve_p2p_identity_data(session, ui_state, from);
        }
        P2pEvent::OtpMessage {
            channel,
            from,
            seq,
            msg_id,
            envelope,
        } => {
            let from_name = name_of(ui_state, from);
            crate::client::otp::on_message(
                session, ui_state, channel, from, from_name, seq, msg_id, envelope,
            )
            .await;
        }
        P2pEvent::OtpFileOffer {
            channel,
            from,
            stream_id,
            seq,
            msg_id,
            envelope,
        } => {
            let from_name = name_of(ui_state, from);
            remember_delivery_id(session, from, stream_id, msg_id);
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
            msg_id,
            envelope,
        } => {
            remember_delivery_id(session, from, stream_id, msg_id);
            crate::client::otp::on_voice_offer(wr, session, ui_state, from, stream_id, seq, envelope).await;
        }
        P2pEvent::CallInvite {
            channel,
            from,
            call_id,
        } => {
            let from_name = name_of(ui_state, from);
            if voice_call::on_call_invite(wr, session, ui_state, from, from_name, call_id, channel).await
            {
                voice_stream::play_bell_chime(session);
            }
        }
        P2pEvent::CallAccept { from, call_id } => {
            voice_call::on_call_accept(wr, session, ui_state, from, call_id).await?;
        }
        P2pEvent::CallReject { from, call_id } => {
            voice_call::on_call_reject(session, ui_state, from, call_id);
        }
        P2pEvent::CallEnd { from, call_id } => {
            voice_call::on_call_end(session, ui_state, from, call_id);
        }
        P2pEvent::CallMute {
            from,
            call_id,
            target,
            muted,
        } => {
            voice_call::on_call_mute(session, ui_state, from, call_id, target, muted);
        }
        P2pEvent::CallRoster {
            from,
            call_id,
            members,
        } => {
            voice_call::on_call_roster(wr, session, ui_state, from, call_id, members).await?;
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
                    session.id_store.set_key_mode(&user.name, user.key_mode);
                    if let Err(e) = session.id_store.save() {
                        crate::log_warn!("failed to save id_store: {e}");
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
                    session.id_store.set_key_mode(&name, user.key_mode);
                    if let Err(e) = session.id_store.save() {
                        crate::log_warn!("failed to save id_store: {e}");
                    }
                    ui_state.push_notice(format!(
                        "{name} moved to a new identity and proved it - pin updated"
                    ));
                }
                Some(previous) => {
                    let previous_public_key_der = previous.to_vec();
                    // The popup itself is withheld until this specific
                    // connection's address/device id are known - see
                    // `maybe_resolve_p2p_identity_data`, called once the
                    // link reaches `Active` (the address) and once the
                    // peer's encrypted `DeviceIdAnnounce` decrypts (the
                    // device id), whichever lands second - or `Lost`, if
                    // punching gives up on either (docs/PROTOCOL.md §12.7).
                    // `begin_identity_review` still gates messaging with
                    // this peer immediately (`is_trust_gated`) - only the
                    // popup waits.
                    ui_state.begin_identity_review(
                        user.id,
                        user.name.clone(),
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

/// Finishes a mismatch review `check_identity` started with
/// `begin_identity_review`, once this specific connection's P2P address
/// and device id are known - or, on `Lost`, once punching has given up
/// trying to learn them (docs/PROTOCOL.md §12.7). Called from
/// `handle_p2p_event`'s `LinkStatusChanged` arm for both transitions, so
/// the review is never stuck open forever behind a link that never
/// punches through. A no-op (returns `false`) if `peer` has no pending
/// `AwaitingPeerInfo` review - the common case, since most `UserJoined`
/// sightings never mismatch at all.
///
/// The "last known" half is read from `id_store` rather than snapshotted
/// at detection time: nothing overwrites it in the meantime, since
/// `maybe_resolve_p2p_identity_data` - the only other place that would
/// (`record_last_seen`) - reveals this same review instead of recording
/// over it, for as long as it stays pending.
fn reveal_pending_identity_review(
    id_store: &idstore::IdStore,
    ui_state: &mut UiState,
    peer: UserId,
    new_addr: Option<SocketAddr>,
    new_device_id: Option<&str>,
) -> bool {
    let Some(review) = ui_state.identity_reviews.get(&peer) else {
        return false;
    };
    if review.status != ui::IdentityStatus::AwaitingPeerInfo {
        return false;
    }
    let IdentityCase::StaticMismatch {
        new_public_key_der,
        previous_public_key_der,
    } = &review.case;
    let nickname = review.nickname.clone();
    let message = format!(
        "'{nickname}' connected with a different key than last time (was {}, now {}) - possible impersonation.\nLast known from {} (device {}).\nNow connecting from {} (device {}).\nAccept their new key, or reject it.",
        short_fingerprint(&crypto::fingerprint_der(previous_public_key_der)),
        short_fingerprint(&crypto::fingerprint_der(new_public_key_der)),
        display_addr(id_store.last_addr(&nickname)),
        display_device_id(id_store.last_device_id(&nickname)),
        display_addr(new_addr),
        display_device_id(new_device_id),
    );
    ui_state.reveal_identity_review(peer, message)
}

fn display_addr(addr: Option<SocketAddr>) -> String {
    addr.map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn display_device_id(id: Option<&str>) -> String {
    match id {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => "unknown".to_string(),
    }
}

/// Refreshes `nickname`'s last-seen address/device id in `id_store` and
/// saves synchronously - called once both are known for a peer with no
/// mismatch review pending (`maybe_resolve_p2p_identity_data`). By this
/// point `check_identity` has always already pinned `nickname` (it runs
/// before `ensure_link` ever starts punching), so this only stays a no-op
/// in the edge case `IdStore::set_last_seen` itself documents: an
/// unstorable nickname that was never actually written to the store.
fn record_last_seen(session: &mut SessionState, nickname: &str, addr: SocketAddr, device_id: &str) {
    session.id_store.set_last_seen(nickname, addr, device_id);
    if let Err(e) = session.id_store.save() {
        crate::log_warn!("failed to save id_store: {e}");
    }
}

/// Sends `peer` our own device id (`SessionState::own_device_id`),
/// encrypted the same way any other per-recipient content is
/// (`Content::DeviceIdAnnounce`) - called every time their link reaches
/// `Active` (`handle_p2p_event`'s `LinkStatusChanged` arm). Silently does
/// nothing if we can't currently address them
/// (`keymode_policy::can_address`) or encryption fails for any other
/// reason - purely informational, so there is nothing to recover or retry
/// here beyond the automatic resend this function already gets on the
/// next `Active` transition (a link flap, a later rotation).
///
/// Deliberately bypasses `SessionState::remote_keys`' fresh-key
/// queueing (`rekey::RemoteKeys`, docs/PROTOCOL.md §11.1): that gate
/// exists to pace a *user's* sends against a rotating peer, and consuming
/// its one-shot bootstrap freshness with this automatic message would
/// delay the user's own first real message until the next rotation. This
/// sends immediately with whichever key (bootstrap or latest rotated) is
/// currently on file for them, same as `otp::recover_and_resend` already
/// does opportunistically on every `Active` transition.
/// The recipient details for a serverless peer, assembled from what is
/// known locally rather than from anything a server said (§7.1.5).
///
/// The key comes from `id_store`: it pins a nickname's full public key,
/// and `direct_punch_to` names peers by that same nickname, so anyone this
/// client has ever met through a server can still be addressed without
/// one. A peer with no pinned key cannot be - there is nothing to encrypt
/// to them with, and inventing a key would defeat the entire point of
/// pinning - so they stay a transport-only link.
///
/// `PqHybrid` is not a default here but a requirement. Registration turns
/// an unauthenticated nickname into a roster entry, and only `pq_hybrid`
/// signs its sends (`docs/PROTOCOL.md` §13.4), so only there can an
/// arriving envelope actually prove who sent it. Under `Password`/`None`
/// anyone able to reach the port could claim any nickname and be believed.
/// What one arriving `ChannelPresence` means for a peer's membership.
#[derive(Debug, PartialEq, Eq)]
pub struct Reconciled {
    /// Channels both sides are in - the peer's whole visible membership
    /// after this announcement.
    pub shared: Vec<String>,
    /// Shared channels the peer is not listed in yet.
    pub join: Vec<String>,
    /// Channels the peer is currently listed in but no longer claims, or
    /// that this client has itself left.
    pub leave: Vec<String>,
}

/// Works out what an announced membership list changes, given what this
/// client has joined and where the peer is currently listed.
///
/// Only channels *we* have joined are ever considered, which is the same
/// rule a server applies when deciding whose `UserJoined` we are told
/// about: a peer listing channels we are not in tells us nothing we have
/// anywhere to put. The list is authoritative rather than additive - a
/// peer that has left a channel says so by omitting it - so this is a
/// reconciliation, not a merge, and a peer can never accumulate channels
/// it has since left.
pub fn reconcile_direct_membership(
    theirs: &[String],
    ours: &[String],
    current: &[String],
) -> Reconciled {
    let shared: Vec<String> = theirs
        .iter()
        .filter(|c| ours.contains(c))
        .cloned()
        .collect();
    let join = shared
        .iter()
        .filter(|c| !current.contains(c))
        .cloned()
        .collect();
    let leave = current
        .iter()
        .filter(|c| !shared.contains(c))
        .cloned()
        .collect();
    Reconciled { shared, join, leave }
}

pub fn direct_peer_identity(
    id_store: &crate::client::idstore::IdStore,
    nickname: &str,
) -> Option<UserInfo> {
    let key = id_store.get(nickname)?.to_vec();
    // A pinned key that is not a PQ bundle belongs to one of the unsigned
    // modes, which cannot authenticate anything.
    proto::decode::<crypto::pq::PqPublicBundle>(&key).ok()?;
    Some(UserInfo {
        id: crate::client::p2p::direct_peer_id(nickname),
        name: nickname.to_string(),
        public_key_der: key,
        key_mode: KeyMode::PqHybrid,
    })
}

/// Tells a serverless peer which channels we are in, so they can place us
/// in the ones we share (`P2pPayload::ChannelPresence`). Sent when their
/// link opens and again whenever our own membership moves; a peer we have
/// no pinned key for is skipped, since nothing can be sealed to them.
/// Records a serverless peer's bootstrap encryption keys from the bundle
/// pinned for their nickname - the job `ServerMessage::UserJoined` does for
/// a peer a server announced (§13.10's "what to encrypt to until the
/// relationship rotates").
///
/// Without this there is nothing to encrypt *to* them with, and since
/// `encrypt_envelope_for` simply yields nothing when the recipient's encap
/// keys are missing, every send to them - including the `ChannelPresence`
/// that would have registered us with them - fails silently. That deadlocks
/// the exchange in exactly the case it exists for: neither side is on a
/// server, so neither is ever announced to the other, so neither ever gets
/// keys. Seeded from the pin instead, which is the same material a server
/// would have relayed.
///
/// Idempotent: a peer whose keys are already known keeps them, so a later
/// rotation is never undone by re-seeding the bootstrap it superseded.
fn seed_direct_peer_keys(session: &mut SessionState, peer: UserId, info: &UserInfo) {
    if session.pq_peer_keys.encap_for(peer).is_some() {
        return;
    }
    let Ok(bundle) = proto::decode::<crypto::pq::PqPublicBundle>(&info.public_key_der) else {
        return;
    };
    let Ok(fingerprint) = crypto::pq::bundle_fingerprint(&bundle) else {
        return;
    };
    session
        .pq_peer_keys
        .bootstrap(peer, bundle.bootstrap_encap().clone(), fingerprint);
}

fn send_channel_presence(session: &mut SessionState, ui_state: &UiState, peer: UserId) {
    let Some(nickname) = session.peer_link.direct_nickname_of(peer) else {
        return;
    };
    let Some(info) = direct_peer_identity(&session.id_store, &nickname) else {
        return;
    };
    seed_direct_peer_keys(session, peer, &info);
    let channels: Vec<String> = ui_state
        .channels
        .iter()
        .filter(|c| c.joined)
        .map(|c| c.name.clone())
        .collect();
    let Ok(plaintext) = proto::encode(&channels) else {
        return;
    };
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
    let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
        session.own_pq_private.as_ref(),
        session.pq_peer_keys.encap_for(peer),
        info.key_mode,
        &info.public_key_der,
        None,
        send_id,
        &plaintext,
        Content::ChannelPresence,
    ) else {
        return;
    };
    session
        .peer_link
        .send_reliable_or_queue(peer, P2pPayload::ChannelPresence { envelope });
}

/// Sends our channel membership to every serverless peer whose link is up.
/// Called whenever that membership changes, so a peer never goes on
/// believing we share a channel we have left, or misses one we just joined.
pub(crate) fn broadcast_channel_presence(session: &mut SessionState, ui_state: &UiState) {
    for peer in session.peer_link.active_direct_peers() {
        send_channel_presence(session, ui_state, peer);
    }
}

/// Handles an arriving `ChannelPresence` - the moment a serverless peer
/// stops being a bare transport link and becomes someone this client can
/// actually see and address (§7.1.5).
///
/// Opening the envelope *is* the authentication: `decrypt_own_envelope`
/// verifies the sender's signature against the key pinned for their
/// nickname and checks the recipient binding, so an envelope that opens
/// could only have come from whoever holds that key. Nothing registers a
/// peer before that - a `DirectPing` carries an unauthenticated nickname
/// and is believed by nobody.
///
/// Membership is reconciled, not merely added to: a peer who has left a
/// channel says so by sending a list without it, and is dropped from that
/// channel here. Only channels *we* have joined are considered, which is
/// the same rule a server applies when it decides whose `UserJoined` we
/// are told about.
fn on_channel_presence(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    envelope: Envelope,
) -> Option<UiAction> {
    if envelope.content != Content::ChannelPresence {
        return None;
    }
    let nickname = session.peer_link.direct_nickname_of(from)?;
    let info = direct_peer_identity(&session.id_store, &nickname)?;
    let plaintext = decrypt_own_envelope(&envelope, from, &info, None, session)?;
    // Only once they have proved who they are: seeding keys for an
    // unauthenticated claim would let anyone reaching the port decide what
    // this client encrypts to under that nickname.
    seed_direct_peer_keys(session, from, &info);
    let theirs: Vec<String> = proto::decode(&plaintext).ok()?;

    let ours: Vec<String> = ui_state
        .channels
        .iter()
        .filter(|c| c.joined)
        .map(|c| c.name.clone())
        .collect();
    let current = ui_state.channels_containing_member(from);
    let Reconciled { shared, join, leave } = reconcile_direct_membership(&theirs, &ours, &current);

    // Departures first, so a peer moving from one channel to another is
    // never momentarily in neither.
    for channel in leave {
        ui_state.on_user_left(&channel, from);
    }

    let mut action = None;
    for channel in &join {
        // The same entry point `ServerMessage::UserJoined` uses: from here
        // on nothing downstream - the sidebar, channel sends, voice, the
        // call roster, `--focus` - can tell this peer apart from one a
        // server introduced, which is the entire point.
        ui_state.on_user_joined(channel, info.clone());
        // And the same daemon hooks, so a punched peer arriving while
        // nobody is watching still rings, notifies, and takes the focus it
        // was started with.
        if action.is_none() {
            action = on_daemon_peer_appeared(ui_state, session, from, &nickname, Some(channel));
        }
    }
    // A peer we share no channel with is still reachable as a DM - that is
    // what `direct_punch_to` on its own buys, and what `--focus <nickname>`
    // addresses - so they are registered either way, and the daemon hooks
    // still run for them. Without this a DM-only pair got a working link
    // and nothing else: no focus placed, no chime, and - the one that
    // actually loses data - no `--otp` proposal, since that is what a
    // focused peer *appearing* is supposed to trigger.
    if shared.is_empty() {
        let first_sighting = !ui_state.known_users.contains_key(&from);
        ui_state.known_users.insert(from, info);
        if first_sighting {
            action = on_daemon_peer_appeared(ui_state, session, from, &nickname, None);
        }
    }
    action
}

fn send_device_id_announce(session: &mut SessionState, ui_state: &UiState, peer: UserId) {
    let Some(user) = ui_state.known_users.get(&peer) else {
        return;
    };
    if !crate::client::keymode_policy::can_address(user.key_mode, session.own_key_mode) {
        return;
    }
    let key_mode = user.key_mode;
    let pubkey_der = user.public_key_der.clone();
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
    let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
        session.own_pq_private.as_ref(),
        session.pq_peer_keys.encap_for(peer),
        key_mode,
        &pubkey_der,
        None,
        send_id,
        session.own_device_id.as_bytes(),
        Content::DeviceIdAnnounce,
    ) else {
        return;
    };
    session
        .peer_link
        .send_reliable_or_queue(peer, P2pPayload::DeviceIdAnnounce { envelope });
    request_rotation(session, peer);
}

/// Decrypts `from`'s `Content::DeviceIdAnnounce` (`P2pEvent::DeviceIdAnnounce`)
/// and caches the result in `SessionState::peer_device_ids`. Processed
/// unconditionally, regardless of any pending trust gate on `from` - this
/// is exactly the data an impersonation review needs to resolve, not
/// visible chat content subject to §12.4's hold-and-reveal. Silently does
/// nothing on any failure (unknown sender, decrypt failure, non-UTF-8
/// plaintext, or a mislabeled `envelope.content`) - there is no user-facing
/// consequence beyond the review continuing to show "unknown" for this
/// peer's device id.
fn on_device_id_announce(session: &mut SessionState, ui_state: &UiState, from: UserId, envelope: Envelope) {
    if envelope.content != Content::DeviceIdAnnounce {
        return;
    }
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return;
    };
    let Some(plaintext) = decrypt_own_envelope(&envelope, from, &sender, None, session) else {
        return;
    };
    let Ok(device_id) = String::from_utf8(plaintext) else {
        return;
    };
    session.peer_device_ids.insert(from, device_id);
}

/// Checks whether `peer`'s address (`PeerLinkManager::active_addr`) and
/// device id (`SessionState::peer_device_ids`, from `on_device_id_announce`)
/// are *both* now known, and if so either reveals a pending mismatch
/// review (`reveal_pending_identity_review`) or, the ordinary case,
/// refreshes their pinned key's last-seen values (`record_last_seen`). A
/// no-op otherwise - called from both `LinkStatusChanged`'s `Active` arm
/// and `DeviceIdAnnounce`'s arm, since those two pieces of information
/// arrive independently and can race either way; whichever event
/// completes the pair is the one that actually acts.
fn maybe_resolve_p2p_identity_data(session: &mut SessionState, ui_state: &mut UiState, peer: UserId) {
    let Some(addr) = session.peer_link.active_addr(peer) else {
        return;
    };
    let Some(device_id) = session.peer_device_ids.get(&peer).cloned() else {
        return;
    };
    if reveal_pending_identity_review(&session.id_store, ui_state, peer, Some(addr), Some(&device_id)) {
        voice_stream::play_bell_chime(session);
    } else {
        let nickname = ui_state
            .known_users
            .get(&peer)
            .map(|u| u.name.clone())
            .unwrap_or_default();
        record_last_seen(session, &nickname, addr, &device_id);
    }
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
/// Returns `(to_send, given_up)` from `rekey::RemoteKeys::on_rotated` for
/// the caller to put through `flush_queued_outbound` - split that way
/// because installing a rotation is pure state work while sending needs
/// the control sink.
fn handle_pq_key_rotated(
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
    rotation_bytes: Vec<u8>,
    signature: Vec<u8>,
) -> (Vec<rekey::QueuedOutbound>, Vec<rekey::QueuedOutbound>) {
    let Some(you) = ui_state.own_id else {
        return (Vec::new(), Vec::new());
    };
    let Some(my_fp) = session.own_pq_fp else {
        return (Vec::new(), Vec::new());
    };
    let Some(sender_public) = ui_state
        .known_users
        .get(&peer)
        .and_then(|u| proto::decode::<crate::crypto::pq::PqPublicBundle>(&u.public_key_der).ok())
    else {
        return (Vec::new(), Vec::new());
    };
    let Some(rotation) = crate::crypto::pq::verify_rotation(
        &sender_public,
        you,
        &my_fp,
        &rotation_bytes,
        &signature,
    ) else {
        return (Vec::new(), Vec::new());
    };
    if session.pq_peer_keys.install(peer, rotation) {
        return session.remote_keys.on_rotated(peer);
    }
    (Vec::new(), Vec::new())
}

/// Sends everything that was waiting on `peer`'s key (§13.10) and reports
/// everything that has now waited too long. A queued message is a message
/// the user already sees in their log: leaving it in the queue forever -
/// which is what dropping `on_rotated`'s result used to do - meant a
/// message that was never sent and never said so.
///
/// An item that still cannot go out goes back on the queue with its
/// attempt already spent, so the retry is bounded by
/// `rekey::MAX_QUEUED_SEND_ATTEMPTS` rather than by nothing at all. One
/// that has run out is marked failed on its own row - red, exactly like
/// any other send that turned out not to have happened.
async fn flush_queued_outbound(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
    to_send: Vec<rekey::QueuedOutbound>,
    given_up: Vec<rekey::QueuedOutbound>,
) -> proto::Result<()> {
    for item in given_up {
        if let rekey::QueuedOutbound::Direct {
            log_index: Some(index),
            ..
        } = &item
        {
            ui_state.mark_dm_message_failed(peer, *index);
        }
        let name = ui_state
            .known_users
            .get(&peer)
            .map(|u| u.name.clone())
            .unwrap_or_else(|| format!("{peer:?}"));
        ui_state.push_status_notice(
            format!("could not send to {name}: their key never became usable"),
            false,
        );
    }
    if to_send.is_empty() {
        return Ok(());
    }
    let Some(recipient) = ui_state.known_users.get(&peer).cloned() else {
        // The peer is gone entirely; there is nothing left to send to and
        // nothing to retry against either.
        return Ok(());
    };
    let mut sent_any = false;
    for item in to_send {
        let (channel, plaintext, msg_id) = match &item {
            rekey::QueuedOutbound::Channel {
                channel,
                plaintext,
                msg_id,
                ..
            } => (Some(channel.clone()), plaintext.clone(), *msg_id),
            rekey::QueuedOutbound::Direct {
                plaintext, msg_id, ..
            } => (None, plaintext.clone(), *msg_id),
        };
        let send_id = session.next_stream_id;
        session.next_stream_id += 1;
        let envelope = crate::client::envelope::encrypt_envelope_for(
            session.own_pq_private.as_ref(),
            session.pq_peer_keys.encap_for(peer),
            recipient.key_mode,
            &recipient.public_key_der,
            channel.clone(),
            send_id,
            plaintext.as_bytes(),
            Content::Text,
        );
        let Some(envelope) = envelope else {
            session.remote_keys.requeue(peer, item);
            continue;
        };
        session.peer_link.ensure_link(wr, peer).await;
        session.peer_link.send_reliable_or_queue(
            peer,
            crate::p2p_proto::P2pPayload::Envelope {
                channel,
                msg_id: Some(msg_id),
                envelope,
            },
        );
        sent_any = true;
    }
    // The whole batch went out under the one key this rotation supplied,
    // so it is spent exactly once (`RemoteKeys::on_rotated`'s contract).
    if sent_any {
        session.remote_keys.mark_used(peer);
        request_rotation(session, peer);
    }
    Ok(())
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

/// What a test needs to state about the session it wants
/// (`SessionState::for_test`) - this client's own identity, and a
/// directory to keep the on-disk stores in.
pub struct TestSessionSpec {
    pub key_mode: KeyMode,
    /// This client's own key material, in exactly the form the real
    /// connect path hands to `run_connected_session`.
    pub identity: ResolvedIdentity,
    /// Where every store that would otherwise live under the user's real
    /// `~/.aloo` is put instead. Nothing in it is read back; it exists so
    /// a test can never touch, or be perturbed by, real local state.
    pub scratch: std::path::PathBuf,
}

impl SessionState {
    /// The session's direct transport (`crate::client::p2p`) - exposed for
    /// tests, which need it to open a link a receive path can then answer
    /// over, and to read back what that path decided to send
    /// (`PeerLinkManager::pending_payloads`).
    pub fn peer_link_mut(&mut self) -> &mut PeerLinkManager {
        &mut self.peer_link
    }

    /// Builds a session for tests, without a terminal, an audio device, a
    /// server or a peer.
    ///
    /// The receive paths worth testing - `channel::on_message`,
    /// `direct_message::on_message`, `handle_p2p_event` - are ordinary
    /// functions over this struct, but the real thing is only ever built
    /// half way through `run_connected_session`, wired to a live socket
    /// and a running mixer. This is the same trade `serve_with_heartbeat_timeout`
    /// makes on the server side: one constructor whose only job is to make
    /// the logic reachable.
    ///
    /// Every worker channel is created and its receiver dropped. That is
    /// safe rather than sloppy: each of them is written to as
    /// `let _ = tx.send(..)`, so a dropped receiver changes nothing any
    /// path under test decides - it only means nobody plays the audio or
    /// writes the file, which is the point.
    ///
    /// The UDP transport is real, bound to an ephemeral loopback port with
    /// no rendezvous server. A test can therefore call `ensure_link` and
    /// then read back what a code path decided to send with
    /// `PeerLinkManager::pending_payloads`, since nothing is `Active`.
    pub async fn for_test(spec: TestSessionSpec) -> Self {
        let (file_events_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (record_out_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (own_stream_done_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (otp_keygen_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (otp_pad_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (mixer_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (stream_finished_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (audio_err_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (call_level_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (rotate_out_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (direct_resolved_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (auto_stop_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (p2p_events_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let (peer_link, _socket) =
            PeerLinkManager::bind("127.0.0.1:0".parse().expect("loopback"), None, p2p_events_tx)
                .await
                .expect("binding an ephemeral loopback port");

        // The same split the real path makes - see there for why
        // `PqHybrid` has no `own_keys` and vice versa.
        let (own_keys, own_pq_private, own_pq_fp, own_pq_keys) = match spec.identity {
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

        Self {
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
            otp_keygen_tx,
            otp_pad_tx,
            mixer_tx,
            stream_finished_tx,
            audio_err_tx,
            call_level_tx,
            own_key_mode: spec.key_mode,
            own_keys,
            own_pq_private,
            own_pq_fp,
            own_pq_keys,
            pq_peer_keys: crate::client::pq_rekey::PqPeerKeys::new(),
            rotate_out_tx,
            replay: crate::client::replay::ReplayGuard::new(),
            remote_keys: rekey::RemoteKeys::new(),
            id_store: idstore::IdStore::new_empty(spec.scratch.join("id_store")),
            conn_stats: netstats::ConnStats::new(),
            server: ServerState::Absent,
            server_retry: None,
            channel_passwords: HashMap::new(),
            direct_resolved_tx,
            auto_stop_tx,
            active_replay_id: None,
            peer_link,
            otp_cli_cfg: crate::client::otp_cli::OtpCliConfig {
                binary_path: spec.scratch.join("no-such-otp-binary"),
                working_dir: spec.scratch.join("otp"),
            },
            otp_store: crate::client::otp_store::OtpStore::new_empty(
                spec.scratch.join("otp_store"),
            ),
            otp_out_queue: crate::client::otp::OtpOutQueue::new(),
            otp_text_msg_ids: std::collections::HashMap::new(),
            pending_receipts: crate::client::delivery::PendingReceipts::new(),
            otp_incoming_setup: HashMap::new(),
            otp_incoming_pads: HashMap::new(),
            otp_outgoing_pads: HashMap::new(),
            otp_mail_store: crate::client::otp_mail_store::OtpMailStore::new_empty(
                spec.scratch.join("otp_mail"),
            ),
            own_device_id: "test-device".to_string(),
            peer_device_ids: HashMap::new(),
            active_call: None,
            daemon_plan: None,
            viewer_attached: true,
            announced_online: std::collections::HashSet::new(),
            daemon_awaiting_otp: None,
        }
    }
}

/// Tells `peer` that the message they named `msg_id` has been decrypted
/// here (docs/PROTOCOL.md 7.2.1) - the single place a receipt is ever
/// sent, called only from a branch that has already opened the envelope.
/// A no-op when the sender asked for no receipt.
///
/// Sent reliably like any other content, so a receipt is not lost to one
/// dropped datagram; queued rather than dropped if the link happens to be
/// down, which is what lets a row turn green late rather than never.
pub(crate) fn send_delivery_receipt(
    session: &mut SessionState,
    peer: UserId,
    msg_id: Option<u64>,
    stage: ReceiptStage,
) {
    let Some(msg_id) = msg_id else {
        return;
    };
    session.peer_link.send_reliable_or_queue(
        peer,
        crate::p2p_proto::P2pPayload::DeliveryReceipt { msg_id, stage },
    );
}

/// Notes that the voice message or file transfer `(from, stream_id)` will
/// owe `from` a receipt once it completes (docs/PROTOCOL.md 7.2.1). Unlike
/// a text message, neither can be receipted on arrival: at that point
/// nothing has been decrypted yet.
pub(crate) fn remember_delivery_id(
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
    msg_id: Option<u64>,
) {
    session.pending_receipts.remember(from, stream_id, msg_id);
}

/// Pays off what `remember_delivery_id` noted, if the transfer got as far
/// as being *used* - the file written to disk, the audio played. Taken
/// rather than read, so one transfer earns one `Consumed` receipt;
/// `consumed: false` simply forgets it, which is what a failed, rejected
/// or never-played one deserves - the sender's row stays at `DELIVERED`
/// because that is all that happened.
pub(crate) fn settle_delivery_id(
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
    consumed: bool,
) {
    let msg_id = session.pending_receipts.settle(from, stream_id, consumed);
    send_delivery_receipt(session, from, msg_id, ReceiptStage::Consumed);
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
///
/// Returns whether the offer actually opened - which is what the sender's
/// `Decrypted` receipt answers (7.2.1). A held offer counts: it was read,
/// and the trust gate is about whether to show it, not whether it made
/// sense.
fn handle_incoming_file_offer(
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    from_name: String,
    stream_id: u64,
    channel: Option<String>,
    envelope: Envelope,
) -> bool {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return false;
    };
    let Some(payload) = decrypt_file_offer(&envelope, from, &sender, channel.as_deref(), session)
    else {
        return false;
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
        return true;
    }
    if ui_state.push_file_offer(offer) {
        voice_stream::play_bell_chime(session);
    }
    true
}

/// Dispatches one file-transfer progress/completion/failure event
/// (`file_transfer::FileEvent`) into the matching log row - see
/// `UiState::update_file_entry` for how a row is found from just
/// `(from, stream_id)`.
/// One pass over every incoming stream that has gone quiet
/// (`voice_stream::idle_stream_action`): a sender that stopped without a
/// `StreamEnd` ever arriving (`docs/PROTOCOL.md` §7.3) is asked once to
/// end, and a stream whose worker never answered that ask is closed out
/// here so its row cannot claim to still be streaming for the rest of the
/// session.
fn sweep_idle_streams(ui_state: &mut UiState, session: &mut SessionState, now: Instant) {
    let idle: Vec<(UserId, u64)> = session
        .active_streams
        .iter()
        .filter(|(_, stream)| {
            voice_stream::idle_stream_action(
                now,
                stream.last_seen,
                stream.end_requested,
                !stream.job_tx.is_closed(),
            ) != IdleStreamAction::Wait
        })
        .map(|(key, _)| *key)
        .collect();
    for key in idle {
        let Some(stream) = session.active_streams.get_mut(&key) else {
            continue;
        };
        let action = voice_stream::idle_stream_action(
            now,
            stream.last_seen,
            stream.end_requested,
            !stream.job_tx.is_closed(),
        );
        match action {
            IdleStreamAction::Wait => {}
            IdleStreamAction::Nudge => {
                stream.end_requested = true;
                // The worker finalizes the row from whatever it managed to
                // decrypt, and its report is what removes this entry
                // (`stream_finished_rx`).
                let _ = stream.job_tx.send(voice_stream::DecryptJob::End);
            }
            IdleStreamAction::GiveUp => {
                let (from, stream_id) = key;
                let Some(stream) = session.active_streams.remove(&key) else {
                    continue;
                };
                // Nothing arrived that anyone could play, so the row is
                // closed as an empty clip rather than left mid-stream.
                match stream.channel {
                    Some(channel) => {
                        ui_state.on_channel_stream_finished(&channel, from, stream_id, 0, Vec::new())
                    }
                    None => {
                        ui_state.on_direct_stream_finished(from, from, stream_id, 0, Vec::new())
                    }
                }
            }
        }
    }
}

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
            // The whole file arrived and was written to disk - which for a
            // file is what "used" means (7.2.1), and is what the sender's
            // details popup shows as DELIVERED+SAVED.
            settle_delivery_id(session, from, stream_id, true);
        }
        file_transfer::FileEvent::ReceiveFailed { from, stream_id } => {
            session.active_file_transfers.remove(&(from, stream_id));
            if let Some(pending) = session.otp_incoming_file_receives.remove(&(from, stream_id)) {
                crate::client::otp::secure_remove_file(&pending.temp_path);
            }
            ui_state.set_file_failed(from, stream_id);
            settle_delivery_id(session, from, stream_id, false);
        }
    }
}
