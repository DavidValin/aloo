//! The live, connected session: the event loop, session-wide state, and
//! the identity-pinning bookkeeping that isn't specific to a channel or a
//! DM. Per-conversation-type send/receive handling lives in
//! `crate::client::channel` and `crate::client::direct_message`; the
//! generic live-voice-streaming plumbing they both share lives in
//! `crate::client::voice_stream`.

//! The four halves this module was split into. Every one of them is free
//! functions over `&mut SessionState` - the state itself, and the loop
//! that drives it, stay here.
mod identity;
mod link_events;
mod server_events;
mod ui_action;

// Brought into scope here because the loop below and these four modules
// call freely across each other - they were one file until they were four.
use identity::*;
use link_events::*;
use server_events::*;
use ui_action::handle_ui_action;

// And re-exported for everything outside this module that already reaches
// for them through `client::session::<name>` - the split was a move, not
// an API change. Each keeps exactly the visibility it had while all of
// this was one file; everything else is `pub(super)`, which is that same
// reach expressed for a module tree instead of a file.
pub use identity::{
    accept_identity_review, direct_peer_identity, register_pad_only_peer, seed_direct_peer_keys,
};
pub use link_events::{
    drain_p2p_events, forget_peer_for_test, reconcile_direct_membership, retry_deferred_dms,
    sweep_otp_outbox,
    sweep_outbox,
};
pub(crate) use link_events::broadcast_channel_presence;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How long a send worker may go without a sign of life before the retry
/// timer stops treating its stream as still going out. Generous next to a
/// chunk interval, short next to a session: a worker that died silently
/// must not block a contact's retries for the rest of one.
pub const SEND_STALL_GRACE: Duration = Duration::from_secs(30);

use crossterm::event::{Event, KeyCode, KeyModifiers};

use crate::BoxError;
use crate::client::connect::ResolvedIdentity;
use crate::client::file_transfer;
use crate::client::idstore;
use crate::client::ip_ban::BanOutcome;
use crate::client::netstats;
use crate::client::p2p::{self, P2pEvent, P2pOutbound, PeerLinkManager};
use crate::client::reconnect::{ServerEvent, ServerLinkState};
use crate::client::rekey;
use crate::client::sysstats;
use crate::client::tui::ui::{
    self, IdentityCase, PendingFileOffer, RecoveredProof, UiAction, UiState,
    UnknownPeerStage, UnverifiedDirectProof, VoiceTarget,
};
use crate::client::voice;
use crate::client::voice_call;
use crate::client::voice_stream;
use crate::crypto;
use crate::p2p_proto::{P2pPayload, ReceiptStage};
use crate::proto::{
    self, ClientMessage, Content, Envelope, KeyMode, ServerMessage, UserId, UserInfo,
};

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
    /// `settings::Settings::voice_echo_ducking`, read once at startup and
    /// handed to every capture worker started afterwards
    /// (`voice_stream::spawn_record_stream_worker`,
    /// `voice_call::spawn_call_audio_worker`) - the setting file is not
    /// re-read per recording.
    pub(crate) echo_ducking: crate::settings::EchoDucking,
    /// `settings::Settings::roger_beep`, mirrored here so
    /// `voice_stream::play_end_chime` can answer "should this sound at
    /// all" without a filesystem read per chime. Unlike `echo_ducking`
    /// this one is *not* fixed for the session: the Ctrl+S settings popup
    /// writes it through live (`ui_action`'s `SaveSettings` arm), so a
    /// user who turns it off hears the difference on the next voice
    /// message rather than the next run.
    pub(crate) roger_beep: bool,
    /// `settings::Settings::sound_notifications`, mirrored and kept live
    /// the same way `roger_beep` is - the switch every *event* sound
    /// (`play_bell_chime`, `play_joined_chime`, `play_ping_chime`) asks
    /// before playing.
    pub(crate) sound_notifications: bool,
    /// The durable send queue (`settings::Settings::queue_send_messages`,
    /// `client::outbox`), or `None` while that setting is off.
    ///
    /// Loaded once at session start - anything a previous run left behind
    /// is still there, which is the point - and turned on or off live by
    /// the Ctrl+S settings popup, which also flips the transport's own
    /// `set_spill_undeliverable` so the two can never disagree about
    /// whether content waits here or in the link's short in-memory queue.
    pub(crate) outbox: Option<crate::client::outbox::Outbox>,
    /// The `P2pEvent` receiver, held only by a `for_test` session so a
    /// test can play the session loop's part and hand each event back
    /// (`drain_p2p_events`). `None` in a real session, where the loop
    /// itself owns it.
    pub(crate) test_p2p_events:
        Option<tokio::sync::mpsc::UnboundedReceiver<crate::client::p2p::P2pEvent>>,
    /// The matching sender, so `sent_or_queued_payloads` can put back
    /// what it read - see its doc.
    pub(crate) test_p2p_events_tx:
        Option<tokio::sync::mpsc::UnboundedSender<crate::client::p2p::P2pEvent>>,
    pub(crate) own_stream_targets: HashMap<u64, voice_stream::OwnStreamTarget>,
    pub(crate) active_streams: HashMap<(UserId, u64), voice_stream::ActiveStream>,
    /// Voice chunks that outran their own `StreamStart` - see
    /// `voice_stream::PendingChunkBuffer`'s doc for why that race exists at
    /// all.
    pub(crate) pending_stream_chunks: voice_stream::PendingChunkBuffer,
    /// File-transfer counterparts of the two maps above - see
    /// `file_transfer::OwnFileTarget`/`ActiveFileTransfer`. Keyed the same
    /// way: `own_file_targets` by our own `stream_id` alone (it's always
    /// our stream), `active_file_transfers` by `(from, stream_id)`.
    pub(crate) own_file_targets: HashMap<u64, file_transfer::OwnFileTarget>,
    pub(crate) active_file_transfers: HashMap<(UserId, u64), file_transfer::ActiveFileTransfer>,
    /// One entry per currently-arriving OTP-protected transfer - see
    /// `file_transfer::OtpIncomingFileReceive`'s doc. Removed once
    /// `ReceiveDone`/`ReceiveFailed` finishes handling it.
    pub(crate) otp_incoming_file_receives:
        HashMap<(UserId, u64), file_transfer::OtpIncomingFileReceive>,
    /// One entry per currently-staged `.txt` receive (`accept_file_offer`) -
    /// its content has fully arrived under
    /// `file_transfer::incoming_preview_dir()` rather than
    /// `default_download_dir()`, previewable without counting as saved.
    /// Removed the moment `ReceiveDone`/`ReceiveFailed` finishes handling
    /// it (see there for why that means "started staging", not "the user
    /// saved it" - `UiAction::SaveStagedFile` is the only thing that moves
    /// the file itself, and that lookup goes through the log row's own
    /// `FileTransferStatus::Received`, not this map).
    pub(crate) staged_text_receives: HashMap<(UserId, u64), std::path::PathBuf>,
    /// Which staged receives have already earned their one `Viewed`
    /// receipt (`UiAction::RequestFilePreview`) - reopening the same
    /// preview must not resend it every time.
    pub(crate) viewed_previews: std::collections::HashSet<(UserId, u64)>,
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
    pub(crate) otp_keygen_tx:
        tokio::sync::mpsc::UnboundedSender<crate::client::otp::OtpKeygenEvent>,
    /// Completion reports from the pad send/receive workers
    /// (`client::otp_pad`) - drained by `run_connected_session`'s select
    /// loop, which is where the two-phase commit advances.
    pub(crate) otp_pad_tx: tokio::sync::mpsc::UnboundedSender<crate::client::otp_pad::PadEvent>,
    pub(crate) mixer_tx: tokio::sync::mpsc::UnboundedSender<voice::MixerCmd>,
    pub(crate) stream_finished_tx: tokio::sync::mpsc::UnboundedSender<(UserId, u64, u32, Vec<u8>)>,
    pub(crate) audio_err_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// This side's own pinned public key (the encoded `PqPublicBundle`),
    /// held once at session build rather than re-derived per use - the
    /// local half of a pure-OTP contact's name
    /// (`crypto::otp::contact_name_for_keys`).
    pub(crate) otp_own_pinned_der: Vec<u8>,
    /// This client's own PQ-hybrid private keybundle (`crypto::pq`,
    /// `docs/PROTOCOL.md` §13). A static identity (no rotation of the
    /// bundle itself), so it is never wrapped for a background worker to
    /// touch - only the per-peer encryption keys below rotate.
    pub(crate) own_pq_private: crate::crypto::pq::PqPrivateBundle,
    /// Our own PQ-hybrid identity fingerprint - what an incoming send's
    /// binding must name as its recipient for us to accept it at all
    /// (`crypto::pq::open_setup`).
    pub(crate) own_pq_fp: [u8; 32],
    /// Our rotating `pq_hybrid` decryption keys, one set per peer
    /// (`docs/PROTOCOL.md` §13.10). ML-KEM/X25519 keygen is fast enough to
    /// run inline on the event-loop task, so this needs no background
    /// worker.
    pub(crate) own_pq_keys: crate::client::pq_rekey::PqOwnKeys,
    /// Which `pq_hybrid` encryption keys each peer currently wants us to
    /// use, and how far along their rotation counter we have seen.
    pub(crate) pq_peer_keys: crate::client::pq_rekey::PqPeerKeys,
    /// Where a `pq_hybrid` rotation to send is queued for the main loop to
    /// write (`request_rotation_if_pq_hybrid`).
    pub(crate) rotate_out_tx: tokio::sync::mpsc::UnboundedSender<ClientMessage>,
    /// Refuses a send that already arrived once - see `replay::ReplayGuard`.
    pub(crate) replay: crate::client::replay::ReplayGuard,
    /// DM sends that reached us before we knew who sent them, held so
    /// that they are shown rather than lost - see `direct_message::on_message`.
    pub(crate) deferred_dms: Vec<DeferredDm>,
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
    /// Which log row (`MessageDelivery::msg_id`) each outstanding pad send
    /// belongs to, keyed by the `(contact, seq)` that names it on the wire.
    ///
    /// Two call sites need it: the ack that clears the gate, so it can also
    /// turn that row's arrow green (`client::tui::ui::DeliveryProof::PadAck`),
    /// and `recover_and_resend_envelope`, so a resend still names the row the
    /// original send did rather than landing untracked.
    ///
    /// Deliberately in memory only, unlike the gate itself
    /// (`otp_store`'s `pending_ack_proof`): the log it points into does not
    /// survive a restart either, so persisting the id would only ever name
    /// a row that no longer exists.
    /// Set when the user abandons an in-progress pad for this peer. Both
    /// background workers poll it, so each stops at a chunk boundary and
    /// unwinds having released its files - rather than being torn down
    /// mid-write, which would leave exactly the partial state a cancel is
    /// meant to remove.
    /// A fresh pad this side has offered and is waiting for the peer to
    /// agree to, by contact name. Nothing is generated until the answer
    /// arrives - the peer pays for the transfer in time and disk, so they
    /// decide first (`otp::confirm_generate`).
    pub(crate) otp_awaiting_consent:
        std::collections::HashMap<String, (crate::client::tui::ui::PendingOtpGenerate, u32)>,
    /// Contacts whose peer has already agreed to a fresh pad, so its
    /// arrival needs no second decision from them - including a full
    /// re-arrival after a reconnect resends the whole pad unchanged
    /// (`otp::on_pad_event`'s `Received` arm checks membership, not
    /// consumes it). Cleared once the exchange actually installs
    /// (`otp::on_pad_commit`) or is cancelled (`otp::on_pad_cancel`).
    pub(crate) otp_consented: std::collections::HashSet<String>,
    pub(crate) otp_cancelled:
        std::collections::HashMap<UserId, std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub(crate) otp_ack_rows: std::collections::HashMap<(String, u64), u64>,
    /// Streams a send worker is currently pushing out, so nothing starts a
    /// second worker on one the first has not finished.
    ///
    /// The retry timer is what needs this, and needs it badly: re-releasing
    /// a recording that is still streaming would put two workers on one
    /// `stream_id`, and their interleaved chunks would decrypt to something
    /// neither side's `ack_proof` matches - turning a lost acknowledgement,
    /// which is recoverable, into a gate that can never open.
    ///
    /// Keyed by when the stream last showed a sign of life - its spawn, or
    /// its most recent chunk - rather than by mere membership. A worker
    /// that dies without saying so (a cancelled task, a panic) would
    /// otherwise sit here forever and block this contact's retries for the
    /// rest of the session, turning a guard against one stall into another
    /// stall. Silence past `SEND_STALL_GRACE` is taken as gone.
    pub(crate) otp_sending_streams: std::collections::HashMap<u64, Instant>,
    /// When each peer's outstanding pad send may next be retried, and how
    /// many attempts it has already had (which sets the backoff).
    pub(crate) otp_retry: std::collections::HashMap<UserId, (Instant, u32)>,
    pub(crate) otp_out_queue: crate::client::otp::OtpOutQueue,
    /// `settings::Settings::queue_send_messages`, held explicitly.
    ///
    /// The pad queue's *existence* used to stand in for this, which
    /// conflated two separate things: where a message waits, and whether
    /// this client holds messages at all. The queue is now always there -
    /// a stop-and-wait send has to wait somewhere, and it waits sealed and
    /// on disk so a restart cannot lose it - so the policy needs a home of
    /// its own. Read by the decisions that genuinely are about the switch,
    /// such as whether a recording is sealed when it is made or staged
    /// until the peer accepts it.
    pub(crate) queue_send_messages: bool,
    /// The durable, sealed, per-contact send queue for pad sessions
    /// (`client::otp_outbox`), or `None` while `queue_send_messages` is
    /// off. Loaded once at session start, so anything a previous run
    /// sealed but never delivered is still there.
    pub(crate) otp_outbox: Option<crate::client::otp_outbox::OtpOutbox>,
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
    pub(crate) direct_resolved_tx: tokio::sync::mpsc::UnboundedSender<(String, Option<SocketAddr>)>,
    /// The No-IP job's configuration, resolved once at session start from
    /// settings (`client::noip::NoipConfig::from_settings`) - `None` when
    /// the feature is off or unusable, in which case `noip_task` never
    /// runs regardless of `server`. See `sync_noip_job`.
    pub(crate) noip_config: Option<crate::client::noip::NoipConfig>,
    /// The running updater, present only while `server.is_absent()` and
    /// `noip_config` is `Some` - started and stopped by `sync_noip_job` at
    /// every server-state transition.
    pub(crate) noip_task: Option<tokio::task::JoinHandle<()>>,
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
    id_store: idstore::IdStore,
    hotkey_rx: Option<
        tokio::sync::mpsc::UnboundedReceiver<crate::client::global_ptt::GlobalPttEvent>,
    >,
    server_addr: Option<SocketAddr>,
    input_rx: tokio::sync::mpsc::UnboundedReceiver<SessionInput>,
    plan: crate::client::daemon::DaemonPlan,
    server_label: String,
) -> Result<(), BoxError> {
    run_connected_session(
        surface,
        server_events,
        wr,
        display_name,
        you,
        my_identity,
        false,
        id_store,
        hotkey_rx,
        server_addr,
        input_rx,
        Some(plan),
        server_label,
    )
    .await
}

// Well past clippy's default 7-argument threshold; grouping the handshake
// outputs into a struct would be a larger, unrelated refactor of an
// already-established call site.
#[allow(clippy::too_many_arguments)]
pub async fn run_connected_session<W: crate::control::ControlSink>(
    surface: &mut crate::client::tui::surface::Surface,
    server_events: Option<tokio::sync::mpsc::UnboundedReceiver<ServerEvent>>,
    mut wr: W,
    display_name: String,
    you: UserId,
    my_identity: ResolvedIdentity,
    keyboard_release_reporting: bool,
    id_store: idstore::IdStore,
    mut hotkey_rx: Option<
        tokio::sync::mpsc::UnboundedReceiver<crate::client::global_ptt::GlobalPttEvent>,
    >,
    server_addr: Option<SocketAddr>,
    mut input_rx: tokio::sync::mpsc::UnboundedReceiver<SessionInput>,
    daemon_plan: Option<crate::client::daemon::DaemonPlan>,
    server_label: String,
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
    let (call_level_tx, mut call_level_rx) = tokio::sync::mpsc::unbounded_channel::<(UserId, u8)>();

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
    // The No-IP updater (`client::noip`, docs/PROTOCOL.md §7.1.5) only
    // ever matters while direct punch has somewhere to send it - resolved
    // once here from the same settings snapshot, so `sync_noip_job` below
    // has nothing left to do but watch `session.server`.
    let noip_config = if settings.noip_when_no_server_and_direct_punch_is_active {
        if !settings.direct_punch || settings.direct_punch_to.is_empty() {
            crate::log_warn!(
                "noip_when_no_server_and_direct_punch_is_active is on but direct_punch names no target; the No-IP updater will not run"
            );
            None
        } else {
            crate::client::noip::NoipConfig::from_settings(&settings).or_else(|| {
                crate::log_warn!(
                    "noip_when_no_server_and_direct_punch_is_active is on but noip_hostname/noip_username/noip_password are not all set; the No-IP updater will not run"
                );
                None
            })
        }
    } else {
        None
    };
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
    // One socket per configured punch port, because what a peer can reach
    // this client on is exactly the set of ports it sends *from*: a router
    // that leaves any one of them unrewritten is then a port that works
    // (§7.1.5). With punching off it is the single ephemeral socket it has
    // always been.
    let bind_addrs: Vec<SocketAddr> = if settings.direct_punch {
        settings
            .direct_punch_ports
            .iter()
            .map(|port| SocketAddr::new(unspecified, *port))
            .collect()
    } else {
        vec![SocketAddr::new(unspecified, 0)]
    };
    // `~/.aloo/d_id` - generated once per nickname, the first session that
    // connects as `display_name` on this machine, and reused for that
    // nickname's whole lifetime (`docs/PROTOCOL.md` §12.7). A failure to
    // load/create it is not fatal - the direct link itself doesn't depend
    // on it at all, it just leaves an impersonation review with less to
    // compare against - so this falls back to an empty string
    // (`display_device_id` renders that as "unknown") rather than
    // refusing to connect.
    let own_device_id = crate::client::device_id::load_or_create(
        &crate::client::device_id::default_path(),
        &display_name,
    )
    .unwrap_or_else(|e| {
        crate::log_warn!("failed to load/create device id: {e} (continuing without one)");
        String::new()
    });
    let (p2p_events_tx, mut p2p_events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (mut peer_link, p2p_sockets) = match PeerLinkManager::bind_all(
        &bind_addrs,
        server_addr,
        p2p_events_tx.clone(),
    )
    .await
    {
        Ok(ok) => ok,
        // Not one of them bound. Ephemeral keeps everything except direct
        // punching working, and says so - a scheduler running with no
        // reachable port looks identical to a peer who never answers.
        Err(e) if bind_addrs.iter().any(|a| a.port() != 0) => {
            crate::log_warn!(
                "could not bind any direct-punch port ({e}); falling back to an \
                 ephemeral port - direct_punch_to peers will not be able to reach \
                 this client"
            );
            PeerLinkManager::bind_all(
                &[SocketAddr::new(unspecified, 0)],
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
        tokio::sync::mpsc::unbounded_channel::<(usize, SocketAddr, p2p::InboundDatagram)>();
    // One loop per bound socket, all feeding the one channel, each tagging
    // what it reads with its own index so a reply leaves from the socket
    // its prompt arrived on.
    for (idx, socket) in p2p_sockets.into_iter().enumerate() {
        let tx = p2p_raw_tx.clone();
        p2p::spawn_receive_loop_on(socket, idx, server_addr, move |idx, addr, dgram| {
            tx.send((idx, addr, dgram)).is_ok()
        });
    }
    drop(p2p_raw_tx);

    // The identity's own bundle never rotates; only the per-peer
    // encryption keys derived from it do (`docs/PROTOCOL.md` §13.10). Its
    // pinned key is the encoded bundle itself, which is also the local
    // half of a pad contact's name (`otp::contact_name_for_peer`).
    let ResolvedIdentity {
        private: own_pq_private,
        public_der: own_pinned_der,
    } = my_identity;
    let own_pq_fp = crate::crypto::pq::fingerprint_of_encoded(&own_pinned_der)
        .ok_or("this client's own keybundle does not decode")?;
    let own_pq_keys =
        crate::client::pq_rekey::PqOwnKeys::new(own_pq_private.bootstrap_decap().clone());
    let (rotate_out_tx, mut rotate_out_rx) =
        tokio::sync::mpsc::unbounded_channel::<ClientMessage>();

    let is_daemon = daemon_plan.is_some();
    // Read before the struct literal takes ownership of `id_store`:
    // every one of this client's stores lives beside it, which is what
    // keeps two clients in one process from sharing a queue.
    let client_home = id_store.path().to_path_buf();
    let mut session = SessionState {
        active_recording: None,
        next_stream_id: 1,
        next_mixer_id: 1,
        echo_ducking: settings.voice_echo_ducking,
        roger_beep: settings.roger_beep,
        sound_notifications: settings.sound_notifications,
        // Beside this client's own `id_store`, not at a fixed path: two
        // clients in one process share `ALOO_HOME` but not their stores,
        // and a queue at a shared path would have each of them sweeping
        // away the other's messages (`outbox::dir_beside`).
        outbox: settings.queue_send_messages.then(|| {
            crate::client::outbox::Outbox::load(&crate::client::outbox::dir_beside(
                &client_home,
            ))
        }),
        test_p2p_events: None,
        test_p2p_events_tx: None,
        own_stream_targets: HashMap::new(),
        active_streams: HashMap::new(),
        pending_stream_chunks: voice_stream::PendingChunkBuffer::new(),
        own_file_targets: HashMap::new(),
        active_file_transfers: HashMap::new(),
        otp_incoming_file_receives: HashMap::new(),
        staged_text_receives: HashMap::new(),
        viewed_previews: std::collections::HashSet::new(),
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
        otp_own_pinned_der: own_pinned_der,
        own_pq_private,
        own_pq_fp,
        own_pq_keys,
        pq_peer_keys: crate::client::pq_rekey::PqPeerKeys::new(),
        rotate_out_tx: rotate_out_tx.clone(),
        replay: crate::client::replay::ReplayGuard::new(),
        deferred_dms: Vec::new(),
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
        otp_cli_cfg: crate::client::otp_cli::OtpCliConfig::resolve_beside(&client_home),
        otp_store: crate::client::otp_store::OtpStore::load(
            &crate::client::otp_store::OtpStore::path_beside(&client_home),
        )
        .unwrap_or_else(|_| {
            crate::client::otp_store::OtpStore::new_empty(
                crate::client::otp_store::OtpStore::path_beside(&client_home),
            )
        }),
        otp_awaiting_consent: std::collections::HashMap::new(),
        otp_consented: std::collections::HashSet::new(),
        otp_cancelled: std::collections::HashMap::new(),
        otp_ack_rows: std::collections::HashMap::new(),
        otp_sending_streams: std::collections::HashMap::new(),
        otp_retry: std::collections::HashMap::new(),
        otp_out_queue: crate::client::otp::OtpOutQueue::new(),
        queue_send_messages: settings.queue_send_messages,
        // Always present, unlike the ordinary outbox above. A pad send is
        // stop-and-wait: anything written while a previous message is
        // unacknowledged has to wait its turn, and waiting is exactly when
        // a crash loses it. Held here it is sealed on write and on disk, so
        // it survives - rather than sitting in memory as plaintext and
        // vanishing. `queue_send_messages` still governs the ordinary
        // outbox; for the pad the queue is what makes ordering possible at
        // all, so there is nothing meaningful to switch off.
        otp_outbox: Some(crate::client::otp_outbox::OtpOutbox::load(
            &crate::client::otp_outbox::dir_beside(&client_home),
        )),
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
        noip_config,
        noip_task: None,
    };
    // The transport hands content it cannot send to the session
    // (`P2pEvent::Undeliverable`) only while there is somewhere durable
    // to put it, so the two are switched on together - here at start, and
    // again on every change made in the Ctrl+S popup.
    session
        .peer_link
        .set_spill_undeliverable(session.outbox.is_some());
    // Anything queued for a contact this machine no longer holds keys for
    // can never be delivered or read back, so it goes - once here at
    // start, and every `SWEEP_INTERVAL` for as long as the session runs.
    let swept = link_events::sweep_outbox(&mut session) + link_events::sweep_otp_outbox(&mut session);
    if swept > 0 {
        crate::log_warn!(
            "dropped {swept} queued message(s) for contacts this machine no longer holds keys for"
        );
    }
    if let Some(waiting) = session.outbox.as_ref().map(|o| o.total())
        && waiting > 0
    {
        crate::log_warn!(
            "{waiting} message(s) queued from an earlier run will be delivered as their recipients become reachable"
        );
    }
    session.sync_noip_job();

    // Anything still in `~/.aloo/otp/.tmp/` is key material some earlier
    // run was still producing or still receiving when it stopped - a
    // superseded invitation, a dropped link, a kill, a power cut. It never
    // completed (completion is an atomic rename *out* of that directory),
    // so it is garbage by definition and is cleared here rather than left
    // to accumulate. See `client::otp_staging`'s module doc.
    crate::client::otp_staging::sweep(&session.otp_cli_cfg);
    // The working files beside it, which `sweep` deliberately does not
    // touch because some of them are meant to outlive the process: a
    // recording staged awaiting its peer's acceptance is exactly that. Only
    // the ones nothing still points at go - and two of those prefixes name
    // plaintext (PCM on its way into the encrypt, and a recording decrypted
    // on the way in), so a process killed mid-operation used to leave
    // readable audio in `~/.aloo/otp/` that nothing ever collected.
    let staged_content: Vec<std::path::PathBuf> = session
        .otp_store
        .content_sends()
        .map(|(_, staged)| staged.path.clone())
        .collect();
    let orphaned =
        crate::client::otp_staging::sweep_orphaned_content(&session.otp_cli_cfg, &staged_content);
    if orphaned > 0 {
        crate::log_warn!(
            "cleared {orphaned} leftover OTP working file(s) from an earlier run"
        );
    }
    // `~/.aloo/tmp/` is the same kind of work-in-progress-only directory,
    // for a long paste's synthesized `.txt` file rather than OTP key
    // material (`file_transfer::paste_tmp_dir`'s doc) - swept here for the
    // same reason.
    crate::client::file_transfer::sweep_paste_tmp_dir();
    // `~/.aloo/tmp/incoming/` holds a staged `.txt` receive between
    // arriving and either being saved (moved out) or the process ending -
    // never a place anything is meant to persist across runs
    // (`file_transfer::incoming_preview_dir`'s doc), same reasoning again.
    crate::client::file_transfer::sweep_incoming_preview_dir();
    // `.tmp/` above is only ever work in progress. A `_pending` directory
    // outlives it by design - it holds a pad this side generated and must
    // keep until the peer accepts - so an abandoned handshake leaves four
    // times the per-key size behind with nothing to reclaim it. Anything
    // the store no longer records as owed has no path back to being
    // installed.
    let still_owed: Vec<String> = session
        .otp_store
        .pending_setups()
        .map(|(name, _)| name.to_string())
        .collect();
    let reclaimed =
        crate::client::otp_staging::sweep_abandoned_setups(&session.otp_cli_cfg, &still_owed);
    if reclaimed > 0 {
        crate::log_warn!(
            "reclaimed {reclaimed} bytes from abandoned OTP setup directories at startup"
        );
    }
    // A write-ahead encrypt intent surviving into this run means the
    // previous process died inside an encrypt's window - settle every such
    // orphan before anything else can spend against the same pad
    // (`client::otp::reconcile_orphaned_sends`'s doc). A promoted *mail*
    // spend additionally needs its retry reference rebuilt, since that
    // lives in the mail store the same crash skipped.
    let promoted = crate::client::otp::reconcile_orphaned_sends(
        &session.otp_cli_cfg,
        &mut session.otp_store,
    )
    .await;
    for (contact_name, seq, content) in promoted {
        if let crate::client::otp_store::PendingOtpContent::Mail { mail_id } = content {
            crate::client::otp_mail::restore_orphaned_mail_ref(
                &mut session.otp_mail_store,
                &session.id_store,
                &session.own_pq_fp,
                &session.own_device_id,
                &contact_name,
                mail_id,
                seq,
            );
        }
    }

    let mut ui_state = UiState::new(display_name);
    ui_state.set_unread_otp_mail_count(session.otp_mail_store.unread_received_count());
    // With no server there is nothing to join a channel *through*, so the
    // channels named in settings are simply the ones this client is in.
    // Seeded before the session starts so a `--initial-focus channel:x` daemon
    // finds its channel already there, and so the first `ChannelPresence`
    // we send a peer is already correct.
    ui_state.serverless = server_state.is_serverless();
    ui_state.server_label = server_label;
    ui_state.autosave_messages = settings.autosave_messages;
    ui_state.resume_from_log = settings.resume_from_log;
    ui_state.voice_autoplay = settings.voice_autoplay;
    ui_state.queue_send_messages = settings.queue_send_messages;
    crate::client::global_ptt::set_enabled(settings.global_ptt_enabled);
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
    // The durable queue's key sweep has already run once by now (just
    // below the settings load), so the next one is a full interval away.
    let mut last_outbox_sweep = Instant::now();
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
    let mut last_otp_retry_sweep = Instant::now();

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
    if !session.server.is_absent() && crate::client::otp_cli::binary_available(&session.otp_cli_cfg)
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
                            // `Quit` (Escape on the account-deactivated
                            // modal) is the same kind of loop-level effect:
                            // ending the whole session is this loop's own
                            // business, not a network send.
                            if matches!(action, UiAction::Detach) {
                                session.viewer_attached = false;
                                surface.detach();
                            } else if matches!(action, UiAction::Quit) {
                                break;
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
                    // A bracketed-paste-enabled terminal (`tui::terminal::setup`)
                    // delivers a whole paste as one event, newlines included -
                    // `handle_paste` decides whether it becomes one message or
                    // a file transfer (docs/PROTOCOL.md's message-length
                    // section) rather than letting it fragment through the
                    // ordinary per-keystroke path below.
                    SessionInput::Key(Event::Paste(text)) => {
                        if let Some(action) = ui_state.handle_paste(text) {
                            handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                        }
                    }
                    // Only ever arrives from a terminal this process owns
                    // (`tui::terminal::setup` enables mouse capture) - the
                    // daemon-attach wire protocol (`daemon_ipc::KeyWire`)
                    // has no mouse variant, so an attached viewer's own
                    // clicks never reach here at all.
                    SessionInput::Key(Event::Mouse(mouse)) => {
                        if let Some(action) = ui_state.handle_mouse(mouse) {
                            handle_ui_action(action, &mut wr, &mut ui_state, &mut session).await?;
                        }
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
                let Some((socket_idx, addr, dgram)) = dgram else { break };
                session.peer_link.on_inbound_on(socket_idx, addr, dgram);
            }
            event = p2p_events_rx.recv() => {
                let Some(event) = event else { break };
                handle_p2p_event(event, &mut ui_state, &mut wr, &mut session).await?;
            }
            msg = rotate_out_rx.recv() => {
                let Some(msg) = msg else { break };
                if let ClientMessage::RotateKey {
                    to,
                    new_public_key_der,
                    signature,
                } = &msg
                    && rotation_rides_the_link(session.server, *to)
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
                // `global_ptt_enabled` is asked here, per event, rather
                // than only at registration: the OS-level grab cannot be
                // undone from this thread (see `global_ptt::set_enabled`),
                // so this is where turning the switch off in the Ctrl+S
                // popup actually stops the shortcut doing anything.
                if !crate::client::global_ptt::enabled() {
                    continue;
                }
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
                let pad_peers: Vec<UserId> = session.otp_outgoing_pads.keys().copied().collect();
                for peer in pad_peers {
                    let depth = session.peer_link.outbound_depth(peer);
                    if let Some(pad) = session.otp_outgoing_pads.get(&peer) {
                        pad.depth.store(depth, std::sync::atomic::Ordering::Relaxed);
                    }
                    // Same tick, same figure: the bar tracks what the link
                    // has actually drained, so it keeps moving after the
                    // worker has finished reading and goes on moving until
                    // the last frame is genuinely away.
                    crate::client::otp::refresh_pad_send_progress(
                        &mut session,
                        &mut ui_state,
                        peer,
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
                // The one thing that ever removes a queued message:
                // the contact it was sealed for is no longer on this
                // machine (`outbox::retain_contacts`). Driven off elapsed
                // wall time for the same reason the two samples above
                // are, and cheap when there is nothing queued - which is
                // almost always.
                if now.duration_since(last_outbox_sweep) >= crate::client::outbox::SWEEP_INTERVAL {
                    link_events::sweep_outbox(&mut session);
                    link_events::sweep_otp_outbox(&mut session);
                    last_outbox_sweep = now;
                }
                // Conn:<quality> refreshes once a second, same reasoning.
                if now.duration_since(last_conn_sample) >= Duration::from_secs(1) {
                    ui_state.set_conn_quality(session.conn_stats.quality());
                    ui_state.set_direct_punch_status(
                        session
                            .peer_link
                            .direct_punch_summary(crate::client::p2p::utc_second_of_hour()),
                    );
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
                if now.duration_since(last_otp_retry_sweep) >= Duration::from_secs(1) {
                    crate::client::otp::tick_otp_retries(&mut wr, &mut session, &mut ui_state, now)
                        .await;
                    last_otp_retry_sweep = now;
                }
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
                session.pending_stream_chunks.sweep(Instant::now());
                session.peer_link.tick_with_clock(crate::client::p2p::utc_second_of_hour());
            }
            Some((nickname, addr)) = direct_resolved_rx.recv() => {
                session.peer_link.on_direct_resolved(&nickname, addr);
            }
        }
        // Once per turn of the loop, whatever woke it: any message that
        // arrived before we knew who sent it is offered again now that
        // this turn may have introduced them. Cheap when there is
        // nothing held, which is almost always.
        link_events::retry_deferred_dms(&mut ui_state, &mut session).await;
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
        None => {
            plan.focused_nickname() == Some(info.name.as_str()) || plan.focused_channel().is_some()
        }
    };
    if !relevant {
        return;
    }
    crate::client::global_notification::notify(
        crate::client::global_notification::Notification::new(
            format!("{} {what}", info.name),
            match channel {
                Some(channel) => format!("No longer in {channel}."),
                None => "They are offline.".to_string(),
            },
        ),
    );
}












/// Sends `peer` our own device id (`SessionState::own_device_id`),
/// encrypted the same way any other per-recipient content is
/// (`Content::DeviceIdAnnounce`) - called every time their link reaches
/// `Active` (`handle_p2p_event`'s `LinkStatusChanged` arm). Silently does
/// nothing if their announced keybundle can't be sealed to, or encryption
/// fails for any other
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









/// What `scan_pinned_keys_for_match` found: which other pinned nickname's
/// key genuinely opened the proof, its raw key bytes (to pin under the new
/// nickname), and what was already recovered doing it - so the caller never
/// decrypts a second time.
struct ScanMatch {
    nickname: String,
    key_der: Vec<u8>,
    recovered: crate::client::tui::ui::RecoveredProof,
}


fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    let my_fp = session.own_pq_fp;
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


/// Rotates our `pq_hybrid` encryption keys for `peer` and offers them the
/// new ones - called unconditionally after any send or receive, via
/// `request_rotation` (§13.10). Rotates **inline**: ML-KEM-1024 and
/// X25519 keygen are microseconds, so there is nothing here worth handing
/// to a background worker. The key it supersedes is dropped the moment it
/// falls out of the retention window, which is what forward secrecy
/// actually consists of here.
pub(crate) fn request_rotation_if_pq_hybrid(session: &mut SessionState, peer: UserId) {
    let Some(peer_fp) = session.pq_peer_keys.fingerprint_for(peer) else {
        return;
    };
    let rotation = session.own_pq_keys.rotate_for(peer);
    let Ok((encoded, signature)) =
        crate::crypto::pq::sign_rotation(&session.own_pq_private, peer, &peer_fp, &rotation)
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
    /// This client's own key material, in exactly the form the real
    /// connect path hands to `run_connected_session`.
    pub identity: ResolvedIdentity,
    /// Where every store that would otherwise live under the user's real
    /// `~/.aloo` is put instead. Nothing in it is read back; it exists so
    /// a test can never touch, or be perturbed by, real local state.
    pub scratch: std::path::PathBuf,
    /// Which `otp` binary and keychain this session should use. `None`
    /// points at a path that deliberately does not exist, so a test that
    /// never meant to involve the pad layer fails closed rather than
    /// reaching for a real one (`otp_cli::binary_available`).
    pub otp: Option<crate::client::otp_cli::OtpCliConfig>,
}

impl SessionState {
    /// Starts or stops the No-IP updater to match `server` and
    /// `noip_config` - called once at session start and again on every
    /// `ServerEvent::Lost`/`Reconnected` transition, the only two things
    /// that can change whether it belongs running (`noip_config` itself is
    /// fixed for the life of the session). A job already in the state it
    /// should be in is left alone rather than restarted.
    pub(crate) fn sync_noip_job(&mut self) {
        let Some(config) = &self.noip_config else {
            return;
        };
        let wanted = self.server.is_absent();
        match (&self.noip_task, wanted) {
            (None, true) => {
                self.noip_task = Some(tokio::spawn(crate::client::noip::run(config.clone())));
            }
            (Some(_), false) => {
                if let Some(handle) = self.noip_task.take() {
                    handle.abort();
                }
            }
            _ => {}
        }
    }

    /// Rebuilds the No-IP updater's configuration from `settings` and
    /// starts or stops it to match, without waiting for a restart - what
    /// makes the Ctrl+S popup's `noip_*` fields take effect when they are
    /// changed rather than on the next run.
    ///
    /// The same three-way check `run_connected_session` makes at start:
    /// the switch on, direct punch actually naming someone, and all three
    /// credentials filled in. Anything missing means no updater, and an
    /// already-running one is stopped.
    pub fn resync_noip(&mut self, settings: &crate::settings::Settings) {
        let wanted = settings.noip_when_no_server_and_direct_punch_is_active
            && settings.direct_punch
            && !settings.direct_punch_to.is_empty();
        let config = wanted
            .then(|| crate::client::noip::NoipConfig::from_settings(settings))
            .flatten();
        if config == self.noip_config {
            return;
        }
        // Whatever is running now was built from the old configuration,
        // so it goes regardless of whether a new one replaces it.
        if let Some(handle) = self.noip_task.take() {
            handle.abort();
        }
        self.noip_config = config;
        self.sync_noip_job();
    }

    /// Re-resolves which `otp` binary to run
    /// (`settings::Settings::otp_binary_path`), so a path corrected in the
    /// Ctrl+S popup is used by the very next OTP command rather than the
    /// next run. Reads the settings file itself, the same way
    /// `OtpCliConfig::resolve` does at start - by this point the popup's
    /// change is already written to it.
    pub(crate) fn resync_otp_binary(&mut self) {
        self.otp_cli_cfg = crate::client::otp_cli::OtpCliConfig::resolve();
    }

    /// Applies the two sound switches (`settings::Settings::roger_beep`,
    /// `sound_notifications`) - the pair every chime asks before playing.
    /// Called at session start and again on every change made in the
    /// Ctrl+S settings popup, which is what makes those two live rather
    /// than next-run.
    pub fn set_sound_switches(&mut self, roger_beep: bool, sound_notifications: bool) {
        self.roger_beep = roger_beep;
        self.sound_notifications = sound_notifications;
    }

    /// Everything this side decided to send `peer` and has not managed
    /// to yet - the transport's own queue plus anything the durable queue
    /// took off it (`P2pEvent::Undeliverable`, not yet drained).
    ///
    /// Exposed for tests the same way `peer_link_mut` is. It exists
    /// because *where* an unsent payload waits is a policy that
    /// `queue_send_messages` moves, and no test asserting "this side sent
    /// that" should have to care which side of that switch it is on.
    pub fn sent_or_queued_payloads(&mut self, peer: UserId) -> Vec<crate::p2p_proto::P2pPayload> {
        let mut out = Vec::new();
        if let Some(rx) = self.test_p2p_events.as_mut() {
            let mut replay = Vec::new();
            while let Ok(event) = rx.try_recv() {
                if let crate::client::p2p::P2pEvent::Undeliverable {
                    peer: to,
                    item: crate::client::outbox::OutboxItem::Reliable(payload),
                } = &event
                    && *to == peer
                {
                    out.push(payload.clone());
                }
                replay.push(event);
            }
            // Read, not consumed: a later `drain_p2p_events` in the same
            // test must still see everything this one looked at.
            if let Some(tx) = self.test_p2p_events_tx.as_ref() {
                for event in replay {
                    let _ = tx.send(event);
                }
            }
        }
        out.extend(self.peer_link.pending_payloads(peer));
        out
    }

    /// Puts one `P2pEvent` where the session loop would have found it -
    /// exposed for tests the same way `peer_link_mut` is, so a test can
    /// drive an event the transport only produces after a real punch
    /// (`LinkStatusChanged { Active }`) and then hand it to
    /// `drain_p2p_events` exactly as the loop does.
    /// The durable send queue itself, for a test that needs to set one up
    /// directly rather than through a send path.
    pub fn outbox_mut(&mut self) -> Option<&mut crate::client::outbox::Outbox> {
        self.outbox.as_mut()
    }

    /// The rotating-key gate a recording has to pass
    /// (`direct_message::recording_may_start`) - exposed because the path
    /// itself needs a live microphone, which a test has no way to build.
    pub fn recording_may_start_for_test(&mut self, to: UserId) -> bool {
        crate::client::direct_message::recording_may_start(self, to)
    }

    /// The pad session's durable queue itself, read-only - what a test
    /// inspects to see entry order and kind without draining anything.
    pub fn otp_outbox_ref(&self) -> Option<&crate::client::otp_outbox::OtpOutbox> {
        self.otp_outbox.as_ref()
    }

    pub fn inject_p2p_event(&mut self, event: crate::client::p2p::P2pEvent) {
        if let Some(tx) = self.test_p2p_events_tx.as_ref() {
            let _ = tx.send(event);
        }
    }

    /// Pins `nickname`'s device as a bare contact - exposed for tests the
    /// same way `peer_link_mut` is, so one can put a contact into the
    /// `id_store` that `sweep_outbox` reads without going through a live
    /// identity exchange to do it.
    pub fn pin_bare_contact_for_test(&mut self, nickname: &str, device_id: &str) {
        self.id_store.pin_bare_contact(nickname, device_id);
    }

    /// Whether the No-IP updater is configured right now - exposed for
    /// tests the same way `queued_for` is, so `resync_noip`'s decision is
    /// observable without a network.
    pub fn noip_is_configured(&self) -> bool {
        self.noip_config.is_some()
    }

    /// How many sealed messages are waiting on disk for the pad contact
    /// `contact_name` (`client::otp_outbox`) - exposed for tests the same
    /// way `queued_for` is.
    pub fn otp_queued_for(&self, contact_name: &str) -> usize {
        self.otp_outbox
            .as_ref()
            .map(|o| o.len_for(contact_name))
            .unwrap_or(0)
    }

    /// How many messages are waiting on disk for `nickname`
    /// (`client::outbox`) - exposed the same way `peer_link_mut` is, so a
    /// test can see what a send path decided without a second peer to
    /// receive it. Zero while `queue_send_messages` is off.
    pub fn queued_for(&self, nickname: &str) -> usize {
        self.outbox.as_ref().map(|o| o.len_for(nickname)).unwrap_or(0)
    }

    /// How many sealed pad messages are waiting across every contact.
    /// Each one is a spent pad position, which is why it is observable:
    /// whether the queue may be torn down turns on this being zero.
    /// How many sends for `contact_name` are held back as plaintext, in
    /// memory, waiting for a non-queued spend's acknowledgement
    /// (`otp::must_hold_plaintext`) - a test's window onto the hold that
    /// keeps `.last_sent` from being overwritten.
    pub fn otp_held_plaintext_for(&self, contact_name: &str) -> usize {
        self.otp_out_queue.len_for(contact_name)
    }

    pub fn otp_queued_total(&self) -> usize {
        self.otp_outbox.as_ref().map(|o| o.total()).unwrap_or(0)
    }

    /// Puts one sealed entry in the pad queue, so a test can set up a
    /// queue that still holds spent pad positions without driving a real
    /// `otp --encrypt`. Same role as `mark_active_for_test`.
    pub fn queue_sealed_otp_for_test(&mut self, contact_name: &str, seq: u64) -> bool {
        let payload = P2pPayload::OtpEnvelope {
            channel: None,
            msg_id: Some(seq),
            seq,
            envelope: proto::Envelope {
                content: proto::Content::Text,
                blocks: vec![vec![seq as u8; 32]],
            },
            sender_device_id: "test".into(),
        };
        self.otp_outbox
            .as_mut()
            .map(|outbox| {
                outbox
                    .queue(contact_name, &payload, seq, Some(seq), None, [seq as u8; 32])
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// How many times the retry sweep has put this peer's outstanding pad
    /// send back on the wire. `None` when nothing is owed.
    ///
    /// The sweep only runs against a live link, and on a live link the
    /// re-sent payload leaves immediately - so it is not visible in
    /// `sent_or_queued_payloads`, which reports only what has *not* gone.
    /// This is what a test watches instead.
    pub fn otp_retry_attempts_for_test(&self, peer: UserId) -> Option<u32> {
        self.otp_retry.get(&peer).map(|(_, attempts)| *attempts)
    }

    /// Arms the pad session's single-outstanding-send gate, so a test can
    /// set up the "sent but never acknowledged" state a kill or a dropped
    /// frame leaves behind. Same role as `queue_sealed_otp_for_test`.
    pub fn arm_otp_ack_gate_for_test(&mut self, contact_name: &str, seq: u64) {
        self.otp_store.record_sent(
            contact_name,
            seq,
            crate::client::otp_store::PendingOtpContent::Text { channel: None },
            Some([seq as u8; 32]),
        );
    }

    /// Re-sends whatever the pad gate is still waiting on, reporting
    /// whether anything went out - the link-up recovery, reachable from a
    /// test without a second live peer.
    pub async fn retry_outstanding_otp_send_for_test(
        &mut self,
        ui_state: &mut crate::client::tui::ui::UiState,
        to: UserId,
        contact_name: &str,
    ) -> bool {
        crate::client::otp::retry_outstanding_otp_send(
            &mut crate::control::NullSink,
            self,
            ui_state,
            to,
            contact_name,
        )
        .await
    }

    /// Releases the front of a contact's pad queue if the gate allows,
    /// reporting whether anything went out - the link-up drain, reachable
    /// from a test without a second live peer.
    pub async fn pump_otp_queue_for_test(
        &mut self,
        ui_state: &mut crate::client::tui::ui::UiState,
        to: UserId,
        contact_name: &str,
    ) -> bool {
        let before = self
            .otp_store
            .get(contact_name)
            .and_then(|s| s.pending_unacked_out_seq);
        crate::client::otp::pump_otp_queue(
            &mut crate::control::NullSink,
            self,
            ui_state,
            to,
            contact_name,
        )
        .await;
        let after = self
            .otp_store
            .get(contact_name)
            .and_then(|s| s.pending_unacked_out_seq);
        before.is_none() && after.is_some()
    }

    /// Turns the durable send queue on or off, the way the Ctrl+S popup
    /// does - the session-level half of `queue_send_messages`, with the
    /// transport's own hand-off kept in step so the two can never
    /// disagree about where content waits.
    /// Whether this client holds messages for someone who is not there.
    /// Distinct from whether the pad queue exists - it always does.
    pub fn queue_send_messages_enabled(&self) -> bool {
        self.queue_send_messages
    }

    pub fn set_queue_send_messages(&mut self, enabled: bool) {
        if enabled && self.outbox.is_none() {
            self.outbox = Some(crate::client::outbox::Outbox::load(
                &crate::client::outbox::default_dir(),
            ));
        } else if !enabled {
            self.outbox = None;
        }
        // The pad session's own queue is the same switch - a sealed
        // message has to have somewhere durable to wait, or it must not
        // be sealed at all - with one asymmetry, because a pad position
        // cannot be un-spent.
        //
        // Turning the setting off stops anything *new* being sealed for
        // an unreachable peer (`otp::send_or_queue` refuses before
        // `otp --encrypt` runs), but it must not abandon what is already
        // sealed and waiting. Those pad positions are spent; dropping the
        // queue would leave them undelivered while the next send went out
        // under a later sequence number, and the peer's pad, which
        // expects exactly the sequence it was given, would be left behind
        // for good. So a non-empty pad queue is kept and allowed to
        // drain; it goes only once it is empty and there is nothing left
        // to desynchronize.
        self.queue_send_messages = enabled;
        // The pad queue is not one of the things this switch governs: a
        // stop-and-wait send has to wait somewhere, and it waits sealed and
        // on disk so a restart cannot lose it. Kept in both positions of
        // the switch.
        if self.otp_outbox.is_none() {
            self.otp_outbox = Some(crate::client::otp_outbox::OtpOutbox::load(
                &crate::client::otp_outbox::default_dir(),
            ));
        }
        self.peer_link
            .set_spill_undeliverable(self.outbox.is_some());
    }

    /// How many sources this session has pushed onto its mixer - exposed
    /// for tests the same way `peer_link_mut` is, and for the same
    /// reason: `for_test` drops the mixer's receiver, so a sound that was
    /// played leaves no other trace. Every chime and every replay takes
    /// one id from this counter (`voice_stream::play_chime`), so a rise
    /// here is exactly "something was played".
    /// How many arrived messages are waiting for their sender to become
    /// known (`defer_dm`). Observable so a test can tell "held" apart from
    /// "dropped", which is the whole distinction AC-420 draws.
    pub fn deferred_dm_count(&self) -> usize {
        self.deferred_dms.len()
    }

    pub fn mixer_sources_started(&self) -> u64 {
        self.next_mixer_id - 1
    }

    /// The session's direct transport (`crate::client::p2p`) - exposed for
    /// tests, which need it to open a link a receive path can then answer
    /// over, and to read back what that path decided to send
    /// (`PeerLinkManager::pending_payloads`).
    pub fn peer_link_mut(&mut self) -> &mut PeerLinkManager {
        &mut self.peer_link
    }

    /// Stands in for what a *peer* has pinned for this side, which is
    /// ordinarily our own announced keybundle. Exposed for tests, which
    /// need to model a pair whose view of each other comes from `id_store`
    /// pins rather than from a server's `Identify` - a serverless
    /// direct-punch pair (`docs/PROTOCOL.md` §7.1.5), where a pin that is
    /// not a readable bundle is what drops the pad to `Direct` framing on
    /// both sides (`otp::framing_for`).
    pub fn set_own_pinned_der_for_test(&mut self, der: Vec<u8>) {
        self.otp_own_pinned_der = der;
    }

    /// Empties `own_file_targets` - simulates the one part of a real
    /// process restart a test needs and cannot otherwise reach: this map
    /// is in-memory only, so a genuine restart always starts it empty
    /// (`OtpStore::PendingContentSend`'s doc covers what survives instead).
    pub fn clear_own_file_targets_for_test(&mut self) {
        self.own_file_targets.clear();
    }

    /// Reads back what `set_own_pinned_der_for_test` put there - what a
    /// peer has pinned for this side, which is one half of the pair
    /// `otp::framing_for` reads.
    pub fn own_pinned_der_for_test(&self) -> &[u8] {
        &self.otp_own_pinned_der
    }

    /// Simulates a `DeviceIdAnnounce` having already decrypted for `peer` -
    /// exposed for tests that build a session/peer pair directly, bypassing
    /// the real P2P handshake (`on_device_id_announce`) that would
    /// otherwise be the only way to populate this, so the device-qualified
    /// `PqWrapped` contact-naming rules (device-pinning plan §4) have
    /// something to resolve against.
    pub fn set_peer_device_id_for_test(&mut self, peer: UserId, device_id: String) {
        self.peer_device_ids.insert(peer, device_id);
    }

    /// This session's own device_id (`client::device_id`) - exposed for
    /// tests that need to reproduce the exact device-qualified contact
    /// name (`crypto::otp::contact_name_for`/`contact_name_for_mail`,
    /// device-pinning plan §4) production code would derive.
    pub fn own_device_id_for_test(&self) -> &str {
        &self.own_device_id
    }

    /// Overrides this session's own device_id for the duration of one send -
    /// exposed for tests that need to simulate a *different* physical
    /// machine claiming the same pad (device-pinning plan §5's
    /// `sender_device_id` cleartext claim), without standing up a second
    /// real session.
    pub fn set_own_device_id_for_test(&mut self, device_id: String) {
        self.own_device_id = device_id;
    }

    /// Overrides the `otp` binary this session shells out to - exposed for
    /// tests that need to simulate the binary becoming unreachable (a bad
    /// `ALOO_OTP_BIN`, one uninstalled mid-session, a moved path) partway
    /// through a scenario, then becoming reachable again, without tearing
    /// down and rebuilding the whole session in between (which would lose
    /// exactly the in-memory state - `otp_incoming_pads`, `otp_store` - the
    /// scenario is trying to hold constant across the change).
    pub fn set_otp_binary_path_for_test(&mut self, path: std::path::PathBuf) {
        self.otp_cli_cfg.binary_path = path;
    }

    /// Reads back this session's `otp` binary/keychain config - exposed for
    /// tests that need to call `otp_cli` functions directly (`show_contact`,
    /// `status`, ...) against the exact same keychain the session itself
    /// installed into, to verify an install actually happened rather than
    /// only that the session's own in-memory bookkeeping believes it did.
    pub fn otp_cli_cfg_for_test(&self) -> crate::client::otp_cli::OtpCliConfig {
        self.otp_cli_cfg.clone()
    }

    /// Stages a pad under `from` exactly as `otp_pad`'s real streaming
    /// reassembly would have left it - `on_pad_commit` expects to find it at
    /// `otp_pad::incoming_paths` inside a staging directory, keyed by
    /// `contact_name` - so a test can drive `on_pad_commit`'s install/retry
    /// logic directly without standing up two peers and a full P2P pad
    /// transfer (`otp::on_pad_start`/`on_pad_chunk`/`on_pad_end`, all
    /// crate-private). The bytes themselves need no relation to any real
    /// peer's half: `on_pad_commit` never re-verifies them against
    /// anything (that already happened in `on_pad_verify`, before a commit
    /// is ever sent) - only `otp_cli::add_contact` reads them, to install
    /// them as this contact's pad.
    pub fn stage_incoming_pad_for_test(&mut self, from: UserId, contact_name: String) {
        let dir = self
            .otp_cli_cfg
            .working_dir
            .join(".tmp")
            .join(format!("test-incoming-{}-{contact_name}", from.0));
        std::fs::create_dir_all(&dir).expect("test staging dir");
        let (enc_path, dec_path) = crate::client::otp_pad::incoming_paths(&dir);
        std::fs::write(&enc_path, vec![0xAB; 4096]).expect("write test enc pad");
        std::fs::write(&dec_path, vec![0xCD; 4096]).expect("write test dec pad");
        let enc_digest =
            crate::crypto::otp::digest_key_file(&enc_path).expect("digest test enc pad");
        let dec_digest =
            crate::crypto::otp::digest_key_file(&dec_path).expect("digest test dec pad");
        let (job_tx, _job_rx) = tokio::sync::mpsc::unbounded_channel();
        self.otp_incoming_pads.insert(
            from,
            crate::client::otp_pad::IncomingPad {
                stream_id: 0,
                contact_name,
                keypair_size_mb: 1,
                enc_digest,
                dec_digest,
                dir,
                job_tx,
                received_bytes: 8192,
                started_at: std::time::Instant::now(),
            },
        );
    }

    /// Whether a pad is still staged under `from`, for whatever contact
    /// name - the other half of `stage_incoming_pad_for_test`'s test seam,
    /// letting a test confirm a failed `on_pad_commit` install left the
    /// staged bytes alone rather than checking their absence only
    /// indirectly (a successful later retry).
    pub fn has_staged_incoming_pad_for_test(&self, from: UserId) -> bool {
        self.otp_incoming_pads.contains_key(&from)
    }

    /// The `(stream_id, enc_digest, dec_digest)` a pad staged by
    /// `stage_incoming_pad_for_test` actually has - what a test builds a
    /// matching `otp_pad::PadEvent::Received` from, since `on_pad_event`
    /// only proceeds when it agrees with the staged pad it names.
    pub fn staged_incoming_pad_identity_for_test(
        &self,
        from: UserId,
    ) -> Option<(u64, crate::crypto::otp::KeyDigest, crate::crypto::otp::KeyDigest)> {
        self.otp_incoming_pads
            .get(&from)
            .map(|pad| (pad.stream_id, pad.enc_digest, pad.dec_digest))
    }

    /// Whether this side is still waiting on the peer's answer to its own
    /// "generate a fresh pad?" proposal for `contact_name`
    /// (`confirm_generate`'s `otp_awaiting_consent` insert) - exposed for
    /// tests confirming glare resolution (`on_session_request`) withdraws
    /// the losing side's proposal and leaves the winning side's untouched.
    pub fn has_awaiting_otp_consent_for_test(&self, contact_name: &str) -> bool {
        self.otp_awaiting_consent.contains_key(contact_name)
    }

    /// This session's rotating pq_hybrid peer keys - exposed for tests
    /// that send an ordinary (non-OTP) sealed envelope without a real
    /// connection's `UserJoined`/`KeyRotated` traffic to bootstrap it,
    /// most notably a fresh `OtpSessionRequest`/`OtpKeySetupAck` exchange
    /// (`test/otp_pad_glare_test.rs`), which `client::envelope::encrypt_envelope_for`
    /// refuses outright with no rotating key on file for the recipient.
    pub fn pq_peer_keys_mut(&mut self) -> &mut crate::client::pq_rekey::PqPeerKeys {
        &mut self.pq_peer_keys
    }

    /// This session's identity-pinning store - exposed for tests, which
    /// need to pin a serverless peer's key the way a previous connection
    /// (or a hand-installed contact) would have.
    pub fn id_store_mut(&mut self) -> &mut idstore::IdStore {
        &mut self.id_store
    }

    /// Read-only counterpart of `id_store_mut` - exposed for tests that
    /// only need to derive a contact name (`contacts::otp_contact_name_for`)
    /// against an already-pinned device, not to pin one themselves.
    pub fn id_store_ref(&self) -> &idstore::IdStore {
        &self.id_store
    }

    /// Stages this side's own "generate a fresh pad?" proposal as already
    /// awaiting the peer's answer, exactly as `client::otp::confirm_generate`
    /// leaves it right after sending the real request - exposed for tests
    /// that need to simulate that in-flight state directly
    /// (`test/otp_install_race_test.rs`) without driving the whole
    /// popup/consent round trip to reach it.
    pub fn stage_awaiting_otp_consent_for_test(
        &mut self,
        contact_name: String,
        pending: crate::client::tui::ui::PendingOtpGenerate,
        size_mb: u32,
    ) {
        self.otp_awaiting_consent.insert(contact_name, (pending, size_mb));
    }

    /// Records `contact_name` as already agreed to a fresh pad, exactly as
    /// `accept_invite`'s "agreeing to a fresh pad" branch leaves it -
    /// exposed for tests proving `otp::on_pad_event`'s `Received` arm no
    /// longer re-prompts for a pad this side already accepted, without
    /// driving the whole popup round trip to reach that state.
    pub fn stage_otp_consented_for_test(&mut self, contact_name: String) {
        self.otp_consented.insert(contact_name);
    }

    /// Whether `contact_name` is still recorded as consented - the other
    /// half of `stage_otp_consented_for_test`, confirming a genuine install
    /// (`on_pad_commit`) or cancellation actually clears it rather than
    /// leaking it past the exchange it was for.
    pub fn has_otp_consented_for_test(&self, contact_name: &str) -> bool {
        self.otp_consented.contains(contact_name)
    }

    /// The OTP layer's per-contact state - exposed for tests, which need
    /// to mark a contact provisioned (standing in for a handshake covered
    /// elsewhere) and to read back whether a send is still awaiting its
    /// acknowledgement.
    pub fn otp_store_mut(&mut self) -> &mut crate::client::otp_store::OtpStore {
        &mut self.otp_store
    }

    /// The OTP mail layer's sent/received indexes - exposed for tests,
    /// which need to seed a mail as already sent and awaiting the
    /// server's storage acknowledgement without driving a real encrypt.
    pub fn otp_mail_store_mut(&mut self) -> &mut crate::client::otp_mail_store::OtpMailStore {
        &mut self.otp_mail_store
    }

    /// The OTP ciphertext this side staged for `stream_id`'s content
    /// phase. Exposed for tests, which stand in for the chunked transport
    /// by handing that file to the other session directly.
    /// Whether a send worker is still pushing `stream_id` out.
    pub fn otp_sending_streams_contains_for_test(&self, stream_id: u64) -> bool {
        self.is_stream_sending(stream_id, Instant::now())
    }

    /// The stream id the next voice or file send will use - so a test can
    /// lay down the row that send will look for (`own_stream_msg_id`),
    /// which is where its `msg_id` comes from.
    pub fn next_stream_id_for_test(&self) -> u64 {
        self.next_stream_id
    }

    /// Drops the transient half of the pad-retry state, as a process
    /// restart does: no worker is running after one, and no schedule is
    /// owed. Both are deliberately in-memory, so a restart is the one
    /// event that always clears them.
    pub fn forget_transient_otp_state_for_test(&mut self) {
        self.otp_sending_streams.clear();
        self.otp_retry.clear();
    }

    /// Registers a stream as being sent, as a spawn does.
    pub fn register_sending_stream_for_test(&mut self, stream_id: u64, at: Instant) {
        self.otp_sending_streams.insert(stream_id, at);
    }

    /// `is_stream_sending`, at a time a test chooses.
    pub fn is_stream_sending_for_test(&self, stream_id: u64, now: Instant) -> bool {
        self.is_stream_sending(stream_id, now)
    }

    /// Whether a send worker still looks alive for `stream_id`: registered,
    /// and having shown a sign of life within `SEND_STALL_GRACE`.
    pub(crate) fn is_stream_sending(&self, stream_id: u64, now: Instant) -> bool {
        self.otp_sending_streams
            .get(&stream_id)
            .is_some_and(|seen| now.duration_since(*seen) < SEND_STALL_GRACE)
    }

    pub fn otp_send_temp_file(&self, stream_id: u64) -> Option<&std::path::PathBuf> {
        self.otp_send_temp_files.get(&stream_id)
    }

    /// The bookkeeping a receive path registered for an arriving OTP
    /// transfer - exposed for tests, which drive `otp::finish_incoming_file`
    /// by hand rather than through a spawned worker.
    pub fn take_otp_incoming_receive(
        &mut self,
        from: UserId,
        stream_id: u64,
    ) -> Option<crate::client::file_transfer::OtpIncomingFileReceive> {
        self.otp_incoming_file_receives.remove(&(from, stream_id))
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
        // Kept, not dropped like the worker channels above: this is the
        // one channel a test needs to read back, since it carries the
        // decisions a send path made (`P2pEvent::Undeliverable`) rather
        // than audio nobody is listening to. See `drain_p2p_events`.
        let (p2p_events_tx, p2p_events_rx) = tokio::sync::mpsc::unbounded_channel();
        let p2p_events_tx_for_test = p2p_events_tx.clone();
        let (peer_link, _socket) = PeerLinkManager::bind(
            "127.0.0.1:0".parse().expect("loopback"),
            None,
            p2p_events_tx,
        )
        .await
        .expect("binding an ephemeral loopback port");

        // The same unpacking the real path does.
        let ResolvedIdentity {
            private: own_pq_private,
            public_der: own_pinned_der,
        } = spec.identity;
        let own_pq_fp = crate::crypto::pq::fingerprint_of_encoded(&own_pinned_der)
            .expect("a test identity's own keybundle decodes");
        let own_pq_keys =
            crate::client::pq_rekey::PqOwnKeys::new(own_pq_private.bootstrap_decap().clone());

        let mut session = Self {
            active_recording: None,
            next_stream_id: 1,
            next_mixer_id: 1,
            echo_ducking: crate::settings::EchoDucking::default(),
            roger_beep: true,
            sound_notifications: true,
            // A scratch directory per test session, so a test never
            // reads or writes the real `~/.aloo/outbox` - same rule every
            // other store `for_test` points somewhere harmless follows.
            outbox: Some(crate::client::outbox::Outbox::load(&spec.scratch.join("outbox"))),
            test_p2p_events: Some(p2p_events_rx),
            test_p2p_events_tx: Some(p2p_events_tx_for_test),
            own_stream_targets: HashMap::new(),
            active_streams: HashMap::new(),
            pending_stream_chunks: voice_stream::PendingChunkBuffer::new(),
            own_file_targets: HashMap::new(),
            active_file_transfers: HashMap::new(),
            otp_incoming_file_receives: HashMap::new(),
            staged_text_receives: HashMap::new(),
            viewed_previews: std::collections::HashSet::new(),
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
            otp_own_pinned_der: own_pinned_der,
            own_pq_private,
            own_pq_fp,
            own_pq_keys,
            pq_peer_keys: crate::client::pq_rekey::PqPeerKeys::new(),
            rotate_out_tx,
            replay: crate::client::replay::ReplayGuard::new(),
            deferred_dms: Vec::new(),
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
            otp_cli_cfg: spec.otp.unwrap_or(crate::client::otp_cli::OtpCliConfig {
                binary_path: spec.scratch.join("no-such-otp-binary"),
                working_dir: spec.scratch.join("otp"),
            }),
            otp_store: crate::client::otp_store::OtpStore::new_empty(
                spec.scratch.join("otp_store"),
            ),
            otp_awaiting_consent: std::collections::HashMap::new(),
            otp_consented: std::collections::HashSet::new(),
            otp_cancelled: std::collections::HashMap::new(),
            otp_ack_rows: std::collections::HashMap::new(),
        otp_sending_streams: std::collections::HashMap::new(),
        otp_retry: std::collections::HashMap::new(),
            otp_out_queue: crate::client::otp::OtpOutQueue::new(),
            queue_send_messages: true,
            otp_outbox: Some(crate::client::otp_outbox::OtpOutbox::load(
                &spec.scratch.join("otp_outbox"),
            )),
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
            noip_config: None,
            noip_task: None,
        };
        // `for_test` starts with the durable queue on, so a test sees
        // what a default settings file gives. Set directly rather than
        // through `set_queue_send_messages`, whose "turn it on" branch
        // loads the *real* `~/.aloo/outbox` - the scratch one above is
        // the whole point of this constructor.
        session.peer_link.set_spill_undeliverable(true);
        session
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

/// Whether an encryption-key rotation (`docs/PROTOCOL.md` §13.10) has to
/// travel over the direct link rather than being relayed by the server.
///
/// True in two cases, and they are different: no server can relay
/// anything right now (`--no-server`, or one that is merely away), or the
/// peer is one of `p2p::direct_peer_id`'s synthetic ids that no server has
/// ever heard of (§7.1.5) - which stays true even while a server *is*
/// connected. Otherwise the rotation goes on the control channel like
/// every other `RotateKey`.
///
/// The link is already authenticated and the rotation carries its own
/// signature, so the transport changes nothing about trust. Getting this
/// wrong is quiet rather than loud: messages keep encrypting and
/// decrypting fine against the un-rotated bootstrap keys, and forward
/// secrecy simply stops - for precisely the peers §7.1.5 exists for.
pub fn rotation_rides_the_link(server: ServerState, to: UserId) -> bool {
    server.is_absent() || p2p::is_direct_peer_id(to)
}

/// Rotates our own key material for `peer` - the single trigger every send
/// and receive path calls, so rotation needs no sprinkling of call sites
/// of its own.
pub(crate) fn request_rotation(session: &mut SessionState, peer: UserId) {
    request_rotation_if_pq_hybrid(session, peer);
}

/// Decrypts `envelope`, addressed to *us*, from `from`. It was sealed
/// against the key material *we* announced, so the decryption keys are our
/// own rotating ones; `sender`'s `UserInfo` is needed only to verify their
/// signature over it (`docs/PROTOCOL.md` §13).
/// A DM that arrived before its sender was in `known_users`, kept until
/// they are (`link_events::retry_deferred_dms`).
///
/// Nothing can be done with one at the time it lands: decrypting needs the
/// sender's public key, and rendering needs their name, and neither exists
/// yet. Dropping it was the old behaviour and it is the one outcome that
/// cannot be recovered from - the message is gone, having been both sent
/// and received. So it waits instead.
/// How many undeliverable-yet DMs are held. A peer who never becomes
/// known never drains, so this is bounded; the bound is generous because
/// the wait is normally milliseconds.
pub(crate) const DEFERRED_DM_MAX: usize = 256;

/// Holds a DM whose sender is not known yet, dropping the *oldest* if the
/// bound is reached - the newest is the one most likely still to have a
/// sender arriving for it.
pub(crate) fn defer_dm(
    session: &mut SessionState,
    from: UserId,
    msg_id: Option<u64>,
    envelope: Envelope,
) {
    if session.deferred_dms.len() >= DEFERRED_DM_MAX {
        session.deferred_dms.remove(0);
    }
    session.deferred_dms.push(DeferredDm {
        from,
        msg_id,
        envelope,
    });
}

pub(crate) struct DeferredDm {
    pub(crate) from: UserId,
    pub(crate) msg_id: Option<u64>,
    pub(crate) envelope: Envelope,
}

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
/// different output shape (there's no `MessageBody`
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
    let candidates = session.own_pq_keys.candidates_for(from);
    let sender_public: crypto::pq::PqPublicBundle = proto::decode(&sender.public_key_der).ok()?;
    let blob = envelope.blocks.first()?;
    let (binding, plaintext) =
        crypto::pq::open_send(&candidates, &session.own_pq_fp, &sender_public, blob)?;
    if binding.channel.as_deref() != channel {
        return None;
    }
    if !session.replay.accept(from, binding.send_id) {
        return None;
    }
    Some(plaintext)
}

/// `decrypt_own_envelope` for an OTP-layer envelope, whose seal names no
/// recipient and no channel (`crypto::pq::open_send_blinded`). Enforces
/// the one part of the binding that is still the caller's to judge - that
/// `send_id` is newer than anything already accepted from this sender -
/// and leaves the channel check to the OTP layer, which makes it against
/// what it recovers from under the pad (`client::otp`'s `OtpInner`).
pub(crate) fn decrypt_own_blinded_envelope(
    envelope: &Envelope,
    from: UserId,
    sender: &UserInfo,
    session: &mut SessionState,
) -> Option<Vec<u8>> {
    let candidates = session.own_pq_keys.candidates_for(from);
    let sender_public: crypto::pq::PqPublicBundle = proto::decode(&sender.public_key_der).ok()?;
    let blob = envelope.blocks.first()?;
    let (send_id, plaintext) =
        crypto::pq::open_send_blinded(&candidates, &session.own_pq_fp, &sender_public, blob)?;
    if !session.replay.accept(from, send_id) {
        return None;
    }
    Some(plaintext)
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
                    Some(channel) => ui_state.on_channel_stream_finished(
                        &channel,
                        from,
                        stream_id,
                        0,
                        Vec::new(),
                    ),
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
            // A chunk went out, so this worker is demonstrably alive.
            if let Some(seen) = session.otp_sending_streams.get_mut(&stream_id) {
                *seen = Instant::now();
            }
            ui_state.set_file_progress(me, stream_id, bytes)
        }
        file_transfer::FileEvent::SendDone { stream_id } => {
            session.otp_sending_streams.remove(&stream_id);
            if let Some(temp) = session.otp_send_temp_files.remove(&stream_id) {
                crate::client::otp::secure_remove_file(&temp);
            }
            ui_state.set_file_completed(me, stream_id)
        }
        file_transfer::FileEvent::SendFailed { stream_id } => {
            session.otp_sending_streams.remove(&stream_id);
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
            let staged_path = session.staged_text_receives.remove(&(from, stream_id));
            let is_staged = staged_path.is_some();
            match session
                .otp_incoming_file_receives
                .remove(&(from, stream_id))
            {
                Some(pending) => {
                    crate::client::otp::finish_incoming_file(
                        session, ui_state, from, stream_id, pending,
                    )
                    .await;
                }
                None => match staged_path {
                    // Staged rather than saved - the row shows it as
                    // previewable, not `Completed`, and no receipt fires
                    // yet (below): a `.txt` landing in the preview
                    // directory has not been "used" the way 7.2.1 means it
                    // until the user actually saves it.
                    Some(path) => ui_state.set_file_received_staged(from, stream_id, path),
                    None => ui_state.set_file_completed(from, stream_id),
                },
            }
            // The whole file arrived and was written to disk - which for
            // an ordinary file is what "used" means (7.2.1), and is what
            // the sender's details popup shows as DELIVERED+SAVED. A
            // staged `.txt` receive earns this only once actually saved
            // (`UiAction::SaveStagedFile`), not on arrival.
            if !is_staged {
                settle_delivery_id(session, from, stream_id, true);
            }
        }
        file_transfer::FileEvent::ReceiveFailed { from, stream_id } => {
            session.active_file_transfers.remove(&(from, stream_id));
            session.staged_text_receives.remove(&(from, stream_id));
            session.viewed_previews.remove(&(from, stream_id));
            if let Some(pending) = session
                .otp_incoming_file_receives
                .remove(&(from, stream_id))
            {
                crate::client::otp::secure_remove_file(&pending.temp_path);
            }
            ui_state.set_file_failed(from, stream_id);
            settle_delivery_id(session, from, stream_id, false);
        }
    }
}
