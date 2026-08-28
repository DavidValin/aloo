//! One row in a conversation, and everything that decorates it.
//!
//! [`LogEntry`] is what a channel tab or a DM room actually holds a list
//! of - a message, a file transfer, a voice clip, a presence notice or a
//! system line, all the same shape. [`MessageBody`] is which of those it
//! is; the rest of this module is the state that hangs off a row over its
//! life: how far a send got ([`MessageDelivery`], [`DeliveryStatus`],
//! [`DeliveryRecipient`]), what protected it ([`MessageCrypto`]), and how
//! a file transfer is progressing ([`FileTransferStatus`],
//! [`FileRowProgress`]).
//!
//! `LogEntry`'s constructors are the only way a row is built, which is
//! what keeps a row's two timestamps from ever coming from two different
//! instants.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use ratatui::style::Color;

use crate::proto::UserId;

use super::ui::*;

/// Where one file transfer's log row currently stands
/// (`docs/PROTOCOL.md`'s file transfer section) - `Pending` only ever shown
/// on the *sender's* side (the receiver never gets a row at all until they
/// decide; see `PendingFileOffer`/`file_offer_queue`), the other three
/// apply to either direction.
#[derive(Debug, Clone, PartialEq)]
pub enum FileTransferStatus {
    /// Offer sent, waiting for the recipient's Accept/Reject.
    Pending,
    /// Accepted; bytes are actively flowing (sent, if this is our own
    /// outgoing row, or written to disk, if incoming).
    InProgress { bytes: u64 },
    /// Every byte sent (outgoing) or written to `~/.aloo/downloads`
    /// (incoming).
    Completed,
    /// Incoming only: a `.txt` offer whose bytes have fully arrived, but
    /// staged under `file_transfer::incoming_preview_dir()` rather than
    /// `~/.aloo/downloads` - previewable (`UiAction::RequestFilePreview`)
    /// without being considered saved. Becomes `Completed` the moment the
    /// user actually saves it (`UiAction::SaveStagedFile`, the `d` key
    /// inside the preview popup) - the only way out of this state besides
    /// leaving it, which the next startup's sweep quietly cleans up.
    Received { staged_path: std::path::PathBuf },
    /// The recipient declined the offer - outgoing rows only.
    Rejected,
    /// A local error ended the transfer early (disk/read/write failure) -
    /// surfaced rather than left stuck mid-progress forever.
    Failed,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MessageBody {
    Text(String),
    /// A finished voice message: `pcm` is decoded, decrypted PCM16 (see
    /// `voice::pcm_from_bytes`), ready to replay through `voice::MixerCmd`.
    Voice {
        duration_ms: u32,
        pcm: Vec<u8>,
    },
    /// A voice message that's still being recorded/received live - see
    /// `log_own_voice_stream_start_channel`/`on_channel_stream_start` and
    /// their `_finished` counterparts, which swap this in place for a
    /// `Voice` once the stream ends. `stream_id` alone doesn't identify
    /// which stream this is - callers must always also match on the
    /// entry's `from`, since two different senders' independent
    /// per-connection counters can coincidentally collide.
    VoiceStreaming {
        stream_id: u64,
    },
    /// A voice row reconstructed from `resume_from_log` history that
    /// hasn't been loaded into memory yet - `client::export`'s reader
    /// deliberately never decodes the referenced `.wav` up front (see its
    /// own module doc). `wav_path` is `None` when the original autosave
    /// couldn't write the audio at the time (its `.log` line names a
    /// duration but no file) - replaying that row can only report that
    /// nothing was saved, not play anything. Replaying a `Some` row
    /// (`handle_messages_key`'s `Enter`) decodes it on the spot and
    /// mutates this entry into an ordinary `Voice` in place, so a second
    /// replay of the same row is instant.
    VoiceOnDisk {
        duration_ms: u32,
        wav_path: Option<PathBuf>,
    },
    /// One file transfer, consent-gated and streamed
    /// (`docs/PROTOCOL.md`'s file transfer section) - `stream_id` identifies
    /// it the same way `VoiceStreaming`'s does (paired with the entry's
    /// `from`, never alone), so a later progress/completion event can find
    /// and update this exact row (`UiState::update_file_entry`).
    File {
        filename: String,
        total: u64,
        stream_id: u64,
        status: FileTransferStatus,
    },
    /// An app-generated line about the conversation itself rather than
    /// something either party said - currently only the OTP layer's own
    /// errors/confirmations (`client::otp::notify`), mirrored here from the
    /// same text shown in the top-right status notice so the history of a
    /// session's setup isn't lost the moment that notice clears. Never
    /// given the OTP prefix (`render_messages`) - it would be
    /// redundant on a line that already names OTP explicitly, and the
    /// prefix is meant to mark *content*, not the app's own narration.
    System(String),
    /// A peer joining a channel, leaving one, or disconnecting entirely -
    /// rendered in yellow (`render_messages`), unlike the gray/italic
    /// `System` above, so it stands out as a presence change rather than
    /// app narration. Already-formatted text (`local_time_short` prefix
    /// plus the peer's name and the event) built by
    /// `channel::on_user_joined`/`on_user_left`/`ui::on_user_offline` -
    /// see `docs/SPEC.md` Functionality #12. Excluded from the OTP
    /// prefix for the same reason `System` is.
    Presence(String),
}

/// What the transfers behind one outgoing file row have reported.
///
/// A channel file send is one row - the same shape a channel voice message
/// has, and what the details popup lists every recipient of - but the
/// transfer underneath it is per recipient: each has its own `stream_id`,
/// its own worker, and its own accept/reject/progress/completion. This is
/// how those separate answers become the single status that row shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileRowProgress {
    /// Every transfer this row covers, and how many bytes each has sent.
    /// A transfer that has not started yet is present with `0`.
    pub(crate) sent: HashMap<u64, u64>,
    pub(crate) done: HashSet<u64>,
    pub(crate) failed: HashSet<u64>,
    pub(crate) rejected: HashSet<u64>,
}

impl FileRowProgress {
    /// The one status the row shows, from what every transfer behind it
    /// has said so far.
    ///
    /// While any are still going, the row reports the *least* advanced of
    /// them: the row means "this file, to these people", and it is not
    /// sent until it is sent to all of them. Once none are left, the row
    /// is Completed if any recipient took it, Rejected if they all
    /// declined, and Failed otherwise - a send nobody took because
    /// something broke is not the same as one everybody turned down.
    pub(crate) fn status(&self) -> FileTransferStatus {
        let outstanding: Vec<u64> = self
            .sent
            .keys()
            .copied()
            .filter(|s| {
                !self.done.contains(s) && !self.failed.contains(s) && !self.rejected.contains(s)
            })
            .collect();
        if outstanding.is_empty() {
            if !self.done.is_empty() {
                return FileTransferStatus::Completed;
            }
            if self.failed.is_empty() && !self.rejected.is_empty() {
                return FileTransferStatus::Rejected;
            }
            return FileTransferStatus::Failed;
        }
        let bytes = outstanding
            .iter()
            .map(|s| self.sent.get(s).copied().unwrap_or(0))
            .min()
            .unwrap_or(0);
        FileTransferStatus::InProgress { bytes }
    }
}

/// One recipient of an outgoing message, and whether that recipient has
/// acknowledged it yet (`docs/PROTOCOL.md` 7.2.1). A DM has exactly one of
/// these; a channel send has one per member it was addressed to, which is
/// what lets the row distinguish "nobody yet" from "some of them" from
/// "everyone" (`DeliveryStatus`).
#[derive(Debug, Clone, PartialEq)]
pub struct DeliveryRecipient {
    pub id: UserId,
    /// The nickname as it was at send time. Snapshotted rather than looked
    /// up when the info popup renders, so a recipient who has since left
    /// is still named rather than disappearing from the list of who a
    /// message went to.
    pub name: String,
    /// They could read it (`p2p_proto::ReceiptStage::Decrypted`).
    pub delivered: bool,
    /// This leg is not on the wire at all: it is waiting on disk for them
    /// to become reachable (`queue_send_messages`, `client::outbox`).
    ///
    /// Only ever read while `delivered` is false - once they have it, how
    /// it got to them is not what the popup is reporting. Cleared when the
    /// queue is flushed to them, so a leg that is genuinely in flight
    /// again stops claiming to be waiting.
    pub queued: bool,
    /// Whether this leg went out under the one-time-pad layer, and so
    /// answers to the pad's own acknowledgement rather than to an ordinary
    /// delivery receipt (`DeliveryProof`).
    ///
    /// Per recipient rather than per row, because a channel send can be
    /// mixed: some members reachable under a pad, others not, all sharing
    /// one `msg_id`.
    pub awaits_pad_ack: bool,
    /// They have since done the thing the message was for - played the
    /// audio, saved the file (`p2p_proto::ReceiptStage::Consumed`). Only
    /// ever true for a voice or file row, and shown only in the details
    /// popup: the log's own arrow stays a three-state summary of who has
    /// the message, not of what they did with it.
    pub consumed: bool,
    /// They opened this file in the preview popup without saving it
    /// (`p2p_proto::ReceiptStage::Viewed`) - a weaker claim than
    /// `consumed`, which always wins once true (`recipient_label`). File
    /// rows only.
    pub viewed: bool,
}

/// What one message row's indicator says, aggregated over its recipients
/// (`docs/SPEC.md` "Delivery acknowledgments"). `Some` never applies to a
/// DM - one recipient is either delivered or not - so a DM row's arrow is
/// only ever gray or green.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// Not one recipient has acknowledged it yet.
    None,
    /// At least one has, but not all of them.
    Some,
    /// Every recipient has.
    All,
}

impl DeliveryStatus {
    /// The colour this status paints `DELIVERY_ARROW` in: gray for
    /// nothing acknowledged yet, orange while only some of a channel's
    /// recipients have, green once all of them have.
    pub fn color(self) -> Color {
        match self {
            DeliveryStatus::None => Color::DarkGray,
            // Ratatui's `Yellow` is the terminal's colour 3, which every
            // palette renders as an orange/amber - this app's existing
            // "partway there" colour (a reconnect in progress, a peer
            // still being punched at).
            DeliveryStatus::Some => Color::Yellow,
            DeliveryStatus::All => Color::Green,
        }
    }
}

/// How one logged message's content was actually protected, as the
/// details popup reports it (`docs/SPEC.md` "Delivery acknowledgments").
///
/// Recorded on the row when it is logged rather than derived when the
/// popup opens: an OTP session's pad walks forward with every message, so
/// by the time anyone presses `i` the live figures describe some later
/// message, not this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageCrypto {
    /// The ordinary per-recipient PQ-hybrid envelope
    /// (`client::envelope`). `key_id` is a short fingerprint of the one
    /// public key involved (`crypto::short_fingerprint_der`), or `None`
    /// for a channel send addressed to several keys at once.
    Envelope { key_id: Option<String> },
    /// The one-time-pad layer (`docs/PROTOCOL.md` §16): which sequence
    /// this message is, the pad offset its key bytes start at, and the key
    /// file they were taken from.
    Otp {
        seq: u64,
        offset: u64,
        key_path: String,
        /// Whether a sealed envelope was built around the pad
        /// (`PqWrapped`) or the pad ciphertext travelled on its own
        /// (`Direct`, §16.2) - the one thing about a pad-protected message
        /// that is not the same on every pair, so the popup must not
        /// assume it.
        inside_envelope: bool,
    },
}

/// What the details popup calls each layer - the mechanism, not the
/// `my_key` tag `KeyMode::label` shows in the sidebar. Someone asking how
/// one specific message was encrypted is asking about the cipher.
impl MessageCrypto {
    pub fn method_label(&self) -> &'static str {
        match self {
            MessageCrypto::Envelope { .. } => {
                "ML-KEM-1024 + RSA-4096 -> AES-256-GCM, ML-DSA-87 signed"
            }
            MessageCrypto::Otp {
                inside_envelope: true,
                ..
            } => "one-time pad (XOR) inside the pq_hybrid envelope",
            MessageCrypto::Otp {
                inside_envelope: false,
                ..
            } => "one-time pad (XOR), carrying the message directly",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogEntry {
    pub from: UserId,
    pub from_name: String,
    pub body: MessageBody,
    pub outgoing: bool,
    /// Set after the fact, once an async send this row was optimistically
    /// logged for (`push_outgoing_dm`) turns out to have failed - currently
    /// only OTP sends, the one case that can fail per-message after the
    /// row is already showing (`client::otp::send_now`'s failure paths via
    /// `UiState::mark_dm_message_failed`). Never true for anything but an
    /// `outgoing` entry.
    pub failed: bool,
    /// When this row was created, in local time - what the info popup
    /// shows (`docs/SPEC.md` "Delivery acknowledgments"). Formatted at
    /// creation (`local_time_stamp`) rather than stored as an instant, the
    /// same way presence notices already carry their own formatted time.
    pub sent_at: String,
    /// The same instant as `sent_at`, in UTC (`export::utc_time_stamp`) -
    /// `sent_at` is local-time-only, and `client::export`'s autosave/manual
    /// export log lines need real UTC rather than whatever timezone this
    /// machine happens to be in.
    pub sent_at_utc: String,
    /// Set only on an outgoing message whose delivery this client tracks
    /// (`docs/PROTOCOL.md` 7.2.1). `None` everywhere else, including
    /// everything incoming (which was delivered to us by the fact of being
    /// here), so those rows show no indicator rather than a misleading
    /// gray one.
    pub delivery: Option<MessageDelivery>,
    /// The mirror image, on an *incoming* voice row: what this side still
    /// owes its sender a `Consumed` receipt for, because the audio decoded
    /// but was not played at the time - the sender had been muted, or was
    /// still under identity review. Taken and sent if the user ever
    /// replays the row (`handle_messages_key`'s Enter); `None` on every
    /// row that owes nothing, which is almost all of them.
    pub owed_receipt: Option<u64>,
    /// How this row's content was protected, for the details popup
    /// (`MessageCrypto`). `None` on a row there is nothing to say it
    /// about: a system or presence line this client wrote itself, or a
    /// channel send whose members do not share one scheme.
    pub crypto: Option<MessageCrypto>,
    /// Whether this row's voice has actually been heard - either it
    /// autoplayed live (the sending channel/DM was the one on screen when
    /// it arrived), or it was later replayed manually (`Enter` in
    /// `handle_messages_key`). `true` on every non-voice row, and on every
    /// outgoing voice row (the marker below only ever applies to something
    /// received - `render_messages` also gates on `!entry.outgoing` as a
    /// second safeguard). Drives the red "not listened" end-of-line
    /// marker for a received `MessageBody::Voice` row that never got
    /// either.
    pub listened: bool,
}

/// One outgoing message's delivery state: who it was addressed to, and
/// which of them have acknowledged it (`docs/PROTOCOL.md` 7.2.1).
#[derive(Debug, Clone, PartialEq)]
pub struct MessageDelivery {
    /// This message's own identifier within this client, handed out by
    /// `UiState::alloc_msg_id`. It goes on the wire as the reliable
    /// frame's delivery tag, so a recipient's acknowledgement can be routed
    /// straight back to this row (`UiState::mark_delivered`) - which a log
    /// index could not do, since a row lives in one of many logs.
    pub msg_id: u64,
    pub recipients: Vec<DeliveryRecipient>,
}

impl MessageDelivery {
    /// This message's aggregate status, over every recipient it was
    /// addressed to. A send that reached nobody - every member filtered
    /// out by the key-mode policy, or an empty channel - is `None` rather
    /// than a vacuous `All`: nothing was acknowledged because nothing went
    /// anywhere, and the row must not claim otherwise.
    pub fn status(&self) -> DeliveryStatus {
        let delivered = self.recipients.iter().filter(|r| r.delivered).count();
        if delivered == 0 || self.recipients.is_empty() {
            DeliveryStatus::None
        } else if delivered == self.recipients.len() {
            DeliveryStatus::All
        } else {
            DeliveryStatus::Some
        }
    }
}

impl LogEntry {
    /// The five fields every row in this app sets the same way, plus the
    /// seven that vary - the shape twenty call sites were writing out by
    /// hand.
    ///
    /// `sent_at`/`sent_at_utc` are stamped here rather than passed in, so
    /// a row's two timestamps can never come from two different instants.
    fn now(
        from: UserId,
        from_name: String,
        body: MessageBody,
        outgoing: bool,
        delivery: Option<MessageDelivery>,
        crypto: Option<MessageCrypto>,
    ) -> Self {
        Self {
            from,
            from_name,
            body,
            outgoing,
            failed: false,
            sent_at: local_time_stamp(),
            sent_at_utc: crate::client::export::utc_time_stamp(),
            owed_receipt: None,
            listened: true,
            delivery,
            crypto,
        }
    }

    /// A row that arrived from someone else. Never carries a `delivery`:
    /// that is an *outgoing* row's record of who has acknowledged it, and
    /// an incoming one was delivered by the fact of being here.
    pub(crate) fn incoming(
        from: UserId,
        from_name: String,
        body: MessageBody,
        crypto: Option<MessageCrypto>,
    ) -> Self {
        Self::now(from, from_name, body, false, None, crypto)
    }

    /// A row this client is sending, logged optimistically before the
    /// wire says anything (`docs/PROTOCOL.md` 7.2.1). `delivery` is what
    /// gives it an indicator; `None` leaves the row untracked.
    pub(crate) fn outgoing(
        from: UserId,
        from_name: String,
        body: MessageBody,
        delivery: Option<MessageDelivery>,
        crypto: Option<MessageCrypto>,
    ) -> Self {
        Self::now(from, from_name, body, true, delivery, crypto)
    }

    /// A yellow presence notice this client wrote itself - someone joined,
    /// left, was banned, a channel's admin changed.
    ///
    /// `crypto` is `None` because there is nothing to report: no message
    /// travelled. `from`/`from_name` are cosmetic, since a `Presence` row
    /// renders its text alone (`render_messages`) - an event about nobody
    /// in particular may pass `UserId(0)` and an empty name.
    pub(crate) fn presence(from: UserId, from_name: String, text: String) -> Self {
        Self::now(from, from_name, MessageBody::Presence(text), false, None, None)
    }

    /// An app-generated line - the OTP layer narrating its own setup
    /// (`client::otp::notify`). Same "nothing travelled, so nothing to
    /// report" reasoning as `presence`.
    pub(crate) fn system(from: UserId, from_name: String, text: String) -> Self {
        Self::now(from, from_name, MessageBody::System(text), false, None, None)
    }

    /// Overrides the default `listened: true` - for an incoming voice row
    /// whose audio was suppressed on arrival (a muted sender, a
    /// trust-gated one, or a room that was not on screen), which is what
    /// earns it the red "not listened" marker until it is replayed.
    pub(crate) fn with_listened(mut self, listened: bool) -> Self {
        self.listened = listened;
        self
    }

    /// This row's delivery status, or `None` for a row that tracks no
    /// delivery at all - such a row shows no indicator.
    pub fn delivery_status(&self) -> Option<DeliveryStatus> {
        self.delivery.as_ref().map(MessageDelivery::status)
    }

    /// Whether this row was sent and reached nobody at all - an empty
    /// channel, or every member excluded by the key-mode policy. Distinct
    /// from merely undelivered: there is no acknowledgement still to come,
    /// so the row is struck through rather than left looking like it is
    /// waiting (`render_messages`).
    pub fn reached_nobody(&self) -> bool {
        self.delivery
            .as_ref()
            .is_some_and(|d| d.recipients.is_empty())
    }
}
