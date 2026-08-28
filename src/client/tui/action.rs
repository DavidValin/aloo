//! What the UI asks the session to do.
//!
//! [`UiAction`] is the whole vocabulary between the terminal and the rest
//! of the app: `UiState`'s key handling returns one, and
//! `client::session::handle_ui_action` is the single place they are acted
//! on. Nothing here does anything - a variant is a request, already
//! validated by the UI as far as the UI can validate it, carrying exactly
//! what the session needs to encrypt it and put it on the wire.
//!
//! Kept as one flat enum on purpose: it is the app's contract with itself,
//! and one list you can read top to bottom is worth more than a tidier
//! hierarchy that has to be assembled in your head.


use crate::proto::{ChannelKind, UserId};

use super::ui::*;

#[derive(Debug, Clone, PartialEq)]
pub enum UiAction {
    /// Ctrl+O on the focused message: open this URL in the OS default
    /// browser (`session::handle_ui_action`, `client::open_url`).
    OpenUrl(String),
    JoinChannel {
        name: String,
        kind: ChannelKind,
        password: Option<String>,
    },
    /// Sent by the `/leave` command (`submit_input`) for the currently
    /// selected channel tab.
    LeaveChannel {
        name: String,
    },
    SendChannelText {
        channel: String,
        plaintext: String,
        recipients: Vec<Recipient>,
        /// This send's delivery tag, shared by every per-recipient frame
        /// it turns into and matching the log row's own
        /// `MessageDelivery::msg_id` - what routes each recipient's
        /// acknowledgement back to that one row (`docs/PROTOCOL.md` 7.2.1).
        msg_id: u64,
    },
    SendDirectText {
        to: UserId,
        plaintext: String,
        recipient_pubkey_der: Vec<u8>,
        /// Where this text landed in the DM's log when it was optimistically
        /// shown (`push_outgoing_dm`) - lets a later async failure
        /// (currently only an OTP send) find and mark that exact row
        /// (`UiState::mark_dm_message_failed`) rather than leaving a
        /// message that was never delivered looking identical to one that
        /// was.
        log_index: Option<usize>,
        /// This send's delivery tag - see `SendChannelText::msg_id`.
        msg_id: u64,
    },
    /// The target is captured at press-time (not release-time): live
    /// streaming needs to know who to address the wire `StreamXStart` to
    /// the moment recording starts, not just once it's done.
    VoiceRecordStart(VoiceTarget),
    VoiceRecordStop,
    ReplayVoice {
        duration_ms: u32,
        pcm: Vec<u8>,
        /// Who sent the clip being replayed - who `owed_receipt` is owed
        /// to.
        from: UserId,
        /// Set when this replay is the first time the clip has actually
        /// been heard, because playback was suppressed when it arrived
        /// (`docs/PROTOCOL.md` 7.2.1). The session sends that peer a
        /// `Consumed` receipt for it; `None` means nothing is owed -
        /// either it played on arrival, or it has been replayed before.
        owed_receipt: Option<u64>,
    },
    /// Escape while a replayed (previously-received) voice message is
    /// playing - `session::handle_ui_action` stops it on the mixer, since
    /// `UiState` has no access to audio.
    StopPlayback,
    /// The user confirmed Accept/Reject in the identity review popup for
    /// this peer (`docs/PROTOCOL.md` §12) - `session::handle_ui_action`
    /// does the actual `id_store`/`rekey` side effects, since `UiState`
    /// has no access to either.
    AcceptIdentity(UserId),
    RejectIdentity(UserId),
    /// "Yes" on the first unknown-direct-peer popup (`docs/PROTOCOL.md`
    /// §7.1.5) - `session::handle_ui_action` runs the real cryptographic
    /// scan, since `UiState` has no crypto/session access.
    CheckUnknownPeerIdentity(UserId),
    /// "No" on the first popup - no scan runs, no ban-counting; the
    /// captured proof is simply discarded.
    DeclineUnknownPeerIdentity(UserId),
    /// "Yes" on the second ("use <nickname>'s key?") popup - pins the
    /// matched key under the new nickname and completes registration from
    /// the plaintext the scan already recovered.
    ConfirmUnknownPeerKey(UserId),
    /// "No" on the second popup - discards this specific match; a later,
    /// distinct proof re-triggers the whole flow from the top.
    DeclineUnknownPeerKey(UserId),
    /// A file send confirmed in the `/file` popup (`crate::client::tui::file_send`) -
    /// `crate::client::channel::handle_send_file` builds and sends one `FileOffer`
    /// per ready recipient (rotating-key readiness is snapshotted here,
    /// same as a voice stream's recipients - see `docs/PROTOCOL.md`'s file
    /// transfer section); nothing is read from `path` until each recipient
    /// individually accepts.
    SendFileChannel {
        channel: String,
        path: std::path::PathBuf,
        filename: String,
        size: u64,
        recipients: Vec<Recipient>,
    },
    SendFileDirect {
        to: UserId,
        path: std::path::PathBuf,
        filename: String,
        size: u64,
        recipient_pubkey_der: Vec<u8>,
    },
    /// The user confirmed Accept/Reject in the file-offer popup for
    /// `(from, stream_id)` - `session::handle_ui_action` does the actual
    /// `FileAccept`/`FileReject` wire send and, on Accept, spawns the
    /// receiving worker (`UiState` has no access to the network or disk).
    AcceptFileOffer {
        from: UserId,
        stream_id: u64,
    },
    RejectFileOffer {
        from: UserId,
        stream_id: u64,
    },
    /// `Enter` on a staged `.txt` receive (`FileTransferStatus::Received`)
    /// - `session::handle_ui_action` reads the file (capped, if oversized)
    /// and hands it back via `UiState::open_file_preview`, and sends a
    /// `Viewed` receipt the first time this row is opened (`UiState` has
    /// no disk/network access to do either itself).
    RequestFilePreview {
        from: UserId,
        stream_id: u64,
    },
    /// `d` inside the preview popup - identical in effect to accepting any
    /// other file transfer's default save (`session::handle_ui_action`):
    /// moves the staged file into `~/.aloo/downloads` and settles delivery
    /// as `Consumed`, exactly as an ordinary (non-`.txt`) receive already
    /// does on arrival.
    SaveStagedFile {
        from: UserId,
        stream_id: u64,
    },
    /// Sent by the `/otp` command (`submit_input`) for the currently open
    /// DM room - the one and only trigger for starting an OTP session
    /// (`client::otp::handle_provisioning_command`). Never sent automatically.
    RequestOtpSession {
        peer: UserId,
        pubkey_der: Vec<u8>,
    },
    /// Sent by the `/new-otp-mail-key` command (`submit_input`) for the
    /// currently open DM room - the one and only trigger for provisioning a
    /// mail-only key (`client::otp::handle_provisioning_command`, same
    /// mechanics as `RequestOtpSession`, different purpose).
    RequestOtpMailKey {
        peer: UserId,
        pubkey_der: Vec<u8>,
    },
    /// The user confirmed "generate and share a fresh OTP pad?"
    /// (`otp_generate_confirm`) and then chose a size for it
    /// (`otp_size_input`, MB per key, `crypto::otp::OTP_SIZE_MB_MIN..=OTP_SIZE_MB_MAX`)
    /// - `client::otp::confirm_generate` does the actual generation and
    /// send.
    ConfirmOtpGenerate {
        size_mb: u32,
    },
    /// The user declined generating a pad, at either step
    /// (`otp_generate_confirm`'s Reject, or Escape out of `otp_size_input`)
    /// - purely local, nothing was ever sent.
    CancelOtpGenerate,
    /// Escape during generation or transfer: abandon the pad on both sides
    /// and erase whatever has been staged for it.
    CancelOtpPad {
        peer: UserId,
    },
    /// The user accepted an incoming OTP session proposal
    /// (`otp_invite_open`) - `client::otp::accept_invite`.
    AcceptOtpInvite,
    /// The user rejected it - `client::otp::reject_invite`.
    RejectOtpInvite,
    /// Sent by the `/endotp` command (`submit_input`) for the currently
    /// open DM room - unilaterally ends an active OTP session with that
    /// peer (`client::otp::handle_end_otp_command`), no accept/reject round
    /// trip the way starting one needs. The one DM action `submit_input`
    /// still allows while that peer is offline - see its doc.
    EndOtpSession {
        peer: UserId,
        pubkey_der: Vec<u8>,
    },
    /// Emitted on every keystroke in the mail compose view's To field
    /// (docs/PROTOCOL.md §17.1) - `client::otp_mail::check_recipient` runs
    /// the pinned-user + keychain + remaining-key checks (which need
    /// `SessionState` and the `otp` CLI, neither of which `UiState` has)
    /// and answers through `UiState::otp_mail_set_check`.
    CheckOtpMailRecipient {
        nickname: String,
    },
    /// Up/Down inside the compose view's device selector
    /// (`MailFocus::Device`) - re-runs `check_recipient` against the
    /// newly highlighted device only, never a full re-enumeration
    /// (`client::otp_mail::handle_select_device`).
    SelectOtpMailDevice {
        nickname: String,
        device_id: String,
    },
    /// The `/mail` command (`submit_input`) - checks the local `otp`
    /// binary is actually available before opening the compose view at all
    /// (`client::otp_mail::handle_open_otp_mail`), the same guard
    /// `RequestOtpSession`/`RequestOtpMailKey` already apply for
    /// `/otp`/`/new-otp-mail-key`. Never opens `UiState::open_otp_mail`
    /// directly from the UI layer, which has no way to check for itself.
    RequestOpenOtpMail,
    /// The `/mailbox` command (`submit_input`) - the session snapshots
    /// the mail store into mailbox rows
    /// (`UiState::otp_mail_set_mailbox_rows`), shown over the mail view
    /// the command just opened as their backdrop.
    OpenOtpMailbox,
    /// The user confirmed Send in the mail confirm popup - the *only*
    /// path that ever encrypts and uploads a mail
    /// (`client::otp_mail::handle_send`).
    SendOtpMail,
    /// Enter on a received mailbox row - the session XORs the stored
    /// (ciphertext, pad) pair in memory and opens the reader
    /// (`client::otp_mail::handle_read`).
    ReadOtpMail {
        mail_id: String,
    },
    /// The user confirmed removing a mail in the mailbox - for a received
    /// mail this securely destroys its stored ciphertext *and* pad
    /// (`client::otp_mail::handle_delete`).
    DeleteOtpMail {
        mail_id: String,
    },
    /// Enter on an attachment row in the mail reader - the session writes
    /// its bytes (already in memory with the open payload) to the
    /// downloads directory.
    SaveOtpMailAttachment {
        index: usize,
    },
    /// The `/call` command (`submit_input`) - starts a live voice call
    /// addressed to `target`. Never sent while already on a call or mid
    /// push-to-talk recording (`submit_input` refuses those itself, with a
    /// status notice); OTP-gating (a DM contact we currently have an OTP
    /// session with) is checked session-side, where `SessionState` is
    /// available (`crate::client::direct_message::handle_start_call`).
    StartCall(CallTarget),
    /// The user accepted an incoming call invite (`docs/PROTOCOL.md` "Live
    /// voice calls") - `crate::client::voice_call::accept_invite`.
    AcceptCallInvite {
        call_id: u64,
    },
    /// The user rejected it - `crate::client::voice_call::reject_invite`.
    RejectCallInvite {
        call_id: u64,
    },
    /// `m` on our own row in the call modal - toggles our own microphone,
    /// ours alone to lift, and announced to everyone on the call
    /// (`crate::client::voice_call::toggle_mute`).
    ToggleCallMute,
    /// The `/endcall` command, or the call modal's END CALL button -
    /// leaves the call we're currently on
    /// (`crate::client::voice_call::end_own_call`).
    EndCall,
    /// The host invited one more person from the call modal - only ever
    /// produced for the host of the call we're on
    /// (`crate::client::voice_call::invite_to_call`).
    InviteToCall {
        to: UserId,
    },
    /// The host muted (or unmuted) one participant with `m` on the call
    /// modal's roster - only the host can lift it again
    /// (`crate::client::voice_call::host_set_muted`).
    HostMuteCallMember {
        peer: UserId,
        muted: bool,
    },
    /// `/mute-voice <nickname>` / `/unmute-voice <nickname>`: stop (or
    /// resume) that nickname's voice messages playing themselves on
    /// arrival (docs/SPEC.md Functionality #15).
    ///
    /// An action rather than a change `UiState` applies itself, because it
    /// has to reach `~/.aloo/settings` - and every other persisted
    /// mutation in this app is likewise carried out session-side
    /// (`id_store`, `otp_store`), leaving `UiState` free of file I/O so
    /// tests can construct one without a filesystem. The session writes
    /// through and hands the stored set back via `set_muted_voice`, so
    /// what is in memory is always what is on disk.
    ///
    /// Deliberately carries a nickname, not a `UserId`: muting someone who
    /// is offline (or has never connected) is meaningful and expected.
    SetVoiceMuted {
        nickname: String,
        muted: bool,
    },
    /// The `/contacts` command - gathers every pinned identity
    /// (`idstore.rs`) merged with its live OTP keychain state, if any
    /// (`client::contacts::gather_contact_rows`), and hands the rows to
    /// the modal `open_contacts` already opened empty.
    OpenContacts,
    /// Ctrl+S - reads `~/.aloo/settings` fresh and hands both the
    /// editable values and the `direct_punch_to` rows to the modal
    /// `open_settings` already opened empty, same split as
    /// `OpenContacts`.
    OpenSettings,
    /// Any change on the settings popup's General/Direct Punch/OTP tabs
    /// (a toggle flipped, a character typed) - persists that draft over
    /// `~/.aloo/settings` through the same merging `Settings::update`
    /// write `SaveDirectPunchTargets` uses, and applies live the values
    /// that can be (the sound switches, `voice_autoplay`, the log
    /// switches, the direct-punch master switch). There is no Save
    /// button: the change is the save.
    SaveSettings(crate::client::tui::settings_popup::SettingsDraft),
    /// `Ctrl+E`'s popup was confirmed with at least one channel/DM
    /// checked - dumps each one's current in-memory log to
    /// `~/.aloo/exports/<server>/...` (`client::export::export_log`),
    /// every file from this one export sharing the `prefix` shortuuid.
    ExportSelected {
        prefix: String,
        channels: Vec<String>,
        dms: Vec<UserId>,
    },
    /// An add, edit or delete on the "Direct Punches" popup - persists the
    /// whole replacement list to `~/.aloo/settings` (a merging write, so a
    /// concurrent daemon's own keys are untouched) and immediately
    /// reconfigures `PeerLinkManager`'s scheduler with it.
    SaveDirectPunchTargets(Vec<crate::settings::DirectPunchTarget>),
    /// `r` on the contacts modal - re-runs the same gather, e.g. after the
    /// remaining OTP key has moved since it was last opened.
    RefreshContacts,
    /// `i` on a channel member, or `/info` in an open DM - gathers exactly
    /// one `(nickname, device_id)`'s pinned identity
    /// (`client::contacts::handle_request_user_info`, a narrower
    /// `gather_contact_rows`) and hands it to the popup `open_user_info`
    /// already opened empty. `nickname` is carried directly rather than
    /// re-read from `known_users` session-side, the same reasoning every
    /// other `UiAction` already follows.
    RequestUserInfo { peer: UserId, nickname: String },
    /// The user confirmed "delete contact" on the contacts modal's list -
    /// forgets `nickname` outright, every device (device-pinning plan §3):
    /// every device's identity pin, and each one's OTP keychain entries
    /// too if it had any (`client::contacts::handle_delete`). See
    /// `DeleteContactDevice` for the per-device counterpart, sent instead
    /// from a specific row's own PQH key detail popup.
    DeleteContact {
        nickname: String,
    },
    /// The contacts modal's PQH key detail popup, "Delete key" - removes
    /// just the one device that popup was opened for: its identity pin,
    /// and that device's own OTP/mail keychain entries, leaving every
    /// sibling device's pin and keys untouched
    /// (`client::contacts::handle_delete_contact_device`, device-pinning
    /// plan §3's additive delete). `None` is the unbound row.
    DeleteContactDevice {
        nickname: String,
        device_id: Option<String>,
    },
    /// The user confirmed "Install OTP key" on the contacts modal, having
    /// picked both key files with its own file browser - runs
    /// `otp --add-contact` against them directly
    /// (`client::contacts::handle_install_otp_key`), the manual
    /// counterpart to `/otp`'s handshake-driven provisioning.
    InstallOtpKey {
        nickname: String,
        /// Which of `nickname`'s devices this installs against - the row
        /// this was opened from; `None` is the unbound row, filed under
        /// the not-yet-qualified name and claimed on first use like any
        /// other unbound entry (device-pinning plan §3).
        device_id: Option<String>,
        /// Which of the two independent keychain entries this installs -
        /// `Live` for the plain `/otp` key, `Mail` for the OTP-mail-only
        /// key (`crypto::otp::contact_name_for_mail`). The contacts
        /// modal's top-level `o` shortcut always sends `Live`; the newer
        /// per-key detail popup (`ContactKeyKind::Otp`/`OtpMail`) can send
        /// either.
        purpose: crate::crypto::otp::OtpPurpose,
        enc_path: std::path::PathBuf,
        dec_path: std::path::PathBuf,
    },
    /// The contacts modal's OTP or OTP-mail key detail popup, "Delete
    /// key" - removes just that one purpose's keychain entry for the
    /// specific device that popup was opened for
    /// (`client::contacts::handle_delete_otp_key`), leaving the identity
    /// pin, the *other* purpose's key, and every sibling device untouched.
    /// `DeleteContactDevice` above is what the PQH key's own "Delete key"
    /// sends instead, since removing the identity pin necessarily takes
    /// both purposes with it.
    DeleteContactKey {
        nickname: String,
        device_id: Option<String>,
        purpose: crate::crypto::otp::OtpPurpose,
    },
    /// The PQH key detail popup's "Create key": imports an identity card
    /// file, pinning it as `Verified` if its self-signed nickname matches
    /// the contact row this was opened from
    /// (`client::contacts::handle_pin_identity_card`).
    PinIdentityCard {
        nickname: String,
        path: std::path::PathBuf,
    },
    /// The "Add contact" popup's PQH step (`client::tui::contacts::
    /// AddContactState`, device-pinning plan §3): the same import, but
    /// binding directly to `device_id` - typed by the user, not learned
    /// live - rather than the nickname's shared unbound entry
    /// (`client::contacts::handle_pin_identity_card_for_device`).
    PinIdentityCardForDevice {
        nickname: String,
        device_id: String,
        path: std::path::PathBuf,
    },
    /// The "Add contact" popup's own submit, before any key is ever
    /// chosen: reserves `(nickname, device_id)` (`device_id` empty for the
    /// nickname's shared unbound slot) as a bare placeholder with no key
    /// at all - `client::contacts::handle_add_bare_contact` - so the
    /// contact already exists and shows in the list even if the user
    /// leaves the key-details popup that opens right after without ever
    /// adding one; the identity card import that popup still offers is
    /// optional, not a precondition for creating the contact.
    AddBareContact {
        nickname: String,
        device_id: String,
    },
    /// `/contacts`' `x`: writes this client's own identity card - the
    /// live-session equivalent of `aloo --export-identity-card`
    /// (`client::contacts::handle_export_own_identity_card`), signed with
    /// the same `pq_hybrid` keybundle already loaded for this session,
    /// no separate prefix/nickname arguments needed. Purely local - never
    /// reaches the server.
    ExportOwnIdentityCard,
    /// A superadmin's `/users` (`UiState::try_superadmin_command`): sends
    /// `ClientMessage::RequestUsersList`, answered with
    /// `ServerMessage::UsersList` (`session::handle_server_message` ->
    /// `UiState::set_users_admin`).
    RequestUsersList,
    /// `/password <old> <new>` (`UiState::try_password_command`): sends
    /// `ClientMessage::ChangePassword`. The result comes back as
    /// `ServerMessage::ChangePasswordResult`, surfaced as a status notice
    /// (`session::handle_server_message`) - there is no local validation
    /// of `old` to skip a round trip, since only the server holds
    /// anything to check it against.
    ChangePassword {
        old_password: String,
        new_password: String,
    },
    /// `/daemon`: stop drawing and hand this session back to the
    /// background, leaving every connection, link and key exactly as they
    /// are (docs/SPEC.md "Running in background mode").
    ///
    /// Answered by `session::run_connected_session`'s own input arm rather
    /// than by `handle_ui_action`: it acts on the `Surface`, which that
    /// loop owns and the action handler - which is about network sends -
    /// has no business holding.
    Detach,
    /// Escape on the full-screen account-deactivated modal
    /// (`UiState::account_deactivated`) - the one key it answers.
    /// Answered by `session::run_connected_session`'s own input arm, the
    /// same way `Detach` is: it ends the whole session (the same exit an
    /// ordinary Ctrl+C already uses), which is a loop-level effect
    /// `handle_ui_action` - about network sends - has no business having.
    Quit,
    /// The channel admin's `/delete-channel` (after its confirmation
    /// popup), `/ban`, `/unban`, `/lock-joins`' Apply, or `/assign-admin`
    /// (after its confirmation popup) - see `docs/PROTOCOL.md`'s
    /// channel-ownership section.
    DeleteChannel {
        name: String,
    },
    BanFromChannel {
        channel: String,
        nickname: String,
    },
    UnbanFromChannel {
        channel: String,
        nickname: String,
    },
    SetChannelJoinLock {
        channel: String,
        allowed: Option<Vec<String>>,
    },
    AssignChannelAdmin {
        channel: String,
        nickname: String,
    },
    /// A superadmin's `/activate`/`/deactivate`/`/remove-account`/
    /// `/remove-channel` (`docs/PROTOCOL.md` §5.5) - see
    /// `UiState::try_superadmin_command`.
    AdminActivate {
        nickname: String,
    },
    AdminDeactivate {
        nickname: String,
        reason: String,
    },
    AdminRemoveAccount {
        nickname: String,
    },
    AdminRemoveChannel {
        name: String,
    },
}

impl UiAction {
    /// What this action needs a server for, or `None` if it can happen
    /// with nothing but a direct link (`docs/PROTOCOL.md` §7.1.5).
    ///
    /// Named rather than boolean because the answer is shown to the user:
    /// "joining a channel needs a server" is actionable, "unavailable" is
    /// not. Everything absent from this list works serverlessly, which is
    /// most of the app - text, voice, files, calls and live OTP sessions
    /// are all peer-to-peer and never involved a server in the first place.
    pub fn needs_server(&self) -> Option<&'static str> {
        match self {
            // Membership is server state. With no server, a channel is a
            // name both sides declare in their settings instead.
            Self::JoinChannel { .. } => Some("joining a channel"),
            // OTP *mail* is stored on the server for an offline recipient;
            // a live OTP session is peer-to-peer and stays available.
            Self::CheckOtpMailRecipient { .. }
            | Self::SelectOtpMailDevice { .. }
            | Self::RequestOpenOtpMail
            | Self::OpenOtpMailbox
            | Self::SendOtpMail
            | Self::ReadOtpMail { .. }
            | Self::DeleteOtpMail { .. }
            | Self::SaveOtpMailAttachment { .. } => Some("OTP mail"),
            // Channel ownership/moderation is server-arbitrated state -
            // there is nobody to enforce a ban, a lock, or an admin
            // handoff against an uncooperative peer with no server.
            Self::DeleteChannel { .. } => Some("deleting a channel"),
            Self::BanFromChannel { .. } | Self::UnbanFromChannel { .. } => {
                Some("banning or unbanning a channel member")
            }
            Self::SetChannelJoinLock { .. } => Some("locking channel joins"),
            Self::AssignChannelAdmin { .. } => Some("changing a channel's admin"),
            // Superadmin actions are server-side account/registry state -
            // there is no "without a server" meaning for any of them.
            Self::AdminActivate { .. } => Some("activating an account"),
            Self::AdminDeactivate { .. } => Some("deactivating an account"),
            Self::AdminRemoveAccount { .. } => Some("removing an account"),
            Self::AdminRemoveChannel { .. } => Some("removing a channel"),
            Self::RequestUsersList => Some("listing registered users"),
            // A password is server-registry state (`server::users_registry`)
            // - there is no account, and so nothing to change, without one.
            Self::ChangePassword { .. } => Some("changing your password"),
            // Everything else is peer-to-peer. Leaving is deliberately not
            // here: with no server a channel is a local declaration, so
            // leaving one is a local act that needs nobody's permission.
            _ => None,
        }
    }
}
