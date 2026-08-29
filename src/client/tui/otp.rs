//! The UI's side of an OTP session: whether one is active with a peer,
//! the pad-generation and pad-transfer progress the popups draw from, and
//! the invite and size-input decisions still owed an answer.
//!
//! The protocol half is `client::otp`; the mail half is
//! `super::otp_mail`. Nothing here spends pad, talks to the `otp` binary,
//! or decides anything - each method records what has already happened or
//! what the user has just chosen.


use crate::proto::{UserId, UserInfo};

use super::ui::*;
use super::widgets::confirm_popup::Confirm;

impl UiState {
    /// Called by `client::otp_mail::refresh_unread_mail_count` whenever the
    /// received set can have changed.
    pub fn set_unread_otp_mail_count(&mut self, count: usize) {
        self.unread_otp_mail_count = count;
    }

    /// Opens the local "generate and share a fresh OTP pad?" confirmation
    /// (`/otp` found no existing keychain entry) - see
    /// `client::otp::handle_otp_command`.
    pub fn open_otp_generate_confirm(
        &mut self,
        peer: UserId,
        peer_name: String,
        pubkey_der: Vec<u8>,
        purpose: crate::crypto::otp::OtpPurpose,
    ) {
        self.otp_generate_confirm = Some(PendingOtpGenerate {
            peer,
            peer_name,
            pubkey_der,
            purpose,
        });
        self.otp_generate_focus = Confirm::Yes;
    }

    pub fn take_otp_generate_confirm(&mut self) -> Option<PendingOtpGenerate> {
        self.otp_generate_focus = Confirm::Yes;
        self.otp_generate_confirm.take()
    }

    /// Read-only counterpart of `take_otp_generate_confirm`, for a caller
    /// that only wants to observe whether the prompt is showing (and who it
    /// names) without answering it - mirrors `otp_invite_open`.
    pub fn otp_generate_confirm_open(&self) -> Option<&PendingOtpGenerate> {
        self.otp_generate_confirm.as_ref()
    }

    /// Opens the pad-size prompt (`handle_key`'s Accept branch for
    /// `otp_generate_confirm`) - carries `pending`'s peer info forward
    /// unchanged, since accepting only decided *that* a pad gets
    /// generated, not how big.
    pub fn open_otp_size_input(&mut self, pending: PendingOtpGenerate) {
        self.otp_size_input = Some(pending);
        self.otp_size_text.clear();
        self.otp_size_error = None;
    }

    pub fn take_otp_size_input(&mut self) -> Option<PendingOtpGenerate> {
        self.otp_size_text.clear();
        self.otp_size_error = None;
        self.otp_size_input.take()
    }

    /// Read-only counterpart of `take_otp_size_input`, mirroring
    /// `otp_generate_confirm_open`.
    pub fn otp_size_input_open(&self) -> Option<&PendingOtpGenerate> {
        self.otp_size_input.as_ref()
    }

    /// Opens the generation spinner for `peer`'s pad, at 0 of
    /// `2 * size_mb` MB - called by `client::otp::confirm_generate` the
    /// moment it hands generation to its background task.
    pub fn open_otp_keygen(
        &mut self,
        peer: UserId,
        peer_name: String,
        size_mb: u32,
        purpose: crate::crypto::otp::OtpPurpose,
    ) {
        self.otp_keygen = Some(OtpKeygenProgress {
            phase: OtpPadPhase::Generating,
            peer,
            peer_name,
            purpose,
            size_mb,
            written_bytes: 0,
            total_bytes: size_mb as u64 * 1024 * 1024 * 2,
            frame: 0,
        });
    }

    /// Moves the spinner's bar - one `otp_keygen_tx` progress report. A
    /// no-op once the popup is closed (a late report arriving after the
    /// generation was already resolved), and equally once it has moved on
    /// to the transfer: generation reports are counted against a different
    /// total, so applying one there would rewind a bar that has genuinely
    /// advanced.
    pub fn set_otp_keygen_progress(&mut self, written_bytes: u64, total_bytes: u64) {
        if let Some(progress) = self.otp_keygen.as_mut()
            && progress.phase == OtpPadPhase::Generating
        {
            progress.written_bytes = written_bytes;
            progress.total_bytes = total_bytes;
        }
    }

    /// Switches the popup to the transfer phase, bar back to zero.
    ///
    /// Generating a pad and pushing it across a link are both slow, for
    /// unrelated reasons, and this is the moment between them. Without it
    /// the popup vanished the instant generation finished and the peer's
    /// invitation appeared minutes later with nothing in between - which
    /// read as the handshake having silently failed.
    ///
    /// `size_mb` is per key; the transfer is both halves, so the total is
    /// twice it (`otp_pad::spawn_send_pad_worker` sends enc then dec).
    pub fn begin_otp_pad_transfer(
        &mut self,
        peer: UserId,
        peer_name: String,
        size_mb: u32,
        phase: OtpPadPhase,
        purpose: crate::crypto::otp::OtpPurpose,
    ) {
        self.otp_keygen = Some(OtpKeygenProgress {
            phase,
            peer,
            peer_name,
            purpose,
            size_mb,
            written_bytes: 0,
            total_bytes: size_mb as u64 * 1024 * 1024 * 2,
            frame: 0,
        });
    }

    /// Closes the spinner - generation finished, failed, or was abandoned.
    pub fn close_otp_keygen(&mut self) {
        self.otp_keygen = None;
    }

    /// Closes it only if it is reporting on `peer` - so a stale transfer
    /// ending cannot tear down a popup that has since moved on to another
    /// contact.
    pub fn close_otp_keygen_for(&mut self, peer: UserId) {
        if self.otp_keygen.as_ref().is_some_and(|p| p.peer == peer) {
            self.otp_keygen = None;
        }
    }

    /// Moves the transfer bar, if the popup is still reporting on `peer`.
    pub fn set_otp_pad_transfer_progress(&mut self, peer: UserId, sent_bytes: u64) {
        if let Some(progress) = self.otp_keygen.as_mut()
            && progress.peer == peer
            && progress.phase != OtpPadPhase::Generating
        {
            progress.written_bytes = sent_bytes.min(progress.total_bytes);
        }
    }

    pub fn otp_keygen_open(&self) -> Option<&OtpKeygenProgress> {
        self.otp_keygen.as_ref()
    }

    /// Advances the spinner one frame - driven by the session ticker, the
    /// same cadence `toggle_blink` rides, so the animation keeps moving
    /// even while no progress report has arrived (which is exactly when a
    /// user most needs to see it is still alive).
    pub fn tick_otp_keygen_spinner(&mut self) {
        if let Some(progress) = self.otp_keygen.as_mut() {
            progress.frame = (progress.frame + 1) % SPINNER_FRAMES.len();
        }
    }

    /// Queues an incoming OTP session proposal - mirrors `push_file_offer`
    /// exactly, one sender at a time (a second proposal from the same
    /// sender while one is already queued simply replaces it, since only
    /// the latest is still meaningful).
    #[allow(clippy::too_many_arguments)]
    pub fn push_otp_invite(
        &mut self,
        from: UserId,
        from_name: String,
        contact_name: String,
        peer_encryption_key: Option<Vec<u8>>,
        peer_decryption_key: Option<Vec<u8>>,
        pad_size_mb: Option<u32>,
    ) {
        self.otp_invites.insert(
            from,
            PendingOtpInvite {
                from,
                from_name,
                contact_name,
                peer_encryption_key,
                peer_decryption_key,
                pad_size_mb,
            },
        );
        if !self.otp_invite_queue.contains(&from) {
            self.otp_invite_queue.push_back(from);
        }
        if self.otp_invite_queue.front() == Some(&from) {
            self.otp_invite_focus = Confirm::Yes;
        }
    }

    pub fn otp_invite_open(&self) -> Option<&PendingOtpInvite> {
        let from = self.otp_invite_queue.front()?;
        self.otp_invites.get(from)
    }

    pub fn take_otp_invite(&mut self) -> Option<PendingOtpInvite> {
        let from = self.otp_invite_queue.pop_front()?;
        self.otp_invite_focus = Confirm::Yes;
        self.otp_invites.remove(&from)
    }

    /// Drops one specific peer's unanswered invitation, wherever it sits in
    /// the queue - unlike `take_otp_invite`, which only ever takes the one
    /// currently showing.
    ///
    /// Used when a fresh `/otp` to that same peer supersedes it
    /// (`client::otp::handle_otp_command`): answering their proposal and
    /// making our own at once would leave two live proposals for one
    /// contact name. Returns whether there was anything to drop. The
    /// returned invite is dropped here rather than handed back, so its key
    /// material is zeroized immediately (`PendingOtpInvite` is
    /// `ZeroizeOnDrop`).
    pub fn take_otp_invite_from(&mut self, from: UserId) -> bool {
        self.otp_invite_queue.retain(|queued| *queued != from);
        if self.otp_invites.remove(&from).is_some() {
            self.otp_invite_focus = Confirm::Yes;
            return true;
        }
        false
    }

    /// Whether `from` has an invite queued at all, at any position - not
    /// just the one on top (`otp_invite_open`). Used to refuse starting a
    /// second provisioning handshake (of either purpose) with a peer who
    /// already has one outstanding.
    pub fn has_otp_invite_from(&self, from: UserId) -> bool {
        self.otp_invites.contains_key(&from)
    }

    /// Records that a mutual-consent OTP session has genuinely started with
    /// `peer` - see `otp_active_peers`'s doc. Also (re-)called, idempotently,
    /// the moment a peer we already have a provisioned OTP contact for
    /// reconnects under a fresh `UserId` (`session::handle_server_message`'s
    /// `UserJoined` arm) - this per-connection flag would otherwise forget
    /// an otherwise still-active session across every reconnect, which is
    /// exactly what `/endotp` (and nothing else) is supposed to end.
    pub fn mark_otp_active(&mut self, peer: UserId) {
        self.otp_active_peers.insert(peer);
    }

    /// The reverse of `mark_otp_active` - `/endotp` ending the session, on
    /// either side (`client::otp::handle_end_otp_command`/`on_end_session`).
    /// Also drops any stale key-metadata snapshot (`otp_key_status`) for
    /// this peer, so a session started fresh with them afterward shows only
    /// its own figures, never a leftover reading from the one just ended.
    pub fn clear_otp_active(&mut self, peer: UserId) {
        self.otp_active_peers.remove(&peer);
        self.otp_key_status.remove(&peer);
    }

    /// Whether `peer`'s messages should carry the `OTP_ICON` prefix right
    /// now.
    pub fn is_otp_active(&self, peer: UserId) -> bool {
        self.otp_active_peers.contains(&peer)
    }

    /// Moves everything this session holds about `previous` onto the id
    /// `user` has now, so a peer who reconnects continues in the very same
    /// DM room rather than opening a second one beside it
    /// (`docs/SPEC.md` "Connected UI").
    ///
    /// Only what is genuinely *about the person* moves: their room and its
    /// history, where it sits on the DM selector, and any one-time-pad
    /// session, which by design outlives a disconnect and only `/endotp`
    /// ever ends (`docs/PROTOCOL.md` §16.6). Everything that belongs to the
    /// connection that just closed - an unanswered identity review, held
    /// messages, a file offer or call invite in flight - is deliberately
    /// left behind: those are transactions with a session that is over,
    /// and the new connection gets its own, including its own identity
    /// check.
    pub fn adopt_returning_peer(&mut self, previous: UserId, user: &UserInfo) {
        let id = user.id;
        self.offline.remove(&previous);
        self.link_status.remove(&previous);
        self.known_users.remove(&previous);
        if let Some(mut room) = self.private_rooms.remove(&previous) {
            // The room keeps its whole log; only who it is *with* is
            // restated, since their key material and id are both new.
            room.peer = user.clone();
            // Every row's delivery record names the id this person had
            // when that message was written, and acknowledgements are
            // matched against it (`mark_delivered`). For anything that was
            // *held* for them that id is precisely the one that never
            // comes back - the durable queue is keyed by nickname for
            // exactly that reason - so leaving these behind means the
            // message arrives, they read it, and the sender's row still
            // says it never got there. Only the id moves; the name is left
            // as it was at send time, which is what it is snapshotted for.
            for entry in &mut room.log {
                if let Some(delivery) = entry.delivery.as_mut() {
                    for recipient in &mut delivery.recipients {
                        if recipient.id == previous {
                            recipient.id = id;
                        }
                    }
                }
            }
            self.private_rooms.insert(id, room);
        }
        for entry in &mut self.dm_order {
            if *entry == previous {
                *entry = id;
            }
        }
        if self.selected_dm == Some(previous) {
            self.selected_dm = Some(id);
        }
        if self.active_private_room == Some(previous) {
            self.active_private_room = Some(id);
        }
        if self.otp_active_peers.remove(&previous) {
            self.otp_active_peers.insert(id);
        }
        if let Some(status) = self.otp_key_status.remove(&previous) {
            self.otp_key_status.insert(id, status);
        }
    }

    /// Records `peer`'s latest `otp --show-contact` snapshot - see
    /// `otp_key_status`'s doc for who calls this and how often.
    pub fn set_otp_key_status(
        &mut self,
        peer: UserId,
        status: crate::client::otp_cli::OtpKeyStatus,
    ) {
        self.otp_key_status.insert(peer, status);
    }

    /// `peer`'s most recently fetched key-metadata snapshot, if any -
    /// `render_otp_header` falls back to `OtpKeyStatus::default()` (all
    /// zeros) when `None`, e.g. the brief window before a session's own
    /// first fetch completes.
    pub fn otp_key_status_for(
        &self,
        peer: UserId,
    ) -> Option<&crate::client::otp_cli::OtpKeyStatus> {
        self.otp_key_status.get(&peer)
    }
}
