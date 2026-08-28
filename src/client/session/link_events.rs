//! Reacting to a direct peer-to-peer link: what it opens, carries and
//! closes.
//!
//! `client::p2p` owns the link itself - punching it, keeping it alive,
//! reporting its state. This module is what the session *does* about
//! those reports: [`handle_p2p_event`] is the dispatcher, and the rest is
//! what its arms need - the presence and device-id envelopes a link
//! opening triggers (`docs/PROTOCOL.md` §7.1.5, §12.7), the queued
//! outbound work a recovered link flushes, and the state a forgotten peer
//! leaves behind.

use super::*;
use super::ui_action::handle_ui_action;

/// Handles a peer appearing while a daemon plan is in effect: the focus
/// sound, the desktop notification, and - for a DM focus - opening the
/// room and, if asked, proposing an OTP session.
///
/// Returns the OTP request as an action rather than performing it, so the
/// caller drives it through the same `handle_ui_action` path `/otp` uses;
/// there is exactly one implementation of "propose an OTP session".
pub(super) fn on_daemon_peer_appeared(
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
    // before anything that gates on the plan's `--initial-focus` - the two differ
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
    crate::client::global_notification::notify(
        crate::client::global_notification::Notification::new(
            format!("{nickname} is here"),
            if is_dm_focus {
                "Hold the push-to-talk shortcut to talk to them.".to_string()
            } else {
                match channel {
                    Some(channel) => format!("Joined {channel}."),
                    None => "Reachable directly.".to_string(),
                }
            },
        ),
    );

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
            pubkey_der: info.public_key_der,
        });
    }
    None
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
pub(super) fn forget_peer(ui_state: &mut UiState, session: &mut SessionState, user_id: UserId) {
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
pub(super) fn drop_peer_state(ui_state: &mut UiState, session: &mut SessionState, user_id: UserId) {
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
    session.own_pq_keys.forget(user_id);
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
pub(super) async fn handle_p2p_event(
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
            crate::client::channel::on_stream_start(
                ui_state, session, channel, from, from_name, stream_id,
            );
        }
        P2pEvent::StreamStart {
            channel: None,
            from,
            stream_id,
            msg_id,
        } => {
            let from_name = name_of(ui_state, from);
            remember_delivery_id(session, from, stream_id, msg_id);
            crate::client::direct_message::on_stream_start(
                ui_state, session, from, from_name, stream_id,
            );
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
            if session.own_file_targets.contains_key(&stream_id) {
                let me = ui_state.own_id.unwrap_or(UserId(0));
                ui_state.set_file_progress(me, stream_id, 0);
                // Setup, then the gate-check-then-encrypt-or-queue decision -
                // shared with the reconnect autoheal pass
                // (`client::otp::begin_file_content`) so a `FileAccepted`
                // reconstructed after this side's own restart behaves
                // identically to a live one.
                crate::client::otp::begin_file_content(session, ui_state, stream_id).await?;
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
            file_transfer::end_incoming_transfer(
                &mut session.active_file_transfers,
                from,
                stream_id,
            );
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
            crate::client::otp::on_pad_chunk(session, ui_state, from, stream_id, seq, blocks);
        }
        P2pEvent::OtpPadCancel { from, stream_id } => {
            let _ = stream_id;
            crate::client::otp::on_pad_cancel(session, ui_state, from);
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
            // (docs/PROTOCOL.md 7.2.1) - what moves a row's indicator off
            // gray, except on a leg that went out under the pad, where the
            // pad's own proof-carrying ack is the only thing that does
            // (`DeliveryProof`).
            ui_state.mark_delivered(
                peer,
                msg_id,
                stage,
                crate::client::tui::ui::DeliveryProof::Receipt,
            );
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
            target_key,
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
                let _ = tx.send((target_key, addr));
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
                    // Same trigger again, for a fresh pair's `OtpPadCommit`
                    // whose acknowledgement never made it back - the one
                    // provisioning payload whose loss leaves the two sides
                    // asymmetric (docs/PROTOCOL.md §16.1).
                    crate::client::otp::resend_pending_commits(wr, session, ui_state).await?;
                    // Same trigger again, for a `/endotp` notice this side
                    // still owes a peer who was unreachable when it ran (or
                    // whose acknowledgement never made it back) - see
                    // `docs/PROTOCOL.md` §16.6.
                    crate::client::otp::resend_pending_end_notices(wr, session, ui_state).await?;
                    // Same trigger again, for a file or voice send whose
                    // offer already left but whose *content* is still
                    // waiting on the peer's acceptance - covers this side's
                    // own restart in that exact window, which the three
                    // passes above do not (docs/PROTOCOL.md §16.2).
                    crate::client::otp::resume_pending_content_sends(session, ui_state).await?;

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
                    // A peer whose pin is not a readable keybundle gets no
                    // `ChannelPresence` (nothing can be sealed to them);
                    // an installed pad is what introduces them instead.
                    if let Some(action) = register_pad_only_peer(session, ui_state, peer) {
                        handle_ui_action(action, wr, ui_state, session).await?;
                    }
                    maybe_resolve_p2p_identity_data(session, ui_state, peer).await;
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
            maybe_resolve_p2p_identity_data(session, ui_state, from).await;
        }
        P2pEvent::OtpMessage {
            channel,
            from,
            seq,
            msg_id,
            envelope,
            sender_device_id,
        } => {
            let from_name = name_of(ui_state, from);
            crate::client::otp::on_message(
                session,
                ui_state,
                channel,
                from,
                from_name,
                seq,
                msg_id,
                envelope,
                sender_device_id,
            )
            .await?;
        }
        P2pEvent::OtpFileOffer {
            channel,
            from,
            stream_id,
            seq,
            msg_id,
            envelope,
            sender_device_id,
        } => {
            let from_name = name_of(ui_state, from);
            remember_delivery_id(session, from, stream_id, msg_id);
            crate::client::otp::on_file_offer(
                session,
                ui_state,
                channel,
                from,
                from_name,
                stream_id,
                seq,
                envelope,
                sender_device_id,
            )
            .await;
        }
        P2pEvent::OtpDeliveryAck { from, seq, proof } => {
            crate::client::otp::on_delivery_ack(wr, ui_state, session, from, seq, proof).await?;
        }
        P2pEvent::OtpFileContentSeq {
            from,
            stream_id,
            seq,
        } => {
            crate::client::otp::on_content_seq(session, ui_state, from, stream_id, seq).await;
        }
        P2pEvent::OtpVoiceOffer {
            from,
            stream_id,
            seq,
            msg_id,
            envelope,
            sender_device_id,
        } => {
            remember_delivery_id(session, from, stream_id, msg_id);
            crate::client::otp::on_voice_offer(
                wr,
                session,
                ui_state,
                from,
                stream_id,
                seq,
                envelope,
                sender_device_id,
            )
            .await;
        }
        P2pEvent::CallInvite {
            channel,
            from,
            call_id,
        } => {
            let from_name = name_of(ui_state, from);
            if voice_call::on_call_invite(wr, session, ui_state, from, from_name, call_id, channel)
                .await
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

pub(super) fn display_addr(addr: Option<SocketAddr>) -> String {
    addr.map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn display_device_id(id: Option<&str>) -> String {
    match id {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => "unknown".to_string(),
    }
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
    Reconciled {
        shared,
        join,
        leave,
    }
}

pub(super) fn send_channel_presence(session: &mut SessionState, ui_state: &UiState, peer: UserId) {
    let Some(nickname) = session.peer_link.direct_nickname_of(peer) else {
        return;
    };
    let device_id = session.peer_link.direct_device_id_of(peer);
    let Some(info) = direct_peer_identity(&session.id_store, &nickname, device_id.as_deref())
    else {
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
        &session.own_pq_private,
        session.pq_peer_keys.encap_for(peer),
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
pub(super) fn on_channel_presence(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    envelope: Envelope,
) -> Option<UiAction> {
    if envelope.content != Content::ChannelPresence {
        return None;
    }
    let nickname = session.peer_link.direct_nickname_of(from)?;
    let device_id = session.peer_link.direct_device_id_of(from);
    let Some(info) = direct_peer_identity(&session.id_store, &nickname, device_id.as_deref())
    else {
        // A `direct_punch_to` target with no key pinned at all - offer to
        // check whether this proof matches something already pinned under
        // a different nickname, instead of silently staying a
        // transport-only link forever (docs/PROTOCOL.md §7.1.5). Never
        // reached for a server-introduced peer: `direct_nickname_of`
        // already returned above for anyone not also a `direct_punch_to`
        // target of ours.
        let addr = session.peer_link.active_addr(from)?;
        ui_state.push_unknown_peer_review(
            from,
            nickname,
            crate::client::tui::ui::UnverifiedDirectProof::ChannelPresence { envelope },
            addr,
        );
        return None;
    };
    let plaintext = decrypt_own_envelope(&envelope, from, &info, None, session)?;
    apply_channel_presence_plaintext(session, ui_state, from, &nickname, &info, &plaintext)
}

/// The registration/membership half of `on_channel_presence`, factored out
/// so a confirmed unknown-peer match (`handle_ui_action`'s
/// `ConfirmUnknownPeerKey` arm) can finish it from the plaintext the scan
/// already recovered, without decrypting a second time.
pub(super) fn apply_channel_presence_plaintext(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    nickname: &str,
    info: &UserInfo,
    plaintext: &[u8],
) -> Option<UiAction> {
    // Only once they have proved who they are: seeding keys for an
    // unauthenticated claim would let anyone reaching the port decide what
    // this client encrypts to under that nickname.
    seed_direct_peer_keys(session, from, info);
    let theirs: Vec<String> = proto::decode(plaintext).ok()?;

    let ours: Vec<String> = ui_state
        .channels
        .iter()
        .filter(|c| c.joined)
        .map(|c| c.name.clone())
        .collect();
    let current = ui_state.channels_containing_member(from);
    let Reconciled {
        shared,
        join,
        leave,
    } = reconcile_direct_membership(&theirs, &ours, &current);

    // Departures first, so a peer moving from one channel to another is
    // never momentarily in neither.
    for channel in leave {
        ui_state.on_user_left(&channel, from);
    }

    let mut action = None;
    for channel in &join {
        // The same entry point `ServerMessage::UserJoined` uses: from here
        // on nothing downstream - the sidebar, channel sends, voice, the
        // call roster, `--initial-focus` - can tell this peer apart from one a
        // server introduced, which is the entire point.
        ui_state.on_user_joined(channel, info.clone());
        // And the same daemon hooks, so a punched peer arriving while
        // nobody is watching still rings, notifies, and takes the focus it
        // was started with.
        if action.is_none() {
            action = on_daemon_peer_appeared(ui_state, session, from, nickname, Some(channel));
        }
    }
    // A peer we share no channel with is still reachable as a DM - that is
    // what `direct_punch_to` on its own buys, and what `--initial-focus <nickname>`
    // addresses - so they are registered either way, and the daemon hooks
    // still run for them. Without this a DM-only pair got a working link
    // and nothing else: no focus placed, no chime, and - the one that
    // actually loses data - no `--otp` proposal, since that is what a
    // focused peer *appearing* is supposed to trigger.
    if shared.is_empty() {
        let first_sighting = !ui_state.known_users.contains_key(&from);
        ui_state.known_users.insert(from, info.clone());
        if first_sighting {
            action = on_daemon_peer_appeared(ui_state, session, from, nickname, None);
        }
    }
    action
}

pub(super) fn send_device_id_announce(session: &mut SessionState, ui_state: &UiState, peer: UserId) {
    let Some(user) = ui_state.known_users.get(&peer) else {
        return;
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
/// plaintext, an empty device_id, or a mislabeled `envelope.content`) -
/// there is no user-facing consequence beyond the review continuing to
/// show "unknown" for this peer's device id.
///
/// An empty string is refused, never cached, even though it's otherwise
/// `is_storable` - it's the reserved sentinel `idstore::IdStore` uses for
/// "no device known yet" (device-pinning plan §1), so a peer that
/// announced one (deliberately or not) must never be treated as if its
/// device genuinely resolved to "unbound": that would let its connection
/// silently adopt whatever unbound entry this nickname already has,
/// exactly the ambiguity the sentinel exists to avoid. Refusing it here
/// just leaves this peer's device "unknown" a little longer, the same as
/// before their real announce ever arrived - never a security-relevant
/// difference, since a device_id only ever narrows, never authenticates.
pub(super) fn on_device_id_announce(
    session: &mut SessionState,
    ui_state: &UiState,
    from: UserId,
    envelope: Envelope,
) {
    if envelope.content != Content::DeviceIdAnnounce {
        return;
    }
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return;
    };
    let Some(plaintext) = decrypt_own_envelope(&envelope, from, &sender, None, session) else {
        return;
    };
    let Some(device_id) = crate::client::device_id::accept_announced(&plaintext) else {
        return;
    };
    session.peer_device_ids.insert(from, device_id);
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
pub(super) async fn flush_queued_outbound(
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
            &session.own_pq_private,
            session.pq_peer_keys.encap_for(peer),
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
