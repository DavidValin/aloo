//! Reacting to the server.
//!
//! [`handle_server_message`] is the dispatcher for everything the control
//! connection delivers (`docs/PROTOCOL.md` §3-§6), [`handle_server_event`]
//! for what the connection itself reports about its own health, and
//! [`on_server_reconnected`] is the catch-up pass a re-established
//! connection owes: re-joining channels, re-announcing, and re-sending
//! whatever was still outstanding when it dropped.

use super::*;
use super::ui_action::handle_ui_action;

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
pub(super) async fn handle_server_event(
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
            session.sync_noip_job();
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
pub(super) async fn on_server_reconnected(
    you: UserId,
    ui_state: &mut UiState,
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
) -> proto::Result<()> {
    session.server = ServerState::Connected;
    session.server_retry = None;
    session.sync_noip_job();
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

pub(super) async fn handle_server_message(
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
        | ServerMessage::RegisterResult { .. }
        | ServerMessage::IdentifyResult { .. } => {
            // only expected during the handshake in connect::handshake_as
        }
        ServerMessage::ChannelList { channels, superadmins } => {
            ui_state.superadmins = superadmins.into_iter().collect();
            // A daemon joins exactly what it was configured to join, and
            // never `the-hall` unless that was one of them - the whole
            // point of the mode is to be where the user actually wants
            // their voice to land. `on_list`'s auto-join is skipped
            // entirely rather than joined-then-left, which would show up
            // to everyone in the hall as a connect/disconnect flicker.
            if session.daemon_plan.is_some() {
                ui_state.on_channel_list(channels);
                request_daemon_joins(wr, ui_state, session).await?;
            } else if let Some(action) = crate::client::channel::on_list(ui_state, channels) {
                return Ok(Some(action));
            }
        }
        ServerMessage::Joined { channel, admin } => {
            let name = channel.name.clone();
            crate::client::channel::on_joined(ui_state, channel);
            ui_state.set_channel_admin(&name, admin);
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
        ServerMessage::ChannelRemoved { name, reason } => {
            ui_state.on_channel_removed(&name);
            ui_state.push_status_notice(format!("#{name}: {reason}"), false);
        }
        ServerMessage::UserBanned {
            channel,
            user_id,
            nickname,
        } => {
            if Some(user_id) == ui_state.own_id {
                ui_state.on_channel_removed(&channel);
                ui_state.push_status_notice(
                    format!("you have been banned from #{channel}"),
                    false,
                );
            } else {
                ui_state.on_user_banned(&channel, user_id, nickname);
            }
            if !ui_state.has_reason_to_keep_link(user_id) {
                session.peer_link.forget(user_id);
                ui_state.forget_link_status(user_id);
            }
        }
        ServerMessage::UserUnbanned { channel, nickname } => {
            ui_state.on_user_unbanned(&channel, nickname);
        }
        ServerMessage::ChannelJoinLockUpdated { channel, by } => {
            ui_state.on_join_lock_updated(&channel, by);
        }
        ServerMessage::ChannelAdminChanged { channel, admin } => {
            ui_state.on_channel_admin_changed(&channel, admin);
        }
        ServerMessage::AccountDeactivated { reason } => {
            ui_state.account_deactivated = Some(reason);
        }
        ServerMessage::UsersList { users } => {
            ui_state.set_users_admin(users);
        }
        ServerMessage::ChangePasswordResult { ok, reason } => {
            if ok {
                ui_state.push_status_notice("password changed".to_string(), true);
            } else {
                ui_state.push_status_notice(
                    format!("password not changed: {}", reason.unwrap_or_default()),
                    false,
                );
            }
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
                session.pq_peer_keys.bootstrap(
                    user.id,
                    bundle.bootstrap_encap().clone(),
                    fingerprint,
                );
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
                    crate::client::otp::contact_name_if_active(session, user.id, &user.public_key_der)
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
        ServerMessage::Error { message } => {
            // Historically a silent log line (RotateKey/RequestPeerLink
            // failures are internal protocol hiccups nobody typed a
            // command to trigger), but every new channel-admin/superadmin
            // command's own rejection ("only this channel's admin may do
            // that", "only a superadmin may do that", ...) rides this same
            // generic path and *is* a direct answer to something the user
            // just typed - so it also needs to actually reach the screen.
            crate::log_warn!("server error: {message}");
            // ...but not the two that answer nothing the user typed.
            // Signalling a link to a peer who has gone offline, or
            // offering them a key rotation, both fail this way as a
            // matter of course - the link simply retries - and putting a
            // red "unknown recipient" on screen for it makes an ordinary
            // absence look like a broken send. Named constants, shared
            // with the server, so the two cannot drift apart.
            if message != crate::proto::UNKNOWN_RECIPIENT
                && message != crate::proto::UNKNOWN_SENDER
            {
                ui_state.push_status_notice(message, false);
            }
        }
        ServerMessage::OtpMailResult {
            mail_id,
            ok,
            reason,
        } => {
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
                wr,
                session,
                ui_state,
                mail_id,
                from,
                contact_name,
                seq,
                ciphertext,
            )
            .await?;
        }
        ServerMessage::OtpMailDelivered { mail_id } => {
            crate::client::otp_mail::on_mail_delivered(wr, session, ui_state, mail_id).await?;
        }
    }
    Ok(None)
}
