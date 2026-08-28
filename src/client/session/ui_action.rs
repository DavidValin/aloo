//! Acting on what the user asked for.
//!
//! [`handle_ui_action`] is the single place a [`UiAction`] is turned into
//! something real - encrypted, queued, written to disk, put on the wire.
//! The UI produces actions and never does any of that itself, which is
//! what lets the whole terminal surface be driven from a test with no
//! socket and no audio device; this module is the other side of that
//! bargain.
//!
//! Kept as one match rather than split by feature: the ordering between
//! arms occasionally matters, and one list you can read top to bottom is
//! worth more here than a tidier arrangement.

use super::*;

pub(super) async fn handle_ui_action(
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
        UiAction::OpenUrl(url) => {
            if crate::client::open_url::open(url.clone()) {
                ui_state.push_status_notice(format!("opening {url}"), true);
            } else {
                ui_state.push_status_notice(format!("could not open {url}"), false);
            }
        }
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
                            recipient_pubkey_der,
                        } => {
                            crate::client::direct_message::handle_voice_record_start(
                                wr,
                                ui_state,
                                session,
                                recorder,
                                stream_id,
                                to,
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
                            session
                                .own_stream_targets
                                .insert(stream_id, voice_stream::OwnStreamTarget::MailAttachment);
                            let echo_ducking = voice_stream::effective_echo_ducking(
                                &recorder,
                                session.echo_ducking,
                            );
                            voice_stream::spawn_record_accumulate_worker(
                                recorder,
                                stream_id,
                                session.own_stream_done_tx.clone(),
                                stop_rx,
                                session.auto_stop_tx.clone(),
                                echo_ducking,
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
            if accept_identity_review(session, ui_state, peer).await {
                voice_stream::play_bell_chime(session);
            }
        }
        UiAction::RejectIdentity(peer) => {
            // No `id_store`/`rekey` writes at all - the previous pin (if
            // any) is left exactly as it was, so this is never persisted
            // (docs/PROTOCOL.md §12).
            ui_state.resolve_identity_reject(peer);
        }
        UiAction::CheckUnknownPeerIdentity(peer) => {
            let Some(review) = ui_state.unknown_peer_reviews.get(&peer).cloned() else {
                return Ok(());
            };
            match scan_pinned_keys_for_match(
                session,
                ui_state,
                peer,
                &review.requested_nickname,
                &review.proof,
            )
            .await
            {
                Some(scan_match) => {
                    ui_state.advance_to_confirm_match(
                        peer,
                        scan_match.nickname,
                        scan_match.key_der,
                        scan_match.recovered,
                    );
                }
                None => {
                    ui_state.resolve_unknown_peer_review(peer);
                    // Only a genuinely completed, failed check counts toward
                    // a ban - declining the popup never reaches here at all.
                    if let BanOutcome::Banned =
                        session.peer_link.record_direct_proof_failure(review.source_addr.ip(), now_unix())
                    {
                        crate::log_warn!(
                            "banned {} after repeated unproven direct-punch checks",
                            review.source_addr.ip()
                        );
                    }
                    // `push_status_notice`, not `push_notice`: `audio_error`
                    // has no render call site anywhere in this codebase (see
                    // `push_status_notice`'s own doc) - this is the one
                    // surface that is actually shown.
                    ui_state.push_status_notice(
                        "Impossible to establish communication with the user without a key. \
                         Requires a server for key exchange or manually exchanging the keys"
                            .to_string(),
                        false,
                    );
                }
            }
        }
        UiAction::DeclineUnknownPeerIdentity(peer) => {
            // No scan ever ran, so no ban-counting either - declining costs
            // nothing, and a later, distinct proof asks again from scratch.
            ui_state.resolve_unknown_peer_review(peer);
        }
        UiAction::ConfirmUnknownPeerKey(peer) => {
            let Some(review) = ui_state.unknown_peer_reviews.get(&peer).cloned() else {
                return Ok(());
            };
            let UnknownPeerStage::ConfirmMatch {
                matched_nickname,
                matched_key_der,
                recovered,
            } = review.stage
            else {
                return Ok(());
            };
            // Unbound: no live device_id is available for this
            // serverless flow (§7.1.5's proof carries no device data),
            // resolved the same "filled in on first use" way any other
            // unbound entry is (§1) - here, by §5's per-message device
            // claim once real traffic flows under the now-pinned key.
            session.id_store.pin_new_device(
                &review.requested_nickname,
                "",
                &matched_key_der,
                idstore::Trust::Tofu,
            );
            session.id_store.save_or_warn();
            ui_state.resolve_unknown_peer_review(peer);
            match recovered {
                RecoveredProof::ChannelPresence { plaintext } => {
                    let info = direct_peer_identity(&session.id_store, &review.requested_nickname, None)
                        .expect("just pinned above");
                    if let Some(action) = apply_channel_presence_plaintext(
                        session,
                        ui_state,
                        peer,
                        &review.requested_nickname,
                        &info,
                        &plaintext,
                    ) {
                        Box::pin(handle_ui_action(action, wr, ui_state, session)).await?;
                    }
                }
                RecoveredProof::OtpMessage {
                    plaintext,
                    ack_proof,
                    contact_name,
                } => {
                    let info = direct_peer_identity(&session.id_store, &review.requested_nickname, None)
                        .expect("just pinned above");
                    let UnverifiedDirectProof::OtpMessage {
                        channel,
                        seq,
                        envelope,
                        ..
                    } = review.proof
                    else {
                        return Ok(());
                    };
                    crate::client::otp::apply_otp_message(
                        session,
                        ui_state,
                        channel,
                        peer,
                        matched_nickname,
                        seq,
                        &info,
                        &contact_name,
                        envelope.content,
                        plaintext,
                        ack_proof,
                    )
                    .await?;
                }
            }
        }
        UiAction::DeclineUnknownPeerKey(peer) => {
            // This specific match is discarded; a later, distinct proof
            // re-triggers the whole flow from Initial and scans again
            // cleanly (the one already spent - real key/replay state
            // consumed by the scan itself - cannot be un-spent, but nothing
            // further happens with it).
            ui_state.resolve_unknown_peer_review(peer);
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
        UiAction::RequestFilePreview { from, stream_id } => {
            if let Some((staged_path, filename)) = ui_state.staged_file(from, stream_id) {
                match crate::client::file_transfer::read_txt_preview(&staged_path) {
                    Ok((content, truncated)) => {
                        ui_state.open_file_preview(from, stream_id, filename, content, truncated);
                        // A bare open earns `Viewed` only once per staged
                        // receive - reopening the same preview (or one
                        // already fully saved and hence no longer tracked
                        // by `pending_receipts`) sends nothing further.
                        if let Some(msg_id) = session.pending_receipts.msg_id_of(from, stream_id)
                            && session.viewed_previews.insert((from, stream_id))
                        {
                            send_delivery_receipt(session, from, Some(msg_id), ReceiptStage::Viewed);
                        }
                    }
                    Err(e) => ui_state.push_status_notice(
                        format!("could not open {filename} for preview: {e}"),
                        false,
                    ),
                }
            }
        }
        UiAction::SaveStagedFile { from, stream_id } => {
            if let Some((staged_path, filename)) = ui_state.staged_file(from, stream_id) {
                match crate::client::file_transfer::save_staged_file(&staged_path) {
                    // Identical effect to an ordinary (non-staged) file's
                    // on-arrival save: `Completed`, and the one `Consumed`
                    // receipt `ReceiveDone` deliberately withheld for a
                    // staged receive (`pending_receipts` still holds it).
                    Ok(_) => {
                        ui_state.set_file_completed(from, stream_id);
                        settle_delivery_id(session, from, stream_id, true);
                    }
                    Err(e) => ui_state.push_status_notice(
                        format!("could not save {filename}: {e}"),
                        false,
                    ),
                }
            }
        }
        UiAction::RequestOtpSession { peer, pubkey_der } => {
            // Snapshotted so a refusal raised by *this* call can be told
            // apart from a notice that was already on screen.
            let notice_before = ui_state.status_notice.clone();
            crate::client::otp::handle_provisioning_command(
                wr,
                ui_state,
                session,
                peer,
                pubkey_der,
                crate::crypto::otp::OtpPurpose::Live,
            )
            .await?;
            // `handle_provisioning_command` refuses some proposals outright
            // - no `otp` binary, an unreadable peer identity, a peer with no
            // announced keybundle to share a fresh pad over - and those
            // never reach the peer at all, so
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
        UiAction::RequestOtpMailKey { peer, pubkey_der } => {
            crate::client::otp::handle_provisioning_command(
                wr,
                ui_state,
                session,
                peer,
                pubkey_der,
                crate::crypto::otp::OtpPurpose::Mail,
            )
            .await?;
        }
        UiAction::ConfirmOtpGenerate { size_mb } => {
            crate::client::otp::confirm_generate(wr, session, ui_state, size_mb).await?;
        }
        UiAction::CancelOtpGenerate => {
            crate::client::otp::cancel_generate(ui_state);
        }
        UiAction::CancelOtpPad { peer } => {
            crate::client::otp::cancel_pad(session, ui_state, peer);
        }
        UiAction::AcceptOtpInvite => {
            crate::client::otp::accept_invite(wr, session, ui_state).await?;
        }
        UiAction::RejectOtpInvite => {
            crate::client::otp::reject_invite(wr, session, ui_state).await?;
        }
        UiAction::EndOtpSession { peer, pubkey_der } => {
            crate::client::otp::handle_end_otp_command(wr, ui_state, session, peer, pubkey_der)
                .await?;
        }
        UiAction::CheckOtpMailRecipient { nickname } => {
            crate::client::otp_mail::handle_check_recipient(session, ui_state, nickname).await;
        }
        UiAction::SelectOtpMailDevice { nickname, device_id } => {
            crate::client::otp_mail::handle_select_device(session, ui_state, nickname, device_id)
                .await;
        }
        UiAction::RequestOpenOtpMail => {
            crate::client::otp_mail::handle_open_otp_mail(session, ui_state);
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
                recipient_pubkey_der,
            } => {
                crate::client::direct_message::handle_start_call(
                    wr,
                    ui_state,
                    session,
                    to,
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
        UiAction::RequestUserInfo { peer, nickname } => {
            crate::client::contacts::handle_request_user_info(session, ui_state, peer, nickname)
                .await;
        }
        UiAction::OpenSettings => {
            let settings = crate::settings::Settings::load_or_create(&crate::settings::default_path())
                .unwrap_or_else(|e| {
                    crate::log_warn!("could not read ~/.aloo/settings ({e}); using defaults");
                    crate::settings::Settings::default()
                });
            ui_state.set_settings_draft(
                crate::client::tui::settings_popup::SettingsDraft::from_settings(&settings),
            );
            ui_state.set_direct_punch_rows(settings.direct_punch_to);
        }
        UiAction::SaveSettings(draft) => {
            save_settings_draft(session, ui_state, draft);
        }
        UiAction::ExportSelected { prefix, channels, dms } => {
            for channel in &channels {
                let Some(tab) = ui_state.channels.iter().find(|c| &c.name == channel) else {
                    continue;
                };
                if let Err(e) = crate::client::export::export_log(
                    &ui_state.server_label,
                    crate::client::export::Surface::Channel(channel),
                    &prefix,
                    &tab.log,
                ) {
                    crate::log_warn!("could not export #{channel} ({e})");
                }
            }
            for peer in &dms {
                let Some(room) = ui_state.private_rooms.get(peer) else {
                    continue;
                };
                if let Err(e) = crate::client::export::export_log(
                    &ui_state.server_label,
                    crate::client::export::Surface::Dm(&room.peer.name),
                    &prefix,
                    &room.log,
                ) {
                    crate::log_warn!("could not export DM with {} ({e})", room.peer.name);
                }
            }
        }
        UiAction::SaveDirectPunchTargets(targets) => {
            let path = crate::settings::default_path();
            // A merging write: a daemon or another client editing this
            // same file concurrently keeps every key but this one, the
            // same reasoning `Settings::update`'s own doc gives for
            // `/mute-voice` and `remember_connection`.
            if let Err(e) = crate::settings::Settings::update(&path, |s| {
                s.direct_punch = true;
                s.direct_punch_to = targets.clone();
            }) {
                crate::log_warn!("could not save ~/.aloo/settings ({e})");
            }
            // Takes effect this same tick, not on the next restart -
            // `configure_direct_punch` rebuilds the scheduler from this
            // exact list.
            session.peer_link.configure_direct_punch(
                ui_state.own_name.clone(),
                targets.clone(),
                crate::client::p2p::utc_second_of_hour(),
            );
            ui_state.set_direct_punch_rows(targets);
            ui_state.push_status_notice("direct punch targets saved".to_string(), true);
        }
        UiAction::DeleteContact { nickname } => {
            crate::client::contacts::handle_delete(session, ui_state, nickname).await;
        }
        UiAction::DeleteContactDevice { nickname, device_id } => {
            crate::client::contacts::handle_delete_contact_device(
                session, ui_state, nickname, device_id,
            )
            .await;
        }
        UiAction::InstallOtpKey {
            nickname,
            device_id,
            purpose,
            enc_path,
            dec_path,
        } => {
            crate::client::contacts::handle_install_otp_key(
                session, ui_state, nickname, device_id, purpose, enc_path, dec_path,
            )
            .await;
        }
        UiAction::DeleteContactKey { nickname, device_id, purpose } => {
            crate::client::contacts::handle_delete_otp_key(
                session, ui_state, nickname, device_id, purpose,
            )
            .await;
        }
        UiAction::PinIdentityCard { nickname, path } => {
            crate::client::contacts::handle_pin_identity_card(session, ui_state, nickname, path)
                .await;
        }
        UiAction::PinIdentityCardForDevice { nickname, device_id, path } => {
            crate::client::contacts::handle_pin_identity_card_for_device(
                session, ui_state, nickname, device_id, path,
            )
            .await;
        }
        UiAction::AddBareContact { nickname, device_id } => {
            crate::client::contacts::handle_add_bare_contact(session, ui_state, nickname, device_id)
                .await;
        }
        UiAction::Detach => {
            // Intercepted by `run_connected_session`'s input arm, which
            // owns the `Surface` this acts on. A no-op rather than an
            // `unreachable!` so a future call path that routes one through
            // here degrades to "nothing happened" instead of aborting a
            // live session over a UI command.
        }
        UiAction::Quit => {
            // Intercepted by `run_connected_session`'s input arm, the same
            // way `Detach` is - ending the session is that loop's own
            // business, not a network send. A no-op here for the same
            // "degrade, don't abort" reason `Detach`'s arm gives.
        }
        UiAction::DeleteChannel { name } => {
            wr.send_control(&ClientMessage::DeleteChannel { name }).await?;
        }
        UiAction::BanFromChannel { channel, nickname } => {
            wr.send_control(&ClientMessage::BanFromChannel { channel, nickname })
                .await?;
        }
        UiAction::UnbanFromChannel { channel, nickname } => {
            wr.send_control(&ClientMessage::UnbanFromChannel { channel, nickname })
                .await?;
        }
        UiAction::SetChannelJoinLock { channel, allowed } => {
            wr.send_control(&ClientMessage::SetChannelJoinLock { channel, allowed })
                .await?;
        }
        UiAction::AssignChannelAdmin { channel, nickname } => {
            wr.send_control(&ClientMessage::AssignChannelAdmin { channel, nickname })
                .await?;
        }
        UiAction::AdminActivate { nickname } => {
            wr.send_control(&ClientMessage::AdminActivate { nickname }).await?;
        }
        UiAction::AdminDeactivate { nickname, reason } => {
            wr.send_control(&ClientMessage::AdminDeactivate { nickname, reason })
                .await?;
        }
        UiAction::AdminRemoveAccount { nickname } => {
            wr.send_control(&ClientMessage::AdminRemoveAccount { nickname })
                .await?;
        }
        UiAction::AdminRemoveChannel { name } => {
            wr.send_control(&ClientMessage::AdminRemoveChannel { name }).await?;
        }
        UiAction::ChangePassword { old_password, new_password } => {
            wr.send_control(&ClientMessage::ChangePassword { old_password, new_password })
                .await?;
        }
        UiAction::RequestUsersList => {
            wr.send_control(&ClientMessage::RequestUsersList).await?;
        }
        UiAction::ExportOwnIdentityCard => {
            crate::client::contacts::handle_export_own_identity_card(session, ui_state).await;
        }
    }
    Ok(())
}

/// Persists one change made on the Ctrl+S settings popup and applies the
/// half of it that can take effect without a restart.
///
/// Written through `Settings::update`'s merging write, never a plain
/// `save`, for exactly the reason `set_voice_muted` gives below: a
/// concurrently running `aloo --server` or daemon owns keys this process
/// has no business rewriting from its own in-memory copy.
///
/// Live: the two chime switches and `voice_autoplay` (mirrored onto
/// `SessionState`/`UiState`, which is what every play decision reads),
/// the two log switches, and `direct_punch` - turning that one off
/// reconfigures the scheduler with no targets, which stops the punching
/// this same tick rather than at the next start. Not live, and each said
/// so in its own description on screen: the global shortcut, registered
/// once at startup (`client::global_ptt`), and the No-IP updater, started
/// once for the session (`sync_noip_job`).
///
/// A write failure keeps the in-memory effect and says so, the same
/// policy `set_voice_muted` applies.
fn save_settings_draft(
    session: &mut SessionState,
    ui_state: &mut UiState,
    draft: crate::client::tui::settings_popup::SettingsDraft,
) {
    session.set_sound_switches(draft.roger_beep, draft.sound_notifications);
    // The durable queue and the transport's hand-off are one switch:
    // turning it on starts keeping what cannot go out, turning it off
    // hands the transport back its own short in-memory queue. Whatever a
    // previous run left on disk is picked up when it is turned on, not
    // discarded - a queued message is not this session's to throw away.
    session.set_queue_send_messages(draft.queue_send_messages);
    // `global_ptt_enabled` off silences the OS-level shortcut on the
    // spot; see `client::global_ptt::set_enabled` for what "on" can and
    // cannot do mid-session.
    crate::client::global_ptt::set_enabled(draft.global_ptt_enabled);
    ui_state.voice_autoplay = draft.voice_autoplay;
    ui_state.autosave_messages = draft.autosave_messages;
    ui_state.resume_from_log = draft.resume_from_log;
    ui_state.queue_send_messages = draft.queue_send_messages;
    // The scheduler is reconfigured from the master switch and the rows
    // the popup is showing: off means no targets at all, on means exactly
    // the list under it - so flipping it either way takes effect now.
    let targets = if draft.direct_punch {
        ui_state
            .settings_popup
            .as_ref()
            .map(|p| p.punches.rows.clone())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    session.peer_link.configure_direct_punch(
        ui_state.own_name.clone(),
        targets,
        crate::client::p2p::utc_second_of_hour(),
    );
    let path = crate::settings::default_path();
    match crate::settings::Settings::update(&path, |s| draft.apply_to(s)) {
        // The file is the source of truth for the two settings that are
        // applied by re-reading it rather than by being mirrored into
        // memory, so they are re-applied from what actually landed there.
        Ok(()) => {
            let stored = crate::settings::Settings::load_or_create(&path)
                .unwrap_or_else(|_| crate::settings::Settings::default());
            session.resync_noip(&stored);
            session.resync_otp_binary();
            crate::client::global_ptt::set_shortcut(&stored);
        }
        Err(e) => ui_state.push_status_notice(
            format!("changed for this session only - could not write ~/.aloo/settings ({e})"),
            false,
        ),
    }
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
pub(super) fn set_voice_muted(ui_state: &mut UiState, nickname: &str, muted: bool) {
    let result =
        crate::settings::Settings::update_muted_voice(&crate::settings::default_path(), |set| {
            if muted {
                set.insert(nickname.to_string());
            } else {
                set.remove(nickname);
            }
        });
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
pub(super) async fn accept_file_offer(
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
    // An OTP transfer's chunks are whatever its pair's framing puts on the
    // wire: sealed under `PqWrapped`, raw pad ciphertext under `Direct`
    // (`otp::otp_incoming_stream_key`). Everything else is always sealed.
    let key = match &offer.otp_contact_name {
        Some(_) => {
            crate::client::otp::otp_incoming_stream_key(session, from, &sender_public_key_der)
        }
        None => voice_stream::resolve_incoming_key(session, from, &sender_public_key_der),
    };
    let dest_name = crate::client::file_transfer::safe_filename(
        &crate::client::file_transfer::truncate_filename(&offer.filename),
    );
    // A `.txt` offer stages into `incoming_preview_dir()` instead of the
    // real downloads directory, so it can be previewed
    // (`UiState::open_file_preview`) without counting as saved
    // (`docs/PROTOCOL.md` 7.2.1a) - `handle_file_event`'s `ReceiveDone`
    // leaves it there rather than settling delivery, until
    // `UiAction::SaveStagedFile` (`d` in the preview) moves it out.
    // Scoped to non-OTP transfers: an OTP receive's own ack is earned by
    // successfully decrypting to `final_path` at all (`ack_proof_for_file`
    // reads it back), a materially different, proof-based mechanism this
    // item does not touch.
    let is_staged_preview =
        offer.otp_contact_name.is_none() && crate::client::file_transfer::is_txt_filename(&dest_name);
    let final_path = if is_staged_preview {
        crate::client::file_transfer::incoming_preview_dir().join(&dest_name)
    } else {
        crate::client::file_transfer::default_download_dir().join(&dest_name)
    };
    if is_staged_preview {
        session
            .staged_text_receives
            .insert((from, stream_id), final_path.clone());
    }
    // Only the destination differs for an OTP-active offer: a temp file,
    // decrypted whole into `final_path` once `handle_file_event`'s
    // `ReceiveDone` runs `client::otp::finish_incoming_file`.
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
