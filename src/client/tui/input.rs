//! Everything the user does with a key, a mouse click or a paste, and the
//! selector navigation those keys drive.
//!
//! One `impl UiState` block, split out of `ui.rs` the same way
//! `super::channel` and `super::direct_message` already add theirs - the
//! type stays defined next door; only these methods live here.
//!
//! The shape every entry point shares: a key arrives, state changes, and
//! an optional `UiAction` comes back for `client::session` to actually put
//! on the wire. Nothing here does I/O or encrypts anything, which is what
//! lets the whole surface be driven from a test with no socket and no
//! audio device.
//!
//! `handle_key` is the top of it, and its order *is* the modal precedence:
//! the deactivated-account modal outranks an identity review, which
//! outranks the ordinary view. Read it top to bottom to see which overlay
//! wins.

use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::client::p2p::LinkStatus;
use crate::proto::{ChannelKind, UserId};

use super::ui::*;
use super::widgets::confirm_popup::Confirm;

impl UiState {
    /// Handles one key event. Space is push-to-talk everywhere *except*
    /// with focus on the compose bar, where it types a literal space.
    /// Release detection doesn't rely on `KeyEventKind::Release` (Kitty
    /// terminals only): every Press/Repeat refreshes `recording_last_seen`
    /// and `tick_recording_timeout` auto-stops once that goes quiet for
    /// `RECORD_HOLD_TIMEOUT`; a real `Release` still stops immediately as
    /// a fast path.
    pub fn handle_key(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        kind: KeyEventKind,
    ) -> Option<UiAction> {
        // A live account deactivation outranks everything, including an
        // outstanding identity review: the account is locked out right
        // now, so nothing else this session could still do matters.
        // Absorbs every key but Escape, which ends the whole session (no
        // `UiAction` can express a loop-level exit, so this is answered
        // directly by `session::run_connected_session`'s own input arm,
        // the same way `Detach` already is).
        if self.account_deactivated.is_some() {
            return match (kind, code) {
                (KeyEventKind::Press | KeyEventKind::Repeat, KeyCode::Esc) => Some(UiAction::Quit),
                _ => None,
            };
        }

        // An outstanding identity review takes priority over *everything*
        // else, including Ctrl+H - a peer's identity needs an explicit
        // decision before anything else happens, and unlike the help
        // overlay there is deliberately no dismiss key: `Left`/`Right`/`Tab`
        // move the Accept/Reject focus, `Enter` confirms it, nothing else
        // does anything (docs/PROTOCOL.md §12).
        if let Some(&peer) = self.identity_review_queue.front() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.identity_review_focus.toggle();
                        None
                    }
                    KeyCode::Enter => match self.identity_review_focus {
                        Confirm::Yes => Some(UiAction::AcceptIdentity(peer)),
                        Confirm::No => Some(UiAction::RejectIdentity(peer)),
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // An outstanding unknown-direct-peer review is next: still an
        // absorb-everything decision (docs/PROTOCOL.md §7.1.5), but a
        // genuine identity-mismatch warning above still wins if both are
        // somehow open at once, since impersonation outranks a peer this
        // side has simply never met yet.
        if let Some(&peer) = self.unknown_peer_review_queue.front() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.unknown_peer_review_focus.toggle();
                        None
                    }
                    KeyCode::Enter => {
                        let stage = self.unknown_peer_reviews.get(&peer).map(|r| &r.stage);
                        match (stage, self.unknown_peer_review_focus) {
                            (Some(UnknownPeerStage::Initial), Confirm::Yes) => {
                                Some(UiAction::CheckUnknownPeerIdentity(peer))
                            }
                            (Some(UnknownPeerStage::Initial), Confirm::No) => {
                                Some(UiAction::DeclineUnknownPeerIdentity(peer))
                            }
                            (Some(UnknownPeerStage::ConfirmMatch { .. }), Confirm::Yes) => {
                                Some(UiAction::ConfirmUnknownPeerKey(peer))
                            }
                            (Some(UnknownPeerStage::ConfirmMatch { .. }), Confirm::No) => {
                                Some(UiAction::DeclineUnknownPeerKey(peer))
                            }
                            (None, _) => None,
                        }
                    }
                    _ => None,
                },
                _ => None,
            };
        }

        // An outstanding OTP session proposal from a peer is next -
        // "accepted by both parties" means this decision can't be
        // deferred behind ordinary typing, same absorb-everything shape as
        // identity review/file offer.
        if self.otp_invite_queue.front().is_some() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.otp_invite_focus.toggle();
                        None
                    }
                    KeyCode::Enter => match self.otp_invite_focus {
                        Confirm::Yes => Some(UiAction::AcceptOtpInvite),
                        Confirm::No => Some(UiAction::RejectOtpInvite),
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // Generation actually running - the step after the size prompt
        // below. Absorbs every key without acting on any: there is nothing
        // to decide here, and no cancel either, because the pad is already
        // being written to disk by a real subprocess (abandoning it
        // half-written is exactly the stale-half-pad state
        // `stage_pending_setup` exists to avoid). It closes itself when the
        // generation reports back.
        // Generation and transfer are both long enough to be regretted -
        // minutes, and gigabytes of disk - so Escape has to reach them.
        // Everything else is still absorbed: there is nothing else to
        // decide while one is running.
        if let Some(progress) = self.otp_keygen.as_ref() {
            return match (kind, code) {
                (KeyEventKind::Press | KeyEventKind::Repeat, KeyCode::Esc) => {
                    Some(UiAction::CancelOtpPad {
                        peer: progress.peer,
                    })
                }
                _ => None,
            };
        }

        // The pad-size prompt, shown right after Accept below - same
        // priority tier, and mutually exclusive with `otp_generate_confirm`
        // (checked first only because it's the one more likely to be open
        // once both exist, not because order matters here).
        if self.otp_size_input.is_some() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Esc => Some(UiAction::CancelOtpGenerate),
                    KeyCode::Enter => match self.otp_size_text.parse::<u32>() {
                        Ok(size_mb) if crate::crypto::otp::otp_size_mb_in_range(size_mb) => {
                            Some(UiAction::ConfirmOtpGenerate { size_mb })
                        }
                        _ => {
                            self.otp_size_error = Some(format!(
                                "enter a whole number between {} and {}",
                                crate::crypto::otp::OTP_SIZE_MB_MIN,
                                crate::crypto::otp::OTP_SIZE_MB_MAX
                            ));
                            None
                        }
                    },
                    KeyCode::Backspace => {
                        self.otp_size_text.pop();
                        self.otp_size_error = None;
                        None
                    }
                    // 7 digits covers the max (1048576 - 1TB per key) with no
                    // room for a typo'd extra digit to even be entered.
                    KeyCode::Char(c) if c.is_ascii_digit() && self.otp_size_text.len() < 7 => {
                        self.otp_size_text.push(c);
                        self.otp_size_error = None;
                        None
                    }
                    _ => None,
                },
                _ => None,
            };
        }

        // The local "generate and share a fresh pad?" confirmation - same
        // priority tier as the invite popup above (they can never both be
        // open at once: typing `/otp` is itself unreachable while any
        // modal popup, including an invite, is absorbing every key).
        if self.otp_generate_confirm.is_some() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.otp_generate_focus.toggle();
                        None
                    }
                    KeyCode::Enter => match self.otp_generate_focus {
                        Confirm::Yes => {
                            // Confirming only decides "yes, generate one" -
                            // the size prompt above is the next step, not
                            // an immediate `ConfirmOtpGenerate`.
                            let pending = self
                                .take_otp_generate_confirm()
                                .expect("otp_generate_confirm.is_some() was just checked");
                            self.open_otp_size_input(pending);
                            None
                        }
                        Confirm::No => Some(UiAction::CancelOtpGenerate),
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // An outstanding file offer is next-highest priority - below an
        // identity review (trust is the more fundamental concern) but
        // above everything else, including Ctrl+H, same reasoning and same
        // shape as the identity review block above: every other key is
        // absorbed while one is showing.
        if let Some(&(from, stream_id)) = self.file_offer_queue.front() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.file_offer_focus.toggle();
                        None
                    }
                    KeyCode::Enter => match self.file_offer_focus {
                        Confirm::Yes => {
                            Some(UiAction::AcceptFileOffer { from, stream_id })
                        }
                        Confirm::No => {
                            Some(UiAction::RejectFileOffer { from, stream_id })
                        }
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // An incoming call invite is the same priority tier as a file
        // offer - both are "someone needs a consent decision before
        // anything else happens" popups, absorbing every key the same way.
        if let Some(&call_id) = self.call_invite_queue.front() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.call_invite_focus.toggle();
                        None
                    }
                    KeyCode::Enter => match self.call_invite_focus {
                        Confirm::Yes => self.accept_call_invite(call_id),
                        Confirm::No => Some(UiAction::RejectCallInvite { call_id }),
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // `/delete-channel`/`/assign-admin`'s confirmation - same tier and
        // shape as `/call`'s just below, reusing `Confirm`.
        if self.channel_command_confirm.is_some() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.channel_command_confirm_focus.toggle();
                        None
                    }
                    KeyCode::Esc => {
                        self.channel_command_confirm = None;
                        None
                    }
                    KeyCode::Enter => {
                        let pending = self.channel_command_confirm.take()?;
                        match self.channel_command_confirm_focus {
                            Confirm::Yes => Some(match pending.action {
                                ChannelCommandConfirmAction::DeleteChannel { name } => {
                                    UiAction::DeleteChannel { name }
                                }
                                ChannelCommandConfirmAction::AssignAdmin { channel, nickname } => {
                                    UiAction::AssignChannelAdmin { channel, nickname }
                                }
                            }),
                            Confirm::No => None,
                        }
                    }
                    _ => None,
                },
                _ => None,
            };
        }

        // The `/call` confirmation is the same "absorb everything until
        // it's answered" tier as the popups above - nothing is rung until
        // it is resolved.
        if self.call_confirm.is_some() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.call_confirm_focus.toggle();
                        None
                    }
                    KeyCode::Esc => {
                        self.call_confirm = None;
                        None
                    }
                    KeyCode::Enter => {
                        let pending = self.call_confirm.take()?;
                        match self.call_confirm_focus {
                            Confirm::Yes => Some(UiAction::StartCall(pending.target)),
                            Confirm::No => None,
                        }
                    }
                    _ => None,
                },
                _ => None,
            };
        }

        // The call modal owns every key while it is actually on screen -
        // either overlaid (not yet minimized) or as its own selected tab.
        // Below the consent popups above (a trust decision always comes
        // first) and above everything else, including Ctrl+H.
        if self.call_modal_showing() && kind != KeyEventKind::Release {
            return self.handle_call_modal_key(code);
        }

        // The message info popup owns every key while it is open
        // (`docs/SPEC.md` "Delivery acknowledgments"): Esc and `i` close
        // it, everything else is absorbed. Above Ctrl+H so it is a real
        // popup rather than something the help overlay can be stacked on
        // top of, and below the consent popups above, which must always
        // stay answerable.
        if self.message_info.is_some() {
            if kind == KeyEventKind::Press
                && matches!(code, KeyCode::Esc | KeyCode::Char('i') | KeyCode::Char('I'))
            {
                self.message_info = None;
            }
            return None;
        }

        // The `.txt` preview popup - same "absorb everything, Esc closes
        // it" tier as message-info above, plus scrolling and `d` to save
        // (identical effect to any other file transfer's default save;
        // `session::handle_ui_action` does the actual move + receipt,
        // since `UiState` has no disk/network access). Closes itself on
        // `d` rather than waiting for a round trip - the save is a local
        // move, not something that can meaningfully fail from here.
        if let Some(preview) = self.file_preview.as_ref() {
            let (from, stream_id) = (preview.from, preview.stream_id);
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Esc => {
                        self.file_preview = None;
                        None
                    }
                    KeyCode::Char('d') | KeyCode::Char('D') => {
                        self.file_preview = None;
                        Some(UiAction::SaveStagedFile { from, stream_id })
                    }
                    KeyCode::Up => {
                        if let Some(preview) = self.file_preview.as_mut() {
                            preview.scroll = preview.scroll.saturating_sub(1);
                        }
                        None
                    }
                    KeyCode::Down => {
                        if let Some(preview) = self.file_preview.as_mut() {
                            preview.scroll += 1;
                        }
                        None
                    }
                    KeyCode::PageUp => {
                        if let Some(preview) = self.file_preview.as_mut() {
                            preview.scroll = preview.scroll.saturating_sub(HELP_SCROLL_PAGE);
                        }
                        None
                    }
                    KeyCode::PageDown => {
                        if let Some(preview) = self.file_preview.as_mut() {
                            preview.scroll += HELP_SCROLL_PAGE;
                        }
                        None
                    }
                    KeyCode::Home => {
                        if let Some(preview) = self.file_preview.as_mut() {
                            preview.scroll = 0;
                        }
                        None
                    }
                    _ => None,
                },
                _ => None,
            };
        }

        // The user-info popup (`i`/`/info`) is the same "absorb every key,
        // Esc or `i` closes it" tier as message-info above.
        if self.user_info.is_some() {
            if kind == KeyEventKind::Press
                && matches!(code, KeyCode::Esc | KeyCode::Char('i') | KeyCode::Char('I'))
            {
                self.user_info = None;
            }
            return None;
        }

        // The superadmin `/users` popup - same tier, but Esc-only, since
        // there is no single letter shortcut that opened it the way `i`
        // did above.
        if self.users_admin.is_some() {
            if kind == KeyEventKind::Press && code == KeyCode::Esc {
                self.users_admin = None;
            }
            return None;
        }

        // Ctrl+H toggles the help overlay from any view/mode/focus, taking
        // priority over everything below. Gated on `Press`: on a Kitty
        // terminal the matching `Release` also reaches here, and toggling
        // on both would open and instantly close it. Both kinds return
        // `None` so the `Release` is absorbed rather than falling through
        // to a bare 'h'.
        if modifiers.contains(KeyModifiers::CONTROL)
            && matches!(code, KeyCode::Char('h') | KeyCode::Char('H'))
        {
            if kind == KeyEventKind::Press {
                self.help_open = !self.help_open;
                // Always reopen at the top rather than wherever it was
                // scrolled to last time it was closed.
                self.help_scroll = 0;
            }
            return None;
        }
        if self.help_open {
            // Only scrolling and closing are honored while the overlay is
            // up; every other key is swallowed. Closing is Ctrl+H (the
            // toggle above) or Esc - the Esc close is gated on `Press`,
            // and its paired `Release` on a kitty-protocol terminal is
            // still absorbed safely below even though `help_open` has
            // already flipped: the DM-closing Esc branch further down is
            // itself `Press`-gated, so no second side effect can leak.
            if code == KeyCode::Esc {
                if kind == KeyEventKind::Press {
                    self.help_open = false;
                }
                return None;
            }
            // The bound the overlay can ever reach at any width - the
            // exact one for this frame is applied when it renders (see
            // `help_total_lines`).
            let max_scroll = help_total_lines().saturating_sub(1);
            match code {
                KeyCode::Up => self.help_scroll = self.help_scroll.saturating_sub(1),
                KeyCode::Down => self.help_scroll = (self.help_scroll + 1).min(max_scroll),
                KeyCode::PageUp => {
                    self.help_scroll = self.help_scroll.saturating_sub(HELP_SCROLL_PAGE)
                }
                KeyCode::PageDown => {
                    self.help_scroll = (self.help_scroll + HELP_SCROLL_PAGE).min(max_scroll)
                }
                KeyCode::Home => self.help_scroll = 0,
                KeyCode::End => self.help_scroll = max_scroll,
                _ => {}
            }
            return None;
        }

        // The OTP mail view owns every key while open (below the modal
        // popups and Ctrl+H above, which must stay reachable over it) -
        // including its own Space handling, since Space types text in its
        // fields but records in its attachments pane. Opened only by the
        // `/mail` and `/mailbox` commands (`submit_input`) - deliberately
        // no key chord: Ctrl+M is indistinguishable from Enter on
        // terminals without the kitty keyboard protocol (both are 0x0D).
        if self.otp_mail.is_some() {
            return self.handle_otp_mail_key(code, modifiers, kind);
        }

        if code == KeyCode::Char(' ') && self.focus != Focus::Input {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => {
                    self.recording_last_seen = Some(Instant::now());
                    if self.recording {
                        None
                    } else {
                        // The target has to be known now, at press-time,
                        // not deferred to release: a live stream needs
                        // somewhere to address its Start message to the
                        // instant recording begins. Without anywhere to
                        // send it, don't start the recorder at all -
                        // previously this started local capture
                        // unconditionally and only discovered there was
                        // nowhere to send it at release, leaving the
                        // recorder running with no way to stop it.
                        match self.current_voice_target() {
                            Some(target) => {
                                self.recording = true;
                                self.recording_source = Some(RecordSource::Space);
                                self.audio_error = None;
                                Some(UiAction::VoiceRecordStart(target))
                            }
                            None => {
                                self.audio_error = Some("not joined to a channel yet".to_string());
                                None
                            }
                        }
                    }
                }
                // Only ends a recording Space itself started - a
                // Global-triggered one (see `global_record_stop`) only
                // ever ends on its own release, never on Space.
                KeyEventKind::Release
                    if self.recording && self.recording_source == Some(RecordSource::Space) =>
                {
                    self.recording = false;
                    self.recording_source = None;
                    self.recording_last_seen = None;
                    Some(UiAction::VoiceRecordStop)
                }
                _ => None,
            };
        }

        if self.mode == Mode::JoinPrivatePopup {
            return self.handle_join_popup_key(code);
        }
        if self.mode == Mode::ChannelPasswordPopup {
            return self.handle_channel_password_popup_key(code);
        }
        if self.mode == Mode::ChannelsPopup {
            return self.handle_channels_popup_key(code);
        }
        if self.mode == Mode::FileSend {
            return self.handle_file_send_key(code);
        }
        if self.mode == Mode::Contacts {
            return self.handle_contacts_key(code);
        }
        if self.mode == Mode::DirectPunches {
            return self.handle_direct_punches_key(code);
        }
        if self.mode == Mode::ChannelLockPopup {
            return self.handle_channel_lock_popup_key(code);
        }
        if self.mode == Mode::ExportPopup {
            return self.handle_export_popup_key(code);
        }

        // The top row's two selectors (`docs/SPEC.md` "Connected UI"):
        // `[` walks left, `]` walks right, and the outermost press on
        // either side opens that selector's own dropdown instead of
        // wrapping around to the other end of the row.
        match code {
            KeyCode::Char('[') => {
                self.selector_left();
                return None;
            }
            KeyCode::Char(']') => {
                self.selector_right();
                return None;
            }
            _ => {}
        }

        // An open dropdown owns Up/Down (which move the selection, and
        // with it the view behind the overlay, straight away) and
        // Enter/Escape/Tab (which close it, keeping whatever Up/Down
        // landed on). Tab is in that group because its usual job - moving
        // focus between the sidebar, the log and the compose bar - is
        // about the view *behind* the overlay: getting on with it means
        // being done with the dropdown, so it closes rather than cycling
        // underneath. Everything else still falls through - this is an
        // overlay, not a modal.
        if self.selector_dropdown_open {
            match code {
                KeyCode::Up => {
                    self.selector_step(false);
                    return None;
                }
                KeyCode::Down => {
                    self.selector_step(true);
                    return None;
                }
                KeyCode::Enter | KeyCode::Esc | KeyCode::Tab => {
                    self.close_selector_dropdown();
                    return None;
                }
                _ => {}
            }
        }

        if modifiers.contains(KeyModifiers::CONTROL) {
            match code {
                // Brings a folded-away call modal back up - the header's
                // `\u{23FA} Call Ctrl+R` indicator is what advertises it
                // (`docs/SPEC.md` "Live voice calls"). A no-op with no
                // call on; it can only be reached while the modal is
                // down, since the modal absorbs keys before this.
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    if let Some(call) = self.call.as_mut() {
                        call.minimized = false;
                    }
                    return None;
                }
                KeyCode::Char('j') | KeyCode::Char('J') => {
                    // With no server there is nothing to create and no
                    // directory to search, so the free-text form would only
                    // ever be a way to type a name that cannot work. The
                    // configured channels are the only ones that exist, so
                    // this shows exactly those - the same modal `/channels`
                    // uses, over the same list.
                    if self.serverless {
                        self.mode = Mode::ChannelsPopup;
                        self.channels_popup_selected = 0;
                        return None;
                    }
                    self.mode = Mode::JoinPrivatePopup;
                    self.join_popup_input.clear();
                    self.join_popup_kind = ChannelKind::Private;
                    self.join_popup_password.clear();
                    self.join_popup_focus = JoinPopupFocus::Name;
                    return None;
                }
                // Opens the first not-yet-opened http(s) link in the
                // focused message (`message_selected`) in the OS default
                // browser; pressing it again cycles to that same
                // message's next link before starting over.
                KeyCode::Char('o') | KeyCode::Char('O') => {
                    return self.next_url_in_focused_message().map(UiAction::OpenUrl);
                }
                // Opens the "Direct Punches" popup - only worth reaching
                // for once direct punching is at least worth looking at,
                // but the popup itself (`open_direct_punches`) is where
                // adding the very first one from scratch happens too, so
                // it's never gated on any already being configured.
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    self.open_direct_punches();
                    return Some(UiAction::OpenDirectPunches);
                }
                // Opens the export popup - checkbox-pick any joined
                // channel or open DM, Confirm to dump each one's current
                // log to `~/.aloo/exports/<server>/...`
                // (`client::export::export_log`). Purely local, so unlike
                // `Ctrl+S` this never needs a `UiAction` just to populate
                // itself.
                KeyCode::Char('e') | KeyCode::Char('E') => {
                    self.open_export_popup();
                    return None;
                }
                _ => {}
            }
        }

        if code == KeyCode::Esc {
            // Gated on `Press` only (same reasoning as the Ctrl+H toggle
            // above): a terminal that also reports `Release` for this key
            // must not act on it a second time, which matters here because
            // - unlike `focus_channel_selector` below, idempotent either
            // way - stopping playback is a real state transition that a
            // second, redundant firing must not follow through the
            // fallback branch and additionally close the room.
            if kind != KeyEventKind::Press {
                return None;
            }
            if self.replaying {
                self.replaying = false;
                return Some(UiAction::StopPlayback);
            }
            self.focus_channel_selector();
            return None;
        }

        if code == KeyCode::Tab && !modifiers.contains(KeyModifiers::CONTROL) {
            self.cycle_focus();
            return None;
        }

        match self.focus {
            Focus::Input => self.handle_input_key(code),
            Focus::Sidebar => self.handle_sidebar_key(code),
            Focus::Messages => self.handle_messages_key(code),
        }
    }

    /// Every key the call modal handles (`docs/SPEC.md` "Live voice
    /// calls"): Up/Down walk the roster, `m` is the host's mute toggle for
    /// whoever the cursor is on, `i` opens the host's invite picker,
    /// Enter/`e` press END CALL, and Escape folds the modal away into its
    /// tab. Every other key is absorbed - it is a modal.
    fn handle_call_modal_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let own_id = self.own_id;
        // Answered before anything else the modal does, the same tier its
        // invite picker sits at: nothing about the call changes while
        // either is open.
        if self.call.as_ref()?.end_confirm.is_some() {
            return self.handle_end_call_confirm_key(code);
        }
        if self.call.as_ref()?.invite_picker.is_some() {
            return self.handle_call_invite_picker_key(code);
        }
        match code {
            KeyCode::Up => {
                let call = self.call.as_mut()?;
                if !call.members.is_empty() {
                    let len = call.members.len();
                    call.selected = (call.selected + len - 1) % len;
                }
                None
            }
            KeyCode::Down => {
                let call = self.call.as_mut()?;
                if !call.members.is_empty() {
                    call.selected = (call.selected + 1) % call.members.len();
                }
                None
            }
            KeyCode::Char('i') | KeyCode::Char('I') => {
                self.open_call_invite_picker();
                None
            }
            KeyCode::Char('m') | KeyCode::Char('M') => {
                let call = self.call.as_ref()?;
                let member = call.members.get(call.selected)?;
                // Our own row toggles our own microphone: ours alone to
                // lift again, though everyone's roster is told. Anyone
                // else's row is the host's mute instead - a different
                // thing entirely, and only the host may use it.
                if Some(member.id) == own_id {
                    return Some(UiAction::ToggleCallMute);
                }
                if !call.we_are_host(own_id) {
                    return None;
                }
                Some(UiAction::HostMuteCallMember {
                    peer: member.id,
                    muted: !member.host_muted,
                })
            }
            // END CALL asks first (see `CallUiState::end_confirm`); the
            // answer is what actually leaves.
            KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char('E') => {
                self.call.as_mut()?.end_confirm = Some(Confirm::No);
                None
            }
            // Selector navigation keeps working through the modal - it is
            // how the user gets on with reading a channel or a DM without
            // ending anything. It folds the modal away first, so it
            // doesn't simply reappear on top of whatever was navigated to
            // (Ctrl+R brings it back).
            KeyCode::Char('[') | KeyCode::Char(']') => {
                if let Some(call) = self.call.as_mut() {
                    call.minimized = true;
                }
                if code == KeyCode::Char(']') {
                    self.selector_right();
                } else {
                    self.selector_left();
                }
                None
            }
            KeyCode::Esc => {
                if let Some(call) = self.call.as_mut() {
                    call.minimized = true;
                }
                None
            }
            _ => None,
        }
    }

    /// END CALL's confirmation, while it is open over the modal:
    /// Left/Right/Tab move between the two buttons, Enter answers, Escape
    /// is the same as answering Cancel. Nothing else reaches the modal
    /// underneath, so no roster key can be mistaken for an answer.
    fn handle_end_call_confirm_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let call = self.call.as_mut()?;
        let focus = call.end_confirm?;
        match code {
            KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                call.end_confirm = Some(focus.toggled());
                None
            }
            KeyCode::Esc => {
                call.end_confirm = None;
                None
            }
            KeyCode::Enter => {
                call.end_confirm = None;
                match focus {
                    Confirm::Yes => Some(UiAction::EndCall),
                    Confirm::No => None,
                }
            }
            _ => None,
        }
    }

    /// The host's invite picker, while it is open over the modal: Up/Down
    /// pick, Enter invites, Escape closes it without inviting anyone.
    fn handle_call_invite_picker_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let call = self.call.as_mut()?;
        let picker = call.invite_picker.as_mut()?;
        match code {
            KeyCode::Up => {
                let len = picker.candidates.len();
                if len > 0 {
                    picker.selected = (picker.selected + len - 1) % len;
                }
                None
            }
            KeyCode::Down => {
                let len = picker.candidates.len();
                if len > 0 {
                    picker.selected = (picker.selected + 1) % len;
                }
                None
            }
            KeyCode::Enter => {
                let &(to, _) = picker.candidates.get(picker.selected)?;
                call.invite_picker = None;
                Some(UiAction::InviteToCall { to })
            }
            KeyCode::Esc => {
                call.invite_picker = None;
                None
            }
            _ => None,
        }
    }

    // -------------------------------------------------------------
    // The top row's two selectors
    // -------------------------------------------------------------

    /// `[`. From the DM selector it steps left onto the channel one; on
    /// the channel selector - already the leftmost thing in the row -
    /// there is nothing further left to step onto, so it opens that
    /// selector's own dropdown instead. With a dropdown already open it is
    /// the *DM* dropdown's close key, mirroring the side each selector
    /// sits on (`docs/SPEC.md` "Connected UI").
    pub(crate) fn selector_left(&mut self) {
        if self.selector_dropdown_open {
            if self.selector_focus == SelectorFocus::Dms {
                self.close_selector_dropdown();
            }
            return;
        }
        match self.selector_focus {
            SelectorFocus::Channels => self.open_selector_dropdown(),
            SelectorFocus::Dms => self.focus_channel_selector(),
        }
    }

    /// `]` - `selector_left`'s mirror image: from the channel selector it
    /// steps right onto the DM one (which isn't there at all until a room
    /// has been opened, in which case nothing happens), and on the DM
    /// selector it opens that selector's dropdown. With the *channel*
    /// dropdown open it closes it.
    pub(crate) fn selector_right(&mut self) {
        if self.selector_dropdown_open {
            if self.selector_focus == SelectorFocus::Channels {
                self.close_selector_dropdown();
            }
            return;
        }
        match self.selector_focus {
            SelectorFocus::Channels => self.focus_dm_selector(),
            SelectorFocus::Dms => self.open_selector_dropdown(),
        }
    }

    /// Opens the focused selector's dropdown - unless it would be empty,
    /// which is exactly when there is nothing else to switch to (one
    /// channel joined, one room open), and an empty overlay in the way
    /// would be pure obstruction.
    fn open_selector_dropdown(&mut self) {
        if !self.selector_dropdown_entries().is_empty() {
            self.selector_dropdown_open = true;
            self.selector_dropdown_since = Some(Instant::now());
        }
    }

    /// The one way a dropdown is ever put away - every closing key and the
    /// idle timeout alike - so its timer never outlives it.
    pub(crate) fn close_selector_dropdown(&mut self) {
        self.selector_dropdown_open = false;
        self.selector_dropdown_since = None;
    }

    /// Folds an open dropdown away once `SELECTOR_DROPDOWN_IDLE_TIMEOUT`
    /// has passed with nothing driving it - called from the session's
    /// ticker, the same cadence `tick_status_notice` rides. An open
    /// dropdown whose timestamp is missing (set by writing the pub field
    /// directly, as tests do) is adopted from `now` rather than left
    /// immortal.
    pub fn tick_selector_dropdown(&mut self, now: Instant) {
        if !self.selector_dropdown_open {
            self.selector_dropdown_since = None;
            return;
        }
        match self.selector_dropdown_since {
            Some(since) if now.duration_since(since) >= SELECTOR_DROPDOWN_IDLE_TIMEOUT => {
                self.close_selector_dropdown();
            }
            None => self.selector_dropdown_since = Some(now),
            _ => {}
        }
    }

    /// Up/Down while a dropdown is open: moves the focused selector's own
    /// selection one entry on, wrapping at both ends the way the sidebar
    /// and the `/channels` modal already do. The view behind the overlay
    /// follows immediately - the dropdown lists everything *except* the
    /// selection, so the row that was picked leaves the list and the one
    /// stepped off rejoins it.
    pub(crate) fn selector_step(&mut self, forward: bool) {
        // Driving the list is what "not idle" means (`tick_selector_dropdown`).
        self.selector_dropdown_since = Some(Instant::now());
        match self.selector_focus {
            SelectorFocus::Channels => {
                let len = self.channels.len();
                if len == 0 {
                    return;
                }
                let next = if forward {
                    (self.selected_channel + 1) % len
                } else {
                    (self.selected_channel + len - 1) % len
                };
                self.select_channel_at(next);
            }
            SelectorFocus::Dms => {
                let len = self.dm_order.len();
                if len == 0 {
                    return;
                }
                let current = self
                    .selected_dm
                    .and_then(|id| self.dm_order.iter().position(|d| *d == id))
                    .unwrap_or(0);
                let next = if forward {
                    (current + 1) % len
                } else {
                    (current + len - 1) % len
                };
                self.select_dm(self.dm_order[next]);
            }
        }
    }

    /// Focuses the left-hand selector: its channel becomes the view, so
    /// any open room is closed (it stays on the DM selector, one `]`
    /// away). Also where Escape lands from inside a room.
    pub(crate) fn focus_channel_selector(&mut self) {
        self.selector_focus = SelectorFocus::Channels;
        self.close_selector_dropdown();
        self.active_private_room = None;
        self.sidebar_selected = 0;
        self.select_channel_at(self.selected_channel);
    }

    /// Focuses the right-hand selector, opening the room it names. A no-op
    /// while no room has ever been opened - that selector isn't rendered
    /// at all then, and `]` from the channel one has nowhere to go.
    pub(crate) fn focus_dm_selector(&mut self) {
        let Some(peer) = self.selected_dm else {
            return;
        };
        self.selector_focus = SelectorFocus::Dms;
        self.close_selector_dropdown();
        self.select_dm(peer);
    }

    /// The focused selector's dropdown rows: every entry it holds *except*
    /// the one it currently names, in that selector's own order
    /// (`channels`, `dm_order`). Also what decides whether there is a
    /// dropdown worth opening at all (`open_selector_dropdown`).
    pub fn selector_dropdown_entries(&self) -> Vec<SelectorEntry> {
        match self.selector_focus {
            SelectorFocus::Channels => self
                .channels
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != self.selected_channel)
                .map(|(_, c)| SelectorEntry {
                    label: channel_label(c.kind, &c.name),
                    unread: c.unread,
                    otp: false,
                    presence: None,
                })
                .collect(),
            SelectorFocus::Dms => self
                .dm_order
                .iter()
                .filter(|id| Some(**id) != self.selected_dm)
                .filter_map(|id| self.private_rooms.get(id))
                .map(|room| SelectorEntry {
                    label: format!("{DM_ICON} {}", room.peer.name),
                    unread: room.unread,
                    otp: self.is_otp_active(room.peer.id),
                    presence: Some(self.presence_of(room.peer.id)),
                })
                .collect(),
        }
    }

    /// Which dropdown row the list has to keep on screen when it holds
    /// more entries than fit (`render_selector_dropdown`).
    ///
    /// The dropdown lists everything *except* the current selection, so
    /// there is no selected row in it to follow. What there is instead is
    /// the *gap* the selection left: the number of entries ahead of it in
    /// the selector's own order. Keeping that position in view is what
    /// makes Up/Down walk a long list continuously - the row stepped onto
    /// leaves the list and the one stepped off rejoins it right there, so
    /// the neighbourhood of the gap is exactly where the movement is
    /// visible.
    pub fn selector_dropdown_focus_row(&self) -> usize {
        let entries = self.selector_dropdown_entries().len();
        let gap = match self.selector_focus {
            SelectorFocus::Channels => self.selected_channel,
            SelectorFocus::Dms => self
                .selected_dm
                .and_then(|id| self.dm_order.iter().position(|d| *d == id))
                .unwrap_or(0),
        };
        gap.min(entries.saturating_sub(1))
    }

    /// Whether any channel behind the left-hand selector holds messages
    /// the user has not seen - what makes its envelope blink. The channel
    /// on screen is never one of them: selecting it clears the flag, and
    /// nothing sets it again while it is the log being looked at.
    pub fn any_channel_unread(&self) -> bool {
        self.channels.iter().any(|c| c.unread)
    }

    /// `any_channel_unread`'s DM counterpart, for the right-hand selector.
    pub fn any_dm_unread(&self) -> bool {
        self.private_rooms.values().any(|r| r.unread)
    }

    fn cycle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Sidebar => Focus::Messages,
            Focus::Messages => Focus::Input,
            Focus::Input => Focus::Sidebar,
        };
    }

    fn handle_input_key(&mut self, code: KeyCode) -> Option<UiAction> {
        // Reading back history is the one thing the compose bar hands
        // straight to the log: focus starts here and stays here while
        // typing, so requiring a Tab round-trip to scroll would leave the
        // history effectively unreachable in normal use. None of these keys
        // mean anything to a single-line, append-only compose buffer.
        // Deliberately ahead of the guards below - a log stays readable
        // even in a room that can no longer be typed in.
        if matches!(
            code,
            KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown
        ) {
            return self.handle_messages_key(code);
        }
        // A Pending/Rejected identity (docs/PROTOCOL.md §12) blocks typing
        // outright - normal navigation can no longer even open this room,
        // but a room already open before the mismatch arrived must stop
        // accepting input too. An offline DM peer, by contrast, no longer
        // blocks typing here: `/endotp` must still be composable and
        // submitted for a peer who isn't currently reachable (ending a
        // session must not require them to be reachable - see
        // `client::otp`'s module doc), so `submit_input` itself is what
        // refuses every *other* command/plain send to an offline peer, with
        // `/endotp` the one deliberate exception. `render_input_bar` shows
        // whatever's actually typed once it's non-empty, offline or not.
        if self.active_dm_peer_trust_gated() {
            return None;
        }
        match code {
            KeyCode::Backspace => {
                self.input.pop();
                None
            }
            KeyCode::Char(c) => {
                // `proto::TEXT_MESSAGE_MAX_LEN` - same per-keystroke cap
                // shape as `ui_connect_popup`'s nickname field. A paste
                // long enough to matter here is always diverted to a file
                // first (`handle_paste`), so this only ever bites manually
                // typed text.
                if self.input.chars().count() < crate::proto::TEXT_MESSAGE_MAX_LEN {
                    self.input.push(c);
                }
                None
            }
            KeyCode::Enter => self.submit_input(),
            _ => None,
        }
    }

    /// Only clears `input` once we know the message can actually be
    /// produced - otherwise (not joined yet, unknown DM peer) the user's
    /// typed text would silently vanish instead of just staying put.
    fn submit_input(&mut self) -> Option<UiAction> {
        if self.input.trim().is_empty() {
            return None;
        }
        if self.input.trim() == "/endotp" {
            // Ending is a synchronised, two-party operation now
            // (docs/PROTOCOL.md §16.6): it takes effect only when the
            // peer's proof-carrying acknowledgement comes back, so both
            // sides leave the session together. A peer who is offline
            // cannot confirm anything, so this is refused out loud rather
            // than silently swallowed like other DM actions - the user
            // asked for something specific and deserves to know why it
            // didn't happen. Still a no-op for a trust-gated peer
            // (docs/PROTOCOL.md §12), same as every other DM action.
            let peer_id = self.active_private_room?;
            if self.is_trust_gated(peer_id) {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?.clone();
            // Checked against the direct link too, not only
            // `active_dm_peer_offline` (`ui_state.offline`, gated behind the
            // server's `HEARTBEAT_TIMEOUT`) - the same race
            // `handle_end_otp_command`'s authoritative guard closes further,
            // narrowed here as well so the refusal is immediate rather than
            // a round trip through session handling.
            if self.active_dm_peer_offline() || self.link_status_of(peer_id) != LinkStatus::Active
            {
                self.input.clear();
                self.push_status_notice(
                    format!(
                        "OTP: {} is offline - /endotp needs both sides online so the end \
                         is confirmed on both; try again when they are back",
                        peer.name
                    ),
                    false,
                );
                return None;
            }
            self.input.clear();
            return Some(UiAction::EndOtpSession {
                peer: peer_id,
                pubkey_der: peer.public_key_der,
            });
        }
        if self.input.trim() == "/info" {
            // Read-only and purely local (`id_store`/keychain), so - like
            // `/endotp` above - never gated on the peer being reachable:
            // there is nothing here that needs them online, and it works
            // even for a trust-gated peer, same reasoning as `i` in the
            // sidebar.
            let Some(peer_id) = self.active_private_room else {
                return None;
            };
            let Some(peer) = self.known_users.get(&peer_id).cloned() else {
                return None;
            };
            self.input.clear();
            self.open_user_info(peer_id, peer.name.clone(), None);
            return Some(UiAction::RequestUserInfo { peer: peer_id, nickname: peer.name });
        }
        // Everything below requires the open DM's peer (if any) to actually
        // be reachable - `/endotp` above is the one deliberate exception.
        // `active_dm_peer_offline` is `false` whenever no DM room is open at
        // all, so this never touches a channel send.
        if self.active_dm_peer_offline() || self.active_dm_peer_trust_gated() {
            return None;
        }
        if self.input.trim() == "/file" {
            // Leaves `input` untouched on failure (no addressable target,
            // or the directory listing itself failed) - same as every
            // other "can't send right now" path below, so the user isn't
            // left wondering where their typed command went.
            return self.start_file_send();
        }
        if self.input.trim() == "/otp" {
            // Only meaningful inside an open DM room - OTP is provisioned
            // pairwise, per contact, never for a whole channel at once
            // (see `client::otp`'s module doc). A no-op if the peer is
            // trust-gated (docs/PROTOCOL.md §12) - the same guard the
            // compose bar itself already applies before any send.
            let peer_id = self.active_private_room?;
            if self.is_trust_gated(peer_id) {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?.clone();
            self.input.clear();
            return Some(UiAction::RequestOtpSession {
                peer: peer_id,
                pubkey_der: peer.public_key_der,
            });
        }
        if self.input.trim() == "/new-otp-mail-key" {
            // The one way to provision OTP mail's own key, independent of
            // any live `/otp` session with the same person - same
            // provisioning mechanics as `/otp` just above, same guards.
            let peer_id = self.active_private_room?;
            if self.is_trust_gated(peer_id) {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?.clone();
            self.input.clear();
            return Some(UiAction::RequestOtpMailKey {
                peer: peer_id,
                pubkey_der: peer.public_key_der,
            });
        }
        if self.input.trim() == "/mail" {
            // The one way to compose an OTP mail (docs/PROTOCOL.md §17.1) -
            // a command rather than a key chord, since the natural chord
            // (Ctrl+M) is indistinguishable from Enter on terminals
            // without the kitty keyboard protocol (both are 0x0D). Routed
            // through the session rather than opening the compose view
            // directly - only it can check the local `otp` binary is
            // actually available (`client::otp_mail::handle_open_otp_mail`),
            // which `UiState` has no way to do for itself.
            self.input.clear();
            return Some(UiAction::RequestOpenOtpMail);
        }
        if self.input.trim() == "/mailbox" {
            // The one way to open the mailbox: opens the mail view with
            // the mailbox popup on top - the session answers the action
            // with the current rows (`client::otp_mail::handle_open_mailbox`).
            self.input.clear();
            self.open_otp_mail();
            return Some(UiAction::OpenOtpMailbox);
        }
        if self.input.trim() == "/channels" {
            // The one way to see the server's public channel directory:
            // the tab row only ever shows the channels already joined
            // (docs/PROTOCOL.md §6.3), so this modal is where the rest
            // are, and where joining one from the list happens.
            self.input.clear();
            self.open_channels_popup();
            return None;
        }
        if self.input.trim() == "/clear" {
            // Wipes the log of whichever screen is open right now - not
            // just what's on screen, the `Vec<LogEntry>` backing it, so a
            // scrollback of anything cleared this way is genuinely gone,
            // not merely scrolled past.
            self.input.clear();
            if let Some(log) = self.current_log_mut() {
                log.clear();
            }
            self.message_selected = 0;
            self.message_info = None;
            self.push_status_notice("cleared this screen's messages".to_string(), true);
            return None;
        }
        if self.input.trim() == "/clear-all" {
            // Same as `/clear`, but for every channel tab and every DM
            // room at once - not just the one currently open.
            self.input.clear();
            for channel in self.channels.iter_mut() {
                channel.log.clear();
            }
            for room in self.private_rooms.values_mut() {
                room.log.clear();
            }
            self.message_selected = 0;
            self.message_info = None;
            self.push_status_notice("cleared every screen's messages".to_string(), true);
            return None;
        }
        if self.input.trim() == "/contacts" {
            // The one way to see every pinned identity (`idstore.rs`) -
            // unlike `/otp`/`/file`/`/endotp` above, this is never scoped
            // to an open DM room: a contacts list is precisely the roster
            // of people the app knows about *without* requiring one to be
            // reachable, or even a room to be open, right now.
            self.input.clear();
            self.open_contacts();
            return Some(UiAction::OpenContacts);
        }
        if self.input.trim() == "/leave" {
            // Always the currently selected channel tab - `/leave` takes
            // no argument. A no-op if that tab isn't actually joined yet
            // (its `Joined` confirmation still in flight) - nothing to
            // leave.
            let channel = self.channels.get(self.selected_channel)?;
            if !channel.joined {
                return None;
            }
            let name = channel.name.clone();
            self.input.clear();
            return Some(UiAction::LeaveChannel { name });
        }
        if self.input.trim() == "/delete-channel" {
            // Always the currently selected channel, same "no argument"
            // convention `/leave` uses - and the same confirmation tier
            // `/call` uses just below, since deleting a channel is
            // destructive and not one Enter away.
            let channel = self.channels.get(self.selected_channel)?;
            let name = channel.name.clone();
            self.input.clear();
            self.channel_command_confirm = Some(ChannelCommandConfirm {
                title: "Delete channel?",
                question: format!("Delete #{name}? This cannot be undone."),
                action: ChannelCommandConfirmAction::DeleteChannel { name },
            });
            self.channel_command_confirm_focus = Confirm::No;
            return None;
        }
        if self.input.trim() == "/lock-joins" {
            // Purely local to open (see `channel_lock_popup`'s module
            // doc) - prefilled with the channel's current members, per
            // the spec's own "by default the current users joined should
            // be included".
            let channel = self.channels.get(self.selected_channel)?;
            let name = channel.name.clone();
            let members: Vec<String> = channel.members.iter().map(|m| m.name.clone()).collect();
            self.input.clear();
            self.open_channel_lock_popup(name, members);
            return None;
        }
        if self.input.trim() == "/call" {
            // Distinct from push-to-talk: a continuous, multi-user call
            // (`docs/PROTOCOL.md` "Live voice calls"), never available under
            // OTP - that gate needs `SessionState`, so it's checked
            // session-side (`crate::client::direct_message::handle_start_call`)
            // once this actually reaches it.
            if self.call.is_some() {
                self.push_status_notice("already on a call".to_string(), false);
                self.input.clear();
                return None;
            }
            if self.recording {
                self.push_status_notice(
                    "can't start a call while recording a voice message".to_string(),
                    false,
                );
                self.input.clear();
                return None;
            }
            let Some(target) = self.current_call_target() else {
                self.push_status_notice("nobody to call here".to_string(), false);
                self.input.clear();
                return None;
            };
            self.input.clear();
            // A DM call to a peer under an active OTP session can never
            // happen, so it must not be confirmed either: asking "invite 1
            // user?" and refusing the moment it is agreed to would be
            // worse than the plain refusal this had before there was a
            // confirmation at all. `direct_message::handle_start_call`
            // still rechecks against `SessionState` - the authority - but
            // by then this has already spared the user the popup.
            if let CallTarget::Direct { to, .. } = &target
                && self.is_otp_active(*to)
            {
                self.push_status_notice(OTP_CALL_REFUSAL.to_string(), false);
                return None;
            }
            // Nobody is rung before the user has seen how many people that
            // is (`docs/SPEC.md` "Live voice calls") - except when the
            // answer is nobody at all, which needs no decision, only the
            // same notice the session side would have produced a moment
            // later once its own recount agreed.
            let invitee_count = self.call_invitee_count(&target);
            if invitee_count == 0 {
                self.push_status_notice(NO_ONE_INVITED_NOTICE.to_string(), false);
                return None;
            }
            self.call_confirm = Some(PendingCallConfirm {
                target,
                invitee_count,
            });
            self.call_confirm_focus = Confirm::Yes;
            return None;
        }
        if self.input.trim() == "/daemon" {
            self.input.clear();
            if !self.daemon_mode {
                self.push_status_notice(
                    "not running as a daemon - start one with: aloo --daemon".to_string(),
                    false,
                );
                return None;
            }
            return Some(UiAction::Detach);
        }
        if self.input.trim() == "/endcall" {
            if self.call.is_none() {
                self.push_status_notice("not on a call".to_string(), false);
                self.input.clear();
                return None;
            }
            self.input.clear();
            return Some(UiAction::EndCall);
        }
        // The first commands in this app that take an argument - every
        // other one above matches on whole-string equality, and `/leave`
        // makes a point of taking none. Both must be handled before the
        // unknown-command catch-all below, or they'd be swallowed as
        // typos of a real command.
        if let Some(action) = self.try_voice_mute_command() {
            return action;
        }
        if let Some(action) = self.try_channel_moderation_command() {
            return action;
        }
        if let Some(action) = self.try_superadmin_command() {
            return action;
        }
        if let Some(action) = self.try_password_command() {
            return action;
        }
        // Anything else starting with `/` is an attempted command, not a
        // message - even one this build doesn't recognize, or a typo of a
        // real one. It must never leak into a channel or DM as literal
        // text: silently falling through to the send paths below would
        // send "/otpp" (or worse, "/leave" typed one keystroke wrong) as a
        // plain chat message every recipient sees.
        if self.input.trim().starts_with('/') {
            let attempted = std::mem::take(&mut self.input);
            self.push_status_notice(format!("unknown command: {}", attempted.trim()), false);
            return None;
        }
        // Checked *before* taking `input` - a send that can't actually go
        // through (channel not joined, DM peer unknown) must leave the
        // typed text in place rather than silently discarding it (AC-026),
        // and `submit_text` itself can't tell the difference between "not
        // sent because unaddressable" and "not sent for some other reason"
        // from the outside.
        if !self.can_submit_text() {
            return None;
        }
        let text = std::mem::take(&mut self.input);
        self.submit_text(text)
    }

    /// Whether `submit_text` would actually produce a send right now -
    /// `submit_input`'s guard for AC-026 (see its call site). Mirrors the
    /// addressability checks `submit_text` makes internally; kept as its
    /// own read-only check because `submit_input` needs the answer before
    /// it decides whether to touch `input` at all, and `handle_paste` has
    /// no equivalent "must preserve unsent text" concern (a paste that
    /// can't be sent was never staged anywhere to lose).
    fn can_submit_text(&self) -> bool {
        if let Some(peer_id) = self.active_private_room {
            !self.is_trust_gated(peer_id) && self.known_users.contains_key(&peer_id)
        } else {
            self.channels
                .get(self.selected_channel)
                .is_some_and(|c| c.joined)
        }
    }

    /// Shared tail of `submit_input`: send `text` verbatim to whichever
    /// room is open (the active DM peer, or the selected channel tab if
    /// none is). Split out so `handle_paste` can reach the exact same send
    /// path for a full paste's content without going through the
    /// single-line `input` buffer at all - a paste already arrives as one
    /// atomic string, embedded newlines included, so there is nothing to
    /// stage there first.
    fn submit_text(&mut self, text: String) -> Option<UiAction> {
        if let Some(peer_id) = self.active_private_room {
            // Defensive: normal navigation can no longer reach a compose
            // bar for a Pending/Rejected peer's room (Enter on their
            // sidebar entry opens the review popup instead), but a room
            // opened before the mismatch arrived must not keep accepting
            // sends either (docs/PROTOCOL.md §12).
            if self.is_trust_gated(peer_id) {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?.clone();
            // Allocated here, before the row exists, because the row and
            // the send have to agree on it: it is both this row's identity
            // and the tag the wire frame carries (`docs/PROTOCOL.md` 7.2.1).
            let (msg_id, delivery) = self.start_delivery(&[peer_id]);
            let log_index =
                self.push_outgoing_dm(peer_id, MessageBody::Text(text.clone()), Some(delivery));
            let action = UiAction::SendDirectText {
                to: peer_id,
                plaintext: text,
                recipient_pubkey_der: peer.public_key_der,
                log_index,
                msg_id,
            };
            Some(action)
        } else {
            let channel = self.channels.get(self.selected_channel)?;
            if !channel.joined {
                return None;
            }
            let name = channel.name.clone();
            let recipients = self.recipients_for_channel(channel);
            let recipient_ids: Vec<UserId> = recipients.iter().map(|(id, ..)| *id).collect();
            let (msg_id, delivery) = self.start_delivery(&recipient_ids);
            let action = UiAction::SendChannelText {
                channel: name.clone(),
                plaintext: text.clone(),
                recipients,
                msg_id,
            };
            self.push_outgoing_channel(&name, MessageBody::Text(text), Some(delivery));
            Some(action)
        }
    }

    /// The set of states `handle_key` checks, in priority order, before it
    /// ever reaches the ordinary compose bar (`handle_input_key`) - reused
    /// by `handle_paste` to route a paste through `handle_key` itself
    /// (into whichever field one of these is actually offering, if any)
    /// rather than misreading it as a message send while one of these is
    /// absorbing every key instead (an open identity review, an invite, a
    /// popup, the help screen, ...).
    fn overlay_absorbing_input(&self) -> bool {
        self.identity_review_queue.front().is_some()
            || self.unknown_peer_review_queue.front().is_some()
            || self.otp_invite_queue.front().is_some()
            || self.otp_keygen.is_some()
            || self.otp_size_input.is_some()
            || self.otp_generate_confirm.is_some()
            || self.file_offer_queue.front().is_some()
            || self.call_invite_queue.front().is_some()
            || self.call_confirm.is_some()
            || self.call_modal_showing()
            || self.message_info.is_some()
            || self.file_preview.is_some()
            || self.user_info.is_some()
            || self.users_admin.is_some()
            || self.help_open
            || self.otp_mail.is_some()
            || self.mode != Mode::Normal
            || self.selector_dropdown_open
    }

    /// A whole paste (`Event::Paste`, delivered atomically by a
    /// bracketed-paste-enabled terminal - `tui::terminal::setup` - with any
    /// embedded newlines intact). While some overlay (a popup, `/mail`, a
    /// decision queue, any non-`Normal` mode) is in front of the compose
    /// bar, it is instead forwarded character-by-character through
    /// `handle_key` - see `overlay_absorbing_input`'s doc. Reaching the
    /// ordinary compose bar itself, two thresholds apply, in order:
    ///
    /// - Longer than `client::file_transfer::PASTE_TO_FILE_CHAR_THRESHOLD`:
    ///   converted to a `.txt` file and sent as a file transfer instead of
    ///   a message - the same "this is clearly a document, not a chat
    ///   line" judgment call, just made automatically rather than asking.
    /// - Otherwise: sent immediately as a single message, newlines and
    ///   all, rather than staged in the single-line `input` buffer (which
    ///   has no way to hold or display one) for a manual Enter.
    ///
    /// Reaching the compose bar, a no-op for a peer this side currently
    /// can't send to, same as an ordinary keystroke would be.
    pub fn handle_paste(&mut self, text: String) -> Option<UiAction> {
        if text.is_empty() {
            return None;
        }
        // Something other than the plain compose bar owns every keystroke
        // right now - a popup, `/mail`, any non-`Normal` mode, or one of
        // the decision overlays `handle_key` absorbs everything for. Fed
        // through the very same per-character path a real keystroke takes
        // (`handle_key`, one `KeyCode::Char` per pasted character), so it
        // lands in whichever field currently has focus with that field's
        // own validation applied - a digits-only port field still refuses
        // non-digits, for instance - exactly as if it had been typed one
        // key at a time. Harmless for a decision overlay with no text
        // field at all (an identity review, an invite, ...): those match
        // only specific non-`Char` `KeyCode`s (`Left`/`Enter`/...), so an
        // arbitrary pasted character never has anything to accidentally
        // trigger there. Only the last of possibly several actions
        // produced along the way is returned, matching `handle_key`'s own
        // one-event-one-action shape and the "final state wins" semantics
        // already correct for a field that re-validates on every
        // keystroke (e.g. the mail compose `To` field's recipient check).
        if self.overlay_absorbing_input() {
            let mut action = None;
            for c in text.chars().filter(|c| *c != '\r') {
                if let Some(a) = self.handle_key(KeyCode::Char(c), KeyModifiers::NONE, KeyEventKind::Press) {
                    action = Some(a);
                }
            }
            return action;
        }
        if self.focus != Focus::Input {
            return None;
        }
        if self.active_dm_peer_offline() || self.active_dm_peer_trust_gated() {
            return None;
        }
        // Bracketed paste's line endings are not reliably `\n`: many
        // terminals (tmux's own `paste-buffer -p` included) send a lone
        // `\r` for each embedded line break, since that is historically
        // what "pressing Enter" sends. Everything downstream - the
        // message-log renderer splitting into one row per line, a
        // receiving peer's own renderer, a `.txt` file's line endings -
        // only ever recognizes `\n`, so it is normalized exactly once,
        // here at the paste boundary, rather than every consumer having
        // to know about `\r` too.
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        if text.chars().count() > crate::client::file_transfer::PASTE_TO_FILE_CHAR_THRESHOLD {
            let target = self.current_file_send_target()?;
            let path = crate::client::file_transfer::write_pasted_text_file(&text).ok()?;
            return self.confirm_pasted_file_send(target, path);
        }
        // Never actually trims anything in practice - anything this long
        // was already diverted to a file above, since
        // `PASTE_TO_FILE_CHAR_THRESHOLD` is well under `TEXT_MESSAGE_MAX_LEN`
        // - kept as a defensive second enforcement point rather than
        // relying on the ordering above never changing silently.
        let capped: String = text
            .chars()
            .take(crate::proto::TEXT_MESSAGE_MAX_LEN)
            .collect();
        self.submit_text(capped)
    }

    /// A left click, hit-tested against wherever the input bar and (while
    /// actually viewing a channel) the member sidebar were last drawn
    /// (`render_input_bar`/`render_sidebar`, via `last_input_bar_area`/
    /// `last_sidebar_area`) - clicking either moves focus there, and a
    /// sidebar click also selects whichever member row it landed on, the
    /// same one line per member every row already is. A no-op while some
    /// overlay is in front of the view (a popup, `/mail`, an open decision
    /// queue, ...) - clicking through it to whatever it's covering would
    /// be indistinguishable from actually answering it - or while viewing
    /// a DM (`render_private_room` draws no sidebar, so the stored area is
    /// stale, left over from the channel view).
    ///
    /// Right clicks, scrolling, and drags do nothing yet - this covers the
    /// two targets a click most obviously means "go here", not every
    /// clickable thing in the app.
    pub fn handle_mouse(&mut self, event: MouseEvent) -> Option<UiAction> {
        if !matches!(event.kind, MouseEventKind::Down(MouseButton::Left)) {
            return None;
        }
        if self.overlay_absorbing_input() {
            return None;
        }
        let (x, y) = (event.column, event.row);
        let input_area = unpack_rect(self.last_input_bar_area.load(Ordering::Relaxed));
        if rect_contains(input_area, x, y) {
            self.focus = Focus::Input;
            return None;
        }
        if self.active_private_room.is_none() {
            let sidebar_area = unpack_rect(self.last_sidebar_area.load(Ordering::Relaxed));
            if rect_contains(sidebar_area, x, y) {
                let member_count = self
                    .channels
                    .get(self.selected_channel)
                    .map(|c| c.members.len())
                    .unwrap_or(0);
                let clicked_row = y.saturating_sub(sidebar_area.y) as usize;
                if clicked_row < member_count {
                    self.focus = Focus::Sidebar;
                    self.sidebar_selected = clicked_row;
                }
            }
        }
        None
    }

    /// Handles `/mute-voice [nickname]` and `/unmute-voice [nickname]`
    /// (docs/SPEC.md Functionality #15).
    ///
    /// The nested `Option` distinguishes two things `submit_input` must
    /// tell apart: the outer one is "this input *was* one of these
    /// commands, stop looking", the inner is the action (if any) it
    /// produced. Without that, a recognized-but-actionless command - a
    /// bare `/mute-voice`, which only prints the current list - would fall
    /// through to the unknown-command notice and then to the send paths.
    /// The input line split into its command word and everything after
    /// it, both trimmed. A line with no whitespace is all verb and an
    /// empty rest, so `/mute-voice` and `/mute-voice bob` parse through
    /// the same two bindings.
    ///
    /// Both halves are owned rather than borrowed: every `try_*_command`
    /// below reads the parsed pieces *and* clears `self.input`, which it
    /// could not do while still borrowing from it.
    fn verb_and_rest(&self) -> (String, String) {
        let input = self.input.trim();
        match input.split_once(char::is_whitespace) {
            Some((verb, rest)) => (verb.to_string(), rest.trim().to_string()),
            None => (input.to_string(), String::new()),
        }
    }

    fn try_voice_mute_command(&mut self) -> Option<Option<UiAction>> {
        let (verb, rest) = self.verb_and_rest();
        let muted = match verb.as_str() {
            "/mute-voice" => true,
            "/unmute-voice" => false,
            _ => return None,
        };
        let rest = rest.as_str();

        // A bare command lists what is currently muted instead of erroring.
        // Nothing else in the UI answers "who have I muted?", and an
        // argument-less command is the natural place to ask it.
        if rest.is_empty() {
            let notice = if self.muted_voice.is_empty() {
                "no voices muted".to_string()
            } else {
                format!(
                    "voices muted: {} (/unmute-voice <nickname> to undo)",
                    self.muted_voice
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            self.input.clear();
            self.push_status_notice(notice, true);
            return Some(None);
        }

        // A nickname never contains whitespace, so anything past the first
        // word is a typo rather than part of the name - refused outright
        // instead of silently muting the first word of it.
        if rest.split_whitespace().count() > 1 {
            self.input.clear();
            self.push_status_notice(
                format!("{verb} takes one nickname, with no spaces in it"),
                false,
            );
            return Some(None);
        }
        // Guards the flat-file store the set is written to, exactly as
        // `IdStore::check_and_pin` guards its own.
        if !crate::validation::is_storable(rest) {
            self.input.clear();
            self.push_status_notice(format!("{rest:?} is not a usable nickname"), false);
            return Some(None);
        }

        let already = self.muted_voice.contains(rest);
        self.input.clear();
        if already == muted {
            // Not an error - just say so, and produce no action, so
            // nothing is rewritten to disk for a no-op.
            self.push_status_notice(
                if muted {
                    format!("{rest} is already muted")
                } else {
                    format!("{rest} is not muted")
                },
                true,
            );
            return Some(None);
        }

        // Applied locally right away so the sidebar marker and any stream
        // starting this instant see it; the session mirrors back whatever
        // actually landed on disk (`SetVoiceMuted`'s doc).
        if muted {
            self.muted_voice.insert(rest.to_string());
        } else {
            self.muted_voice.remove(rest);
        }
        self.push_status_notice(
            if muted {
                format!("{rest}'s voice messages muted")
            } else {
                format!("{rest}'s voice messages unmuted")
            },
            true,
        );
        Some(Some(UiAction::SetVoiceMuted {
            nickname: rest.to_string(),
            muted,
        }))
    }

    /// `/ban <nickname>`, `/unban <nickname>`, `/assign-admin <nickname>` -
    /// admin commands against the currently-selected channel, each taking
    /// one nickname argument, same shape `try_voice_mute_command`
    /// establishes above. `/assign-admin` alone doesn't emit its
    /// `UiAction` directly - it opens the same confirmation tier
    /// `/delete-channel` uses (`docs/PROTOCOL.md` §6.7's own "with popup
    /// confirmation"). None of the three is gated on the local user
    /// actually being this channel's admin - the server is the sole
    /// authority (`Registry::require_caller_is_admin`), and a non-admin's
    /// attempt is simply refused with a reason (`ServerMessage::Error`,
    /// now surfaced as a status notice).
    fn try_channel_moderation_command(&mut self) -> Option<Option<UiAction>> {
        let (verb, rest) = self.verb_and_rest();
        if !matches!(verb.as_str(), "/ban" | "/unban" | "/assign-admin") {
            return None;
        }
        let Some(channel) = self.channels.get(self.selected_channel) else {
            self.input.clear();
            return Some(None);
        };
        let channel_name = channel.name.clone();
        if rest.is_empty() || rest.split_whitespace().count() > 1 {
            self.input.clear();
            self.push_status_notice(
                format!("{verb} takes one nickname, with no spaces in it"),
                false,
            );
            return Some(None);
        }
        let nickname = rest;
        self.input.clear();
        Some(Some(match verb.as_str() {
            "/ban" => UiAction::BanFromChannel {
                channel: channel_name,
                nickname,
            },
            "/unban" => UiAction::UnbanFromChannel {
                channel: channel_name,
                nickname,
            },
            _ => {
                // "/assign-admin"
                self.channel_command_confirm = Some(ChannelCommandConfirm {
                    title: "Assign admin?",
                    question: format!(
                        "Make {nickname} the admin of #{channel_name}? You will no longer be its admin."
                    ),
                    action: ChannelCommandConfirmAction::AssignAdmin {
                        channel: channel_name,
                        nickname,
                    },
                });
                self.channel_command_confirm_focus = Confirm::No;
                return Some(None);
            }
        }))
    }

    /// A superadmin's `/activate <nickname>`, `/deactivate <nickname>
    /// <reason>`, `/remove-account <nickname>`, `/remove-channel <name>`
    /// (`docs/PROTOCOL.md` §5.5). Shown and sendable regardless of
    /// whether the local user actually is one - the server is the sole
    /// authority (`require_superadmin`), matching this codebase's own
    /// "the server never trusts the client" principle; a non-superadmin's
    /// attempt is simply refused with a reason.
    fn try_superadmin_command(&mut self) -> Option<Option<UiAction>> {
        let (verb, rest) = self.verb_and_rest();
        match verb.as_str() {
            "/activate" | "/remove-account" => {
                if rest.is_empty() || rest.split_whitespace().count() > 1 {
                    self.input.clear();
                    self.push_status_notice(
                        format!("{verb} takes one nickname, with no spaces in it"),
                        false,
                    );
                    return Some(None);
                }
                self.input.clear();
                Some(Some(if verb == "/activate" {
                    UiAction::AdminActivate { nickname: rest }
                } else {
                    UiAction::AdminRemoveAccount { nickname: rest }
                }))
            }
            "/remove-channel" => {
                if rest.is_empty() || rest.split_whitespace().count() > 1 {
                    self.input.clear();
                    self.push_status_notice(
                        format!("{verb} takes one channel name, with no spaces in it"),
                        false,
                    );
                    return Some(None);
                }
                self.input.clear();
                Some(Some(UiAction::AdminRemoveChannel { name: rest }))
            }
            "/users" => {
                if !rest.is_empty() {
                    self.input.clear();
                    self.push_status_notice("/users takes no arguments".to_string(), false);
                    return Some(None);
                }
                self.input.clear();
                self.open_users_admin();
                Some(Some(UiAction::RequestUsersList))
            }
            "/deactivate" => {
                // The reason may contain spaces - only the nickname
                // itself is a single word.
                let (nickname, reason) = match rest.split_once(char::is_whitespace) {
                    Some((n, r)) => (n.to_string(), r.trim().to_string()),
                    None => (rest, String::new()),
                };
                if nickname.is_empty() || reason.is_empty() {
                    self.input.clear();
                    self.push_status_notice("/deactivate <nickname> <reason>".to_string(), false);
                    return Some(None);
                }
                self.input.clear();
                Some(Some(UiAction::AdminDeactivate { nickname, reason }))
            }
            _ => None,
        }
    }

    /// `/password <old> <new>`: unlike `try_superadmin_command`, available
    /// to every user, gated on nothing client-side - the server is what
    /// actually re-checks `old` (`ClientMessage::ChangePassword`,
    /// `server::mod::client_loop`), so a wrong one is refused there, not
    /// silently swallowed here. Both fields are exactly one word each,
    /// the same limitation `/deactivate`'s nickname (not its reason) and
    /// every other space-delimited argument in this app already has - a
    /// password containing a space has no way to disambiguate where it
    /// ends and the other one begins.
    fn try_password_command(&mut self) -> Option<Option<UiAction>> {
        let (verb, rest) = self.verb_and_rest();
        if verb != "/password" {
            return None;
        }
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() != 2 {
            self.input.clear();
            self.push_status_notice("/password <old> <new>".to_string(), false);
            return Some(None);
        }
        let old_password = parts[0].to_string();
        let new_password = parts[1].to_string();
        self.input.clear();
        Some(Some(UiAction::ChangePassword { old_password, new_password }))
    }

    /// The last index (`channel.members.len()`) is always our own row
    /// (`channel::render_sidebar`'s synthetic "you" entry, appended after
    /// every real member rather than folded into `channel.members`
    /// itself), so every index below it is a real member at exactly the
    /// same index it already had.
    fn handle_sidebar_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let channel = self.channels.get(self.selected_channel)?;
        // +1 for our own row, always present and always last.
        let len = channel.members.len() + 1;
        match code {
            KeyCode::Up => {
                self.sidebar_selected = (self.sidebar_selected + len - 1) % len;
                None
            }
            KeyCode::Down => {
                self.sidebar_selected = (self.sidebar_selected + 1) % len;
                None
            }
            KeyCode::Enter => {
                let Some(member) = channel.members.get(self.sidebar_selected) else {
                    // Our own row - nothing to open a DM with.
                    return None;
                };
                let member = member.clone();
                // Belt and braces: real members are never supposed to
                // include our own id, but Enter must still never open a
                // "DM" with ourselves if one somehow did.
                if Some(member.id) == self.own_id {
                    return None;
                }
                // A Pending/Rejected identity opens the review popup
                // instead of the private room - can't vouch for who's
                // actually on the other end yet (docs/PROTOCOL.md §12).
                if self.is_trust_gated(member.id) {
                    self.reopen_identity_review(member.id);
                    return None;
                }
                self.open_private_room(member);
                None
            }
            // Read-only, so unlike Enter this works even for a trust-gated
            // member - seeing what's already pinned for them can only help
            // a decision, never leak anything beyond it.
            KeyCode::Char('i') | KeyCode::Char('I') => {
                let Some(member) = channel.members.get(self.sidebar_selected) else {
                    return None;
                };
                if Some(member.id) == self.own_id {
                    return None;
                }
                let (id, name) = (member.id, member.name.clone());
                self.open_user_info(id, name.clone(), Some(channel.name.clone()));
                Some(UiAction::RequestUserInfo { peer: id, nickname: name })
            }
            _ => None,
        }
    }

    /// `Up`/`Down` move one entry at a time, `PageUp`/`PageDown` jump by
    /// `MESSAGE_PAGE_JUMP`, and `Home`/`End` jump straight to the oldest/
    /// newest message - all clamped at the ends of the log rather than
    /// wrapping around (unlike the sidebar's `Up`/`Down`), since a
    /// scrollback history has a genuine top and bottom.
    fn handle_messages_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let len = self.current_log().len();
        match code {
            KeyCode::Up => {
                // Reaching the top of what's loaded, with `resume_from_log`
                // on, pulls one more chunk in first - `load_history_chunk`
                // is a no-op (returns 0) when the setting is off or there's
                // nothing left on disk, so `message_selected` then just
                // clamps at 0 exactly as it always did.
                if self.message_selected == 0 {
                    self.message_selected += self.load_history_chunk();
                }
                self.message_selected = self.message_selected.saturating_sub(1);
                None
            }
            KeyCode::Down => {
                if len > 0 {
                    self.message_selected = (self.message_selected + 1).min(len - 1);
                }
                None
            }
            KeyCode::PageUp => {
                if self.message_selected == 0 {
                    self.message_selected += self.load_history_chunk();
                }
                self.message_selected = self.message_selected.saturating_sub(MESSAGE_PAGE_JUMP);
                None
            }
            KeyCode::PageDown => {
                if len > 0 {
                    self.message_selected =
                        (self.message_selected + MESSAGE_PAGE_JUMP).min(len - 1);
                }
                None
            }
            KeyCode::Home => {
                // Jumps straight to the top of what's loaded - if that
                // triggers a load, the new top (index 0) is still the
                // right landing spot, so `= 0` below is unconditional.
                if self.message_selected == 0 {
                    self.load_history_chunk();
                }
                self.message_selected = 0;
                None
            }
            KeyCode::End => {
                if len > 0 {
                    self.message_selected = len - 1;
                }
                None
            }
            // Opens this row's details - who it was sent to, and which of
            // them have acknowledged it (`docs/SPEC.md` "Delivery
            // acknowledgments"). Available on every row, not just the
            // tracked ones: a row that carries no delivery information
            // says so, which is itself the answer to the question being
            // asked.
            KeyCode::Char('i') | KeyCode::Char('I') => {
                if len > 0 {
                    self.message_info = Some(self.message_selected.min(len - 1));
                }
                None
            }
            // A file entry has nothing left to do on Enter once it's
            // mid-transfer, saved under `~/.aloo/downloads`, rejected, or
            // failed (unlike the old whole-file-in-memory approach, there's
            // no separate save step to trigger for those) - except a
            // staged `.txt` receive, which Enter opens for preview
            // (`UiAction::RequestFilePreview`; `session::handle_ui_action`
            // reads the file, since `UiState` has no disk access).
            KeyCode::Enter => {
                let selected = self.message_selected;
                if let Some(LogEntry {
                    body:
                        MessageBody::File {
                            status: FileTransferStatus::Received { .. },
                            stream_id,
                            ..
                        },
                    from,
                    ..
                }) = self.current_log().get(selected)
                {
                    return Some(UiAction::RequestFilePreview {
                        from: *from,
                        stream_id: *stream_id,
                    });
                }
                // A `resume_from_log` row nobody has asked to hear yet -
                // load it from disk right here (a rare, user-initiated,
                // bounded-size read, not a hot path) and mutate it into an
                // ordinary `Voice` in place, so a second replay of the same
                // row is instant and the row otherwise behaves exactly
                // like any other from then on. `wav_path: None` (the
                // original autosave couldn't write the audio) or a file
                // that no longer decodes both report the reason and stop -
                // there's nothing to fall through into.
                if let Some(LogEntry {
                    body: MessageBody::VoiceOnDisk { duration_ms, wav_path },
                    ..
                }) = self.current_log().get(selected)
                {
                    let duration_ms = *duration_ms;
                    match wav_path.clone() {
                        Some(path) => {
                            let loaded = std::fs::read(&path)
                                .ok()
                                .and_then(|bytes| crate::client::voice::decode_wav_to_mono(&bytes));
                            match loaded {
                                Some(samples) => {
                                    let pcm = crate::client::voice::pcm_to_bytes(&samples);
                                    if let Some(entry) =
                                        self.current_log_mut().and_then(|log| log.get_mut(selected))
                                    {
                                        entry.body = MessageBody::Voice { duration_ms, pcm };
                                    }
                                }
                                None => {
                                    self.push_status_notice(
                                        "could not load this voice message's audio".to_string(),
                                        false,
                                    );
                                    return None;
                                }
                            }
                        }
                        None => {
                            self.push_status_notice("no audio was saved for this message".to_string(), false);
                            return None;
                        }
                    }
                }
                let replay = match self.current_log().get(selected) {
                    Some(LogEntry {
                        body: MessageBody::Voice { duration_ms, pcm },
                        from,
                        ..
                    }) => Some((*duration_ms, pcm.clone(), *from)),
                    _ => None,
                };
                let (duration_ms, pcm, from) = replay?;
                // An empty clip (0 playable samples) never actually starts
                // anything on the mixer (see `handle_ui_action`'s
                // `ReplayVoice` arm) - `replaying` must not be set in that
                // case, or Escape would be stuck stealing its "stop
                // playback" meaning with nothing to stop. Nor is a clip
                // that never played worth telling the sender about.
                if pcm.is_empty() {
                    return Some(UiAction::ReplayVoice {
                        duration_ms,
                        pcm,
                        from,
                        owed_receipt: None,
                    });
                }
                self.replaying = true;
                // Taken, not read: hearing it twice is still hearing it
                // once, and the sender has already been told.
                let owed_receipt = self.current_log_mut().and_then(|log| log.get_mut(selected)).and_then(
                    |entry| {
                        entry.listened = true;
                        entry.owed_receipt.take()
                    },
                );
                Some(UiAction::ReplayVoice {
                    duration_ms,
                    pcm,
                    from,
                    owed_receipt,
                })
            }
            _ => None,
        }
    }
}
