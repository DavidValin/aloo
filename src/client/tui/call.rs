//! What a live voice call looks like on screen, and the state behind it.
//!
//! The UI half of `client::voice_call`: that module owns the signalling
//! and the audio workers, this one owns what the user sees and the
//! decisions they make about it - the roster, the invite queue, the
//! host's mute and invite controls, the call modal's own state.
//!
//! Split out of `ui.rs` along the same line `input` and `render` were: the
//! types live here with the methods that maintain them, and only two
//! methods elsewhere in `UiState` reach in.
//!
//! Nothing here starts, joins or ends an actual call - every method
//! records a decision or a notice that has already been made somewhere
//! else, or hands back a `UiAction` for `client::session` to act on.

use std::time::Instant;

use crate::proto::UserId;

use super::ui::*;
use super::widgets::confirm_popup::Confirm;

/// One incoming live-call invite awaiting an Accept/Reject decision
/// (`docs/PROTOCOL.md` "Live voice calls") - mirrors `PendingFileOffer`'s
/// queued-popup idiom exactly, down to `Accept` being the default focus.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingCallInvite {
    pub call_id: u64,
    pub from: UserId,
    pub from_name: String,
    /// `Some(channel)` for a channel call, `None` for a DM.
    pub channel: Option<String>,
    /// Set once the host's `CallEnd` for this call has arrived while the
    /// invite was still unanswered (`mark_call_invite_ended`): accepting
    /// it then starts nothing and says so (`CALL_ALREADY_ENDED_NOTICE`),
    /// since there is no longer a call to join.
    pub ended: bool,
}
/// Where `/call` should be addressed, resolved at command-submit time (same
/// "known now, not deferred" reasoning as `VoiceTarget`) - `session::
/// handle_ui_action` dispatches into `crate::client::channel`/
/// `crate::client::direct_message`'s `handle_start_call`, which resolve the
/// actual recipient list (channel membership is looked up fresh there,
/// rather than snapshotted here, since a call invite tolerates the extra
/// few milliseconds a bounded live recording can't - see
/// `voice_call::addressable_channel_members`).
#[derive(Debug, Clone, PartialEq)]
pub enum CallTarget {
    Channel {
        channel: String,
    },
    Direct {
        to: UserId,
        recipient_pubkey_der: Vec<u8>,
    },
}
/// The `/call` confirmation (`docs/SPEC.md` "Live voice calls"): nobody
/// is rung until this is answered, and it says up front how many people
/// that will be. Holds the already-resolved `CallTarget` so the answer
/// acts on exactly what `/call` was typed against, even if membership
/// shifts while the popup is up.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingCallConfirm {
    pub target: CallTarget,
    /// How many people the invite fan-out will reach - the count the
    /// popup prints, in yellow.
    pub invitee_count: usize,
}
/// Where one person stands on a call we are on - the roster label the
/// call modal draws next to their name (`docs/SPEC.md` "Live voice
/// calls"). Only the host ever sees `Invited`/`Rejected`: a participant
/// learns about other participants purely from the `CallAccept`s that
/// converge the mesh (`docs/PROTOCOL.md` 7.7), which say nothing about
/// anyone who has not answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallMemberState {
    /// Accepted and exchanging audio with us.
    InCall,
    /// Sent a `CallInvite`, no answer yet.
    Invited,
    /// Answered with `CallReject`.
    Rejected,
}
/// One row of the call modal's roster. Includes ourselves - the modal
/// shows every person on the call, us among them, unlike
/// `voice_call::ActiveCall::participants` (network plumbing, which by
/// definition can only hold *other* people).
#[derive(Debug, Clone, PartialEq)]
pub struct CallMember {
    pub id: UserId,
    pub name: String,
    pub state: CallMemberState,
    /// Muted *by the host* (`p2p_proto::P2pPayload::CallMute`) - a
    /// different thing from this person muting themselves: only the host
    /// can lift this one.
    pub host_muted: bool,
    /// Muted *by themselves* - announced to everyone on the call the
    /// moment they toggle it (`crate::client::voice_call::toggle_mute`),
    /// so every roster says who can currently be heard. Theirs alone to
    /// lift again.
    pub self_muted: bool,
    /// Live 0-100 meter reading for this person's voice
    /// (`crate::client::voice::level_from_pcm`), refreshed every audio
    /// chunk by whichever worker produced it.
    pub level: u8,
}
/// The host-only "invite someone else to this call" picker, opened with
/// `i` from the call modal. Candidates are resolved once at open time
/// (`UiState::open_call_invite_picker`) rather than live, so the list
/// can't shift under the selection between keystrokes.
#[derive(Debug, Clone, PartialEq)]
pub struct CallInvitePicker {
    pub candidates: Vec<(UserId, String)>,
    pub selected: usize,
}
/// Everything on screen about the call we are currently on: the permanent
/// top-right indicator (`docs/SPEC.md` "Live voice calls" requires it stay
/// up for the call's whole duration, in red) *and* the call modal the
/// indicator summarises - roster, live duration, per-person voice meters,
/// and the host's mute/invite controls.
#[derive(Debug, Clone, PartialEq)]
pub struct CallUiState {
    pub call_id: u64,
    pub channel: Option<String>,
    /// Whether we have muted ourselves (`m` on our own row). It gates our
    /// own capture locally and is announced to the call so everyone's
    /// roster shows it (`docs/PROTOCOL.md` 7.7); it stays ours alone to
    /// lift, unlike `CallMember::host_muted`.
    pub muted: bool,
    /// Who started this call: the initiator for a call we started, the
    /// sender of the `CallInvite` for one we accepted. Named
    /// `<nickname> (host)` on the roster, and the only person allowed to
    /// mute anyone else or invite more people.
    pub host: UserId,
    /// The roster, host first, then everyone else in the order we learned
    /// about them - includes our own row.
    pub members: Vec<CallMember>,
    /// Which roster row the modal's cursor is on.
    pub selected: usize,
    /// When we joined, for the live duration readout.
    pub started_at: Instant,
    /// Whole seconds since `started_at`, refreshed by
    /// `UiState::tick_call_duration` off the session's ticker rather than
    /// read from the clock at render time, so the rendered value is
    /// deterministic for a given tick.
    pub elapsed_secs: u64,
    /// `true` once Escape has folded the modal away into the header row's
    /// `\u{23FA} Call Ctrl+R` indicator, leaving the ordinary
    /// sidebar/messages/compose layout usable again. Ctrl+R brings it back.
    pub minimized: bool,
    /// The host's invite picker, while it is open.
    pub invite_picker: Option<CallInvitePicker>,
    /// `true` while END CALL is waiting on its own confirmation
    /// (`docs/SPEC.md` "Live voice calls"). The button is focused from the
    /// moment the modal opens and Enter is the modal's most reachable key,
    /// so without this a stray Enter leaves a call with no way back into
    /// it. `Confirm::No` is the default answer, same as the
    /// identity review's `Reject`: the safe one.
    pub end_confirm: Option<Confirm>,
}
impl CallUiState {
    /// Whether *we* are the host - gates the modal's `m` (mute someone)
    /// and `i` (invite someone) keys.
    pub fn we_are_host(&self, own_id: Option<UserId>) -> bool {
        own_id == Some(self.host)
    }

    /// How many *other* people are actually on the call right now - what
    /// the permanent banner counts.
    pub fn connected_count(&self, own_id: Option<UserId>) -> usize {
        self.members
            .iter()
            .filter(|m| m.state == CallMemberState::InCall && Some(m.id) != own_id)
            .count()
    }

    /// `MM:SS`, or `HH:MM:SS` once a call runs past an hour.
    pub fn duration_label(&self) -> String {
        let secs = self.elapsed_secs;
        let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
        if h > 0 {
            format!("{h:02}:{m:02}:{s:02}")
        } else {
            format!("{m:02}:{s:02}")
        }
    }
}

impl UiState {
    /// Held-invite counterpart for an incoming call invite from a
    /// `Pending`/`Rejected` identity-review sender - see
    /// `pending_call_invites`'s doc.
    pub fn hold_call_invite(&mut self, invite: PendingCallInvite) {
        self.pending_call_invites
            .entry(invite.from)
            .or_default()
            .push(invite);
    }



    /// Queues `invite` and, if nothing else is currently showing, makes it
    /// the one shown right away - mirrors `push_file_offer` exactly.
    pub fn push_call_invite(&mut self, invite: PendingCallInvite) -> bool {
        let key = invite.call_id;
        self.call_invites.insert(key, invite);
        self.call_invite_queue.push_back(key);
        let is_front = self.call_invite_queue.front() == Some(&key);
        if is_front {
            self.call_invite_focus = Confirm::Yes;
        }
        is_front
    }



    /// The invite currently shown in the popup, if any.
    /// The invite currently shown in the popup, if any.
    pub fn call_invite_open(&self) -> Option<&PendingCallInvite> {
        let key = self.call_invite_queue.front()?;
        self.call_invites.get(key)
    }



    /// Accept on the invite popup. An invite whose call has already ended
    /// (`mark_call_invite_ended`) is taken off screen with
    /// `CALL_ALREADY_ENDED_NOTICE` instead of starting anything - the
    /// answer is still spent, there is simply nothing left to join. The
    /// session repeats the check when it handles the action
    /// (`crate::client::voice_call::accept_invite`), for the case where
    /// the `CallEnd` lands in between.
    /// Accept on the invite popup. An invite whose call has already ended
    /// (`mark_call_invite_ended`) is taken off screen with
    /// `CALL_ALREADY_ENDED_NOTICE` instead of starting anything - the
    /// answer is still spent, there is simply nothing left to join. The
    /// session repeats the check when it handles the action
    /// (`crate::client::voice_call::accept_invite`), for the case where
    /// the `CallEnd` lands in between.
    pub(crate) fn accept_call_invite(&mut self, call_id: u64) -> Option<UiAction> {
        if self.call_invites.get(&call_id).is_some_and(|i| i.ended) {
            self.take_call_invite(call_id);
            self.push_status_notice(CALL_ALREADY_ENDED_NOTICE.to_string(), false);
            return None;
        }
        Some(UiAction::AcceptCallInvite { call_id })
    }



    /// The invite we hold for `call_id`, answered or not - lets the
    /// session check who sent it before acting on a `CallEnd` naming it
    /// (`crate::client::voice_call::on_call_end`).
    /// The invite we hold for `call_id`, answered or not - lets the
    /// session check who sent it before acting on a `CallEnd` naming it
    /// (`crate::client::voice_call::on_call_end`).
    pub fn call_invite_for(&self, call_id: u64) -> Option<&PendingCallInvite> {
        self.call_invites.get(&call_id)
    }



    /// Everyone on our own call's roster who was invited and has not
    /// answered yet - who `end_own_call` must also tell, on top of the
    /// participants it is actually exchanging audio with.
    /// Everyone on our own call's roster who was invited and has not
    /// answered yet - who `end_own_call` must also tell, on top of the
    /// participants it is actually exchanging audio with.
    pub fn call_invitees_awaiting_answer(&self) -> Vec<UserId> {
        self.call
            .as_ref()
            .map(|call| {
                call.members
                    .iter()
                    .filter(|m| m.state == CallMemberState::Invited)
                    .map(|m| m.id)
                    .collect()
            })
            .unwrap_or_default()
    }



    /// Marks the still-unanswered invite for `call_id` as belonging to a
    /// call that has since ended, if we hold one. Returns whether it did -
    /// the caller (`crate::client::voice_call::on_call_end`) uses that to
    /// tell "this named an invite of ours" from "this named nothing we
    /// know about". The popup stays up: the user is still owed an answer,
    /// it just can no longer join anything.
    /// Marks the still-unanswered invite for `call_id` as belonging to a
    /// call that has since ended, if we hold one. Returns whether it did -
    /// the caller (`crate::client::voice_call::on_call_end`) uses that to
    /// tell "this named an invite of ours" from "this named nothing we
    /// know about". The popup stays up: the user is still owed an answer,
    /// it just can no longer join anything.
    pub fn mark_call_invite_ended(&mut self, call_id: u64) -> bool {
        match self.call_invites.get_mut(&call_id) {
            Some(invite) => {
                invite.ended = true;
                true
            }
            None => false,
        }
    }



    /// Removes and returns the invite for `call_id` - a decision here is
    /// always final, same as a file offer's.
    /// Removes and returns the invite for `call_id` - a decision here is
    /// always final, same as a file offer's.
    pub fn take_call_invite(&mut self, call_id: u64) -> Option<PendingCallInvite> {
        self.call_invite_queue.retain(|k| *k != call_id);
        self.call_invite_focus = Confirm::Yes;
        self.call_invites.remove(&call_id)
    }



    /// Starts showing the call modal and the permanent top-right "on a
    /// call" indicator - called once we become an active participant,
    /// whether as the initiator or an accepter
    /// (`crate::client::voice_call::begin_own_call`). `host` is whoever
    /// started the call: ourselves for a `/call`, the inviter for an
    /// invite we accepted. The modal opens up front (`minimized: false`)
    /// rather than folded away - a call starting is exactly the moment its
    /// roster matters most; Escape folds it into its tab from there.
    /// Starts showing the call modal and the permanent top-right "on a
    /// call" indicator - called once we become an active participant,
    /// whether as the initiator or an accepter
    /// (`crate::client::voice_call::begin_own_call`). `host` is whoever
    /// started the call: ourselves for a `/call`, the inviter for an
    /// invite we accepted. The modal opens up front (`minimized: false`)
    /// rather than folded away - a call starting is exactly the moment its
    /// roster matters most; Escape folds it into its tab from there.
    pub fn begin_call(&mut self, call_id: u64, channel: Option<String>, host: UserId) {
        let mut members = Vec::new();
        if let Some(own_id) = self.own_id {
            members.push(CallMember {
                id: own_id,
                name: self.own_display_name(),
                state: CallMemberState::InCall,
                host_muted: false,
                self_muted: false,
                level: 0,
            });
        }
        self.call = Some(CallUiState {
            call_id,
            channel,
            muted: false,
            host,
            members,
            selected: 0,
            started_at: Instant::now(),
            elapsed_secs: 0,
            minimized: false,
            invite_picker: None,
            end_confirm: None,
        });
        self.sort_call_members();
    }



    /// Clears the modal, the header's `\u{23FA} Call Ctrl+R` indicator and the
    /// permanent banner - called once we've left the call
    /// (`crate::client::voice_call::end_own_call`).
    /// Clears the modal, the header's `\u{23FA} Call Ctrl+R` indicator and the
    /// permanent banner - called once we've left the call
    /// (`crate::client::voice_call::end_own_call`).
    pub fn end_call(&mut self) {
        self.call = None;
    }

    pub fn set_call_muted(&mut self, muted: bool) {
        if let Some(call) = self.call.as_mut() {
            call.muted = muted;
        }
        // Our own row says the same thing to us as it does to everyone
        // else, without waiting for our own announcement to come back.
        if let Some(own_id) = self.own_id {
            self.set_call_member_self_muted(own_id, muted);
        }
    }



    /// Refreshes the modal's live duration readout - driven off the
    /// session's ticker with `Instant::now()`, taken as a parameter rather
    /// than read here so the whole readout is deterministic under test.
    /// Refreshes the modal's live duration readout - driven off the
    /// session's ticker with `Instant::now()`, taken as a parameter rather
    /// than read here so the whole readout is deterministic under test.
    pub fn tick_call_duration(&mut self, now: Instant) {
        if let Some(call) = self.call.as_mut() {
            call.elapsed_secs = now.saturating_duration_since(call.started_at).as_secs();
        }
    }



    /// Host first, everyone else in the order we learned about them - the
    /// order `docs/SPEC.md` "Live voice calls" specifies for the roster.
    /// Keeps the cursor on whoever it was on rather than on an index.
    fn sort_call_members(&mut self) {
        let Some(call) = self.call.as_mut() else {
            return;
        };
        let cursor_on = call.members.get(call.selected).map(|m| m.id);
        if let Some(idx) = call.members.iter().position(|m| m.id == call.host)
            && idx != 0
        {
            let host = call.members.remove(idx);
            call.members.insert(0, host);
        }
        call.selected = cursor_on
            .and_then(|id| call.members.iter().position(|m| m.id == id))
            .unwrap_or(0);
    }



    /// Upserts one roster row, leaving an existing row's host-mute state
    /// and meter alone (only its `state`/`name` are refreshed) - every
    /// roster mutation below funnels through this so the host-first
    /// ordering is maintained in exactly one place.
    /// Upserts one roster row, leaving an existing row's host-mute state
    /// and meter alone (only its `state`/`name` are refreshed) - every
    /// roster mutation below funnels through this so the host-first
    /// ordering is maintained in exactly one place.
    fn upsert_call_member(&mut self, peer: UserId, name: String, state: CallMemberState) {
        let Some(call) = self.call.as_mut() else {
            return;
        };
        match call.members.iter_mut().find(|m| m.id == peer) {
            Some(existing) => {
                existing.name = name;
                existing.state = state;
            }
            None => call.members.push(CallMember {
                id: peer,
                name,
                state,
                host_muted: false,
                self_muted: false,
                level: 0,
            }),
        }
        self.sort_call_members();
    }



    /// Records a newly-connected participant on the roster - a no-op if
    /// we're not actually shown as on a call (defensive; shouldn't happen,
    /// since `crate::client::voice_call` only ever adds a participant to an
    /// `ActiveCall` that already exists).
    /// Records a newly-connected participant on the roster - a no-op if
    /// we're not actually shown as on a call (defensive; shouldn't happen,
    /// since `crate::client::voice_call` only ever adds a participant to an
    /// `ActiveCall` that already exists).
    pub fn on_call_participant_joined(&mut self, peer: UserId, name: String) {
        self.upsert_call_member(peer, name, CallMemberState::InCall);
    }



    /// Records an invite we (as host) have just sent - the row shows
    /// `INVITED` until they answer.
    /// Records an invite we (as host) have just sent - the row shows
    /// `INVITED` until they answer.
    pub fn on_call_invite_sent(&mut self, peer: UserId, name: String) {
        self.upsert_call_member(peer, name, CallMemberState::Invited);
    }



    /// Records a `CallReject` from someone we invited. Only ever moves an
    /// `Invited` row to `Rejected`: a stale reject from someone who has
    /// since joined (a second invite they answered twice) must not knock
    /// them off the call.
    /// Records a `CallReject` from someone we invited. Only ever moves an
    /// `Invited` row to `Rejected`: a stale reject from someone who has
    /// since joined (a second invite they answered twice) must not knock
    /// them off the call.
    pub fn on_call_invite_rejected(&mut self, peer: UserId) {
        if let Some(call) = self.call.as_mut()
            && let Some(member) = call.members.iter_mut().find(|m| m.id == peer)
            && member.state == CallMemberState::Invited
        {
            member.state = CallMemberState::Rejected;
            member.level = 0;
        }
    }



    /// Drops someone who left the call outright (`CallEnd`, or a dead
    /// link) - unlike a reject, there is no lingering row: they were on
    /// the call and now are not.
    /// Drops someone who left the call outright (`CallEnd`, or a dead
    /// link) - unlike a reject, there is no lingering row: they were on
    /// the call and now are not.
    pub fn on_call_participant_left(&mut self, peer: UserId) {
        let Some(call) = self.call.as_mut() else {
            return;
        };
        call.members.retain(|m| m.id != peer);
        call.selected = call.selected.min(call.members.len().saturating_sub(1));
    }



    /// Applies `peer`'s own mute state to the roster - see
    /// `CallMember::self_muted`. Never touches anyone's capture: this is
    /// what that person says about their own microphone, which everyone
    /// on the call is shown.
    /// Applies `peer`'s own mute state to the roster - see
    /// `CallMember::self_muted`. Never touches anyone's capture: this is
    /// what that person says about their own microphone, which everyone
    /// on the call is shown.
    pub fn set_call_member_self_muted(&mut self, peer: UserId, muted: bool) {
        if let Some(call) = self.call.as_mut()
            && let Some(member) = call.members.iter_mut().find(|m| m.id == peer)
        {
            member.self_muted = muted;
            if muted {
                member.level = 0;
            }
        }
    }



    /// Applies the host's mute decision for `peer` to the roster - see
    /// `CallMember::host_muted`. Whether *we* are the one it silences is
    /// the session's business (`voice_call::on_call_mute`); this is only
    /// what everyone sees.
    /// Applies the host's mute decision for `peer` to the roster - see
    /// `CallMember::host_muted`. Whether *we* are the one it silences is
    /// the session's business (`voice_call::on_call_mute`); this is only
    /// what everyone sees.
    pub fn set_call_member_host_muted(&mut self, peer: UserId, muted: bool) {
        if let Some(call) = self.call.as_mut()
            && let Some(member) = call.members.iter_mut().find(|m| m.id == peer)
        {
            member.host_muted = muted;
            if muted {
                member.level = 0;
            }
        }
    }



    /// Feeds one voice meter (`crate::client::voice::level_from_pcm`) -
    /// called for our own captured audio and for every participant's
    /// decoded audio, from the workers that already hold that PCM.
    /// Feeds one voice meter (`crate::client::voice::level_from_pcm`) -
    /// called for our own captured audio and for every participant's
    /// decoded audio, from the workers that already hold that PCM.
    pub fn set_call_level(&mut self, peer: UserId, level: u8) {
        if let Some(call) = self.call.as_mut()
            && let Some(member) = call.members.iter_mut().find(|m| m.id == peer)
        {
            member.level = level.min(100);
        }
    }



    /// Everyone we could invite to the call we're hosting: someone we
    /// share a joined channel or DM history with (`has_reason_to_keep_link`,
    /// the same relationship bar a direct link already has to clear),
    /// online, not trust-gated, not under an OTP session (which has no
    /// live-streaming concept at all, `docs/PROTOCOL.md` 16), and not
    /// already on the roster. That last one is what makes "only one active
    /// invitation at a time per user" hold.
    /// Everyone we could invite to the call we're hosting: someone we
    /// share a joined channel or DM history with (`has_reason_to_keep_link`,
    /// the same relationship bar a direct link already has to clear),
    /// online, not trust-gated, not under an OTP session (which has no
    /// live-streaming concept at all, `docs/PROTOCOL.md` 16), and not
    /// already on the roster. That last one is what makes "only one active
    /// invitation at a time per user" hold.
    pub fn call_invite_candidates(&self) -> Vec<(UserId, String)> {
        let Some(call) = self.call.as_ref() else {
            return Vec::new();
        };
        let mut out: Vec<(UserId, String)> = self
            .known_users
            .values()
            .filter(|u| {
                Some(u.id) != self.own_id
                    && !self.offline.contains(&u.id)
                    && !self.is_trust_gated(u.id)
                    && !self.is_otp_active(u.id)
                    && self.has_reason_to_keep_link(u.id)
                    && !call.members.iter().any(|m| {
                        m.id == u.id
                            && matches!(m.state, CallMemberState::InCall | CallMemberState::Invited)
                    })
            })
            .map(|u| (u.id, u.name.clone()))
            .collect();
        out.sort_by(|a, b| a.1.cmp(&b.1));
        out
    }



    /// Opens the host-only invite picker, snapshotting its candidate list.
    /// Returns whether it actually opened - `false` when we aren't the
    /// host, or nobody is left to invite (a notice is pushed for the
    /// latter, so the keypress is never silently ignored).
    /// Opens the host-only invite picker, snapshotting its candidate list.
    /// Returns whether it actually opened - `false` when we aren't the
    /// host, or nobody is left to invite (a notice is pushed for the
    /// latter, so the keypress is never silently ignored).
    pub fn open_call_invite_picker(&mut self) -> bool {
        let own_id = self.own_id;
        let Some(call) = self.call.as_ref() else {
            return false;
        };
        if !call.we_are_host(own_id) {
            return false;
        }
        let candidates = self.call_invite_candidates();
        if candidates.is_empty() {
            self.push_status_notice("nobody left to invite to this call".to_string(), false);
            return false;
        }
        if let Some(call) = self.call.as_mut() {
            call.invite_picker = Some(CallInvitePicker {
                candidates,
                selected: 0,
            });
        }
        true
    }



    /// Whether the call modal is the thing currently owning the screen -
    /// i.e. a call is on and Escape has not folded its modal away into the
    /// header's `\u{23FA} Call Ctrl+R` indicator (which is what brings it back).
    pub fn call_modal_showing(&self) -> bool {
        self.call.as_ref().is_some_and(|c| !c.minimized)
    }

    /// Resolves what `/call` should address, mirroring
    /// `current_voice_target`'s DM branch (same offline/trust-gate checks)
    /// but, unlike it, not resolving a channel's recipient list here -
    /// `crate::client::channel::handle_start_call` recomputes that fresh
    /// (`crate::client::voice_call::addressable_channel_members`), since an
    /// invite (unlike an already-flowing recording) tolerates the extra
    /// few milliseconds that costs.
    pub(crate) fn current_call_target(&self) -> Option<CallTarget> {
        if let Some(peer_id) = self.active_private_room {
            if self.offline.contains(&peer_id) || self.is_trust_gated(peer_id) {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?;
            return Some(CallTarget::Direct {
                to: peer_id,
                recipient_pubkey_der: peer.public_key_der.clone(),
            });
        }
        let channel = self.channels.get(self.selected_channel)?;
        if !channel.joined {
            return None;
        }
        Some(CallTarget::Channel {
            channel: channel.name.clone(),
        })
    }



    /// How many people `/call` against `target` will actually ring -
    /// what the confirmation popup prints. Mirrors
    /// `crate::client::voice_call::addressable_channel_members`'s own
    /// filter (an ordinary channel send's recipients, minus anyone under
    /// an OTP session) so the number the user agrees to is the number that
    /// gets invited; the session side recounts for real a moment later,
    /// since membership can shift while the popup is up.
    /// How many people `/call` against `target` will actually ring -
    /// what the confirmation popup prints. Mirrors
    /// `crate::client::voice_call::addressable_channel_members`'s own
    /// filter (an ordinary channel send's recipients, minus anyone under
    /// an OTP session) so the number the user agrees to is the number that
    /// gets invited; the session side recounts for real a moment later,
    /// since membership can shift while the popup is up.
    pub(crate) fn call_invitee_count(&self, target: &CallTarget) -> usize {
        match target {
            CallTarget::Direct { to, .. } => usize::from(!self.is_otp_active(*to)),
            CallTarget::Channel { channel } => self
                .channels
                .iter()
                .find(|c| &c.name == channel)
                .map(|tab| {
                    self.recipients_for_channel(tab)
                        .into_iter()
                        .filter(|(id, ..)| !self.is_otp_active(*id))
                        .count()
                })
                .unwrap_or(0),
        }
    }


}
