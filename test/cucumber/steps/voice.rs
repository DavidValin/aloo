//! Push-to-talk voice steps (US-007, client side).

use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use cucumber::{given, then, when};

use aloo::proto::{KeyMode, UserId};
use aloo::client::tui::ui::{MessageBody, PendingCallInvite, UiAction, VoiceTarget};
use aloo::client::tui::ui::format_duration_label;

use crate::steps::ui_common::id_for;
use crate::support::{header_row, ui_rows};
use crate::world::AlooWorld;

// ---------------------------------------------------------------------
// When
// ---------------------------------------------------------------------

#[when("I hold Space")]
async fn hold_space(w: &mut AlooWorld) {
    let action = w
        .ui_mut()
        .handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    w.action_was_none = action.is_none();
    if action.is_some() {
        w.last_action = action;
    }
}

#[when("I release Space")]
async fn release_space(w: &mut AlooWorld) {
    let action = w.ui_mut().handle_key(
        KeyCode::Char(' '),
        KeyModifiers::NONE,
        KeyEventKind::Release,
    );
    w.action_was_none = action.is_none();
    if action.is_some() {
        w.last_action = action;
    }
}

// Global (works-anywhere, see `aloo::client::global_ptt`) push-to-talk. Deliberately
// exercises `UiState::global_record_start`/`global_record_stop` directly
// rather than `handle_key` - unlike Space, this trigger has no notion of
// terminal focus at all (it fires from the OS while some other window is
// focused), so there's no key event to synthesize.

#[when("I hold Ctrl+Alt+P")]
async fn hold_global_shortcut(w: &mut AlooWorld) {
    let action = w.ui_mut().global_record_start();
    w.action_was_none = action.is_none();
    if action.is_some() {
        w.last_action = action;
    }
}

#[when("I release Ctrl+Alt+P")]
async fn release_global_shortcut(w: &mut AlooWorld) {
    let action = w.ui_mut().global_record_stop();
    w.action_was_none = action.is_none();
    if action.is_some() {
        w.last_action = action;
    }
}

#[given(expr = "{word} starts streaming a voice message into the channel")]
async fn peer_starts_stream(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    w.ui_mut().on_channel_stream_start("general", id, name, 42);
}

#[given(expr = "{word} starts streaming a voice message into our private room")]
async fn peer_starts_dm_stream(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    w.ui_mut().on_direct_stream_start(id, id, name, 5);
}

#[when(expr = "{word}'s voice message finishes after {int} milliseconds")]
async fn peer_stream_finishes(w: &mut AlooWorld, name: String, duration: u32) {
    let id = UserId(id_for(&name));
    w.ui_mut()
        .on_channel_stream_finished("general", id, 42, duration, vec![1, 2, 3, 4]);
}

#[when(expr = "{word}'s private voice message finishes after {int} milliseconds")]
async fn peer_dm_stream_finishes(w: &mut AlooWorld, name: String, duration: u32) {
    let id = UserId(id_for(&name));
    w.ui_mut()
        .on_direct_stream_finished(id, id, 5, duration, vec![1]);
}

#[when("my own voice message starts streaming into the channel")]
async fn own_stream_starts(w: &mut AlooWorld) {
    w.ui_mut().log_own_voice_stream_start_channel("general", 7);
}

#[when(expr = "my own voice message finishes after {int} milliseconds")]
async fn own_stream_finishes(w: &mut AlooWorld, duration: u32) {
    w.ui_mut()
        .on_channel_stream_finished("general", UserId(1), 7, duration, vec![9, 9]);
}

#[when(expr = "the recorder fails with {string}")]
async fn recorder_fails(w: &mut AlooWorld, reason: String) {
    w.ui_mut().recording_failed(reason);
}

#[when(expr = "playback fails with {string}")]
async fn playback_fails(w: &mut AlooWorld, reason: String) {
    w.ui_mut().playback_failed(reason);
}

// ---------------------------------------------------------------------
// Then
// ---------------------------------------------------------------------

#[then(expr = "a voice message starts streaming to the channel, addressed to {word}")]
async fn stream_to_channel(w: &mut AlooWorld, name: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::VoiceRecordStart(VoiceTarget::Channel {
            channel,
            recipients,
        }) => {
            assert_eq!(channel, "general");
            assert_eq!(
                recipients,
                &vec![(
                    UserId(id_for(&name)),
                    KeyMode::Password,
                    vec![id_for(&name) as u8; 4]
                )],
                "the stream must be addressed to that member, carrying their key"
            );
        }
        other => panic!("expected a channel voice recording to start, got {other:?}"),
    }
    assert!(
        w.ui_ref().recording,
        "the UI should now consider itself recording"
    );
}

#[then(expr = "a voice message starts streaming privately to {word}")]
async fn stream_to_dm(w: &mut AlooWorld, name: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::VoiceRecordStart(VoiceTarget::Direct {
            to,
            recipient_pubkey_der,
            ..
        }) => {
            assert_eq!(
                *to,
                UserId(id_for(&name)),
                "a recording in a private room goes to that peer"
            );
            assert_eq!(recipient_pubkey_der, &vec![id_for(&name) as u8; 4]);
        }
        other => panic!("expected a direct voice recording to start, got {other:?}"),
    }
}

#[then("the voice message is sent")]
async fn voice_sent(w: &mut AlooWorld) {
    assert_eq!(
        w.last_action.as_ref(),
        Some(&UiAction::VoiceRecordStop),
        "releasing the key should end the stream"
    );
    assert!(
        !w.ui_ref().recording,
        "and the UI should stop claiming to record"
    );
}

#[then("no recording starts")]
async fn no_recording(w: &mut AlooWorld) {
    assert!(w.action_was_none, "nothing should have been requested");
    assert!(
        !w.ui_ref().recording,
        "and the UI must not claim to be recording"
    );
}

#[then("a recording indicator is shown")]
async fn indicator_shown(w: &mut AlooWorld) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        rows.iter().any(|r| r.contains("recording")),
        "expected a recording indicator: {rows:?}"
    );
}

#[then(expr = "the channel log shows a streaming placeholder from {word}")]
async fn placeholder_shown(w: &mut AlooWorld, name: String) {
    let state = w.ui_ref();
    let log = &state.channels[0].log;
    let entry = log
        .iter()
        .find(|e| e.from == UserId(id_for(&name)))
        .unwrap_or_else(|| panic!("no log entry from {name}"));
    assert!(
        matches!(entry.body, MessageBody::VoiceStreaming { .. }),
        "an in-progress voice message shows as a streaming block, got {:?}",
        entry.body
    );
}

#[then("my own streaming placeholder appears immediately")]
async fn own_placeholder(w: &mut AlooWorld) {
    let state = w.ui_ref();
    let entry = state.channels[0].log.first().expect("nothing logged");
    assert_eq!(entry.body, MessageBody::VoiceStreaming { stream_id: 7 });
    assert!(entry.outgoing, "my own stream should be logged as outgoing");
}

#[then(expr = "it becomes a replayable voice message of {int} milliseconds, in place")]
async fn becomes_replayable(w: &mut AlooWorld, duration: u32) {
    let state = w.ui_ref();
    let log = &state.channels[0].log;
    assert_eq!(
        log.len(),
        1,
        "finishing must swap the placeholder in place, not append a second entry"
    );
    match &log[0].body {
        MessageBody::Voice { duration_ms, pcm } => {
            assert_eq!(
                *duration_ms, duration,
                "the real recorded length must be kept"
            );
            assert!(
                !pcm.is_empty(),
                "the finished message should carry its audio for replay"
            );
        }
        other => panic!("expected a finished voice message, got {other:?}"),
    }
}

#[then(expr = "the private room shows a replayable voice message of {int} milliseconds")]
async fn dm_becomes_replayable(w: &mut AlooWorld, duration: u32) {
    let state = w.ui_ref();
    let room = state
        .private_rooms
        .get(&UserId(2))
        .expect("no private room");
    assert_eq!(
        room.log.len(),
        1,
        "the placeholder must be swapped in place"
    );
    assert_eq!(
        room.log[0].body,
        MessageBody::Voice {
            duration_ms: duration,
            pcm: vec![1]
        }
    );
}

#[then("replaying that voice message is requested")]
async fn replay_requested(w: &mut AlooWorld) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::ReplayVoice { duration_ms, pcm } => {
            assert_eq!(*duration_ms, 4200);
            assert_eq!(
                pcm,
                &vec![1, 2, 3, 4],
                "replay must be handed the audio it recorded"
            );
        }
        other => panic!("expected a replay request, got {other:?}"),
    }
}

#[given("bob has left me a finished voice message")]
async fn finished_voice_from_bob(w: &mut AlooWorld) {
    w.ui_mut().on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Voice {
            duration_ms: 4200,
            pcm: vec![1, 2, 3, 4],
        },
    );
}

#[then("playback is stopped")]
async fn playback_stopped(w: &mut AlooWorld) {
    assert_eq!(w.last_action, Some(UiAction::StopPlayback));
    assert!(
        !w.ui_ref().replaying,
        "the replaying flag should be cleared once Escape stops it"
    );
}

#[given("bob has left me a text message")]
async fn text_from_bob(w: &mut AlooWorld) {
    w.ui_mut().on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("hi".into()),
    );
}

#[then(expr = "a voice message of {int} milliseconds is labelled {string}")]
async fn duration_label(_w: &mut AlooWorld, ms: u32, expected: String) {
    assert_eq!(
        format_duration_label(ms),
        expected,
        "the label must reflect this recording's own length"
    );
}

#[then(expr = "the audio failure {string} is never shown on screen")]
async fn failure_not_rendered(w: &mut AlooWorld, reason: String) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        !rows.iter().any(|r| r.contains(&reason)),
        "transient audio errors are tracked but deliberately not rendered: {rows:?}"
    );
    assert_eq!(
        w.ui_ref().audio_error.as_deref(),
        Some(reason.as_str()),
        "the reason must still be tracked internally, just not displayed"
    );
}

#[then("the UI stops claiming to record")]
async fn stops_claiming(w: &mut AlooWorld) {
    assert!(
        !w.ui_ref().recording,
        "a failed start must not leave a misleading indicator up"
    );
}

#[then("the recording carries on regardless")]
async fn recording_continues(w: &mut AlooWorld) {
    assert!(
        w.ui_ref().recording,
        "a playback failure is unrelated to an in-progress recording"
    );
}

// ---------------------------------------------------------------------
// Live voice calls (US-036) - distinct from push-to-talk above. Only the
// `UiState`-level half is exercised here (invite popup, permanent
// indicator, slash commands); the network/audio orchestration
// (`crate::client::voice_call`) needs a live session, see
// docs/TESTING.md's "Known coverage gaps".
// ---------------------------------------------------------------------

#[given(expr = "{word} is calling me in the channel")]
async fn call_invite_arrives(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    w.ui_mut().push_call_invite(PendingCallInvite {
        call_id: id_for(&name),
        from: id,
        from_name: name,
        channel: Some("general".into()),
        ended: false,
    });
}

/// What the host's `CallEnd` does to an invite of ours that is still
/// unanswered (`crate::client::voice_call::on_call_end`): the popup stays
/// up, but there is no longer a call behind it.
#[when("that call ends before I answer")]
async fn that_call_ends(w: &mut AlooWorld) {
    let call_id = w
        .ui_ref()
        .call_invite_open()
        .expect("no call invite popup is open")
        .call_id;
    assert!(w.ui_mut().mark_call_invite_ended(call_id));
}

#[then("no call invite is accepted")]
async fn no_call_invite_accepted(w: &mut AlooWorld) {
    assert!(
        !matches!(w.last_action, Some(UiAction::AcceptCallInvite { .. })),
        "nothing should have been joined: {:?}",
        w.last_action
    );
}

#[then("no call invite popup is open")]
async fn no_call_invite_popup(w: &mut AlooWorld) {
    assert!(
        w.ui_ref().call_invite_open().is_none(),
        "the answer is spent either way - the popup should be gone"
    );
}

#[then(expr = "the call modal names {word} as the host")]
async fn call_modal_names_host(w: &mut AlooWorld, name: String) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        rows.iter().any(|r| r.contains(&format!("{name} (host)"))),
        "expected {name:?} named as the host: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("HOST")),
        "the host carries no label of its own: {rows:?}"
    );
}

#[then(expr = "a call invite popup names {word}")]
async fn call_invite_names(w: &mut AlooWorld, name: String) {
    let invite = w.ui_ref().call_invite_open().expect("no call invite popup is open");
    assert_eq!(invite.from_name, name);
}

#[then(expr = "accepting {word}'s call is requested")]
async fn accepting_call_requested(w: &mut AlooWorld, name: String) {
    assert_eq!(
        w.last_action,
        Some(UiAction::AcceptCallInvite {
            call_id: id_for(&name)
        })
    );
}

#[then(expr = "rejecting {word}'s call is requested")]
async fn rejecting_call_requested(w: &mut AlooWorld, name: String) {
    assert_eq!(
        w.last_action,
        Some(UiAction::RejectCallInvite {
            call_id: id_for(&name)
        })
    );
}

/// Applies whichever Accept/Reject decision `handle_key` just produced -
/// `session::handle_ui_action` does this over the network in production
/// (`voice_call::accept_invite`/`reject_invite`); here it's just the local
/// `take_call_invite` half, enough to prove the queue advances.
#[when("that decision is applied")]
async fn call_decision_applied(w: &mut AlooWorld) {
    let call_id = match w.last_action {
        Some(UiAction::AcceptCallInvite { call_id } | UiAction::RejectCallInvite { call_id }) => {
            call_id
        }
        ref other => panic!("expected a call invite decision, got {other:?}"),
    };
    w.ui_mut().take_call_invite(call_id);
}

/// Joins a call we host, with the modal folded away into its tab - an
/// open modal deliberately absorbs every key, so the scenarios that go on
/// to type `/endcall` need it out of the way, exactly as a real
/// user pressing Escape would leave it.
#[when("I join a call in the channel")]
async fn i_join_a_call(w: &mut AlooWorld) {
    let ui = w.ui_mut();
    ui.begin_call(1, Some("general".into()), UserId(id_for("me")));
    ui.call.as_mut().expect("just begun").minimized = true;
}

#[when("I open a call in the channel")]
async fn i_open_a_call(w: &mut AlooWorld) {
    w.ui_mut()
        .begin_call(1, Some("general".into()), UserId(id_for("me")));
}

#[when(expr = "{word} hosts a call I am on")]
async fn peer_hosts_a_call(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    w.ui_mut().begin_call(1, Some("general".into()), id);
    w.ui_mut().on_call_participant_joined(id, name);
}

#[when(expr = "{word} is invited to the call")]
async fn peer_is_invited(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    w.ui_mut().on_call_invite_sent(id, name);
}

#[when(expr = "{word} declines the call")]
async fn peer_declines(w: &mut AlooWorld, name: String) {
    w.ui_mut().on_call_invite_rejected(UserId(id_for(&name)));
}

#[when(expr = "the host mutes {word}")]
async fn host_mutes(w: &mut AlooWorld, name: String) {
    w.ui_mut()
        .set_call_member_host_muted(UserId(id_for(&name)), true);
}

#[when(expr = "the call has been running for {int} seconds")]
async fn call_running_for(w: &mut AlooWorld, secs: u64) {
    let started = w.ui_ref().call.as_ref().expect("not on a call").started_at;
    w.ui_mut()
        .tick_call_duration(started + std::time::Duration::from_secs(secs));
}

#[when("the host leaves the call")]
async fn host_leaves(w: &mut AlooWorld) {
    // The local half of `voice_call::on_call_end`'s host branch: the call
    // is over for us too, and we are told why.
    w.ui_mut().end_call();
    w.ui_mut()
        .push_status_notice(aloo::client::tui::ui::HOST_LEFT_NOTICE.to_string(), false);
}

#[then(expr = "the call modal lists {word} as {word}")]
async fn call_modal_lists(w: &mut AlooWorld, name: String, label: String) {
    let rows = ui_rows(w.ui_ref());
    let wanted = label.replace('_', " ");
    assert!(
        rows.iter().any(|r| r.contains(&name) && r.contains(&wanted)),
        "expected {name:?} labelled {wanted:?}: {rows:?}"
    );
}

#[then(expr = "the call modal shows the duration {string}")]
async fn call_modal_duration(w: &mut AlooWorld, expected: String) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        rows.iter().any(|r| r.contains(&expected)),
        "expected the duration {expected:?}: {rows:?}"
    );
}

#[then("the call modal is shown")]
async fn call_modal_shown(w: &mut AlooWorld) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        rows.iter().any(|r| r.contains("END CALL")),
        "expected the call modal: {rows:?}"
    );
}

#[then("the call modal is not shown")]
async fn call_modal_not_shown(w: &mut AlooWorld) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        !rows.iter().any(|r| r.contains("END CALL")),
        "the call modal should be folded away: {rows:?}"
    );
}

#[then("the call indicator is shown in the top row")]
async fn header_call_indicator_shown(w: &mut AlooWorld) {
    let rows = ui_rows(w.ui_ref());
    let top = header_row(&rows);
    assert!(
        top.contains("Call") && top.contains("Ctrl+R"),
        "expected the call indicator, advertising Ctrl+R: {rows:?}"
    );
}

#[then(expr = "the call confirmation says {string}")]
async fn call_confirmation_says(w: &mut AlooWorld, expected: String) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        rows.iter().any(|r| r.contains(&expected)),
        "expected {expected:?} in the confirmation: {rows:?}"
    );
}

#[then("starting the call is requested")]
async fn starting_call_requested(w: &mut AlooWorld) {
    assert!(
        matches!(w.last_action, Some(UiAction::StartCall(_))),
        "expected a StartCall, got {:?}",
        w.last_action
    );
}

#[then("no call is started")]
async fn no_call_started(w: &mut AlooWorld) {
    assert!(
        !matches!(w.last_action, Some(UiAction::StartCall(_))),
        "nothing should have been started: {:?}",
        w.last_action
    );
    assert!(w.ui_ref().call.is_none());
}

#[then(expr = "inviting {word} to the call is requested")]
async fn inviting_requested(w: &mut AlooWorld, name: String) {
    assert_eq!(
        w.last_action,
        Some(UiAction::InviteToCall {
            to: UserId(id_for(&name))
        })
    );
}

#[then(expr = "muting {word} is requested")]
async fn muting_member_requested(w: &mut AlooWorld, name: String) {
    assert_eq!(
        w.last_action,
        Some(UiAction::HostMuteCallMember {
            peer: UserId(id_for(&name)),
            muted: true
        })
    );
}

#[given(expr = "an OTP session is active with {word}")]
async fn otp_session_active(w: &mut AlooWorld, name: String) {
    w.ui_mut().mark_otp_active(UserId(id_for(&name)));
}

#[then("no call confirmation is shown")]
async fn no_call_confirmation(w: &mut AlooWorld) {
    assert!(
        w.ui_ref().call_confirm.is_none(),
        "an impossible call must not be confirmable"
    );
}

#[then("nothing is requested")]
async fn nothing_requested(w: &mut AlooWorld) {
    assert!(w.action_was_none, "the key should have been inert");
}

#[when(expr = "{word} joins the call with me")]
async fn peer_joins_call(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    w.ui_mut().on_call_participant_joined(id, name);
}

#[when("I mute myself")]
async fn i_mute_myself(w: &mut AlooWorld) {
    w.ui_mut().set_call_muted(true);
}

#[when("I leave the call")]
async fn i_leave_the_call(w: &mut AlooWorld) {
    w.ui_mut().end_call();
}

#[then("a call indicator is shown")]
async fn call_indicator_shown(w: &mut AlooWorld) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        rows.iter().any(|r| r.contains("On a call")),
        "expected the permanent call indicator: {rows:?}"
    );
}

#[then("no call indicator is shown")]
async fn no_call_indicator(w: &mut AlooWorld) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        !rows.iter().any(|r| r.contains("On a call")),
        "no call indicator should be showing: {rows:?}"
    );
}

#[then(expr = "the call indicator shows {int} connected")]
async fn call_indicator_connected_count(w: &mut AlooWorld, count: usize) {
    let rows = ui_rows(w.ui_ref());
    let wanted = format!("{count} connected");
    assert!(
        rows.iter().any(|r| r.contains(&wanted)),
        "expected {wanted:?}: {rows:?}"
    );
}

#[then("the call indicator shows muted")]
async fn call_indicator_muted(w: &mut AlooWorld) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        rows.iter().any(|r| r.contains("muted")),
        "expected the muted marker: {rows:?}"
    );
}

#[then(expr = "a call status notice says {string}")]
async fn call_status_notice_says(w: &mut AlooWorld, expected: String) {
    let (text, _) = w
        .ui_ref()
        .status_notice
        .as_ref()
        .expect("no status notice is shown");
    assert!(text.contains(&expected), "expected {expected:?} within {text:?}");
}

#[then("muting is requested")]
async fn muting_requested(w: &mut AlooWorld) {
    assert_eq!(w.last_action, Some(UiAction::ToggleCallMute));
}

#[then("ending the call is requested")]
async fn ending_call_requested(w: &mut AlooWorld) {
    assert_eq!(w.last_action, Some(UiAction::EndCall));
}

// ---------------------------------------------------------------------
// Muting a person's voice messages (US-037, docs/SPEC.md Functionality #15)
// ---------------------------------------------------------------------

#[given(expr = "{word}'s voice messages are muted")]
async fn given_voice_muted(w: &mut AlooWorld, name: String) {
    let mut muted = w.ui_ref().muted_voice.clone();
    muted.insert(name);
    w.ui_mut().set_muted_voice(muted);
}

#[then(expr = "{word}'s voice messages are muted")]
async fn then_voice_muted(w: &mut AlooWorld, name: String) {
    assert!(
        w.ui_ref().muted_voice.contains(&name),
        "{name} should be muted, muted set is {:?}",
        w.ui_ref().muted_voice
    );
}

#[then(expr = "{word}'s voice messages are not muted")]
async fn then_voice_not_muted(w: &mut AlooWorld, name: String) {
    assert!(
        !w.ui_ref().muted_voice.contains(&name),
        "{name} should not be muted, muted set is {:?}",
        w.ui_ref().muted_voice
    );
}

/// The predicate every incoming-audio decision funnels through
/// (`UiState::suppress_playback_from`) - what actually keeps a muted
/// sender's stream off the mixer, and what a trust-gated sender's stream
/// has always been kept off it by.
#[then(expr = "playback from {word} is suppressed")]
async fn then_playback_suppressed(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    assert!(
        w.ui_ref().suppress_playback_from(id),
        "audio from {name} should never reach the mixer"
    );
}

#[then(expr = "playback from {word} is not suppressed")]
async fn then_playback_not_suppressed(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    assert!(
        !w.ui_ref().suppress_playback_from(id),
        "audio from {name} should play as usual"
    );
}

#[then(expr = "a status notice says {string}")]
async fn then_status_notice_says(w: &mut AlooWorld, expected: String) {
    let (text, _) = w
        .ui_ref()
        .status_notice
        .as_ref()
        .expect("no status notice is shown");
    assert!(
        text.contains(&expected),
        "status notice {text:?} should contain {expected:?}"
    );
}

#[then(expr = "a status notice names {word}")]
async fn then_status_notice_names(w: &mut AlooWorld, name: String) {
    let (text, _) = w
        .ui_ref()
        .status_notice
        .as_ref()
        .expect("no status notice is shown");
    assert!(
        text.contains(&name),
        "status notice {text:?} should name {name:?}"
    );
}
