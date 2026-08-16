//! Push-to-talk voice steps (US-007, client side).

use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use cucumber::{given, then, when};

use aloo::proto::{KeyMode, UserId};
use aloo::client::tui::ui::{MessageBody, UiAction, VoiceTarget};
use aloo::client::tui::ui::format_duration_label;

use crate::steps::ui_common::id_for;
use crate::support::ui_rows;
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
                    KeyMode::Rsa,
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
