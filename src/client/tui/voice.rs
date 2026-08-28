//! Push-to-talk recording state, and who is muted.
//!
//! The capture itself lives in `client::voice`; this is only what the UI
//! knows about it - whether a recording is running, what started it, when
//! it was last heard from (so a stalled one can be timed out), and the
//! per-nickname mute list `/mute-voice` maintains.

use std::time::Instant;

use crate::proto::UserId;

use super::ui::*;

impl UiState {
    /// Whether `peer`'s voice messages are muted (`/mute-voice`,
    /// docs/SPEC.md Functionality #15) - resolved through their *current*
    /// nickname, since that is what the user muted and what persists.
    /// A peer we hold no `UserInfo` for is never muted: there is no name
    /// to have matched.
    ///
    /// Paired with `is_trust_gated` at every incoming-audio decision:
    /// either being true means the stream is still decrypted and still
    /// logged, but never reaches the mixer.
    pub fn is_voice_muted(&self, peer: UserId) -> bool {
        self.known_users
            .get(&peer)
            .is_some_and(|u| self.muted_voice.contains(&u.name))
    }

    /// Replaces the muted-voice set - used once at session start to seed
    /// it from `~/.aloo/settings`.
    pub fn set_muted_voice(&mut self, muted: std::collections::BTreeSet<String>) {
        self.muted_voice = muted;
    }

    /// Called by the caller (`session`/`channel`/`direct_message`) when
    /// starting the recorder itself failed (e.g. no audio input device).
    /// Turns off the misleading "recording..." indicator immediately
    /// instead of waiting for the user to release Space, and surfaces why.
    pub fn recording_failed(&mut self, reason: String) {
        self.recording = false;
        self.recording_source = None;
        self.recording_last_seen = None;
        self.audio_error = Some(reason);
    }

    /// Starts a recording from the global Ctrl+Alt+P shortcut. Deliberately
    /// mirrors `handle_key`'s Space branch (same target resolution, same
    /// "nowhere to send it" bail-out) rather than sharing code: they
    /// differ only in `RecordSource` tagging, and Space's branch
    /// interleaves with focus/mode handling that's meaningless for a
    /// shortcut fired while the app isn't focused. A no-op while any
    /// recording is in progress.
    pub fn global_record_start(&mut self) -> Option<UiAction> {
        if self.recording {
            return None;
        }
        match self.current_voice_target() {
            Some(target) => {
                self.recording = true;
                self.recording_source = Some(RecordSource::Global);
                self.audio_error = None;
                Some(UiAction::VoiceRecordStart(target))
            }
            None => {
                self.audio_error = Some("not joined to a channel yet".to_string());
                None
            }
        }
    }

    /// Stops a recording the global shortcut itself started - a no-op if
    /// nothing is recording, or if the current recording was started by
    /// Space instead (that one only ever ends on Space's own release; see
    /// `handle_key`).
    pub fn global_record_stop(&mut self) -> Option<UiAction> {
        if !self.recording || self.recording_source != Some(RecordSource::Global) {
            return None;
        }
        self.recording = false;
        self.recording_source = None;
        self.recording_last_seen = None;
        Some(UiAction::VoiceRecordStop)
    }

    /// Stops whatever recording is currently in progress, regardless of
    /// which trigger started it (unlike `global_record_stop`, which only
    /// ever stops one it itself started) or whether the physical key is
    /// still held. Used when the recording worker hits
    /// `voice::MAX_RECORDING_SAMPLES` and needs to end on its own instead
    /// of waiting for a release event that may not come for a while yet -
    /// see `session::run_connected_session`'s `auto_stop_rx` arm.
    pub fn force_stop_recording(&mut self) -> Option<UiAction> {
        if !self.recording {
            return None;
        }
        self.recording = false;
        self.recording_source = None;
        self.recording_last_seen = None;
        Some(UiAction::VoiceRecordStop)
    }

    /// Call periodically; auto-stops a recording once Space has been quiet
    /// for `RECORD_HOLD_TIMEOUT`, for terminals that never send `Release`
    /// (see `handle_key`). A no-op when `keyboard_release_reporting` is
    /// `true` - a real `Release` is guaranteed there, so the guess must
    /// never fire. Also a no-op for a `Global`-sourced recording: a held
    /// OS hotkey has no repeat heartbeat to go quiet, and its backends all
    /// deliver a real release - the idle guess would wrongly auto-stop
    /// every global recording after ~`RECORD_HOLD_TIMEOUT`.
    pub fn tick_recording_timeout(&mut self, now: Instant) -> Option<UiAction> {
        if !self.recording
            || self.keyboard_release_reporting
            || self.recording_source != Some(RecordSource::Space)
        {
            return None;
        }
        let last = self.recording_last_seen?;
        if now.duration_since(last) < RECORD_HOLD_TIMEOUT {
            return None;
        }
        self.recording = false;
        self.recording_source = None;
        self.recording_last_seen = None;
        Some(UiAction::VoiceRecordStop)
    }
}
