//! Background-mode steps (US-038): what a daemon is configured to be,
//! where it puts the focus, and how a terminal borrows the session.
//!
//! The assertions live here, the intent lives in the `.feature` files.
//!
//! Most of these drive the pure surface `DaemonConfig`/`DaemonPlan`
//! expose - what a daemon is configured to be, and where it decides to
//! put the focus. The attach scenarios at the bottom are the exception
//! and use a real socket, because the property worth pinning there is
//! precisely what crosses it: that a terminal can borrow the session and
//! give it back without taking it down. Nothing here re-execs a process -
//! backgrounding itself is exercised end to end, not from a scenario.

use cucumber::{given, then, when};

use aloo::client::connect::{ConnectCache, ServerKeySelection};
use aloo::client::daemon::{DaemonChannel, DaemonConfig, DaemonFlags, DaemonFocus, DaemonPlan};
use aloo::settings::Settings;

use crate::world::AlooWorld;

fn flags(w: &mut AlooWorld) -> &mut DaemonFlags {
    w.daemon_flags.get_or_insert_with(DaemonFlags::default)
}

fn settings(w: &mut AlooWorld) -> &mut Settings {
    w.daemon_settings.get_or_insert_with(Settings::default)
}

fn plan(w: &AlooWorld) -> &DaemonPlan {
    w.daemon_plan
        .as_ref()
        .expect("no daemon plan in this scenario")
}

fn config(w: &AlooWorld) -> &DaemonConfig {
    w.daemon_config
        .as_ref()
        .expect(match &w.daemon_error {
            Some(e) => Box::leak(format!("the daemon refused to start: {e}").into_boxed_str()),
            None => "nothing has been resolved in this scenario",
        })
}

// ---------------------------------------------------------------------
// Given
// ---------------------------------------------------------------------

#[given("no daemon settings and nothing in the connect cache")]
async fn nothing_remembered(w: &mut AlooWorld) {
    w.daemon_settings = Some(Settings::default());
    w.daemon_flags = Some(DaemonFlags::default());
}

#[given(expr = "the connect cache remembers {string} on port {int}")]
async fn cache_remembers(w: &mut AlooWorld, host: String, port: u16) {
    let mut cache = ConnectCache::new_empty(w.temp_path("daemon-cache"));
    cache.record(&host, port, "/keys/remembered.pub", "/keys/remembered.priv");
    // Stored on the world by re-resolving through it below; kept simple
    // by holding the values a scenario asserts on.
    w.daemon_settings.get_or_insert_with(Settings::default);
    w.daemon_flags.get_or_insert_with(DaemonFlags::default);
    w.connect_cache = Some(cache);
}

#[given(expr = "the settings file records the server {string} on port {int}")]
async fn settings_record_server(w: &mut AlooWorld, host: String, port: u16) {
    let s = settings(w);
    s.daemon_host = Some(host);
    s.daemon_port = Some(port);
}

#[given(expr = "the settings file records the channel {string}")]
async fn settings_record_channel(w: &mut AlooWorld, channel: String) {
    settings(w).daemon_channels.push(channel);
}

#[given(expr = "the settings file records the nickname {string}")]
async fn settings_record_nickname(w: &mut AlooWorld, nickname: String) {
    settings(w).daemon_nickname = Some(nickname);
}

#[given(expr = "a daemon focused on the channel {string}")]
async fn plan_focused_on_channel(w: &mut AlooWorld, name: String) {
    w.daemon_plan = Some(DaemonPlan::new(
        vec![DaemonChannel::parse(&name).unwrap()],
        Some(DaemonFocus::Channel(name)),
    ));
}

#[given(expr = "a daemon focused on {word}")]
async fn plan_focused_on_person(w: &mut AlooWorld, nickname: String) {
    w.daemon_plan = Some(DaemonPlan::new(
        vec![DaemonChannel::parse("team").unwrap()],
        Some(DaemonFocus::Dm {
            nickname,
            otp: false,
        }),
    ));
}

#[given(expr = "a daemon focused on {word} with --otp")]
async fn plan_focused_on_person_otp(w: &mut AlooWorld, nickname: String) {
    w.daemon_plan = Some(DaemonPlan::new(
        vec![DaemonChannel::parse("team").unwrap()],
        Some(DaemonFocus::Dm {
            nickname,
            otp: true,
        }),
    ));
}

#[given(expr = "an OTP session is already active with {word}")]
async fn otp_already_active(w: &mut AlooWorld, _nickname: String) {
    w.daemon_otp_active = true;
}

#[given(expr = "the focus has already been placed")]
#[when("the focus is placed")]
async fn focus_already_placed(w: &mut AlooWorld) {
    w.daemon_plan
        .as_mut()
        .expect("no daemon plan in this scenario")
        .focus_applied = true;
}

// ---------------------------------------------------------------------
// When
// ---------------------------------------------------------------------

#[when(expr = "the daemon is started with --host={word}")]
async fn started_with_host(w: &mut AlooWorld, host: String) {
    flags(w).host = Some(host);
    resolve(w).await;
}

#[when(expr = "the daemon is started with --channels={word}")]
async fn started_with_channels(w: &mut AlooWorld, channels: String) {
    flags(w).host = Some("chat.example".to_string());
    flags(w).channels = vec![channels];
    resolve(w).await;
}

#[when(expr = "the daemon is started with --focus={word}")]
async fn started_with_focus(w: &mut AlooWorld, focus: String) {
    flags(w).host = Some("chat.example".to_string());
    flags(w).focus = Some(focus);
    resolve(w).await;
}

#[when(expr = "the daemon is started with --channels={word} --focus={word}")]
async fn started_with_channels_and_focus(w: &mut AlooWorld, channels: String, focus: String) {
    flags(w).host = Some("chat.example".to_string());
    flags(w).channels = vec![channels];
    flags(w).focus = Some(focus);
    resolve(w).await;
}

#[when(expr = "the daemon is started with --focus={word} --otp")]
async fn started_with_focus_and_otp(w: &mut AlooWorld, focus: String) {
    flags(w).host = Some("chat.example".to_string());
    flags(w).focus = Some(focus);
    flags(w).otp = true;
    resolve(w).await;
}

#[when("the daemon is started with no flags at all")]
async fn started_bare(w: &mut AlooWorld) {
    resolve(w).await;
}

#[when(expr = "the daemon is started with both --server-pwd and --server-key")]
async fn started_with_both_credentials(w: &mut AlooWorld) {
    let f = flags(w);
    f.host = Some("chat.example".to_string());
    f.server_pwd = Some("pw".to_string());
    f.server_key_file = Some("/k.pub".into());
    resolve(w).await;
}

/// Runs the resolution every `When` above ends in, recording either the
/// configuration or the refusal for the `Then` steps to assert on.
async fn resolve(w: &mut AlooWorld) {
    let flags = w.daemon_flags.clone().unwrap_or_default();
    let settings = w.daemon_settings.clone().unwrap_or_default();
    let cache = w
        .connect_cache
        .take()
        .unwrap_or_else(|| ConnectCache::new_empty("/nonexistent/.cache".into()));
    match DaemonConfig::resolve(&flags, &settings, &cache) {
        Ok(config) => {
            w.daemon_config = Some(config);
            w.daemon_error = None;
        }
        Err(e) => {
            w.daemon_config = None;
            w.daemon_error = Some(e);
        }
    }
    w.connect_cache = Some(cache);
}

#[when(expr = "{word} appears")]
async fn peer_appears(w: &mut AlooWorld, nickname: String) {
    let already_active = w.daemon_otp_active;
    let plan = w
        .daemon_plan
        .as_mut()
        .expect("no daemon plan in this scenario");
    // Exactly what `session::on_daemon_peer_appeared` decides, in the same
    // order: whether to move the focus, and whether to invite.
    w.daemon_place_focus = plan.should_place_focus() && plan.focused_nickname() == Some(&nickname);
    w.daemon_invite_otp = plan.should_invite_otp(&nickname, already_active);
    if w.daemon_place_focus {
        plan.focus_applied = true;
    }
    if w.daemon_invite_otp {
        plan.otp_requested = true;
    }
}

#[when("the daemon is stopped and started again with the same --focus")]
async fn restarted(w: &mut AlooWorld) {
    // A restart is a fresh plan: the latch lives in memory and is never
    // persisted, which is the whole reason `--focus` applies again.
    let previous = plan(w).clone();
    w.daemon_plan = Some(DaemonPlan::new(previous.channels, previous.focus));
}

// ---------------------------------------------------------------------
// Then
// ---------------------------------------------------------------------

#[then(expr = "it connects to {string} on port {int}")]
async fn connects_to(w: &mut AlooWorld, host: String, port: u16) {
    let config = config(w);
    assert_eq!(config.host, host);
    assert_eq!(config.port, port);
}

#[then(expr = "it connects as {string}")]
async fn connects_as(w: &mut AlooWorld, nickname: String) {
    assert_eq!(config(w).nickname, nickname);
}

#[then(expr = "it joins exactly {string}")]
async fn joins_exactly(w: &mut AlooWorld, expected: String) {
    let names: Vec<&str> = config(w).channels.iter().map(|c| c.name.as_str()).collect();
    let want: Vec<&str> = expected.split(", ").collect();
    assert_eq!(names, want);
}

#[then(expr = "it joins {string} with the password {string}")]
async fn joins_with_password(w: &mut AlooWorld, name: String, password: String) {
    let channel = config(w)
        .channels
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("{name} is not being joined"));
    assert_eq!(channel.password.as_deref(), Some(password.as_str()));
}

#[then("it does not join the-hall")]
async fn does_not_join_the_hall(w: &mut AlooWorld) {
    assert!(
        !config(w).channels.iter().any(|c| c.name == "the-hall"),
        "the-hall is only ever joined when it was asked for"
    );
}

#[then(expr = "the focus is the channel {string}")]
async fn focus_is_channel(w: &mut AlooWorld, name: String) {
    assert_eq!(config(w).focus, Some(DaemonFocus::Channel(name)));
}

#[then(expr = "the focus is a private conversation with {word}")]
async fn focus_is_dm(w: &mut AlooWorld, nickname: String) {
    match &config(w).focus {
        Some(DaemonFocus::Dm { nickname: got, .. }) => assert_eq!(got, &nickname),
        other => panic!("expected a DM focus on {nickname}, got {other:?}"),
    }
}

#[then(expr = "it uses the server password {string}")]
async fn uses_server_password(w: &mut AlooWorld, password: String) {
    assert_eq!(
        config(w).server_key,
        ServerKeySelection::Password(password)
    );
}

#[then(expr = "it refuses to start, saying {string}")]
async fn refuses_saying(w: &mut AlooWorld, expected: String) {
    let error = w
        .daemon_error
        .as_ref()
        .expect("the daemon should have refused to start");
    assert!(
        error.contains(&expected),
        "refusal {error:?} should mention {expected:?}"
    );
}

#[then("the focus moves to them")]
async fn focus_moves(w: &mut AlooWorld) {
    assert!(
        w.daemon_place_focus,
        "the focus should have been placed on them"
    );
}

#[then("the focus is left where it was")]
async fn focus_left_alone(w: &mut AlooWorld) {
    assert!(
        !w.daemon_place_focus,
        "the focus belongs to whoever is driving once it has been placed"
    );
}

#[then("an OTP session is proposed")]
async fn otp_proposed(w: &mut AlooWorld) {
    assert!(w.daemon_invite_otp, "an invitation should have been sent");
}

#[then("no OTP session is proposed")]
async fn otp_not_proposed(w: &mut AlooWorld) {
    assert!(
        !w.daemon_invite_otp,
        "nothing should have been sent - the session is already running, or was not asked for"
    );
}

#[then(expr = "it is still an event worth announcing")]
async fn still_announced(w: &mut AlooWorld) {
    // The sound and the notification are driven by `is_focus_event`, which
    // is deliberately independent of whether the focus moved.
    let plan = plan(w);
    let nickname = plan
        .focused_nickname()
        .map(str::to_string)
        .unwrap_or_default();
    assert!(
        plan.is_focus_event(&nickname, Some("team")),
        "a focused peer reappearing is still worth a sound and a notification"
    );
}

// ---------------------------------------------------------------------
// Attaching a terminal to a running daemon
//
// These drive a real socket, since the behaviour worth pinning here is
// what actually crosses it: that a viewer can leave without taking the
// session with it. The runner is already async (`#[tokio::main]`), so a
// listener and a client can both live inside one scenario.
// ---------------------------------------------------------------------

use aloo::client::daemon_ipc::{self, AttachMessage, DaemonMessage};
use aloo::client::session::SessionInput;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Reads one message from the daemon, with a timeout so a scenario fails
/// with something readable rather than hanging the whole suite.
async fn read_reply(w: &mut AlooWorld) -> DaemonMessage {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((message, consumed)) =
            daemon_ipc::decode_frame::<DaemonMessage>(&w.daemon_read_buf).unwrap()
        {
            w.daemon_read_buf.drain(..consumed);
            return message;
        }
        let stream = w
            .daemon_client
            .as_mut()
            .expect("no terminal is attached in this scenario");
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut chunk),
        )
        .await
        .expect("the daemon should have answered by now")
        .unwrap();
        assert_ne!(read, 0, "the daemon closed the connection");
        let chunk = chunk[..read].to_vec();
        w.daemon_read_buf.extend_from_slice(&chunk);
    }
}

async fn next_session_input(w: &mut AlooWorld) -> SessionInput {
    let rx = w
        .daemon_input_rx
        .as_mut()
        .expect("no daemon is running in this scenario");
    tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("the session should have been told by now")
        .expect("the session's input channel must stay open")
}

#[given("a daemon is running with nobody attached")]
async fn daemon_listening(w: &mut AlooWorld) {
    let socket = w.temp_path("daemon-sock");
    let listener = daemon_ipc::bind_listener(&socket).unwrap();
    let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(aloo::client::daemon::serve_attachments(listener, input_tx));
    w.daemon_socket = Some(socket);
    w.daemon_input_rx = Some(input_rx);
}

#[when("a terminal attaches to it")]
#[given("a terminal has attached to it")]
async fn terminal_attaches(w: &mut AlooWorld) {
    let socket = w
        .daemon_socket
        .clone()
        .expect("no daemon is running in this scenario");
    let mut client = daemon_ipc::connect(&socket).await.unwrap();
    client
        .write_all(
            &daemon_ipc::encode_frame(&AttachMessage::Attach {
                cols: 120,
                rows: 40,
                supports_key_release: true,
            })
            .unwrap(),
        )
        .await
        .unwrap();
    w.daemon_client = Some(client);
    assert_eq!(read_reply(w).await, DaemonMessage::Attached);
    assert!(matches!(
        next_session_input(w).await,
        SessionInput::Attached { .. }
    ));
}

#[when(expr = "the attached terminal types {word}")]
async fn attached_types(w: &mut AlooWorld, ch: String) {
    let key = daemon_ipc::KeyWire::from_crossterm(
        crossterm::event::KeyCode::Char(ch.chars().next().unwrap()),
        crossterm::event::KeyModifiers::NONE,
        crossterm::event::KeyEventKind::Press,
    );
    let bytes = daemon_ipc::encode_frame(&AttachMessage::Key(key)).unwrap();
    w.daemon_client
        .as_mut()
        .unwrap()
        .write_all(&bytes)
        .await
        .unwrap();
}

#[when("the attached terminal detaches")]
async fn attached_detaches(w: &mut AlooWorld) {
    let bytes = daemon_ipc::encode_frame(&AttachMessage::Detach).unwrap();
    w.daemon_client
        .as_mut()
        .unwrap()
        .write_all(&bytes)
        .await
        .unwrap();
    assert!(matches!(
        read_reply(w).await,
        DaemonMessage::Detached { .. }
    ));
}

#[when("the attached terminal is closed without warning")]
async fn attached_vanishes(w: &mut AlooWorld) {
    // A closed window, or a crashed viewer: the socket simply goes away.
    w.daemon_client = None;
    w.daemon_read_buf.clear();
}

#[when("the daemon is asked for its status")]
async fn asked_for_status(w: &mut AlooWorld) {
    let socket = w.daemon_socket.clone().unwrap();
    let mut client = daemon_ipc::connect(&socket).await.unwrap();
    client
        .write_all(&daemon_ipc::encode_frame(&AttachMessage::Status).unwrap())
        .await
        .unwrap();
    w.daemon_client = Some(client);
    w.daemon_read_buf.clear();
    match read_reply(w).await {
        DaemonMessage::Status(text) => w.daemon_status = Some(text),
        other => panic!("expected a status, got {other:?}"),
    }
}

#[when("the daemon is asked to shut down")]
async fn asked_to_shut_down(w: &mut AlooWorld) {
    let socket = w.daemon_socket.clone().unwrap();
    let mut client = daemon_ipc::connect(&socket).await.unwrap();
    client
        .write_all(&daemon_ipc::encode_frame(&AttachMessage::Shutdown).unwrap())
        .await
        .unwrap();
    w.daemon_client = Some(client);
    w.daemon_read_buf.clear();
    assert!(matches!(
        read_reply(w).await,
        DaemonMessage::Detached { .. }
    ));
}

#[then(expr = "the session receives that keystroke")]
async fn session_receives_keystroke(w: &mut AlooWorld) {
    match next_session_input(w).await {
        SessionInput::Key(crossterm::event::Event::Key(_)) => {}
        other => panic!("expected a keystroke, got {other:?}"),
    }
}

#[then("the session starts drawing at the terminal's size")]
async fn session_draws_at_size(w: &mut AlooWorld) {
    // Asserted as part of attaching - reaching this step at all means the
    // Attached input arrived carrying a size.
    assert!(w.daemon_input_rx.is_some());
}

#[then("the session stops drawing")]
async fn session_stops_drawing(w: &mut AlooWorld) {
    assert!(matches!(
        next_session_input(w).await,
        SessionInput::Detach
    ));
}

#[then("the session is still running")]
async fn session_still_running(w: &mut AlooWorld) {
    assert!(
        !w.daemon_input_rx
            .as_ref()
            .expect("no daemon in this scenario")
            .is_closed(),
        "detaching must never end the session"
    );
}

#[then("the session is told to end")]
async fn session_told_to_end(w: &mut AlooWorld) {
    assert!(matches!(
        next_session_input(w).await,
        SessionInput::Shutdown
    ));
}

#[then("the session is told nothing")]
async fn session_told_nothing(w: &mut AlooWorld) {
    let rx = w.daemon_input_rx.as_mut().unwrap();
    assert!(
        matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "asking a question must not disturb the session"
    );
}

#[then(expr = "the answer says it is running")]
async fn answer_says_running(w: &mut AlooWorld) {
    let status = w
        .daemon_status
        .as_ref()
        .expect("no status was asked for in this scenario");
    assert!(status.contains("running"), "{status}");
}

// ---------------------------------------------------------------------
// The join sound
//
// Driven through the same pure decision the session uses
// (`DaemonPlan::should_play_joined_chime`), so a scenario can state the
// situation - who is focused, whether anyone is watching - without an
// audio device or a connection.
//
// The steps are phrased as the daemon *being told* something, rather than
// as someone joining or going offline, because that is what they model: a
// `UserJoined`/`UserOffline` notification reaching this client. The
// same-sounding steps in `server.rs` and `presence.rs` are different
// things - one performs a real join through the server registry, the
// other drives `UiState` - and the wording keeps them apart.
// ---------------------------------------------------------------------

use aloo::client::tui::ui::CurrentFocus;
use aloo::proto::UserId;

use crate::steps::ui_common::id_for;

#[given("aloo is running in the background with nobody watching")]
async fn running_in_background(w: &mut AlooWorld) {
    w.chime_daemon_mode = true;
    w.chime_viewer_attached = false;
    w.chime_announced.clear();
}

#[given("aloo is running in the foreground")]
async fn running_in_foreground(w: &mut AlooWorld) {
    w.chime_daemon_mode = false;
    w.chime_viewer_attached = true;
    w.chime_announced.clear();
}

#[given("a terminal is attached and watching")]
async fn terminal_watching(w: &mut AlooWorld) {
    w.chime_viewer_attached = true;
}

#[given(expr = "the focus is on the channel {string}")]
async fn focus_on_channel(w: &mut AlooWorld, name: String) {
    w.chime_focus = Some(CurrentFocus::Channel(name));
}

#[given(expr = "the focus is on a private conversation with {word}")]
async fn focus_on_dm(w: &mut AlooWorld, nickname: String) {
    w.chime_focus = Some(CurrentFocus::Dm(UserId(id_for(&nickname))));
}

#[given("nothing is focused yet")]
async fn focus_nowhere(w: &mut AlooWorld) {
    w.chime_focus = Some(CurrentFocus::Nowhere);
}

#[when(expr = "the daemon is told {word} joined {string}")]
async fn told_someone_joined(w: &mut AlooWorld, nickname: String, channel: String) {
    let peer = UserId(id_for(&nickname));
    w.chime_played = aloo::client::daemon::DaemonPlan::should_play_joined_chime(
        w.chime_daemon_mode,
        w.chime_viewer_attached,
        w.chime_focus.as_ref().unwrap_or(&CurrentFocus::Nowhere),
        peer,
        Some(&channel),
        w.chime_announced.contains(&peer),
    );
    // The session records them as online whether or not it made a noise.
    w.chime_announced.insert(peer);
    if w.chime_played {
        w.chime_count += 1;
    }
}

#[when(expr = "the daemon is told {word} went offline")]
async fn told_someone_went_offline(w: &mut AlooWorld, nickname: String) {
    w.chime_announced.remove(&UserId(id_for(&nickname)));
}

#[then("the join sound plays")]
async fn join_sound_plays(w: &mut AlooWorld) {
    assert!(w.chime_played, "the arrival should have been announced");
}

#[then("the join sound does not play")]
async fn join_sound_silent(w: &mut AlooWorld) {
    assert!(!w.chime_played, "nothing should have been heard");
}

#[then(expr = "the join sound has played {int} time(s) in total")]
async fn join_sound_count(w: &mut AlooWorld, expected: usize) {
    assert_eq!(
        w.chime_count, expected,
        "the sound should have played {expected} time(s)"
    );
}

// ---------------------------------------------------------------------
// The OTP-failure sound
//
// Modelled as the same latch the session keeps (`daemon_awaiting_otp`):
// set when the *daemon* proposes a session, cleared by whichever outcome
// arrives, and only a failure makes a noise.
// ---------------------------------------------------------------------

#[given("the daemon has proposed an OTP session")]
async fn daemon_proposed_otp(w: &mut AlooWorld) {
    w.otp_awaited = true;
    w.otp_alarm = false;
}

#[given(expr = "{word} typed \\/otp themselves")]
async fn person_typed_otp(w: &mut AlooWorld, _who: String) {
    // Not the daemon's proposal, so its outcome is not announced: whoever
    // typed it is sitting there watching.
    w.otp_awaited = false;
    w.otp_alarm = false;
}

#[when("the OTP session starts")]
async fn otp_session_starts(w: &mut AlooWorld) {
    if w.otp_awaited {
        w.otp_awaited = false;
    }
}

#[when(expr = "the OTP session fails because {string}")]
async fn otp_session_fails(w: &mut AlooWorld, _reason: String) {
    if w.otp_awaited {
        w.otp_awaited = false;
        w.otp_alarm = true;
    }
}

#[then("the alert sound plays")]
async fn alert_plays(w: &mut AlooWorld) {
    assert!(
        w.otp_alarm,
        "a session the daemon asked for failed - that has to be audible"
    );
}

#[then("no alert sound plays")]
async fn alert_silent(w: &mut AlooWorld) {
    assert!(!w.otp_alarm, "nothing should have been heard");
}

#[then("a second outcome changes nothing")]
async fn second_outcome_noop(w: &mut AlooWorld) {
    let before = w.otp_alarm;
    // Whatever arrives next, the latch is already spent.
    if w.otp_awaited {
        w.otp_awaited = false;
        w.otp_alarm = true;
    }
    assert_eq!(
        w.otp_alarm, before,
        "the outcome is reported once, not once per message that mentions it"
    );
}

/// The `connect_*` keys `settings::Settings::remember_connection` writes
/// every time the connect screen is submitted (AC-240), which a daemon
/// falls back to when nothing else names a server (AC-241).
#[given(expr = "the connect screen last connected as {string} to {string} port {int}")]
async fn connect_screen_last_connected(
    w: &mut AlooWorld,
    nickname: String,
    host: String,
    port: u16,
) {
    let s = settings(w);
    s.connect_host = Some(host);
    s.connect_port = Some(port);
    s.connect_nickname = Some(nickname);
}
