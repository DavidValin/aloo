//! `crate::client::daemon` - the decisions a daemon makes before and
//! after connecting, isolated from the connection itself.
//!
//! The parts that need a live socket (`serve_attachments`,
//! `run_attach_client`, `spawn_detached`) are not covered here, same rule
//! `docs/SPEC.md` states for `session.rs`/`connect.rs`: what is testable
//! without a network or a second process is tested, the rest is exercised
//! end to end.

use aloo::client::daemon::{DaemonChannel, DaemonFocus, DaemonPlan};

// ---------------------------------------------------------------------
// --channels parsing
// ---------------------------------------------------------------------

/// @requirement TB-217
#[test]
fn a_channel_without_a_password_parses_to_just_a_name() {
    let channel = DaemonChannel::parse("ops").unwrap();
    assert_eq!(channel.name, "ops");
    assert_eq!(channel.password, None);
}

/// The separator is a colon and the split is on the *first* one, so a
/// password may contain commas - which is what lets one round-trip
/// through a single `daemon_channel=` line, where nothing splits on
/// commas.
/// @requirement TB-217
#[test]
fn a_channel_password_may_itself_contain_commas() {
    let channel = DaemonChannel::parse("ops:a,b").unwrap();
    assert_eq!(channel.name, "ops");
    assert_eq!(channel.password.as_deref(), Some("a,b"));
}

/// `--channels=#team` is the channel written the way the UI shows it; the
/// `#` is decoration and never part of the name.
/// @requirement AC-247
#[test]
fn a_channel_may_be_given_with_the_hash_it_is_shown_with() {
    let channel = DaemonChannel::parse("#ops").unwrap();
    assert_eq!(channel.name, "ops");
    let with_password = DaemonChannel::parse("#ops:hunter2").unwrap();
    assert_eq!(with_password.name, "ops");
    assert_eq!(with_password.password.as_deref(), Some("hunter2"));
}

/// A comma is legal in a password, so it could never have separated
/// items; a colon is legal in neither a name nor a password, so it can.
/// @requirement TB-217
#[test]
fn a_channels_list_splits_on_commas_and_passwords_on_colons() {
    let list = DaemonChannel::parse_list("team,ops:hunter2").unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].name, "team");
    assert_eq!(list[0].password, None);
    assert_eq!(list[1].name, "ops");
    assert_eq!(list[1].password.as_deref(), Some("hunter2"));
}

/// A stray or trailing comma is a typo that should cost nothing - unlike
/// a malformed name, which silently joins the wrong place.
/// @requirement TB-217
#[test]
fn empty_items_in_a_channels_list_are_skipped_but_bad_names_are_not() {
    let list = DaemonChannel::parse_list("team,,ops,").unwrap();
    assert_eq!(list.len(), 2);
    assert!(DaemonChannel::parse_list("team,not a name").is_err());
}

/// @requirement TB-217
#[test]
fn a_single_channel_is_a_list_of_one() {
    let list = DaemonChannel::parse_list("ops").unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "ops");
}

/// @requirement TB-217
#[test]
fn an_empty_password_means_no_password_rather_than_the_empty_one() {
    // `--channels=ops:` is a typo. Treating the empty string as a real
    // credential would fail the join for a baffling reason.
    let channel = DaemonChannel::parse("ops:").unwrap();
    assert_eq!(channel.password, None);
}

/// @requirement TB-217
#[test]
fn an_unusable_channel_name_is_refused_with_a_reason() {
    for bad in ["", "has space", "sym!bol", "way-too-long-a-channel-name-here"] {
        let err = DaemonChannel::parse(bad).unwrap_err();
        assert!(
            err.contains("not a usable channel name"),
            "{bad:?} should be refused clearly, got {err:?}"
        );
    }
}

/// A channel must survive the round trip through `~/.aloo/settings`, or a
/// bare `aloo --daemon` at the next boot rejoins something different from
/// what it was started with.
/// @requirement TB-217
#[test]
fn a_channel_round_trips_through_its_settings_line() {
    for value in ["ops", "ops:secret", "ops:a,b"] {
        let parsed = DaemonChannel::parse(value).unwrap();
        let reparsed = DaemonChannel::parse(&parsed.to_setting()).unwrap();
        assert_eq!(parsed, reparsed, "{value:?} must survive a round trip");
    }
}

// ---------------------------------------------------------------------
// --initial-focus parsing
// ---------------------------------------------------------------------

/// @requirement TB-218
#[test]
fn focus_reads_a_channel_prefix_and_otherwise_a_nickname() {
    assert_eq!(
        DaemonFocus::parse("channel:ops", false).unwrap(),
        DaemonFocus::Channel("ops".into())
    );
    assert_eq!(
        DaemonFocus::parse("alice", false).unwrap(),
        DaemonFocus::Dm {
            nickname: "alice".into(),
            otp: false
        }
    );
    // The explicit spelling of the bare form.
    assert_eq!(
        DaemonFocus::parse("dm:alice", false).unwrap(),
        DaemonFocus::Dm {
            nickname: "alice".into(),
            otp: false
        }
    );
}

/// OTP is provisioned pairwise, per contact - there is no such thing as an
/// OTP session with a channel, so this is a mistake worth naming rather
/// than quietly dropping.
/// @requirement TB-218
#[test]
fn otp_with_a_channel_focus_is_refused() {
    let err = DaemonFocus::parse("channel:ops", true).unwrap_err();
    assert!(err.contains("needs a person"), "{err}");
}

/// @requirement TB-218
#[test]
fn an_empty_focus_is_refused() {
    assert!(DaemonFocus::parse("", false).is_err());
    assert!(DaemonFocus::parse("channel:", false).is_err());
    assert!(DaemonFocus::parse("dm:", false).is_err());
}

// ---------------------------------------------------------------------
// Which events a plan cares about
// ---------------------------------------------------------------------

fn dm_plan(nickname: &str, otp: bool) -> DaemonPlan {
    DaemonPlan::new(
        vec![DaemonChannel::parse("ops").unwrap()],
        Some(DaemonFocus::Dm {
            nickname: nickname.into(),
            otp,
        }),
    )
}

fn channel_plan(name: &str) -> DaemonPlan {
    DaemonPlan::new(
        vec![DaemonChannel::parse(name).unwrap()],
        Some(DaemonFocus::Channel(name.into())),
    )
}

/// A DM focus cares about one person, wherever they turn up - the channel
/// they were discovered in is incidental.
/// @requirement TB-218
#[test]
fn a_dm_focus_follows_the_person_not_the_channel() {
    let plan = dm_plan("alice", false);
    assert!(plan.is_focus_event("alice", Some("ops")));
    assert!(plan.is_focus_event("alice", Some("somewhere-else")));
    assert!(!plan.is_focus_event("bob", Some("ops")));
}

/// A channel focus cares about anyone arriving there - the focus is the
/// channel, so its arrivals are its events.
/// @requirement TB-218
#[test]
fn a_channel_focus_follows_the_channel_not_the_person() {
    let plan = channel_plan("ops");
    assert!(plan.is_focus_event("alice", Some("ops")));
    assert!(plan.is_focus_event("bob", Some("ops")));
    assert!(!plan.is_focus_event("alice", Some("random")));
}

/// @requirement TB-218
#[test]
fn a_plan_with_no_focus_cares_about_nothing() {
    let plan = DaemonPlan::new(vec![DaemonChannel::parse("ops").unwrap()], None);
    assert!(!plan.is_focus_event("alice", Some("ops")));
    assert!(!plan.wants_otp());
}

// ---------------------------------------------------------------------
// --otp: invite, or continue
// ---------------------------------------------------------------------

/// The case this exists for. An OTP session outlives disconnects and app
/// restarts - only `/endotp` ends one - and the client resumes it the
/// moment the peer reappears. Inviting on top of that would put an
/// Accept/Reject popup in front of someone already in the session.
/// @requirement AC-199
#[test]
fn an_already_active_otp_session_is_continued_not_re_invited() {
    let plan = dm_plan("alice", true);
    assert!(
        !plan.should_invite_otp("alice", true),
        "a live session must be continued silently, never re-proposed"
    );
}

/// @requirement AC-199
#[test]
fn a_peer_with_no_otp_session_is_invited() {
    let plan = dm_plan("alice", true);
    assert!(plan.should_invite_otp("alice", false));
}

/// @requirement AC-199
#[test]
fn without_otp_nobody_is_ever_invited() {
    let plan = dm_plan("alice", false);
    assert!(!plan.should_invite_otp("alice", false));
    assert!(!plan.should_invite_otp("alice", true));
}

/// A peer on a flapping connection must not become a queue of popups.
/// @requirement AC-199
#[test]
fn only_one_invitation_is_sent_per_daemon_run() {
    let mut plan = dm_plan("alice", true);
    assert!(plan.should_invite_otp("alice", false));
    plan.otp_requested = true;
    assert!(
        !plan.should_invite_otp("alice", false),
        "a second appearance must not propose again"
    );
}

/// @requirement AC-199
#[test]
fn someone_other_than_the_focused_peer_is_never_invited() {
    let plan = dm_plan("alice", true);
    assert!(!plan.should_invite_otp("bob", false));
}

/// A channel focus can never want OTP - `DaemonFocus::parse` refuses the
/// combination outright - but the predicate must hold on its own too.
/// @requirement AC-199
#[test]
fn a_channel_focus_never_invites_an_otp_session() {
    let plan = channel_plan("ops");
    assert!(!plan.should_invite_otp("alice", false));
}

// ---------------------------------------------------------------------
// --initial-focus is a starting position, not a standing instruction
// ---------------------------------------------------------------------

/// @requirement AC-200
#[test]
fn the_focus_is_placed_once_and_then_left_alone() {
    let mut plan = dm_plan("alice", false);
    assert!(plan.should_place_focus(), "nothing has been focused yet");

    plan.focus_applied = true;
    assert!(
        !plan.should_place_focus(),
        "once placed, where the focus sits belongs to whoever is driving"
    );
}

/// The case this exists for: boot focused on alice, attach, move to
/// another channel or DM, detach - then alice's connection drops and comes
/// back. Her reappearance must not drag the focus back to her room, or the
/// next held shortcut would go somewhere the user did not choose.
/// @requirement AC-200
#[test]
fn a_focused_peer_reappearing_does_not_re_steal_the_focus() {
    let mut plan = dm_plan("alice", false);
    // Startup: alice appears, the focus is placed on her.
    assert!(plan.should_place_focus());
    plan.focus_applied = true;

    // The user has since moved elsewhere and detached. Alice reconnects.
    assert!(
        !plan.should_place_focus(),
        "a reconnect is not a reason to move the user's focus"
    );
    // ...and it is still a focus *event*, so the sound and notification
    // still fire - only the focus move is suppressed.
    assert!(plan.is_focus_event("alice", Some("ops")));
}

/// Same for a channel focus: rejoining the focused channel later must not
/// pull the selection back to it.
/// @requirement AC-200
#[test]
fn a_focused_channel_being_rejoined_does_not_re_steal_the_focus() {
    let mut plan = channel_plan("ops");
    assert!(plan.should_place_focus());
    plan.focus_applied = true;
    assert!(!plan.should_place_focus());
}

/// A DM focus can only be placed once the person actually appears, which
/// may be hours after startup - "once" means the first opportunity, not
/// the first instant.
/// @requirement AC-200
#[test]
fn a_focus_still_waiting_for_its_peer_has_not_been_used_up() {
    let plan = dm_plan("alice", false);
    // Someone else joining is not alice, so nothing was placed...
    assert!(!plan.is_focus_event("bob", Some("ops")));
    // ...and the focus is still owed.
    assert!(plan.should_place_focus());
}

// ---------------------------------------------------------------------
// Restarting: --initial-focus applies again on a fresh run
// ---------------------------------------------------------------------

/// The other half of `should_place_focus`. The latch lives in the plan,
/// which is built fresh on every start and never persisted - so stopping
/// the daemon and running it again with `--initial-focus` puts the focus back
/// where the flag says, even though the previous run had moved on.
/// @requirement AC-200
#[test]
fn a_restart_places_the_focus_again() {
    let mut previous_run = dm_plan("alice", false);
    previous_run.focus_applied = true;
    assert!(!previous_run.should_place_focus());

    // Stopping and starting again is exactly this: a new plan.
    let fresh_run = dm_plan("alice", false);
    assert!(
        fresh_run.should_place_focus(),
        "a fresh start must honour --initial-focus again"
    );
}

// ---------------------------------------------------------------------
// Resolving what to run as
// ---------------------------------------------------------------------

use aloo::client::connect::{ConnectCache, MyKeySelection};
use aloo::client::daemon::{DaemonConfig, DaemonFlags};
use aloo::settings::Settings;

fn empty_cache() -> ConnectCache {
    ConnectCache::new_empty(std::path::PathBuf::from("/nonexistent/.cache"))
}

fn cache_with(host: &str, port: u16) -> ConnectCache {
    let mut cache = empty_cache();
    cache.record(host, port, "/keys/x.pub", "/keys/x.priv");
    cache
}

fn flags_with_host() -> DaemonFlags {
    DaemonFlags {
        host: Some("flag.example".into()),
        ..Default::default()
    }
}

/// @requirement AC-201
#[test]
fn a_flag_beats_the_settings_file_and_the_cache() {
    let mut settings = Settings::default();
    settings.daemon_host = Some("settings.example".into());
    settings.daemon_port = Some(1111);
    settings.daemon_nickname = Some("from-settings".into());

    let flags = DaemonFlags {
        host: Some("flag.example".into()),
        port: Some(2222),
        nickname: Some("from-flag".into()),
        ..Default::default()
    };
    let config = DaemonConfig::resolve(&flags, &settings, &cache_with("cache.example", 3333)).unwrap();

    assert_eq!(config.host, "flag.example");
    assert_eq!(config.port, 2222);
    assert_eq!(config.nickname, "from-flag");
}

/// @requirement AC-201
#[test]
fn settings_fill_in_whatever_the_flags_left_out() {
    let mut settings = Settings::default();
    settings.daemon_host = Some("settings.example".into());
    settings.daemon_port = Some(1111);
    settings.daemon_nickname = Some("from-settings".into());

    let config =
        DaemonConfig::resolve(&DaemonFlags::default(), &settings, &cache_with("cache.example", 3333))
            .unwrap();

    assert_eq!(config.host, "settings.example");
    assert_eq!(config.port, 1111);
    assert_eq!(config.nickname, "from-settings");
}

/// The last thing you connected to by hand is a better guess than a
/// built-in default, and it is what makes a bare `aloo --daemon` work on a
/// machine that has only ever used the connect screen.
/// @requirement AC-201
#[test]
fn the_connect_cache_is_the_last_resort_before_defaults() {
    let config = DaemonConfig::resolve(
        &DaemonFlags::default(),
        &Settings::default(),
        &cache_with("cache.example", 3333),
    )
    .unwrap();

    assert_eq!(config.host, "cache.example");
    assert_eq!(config.port, 3333);
    // ...including the keybundle it last connected with, so the identity
    // people have already pinned is the one the daemon comes back as.
    assert_eq!(
        config.my_key,
        MyKeySelection {
            file_pub: "/keys/x.pub".into(),
            file_priv: "/keys/x.priv".into(),
        }
    );
}

/// What the connect screen last recorded (`Settings::remember_connection`)
/// is consulted after the `daemon_*` keys and before the cache - which is
/// what makes a first `--daemon` on a machine that has only ever been used
/// interactively need no flags at all, including no `--nick`.
/// @requirement AC-241
#[test]
fn the_last_interactive_connection_fills_in_what_no_daemon_start_ever_recorded() {
    let settings = Settings {
        connect_host: Some("connect.example".into()),
        connect_port: Some(4444),
        connect_nickname: Some("dave".into()),
        ..Settings::default()
    };

    let config =
        DaemonConfig::resolve(&DaemonFlags::default(), &settings, &empty_cache()).unwrap();

    assert_eq!(config.host, "connect.example");
    assert_eq!(config.port, 4444);
    assert_eq!(config.nickname, "dave");
}

/// A previous daemon start's own record is the more specific of the two,
/// and stays ahead of it.
/// @requirement AC-241
#[test]
fn a_previous_daemon_start_still_beats_the_last_interactive_connection() {
    let settings = Settings {
        daemon_host: Some("daemon.example".into()),
        daemon_port: Some(1111),
        daemon_nickname: Some("from-daemon".into()),
        connect_host: Some("connect.example".into()),
        connect_port: Some(4444),
        connect_nickname: Some("dave".into()),
        ..Settings::default()
    };

    let config =
        DaemonConfig::resolve(&DaemonFlags::default(), &settings, &empty_cache()).unwrap();

    assert_eq!(config.host, "daemon.example");
    assert_eq!(config.port, 1111);
    assert_eq!(config.nickname, "from-daemon");
}

/// And a flag given this run still beats both.
/// @requirement AC-241
#[test]
fn a_flag_beats_the_last_interactive_connection_too() {
    let settings = Settings {
        connect_host: Some("connect.example".into()),
        connect_nickname: Some("dave".into()),
        ..Settings::default()
    };

    let flags = DaemonFlags {
        host: Some("flag.example".into()),
        nickname: Some("from-flag".into()),
        ..Default::default()
    };
    let config = DaemonConfig::resolve(&flags, &settings, &empty_cache()).unwrap();

    assert_eq!(config.host, "flag.example");
    assert_eq!(config.nickname, "from-flag");
}

/// With nothing anywhere there is no sensible guess, and silently picking
/// one would connect somewhere the user never named.
/// @requirement AC-201
#[test]
fn with_no_host_anywhere_the_daemon_refuses_to_start() {
    let err = DaemonConfig::resolve(&DaemonFlags::default(), &Settings::default(), &empty_cache())
        .unwrap_err();
    assert!(err.contains("no server to connect to"), "{err}");
}

/// @requirement AC-201
#[test]
fn a_server_password_from_settings_is_used_when_no_flag_gives_one() {
    let mut settings = Settings::default();
    settings.daemon_server_password = Some("hunter2".into());

    let config = DaemonConfig::resolve(&flags_with_host(), &settings, &empty_cache()).unwrap();
    assert_eq!(config.password, "hunter2");

    let flags = DaemonFlags {
        server_pwd: Some("from-flag".into()),
        ..flags_with_host()
    };
    let config = DaemonConfig::resolve(&flags, &settings, &empty_cache()).unwrap();
    assert_eq!(config.password, "from-flag", "a flag given this run wins");
}

/// `--ssl` (or `daemon_ssl`) is carried into the request the daemon
/// connects with; it is the one TLS decision a headless start can make.
/// @requirement AC-201, AC-261
#[test]
fn ssl_comes_from_the_flag_or_the_settings_file() {
    let config =
        DaemonConfig::resolve(&flags_with_host(), &Settings::default(), &empty_cache()).unwrap();
    assert!(!config.ssl, "plain TCP unless asked");
    assert!(!config.to_connect_request().ssl);

    let flags = DaemonFlags {
        ssl: true,
        ..flags_with_host()
    };
    let config = DaemonConfig::resolve(&flags, &Settings::default(), &empty_cache()).unwrap();
    assert!(config.ssl);
    assert!(config.to_connect_request().ssl);

    let mut settings = Settings::default();
    settings.daemon_ssl = true;
    let config = DaemonConfig::resolve(&flags_with_host(), &settings, &empty_cache()).unwrap();
    assert!(config.ssl, "daemon_ssl=on is what a bare start reads back");
}

/// A daemon with a server but no password anywhere refuses to start
/// before touching a socket - the same reasoning `with_no_host_anywhere`
/// gives for a missing host, applied to the one credential login needs.
/// @requirement AC-201
#[tokio::test]
async fn run_refuses_to_start_with_a_server_and_no_password() {
    let config = DaemonConfig::resolve(&flags_with_host(), &Settings::default(), &empty_cache())
        .unwrap();
    assert!(config.password.is_empty());
    let err = aloo::client::daemon::run(config, None).await.unwrap_err();
    assert_eq!(err.to_string(), aloo::client::daemon::NO_PASSWORD_ERROR);
}

/// The request a daemon dials with is the connect popup's own type,
/// carrying the nickname's password and no store path of its own.
/// @requirement AC-201, AC-005
#[test]
fn the_daemon_connects_with_the_resolved_password() {
    let flags = DaemonFlags {
        server_pwd: Some("hunter2".into()),
        ..flags_with_host()
    };
    let config = DaemonConfig::resolve(&flags, &Settings::default(), &empty_cache()).unwrap();
    let request = config.to_connect_request();
    assert_eq!(request.password, "hunter2");
    assert_eq!(request.activation_code, None);
}

/// @requirement AC-202
#[test]
fn a_daemon_joins_exactly_the_channels_it_was_given() {
    let flags = DaemonFlags {
        channels: vec!["team,ops:hunter2".into()],
        ..flags_with_host()
    };
    let config = DaemonConfig::resolve(&flags, &Settings::default(), &empty_cache()).unwrap();

    let names: Vec<&str> = config.channels.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["team", "ops"]);
    assert_eq!(config.channels[1].password.as_deref(), Some("hunter2"));
    assert!(
        !names.contains(&"the-hall"),
        "the-hall is never joined unless it was asked for"
    );
}

/// Forgetting to list the channel you are focusing is a mistake with an
/// obvious fix, so it is fixed rather than reported.
/// @requirement AC-202
#[test]
fn a_focused_channel_is_joined_even_if_it_was_not_listed() {
    let flags = DaemonFlags {
        channels: vec!["team".into()],
        initial_focus: Some("channel:ops".into()),
        ..flags_with_host()
    };
    let config = DaemonConfig::resolve(&flags, &Settings::default(), &empty_cache()).unwrap();

    let names: Vec<&str> = config.channels.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"ops"), "got {names:?}");
}

/// Presence is channel-scoped: a client is only told a person exists if it
/// shares a joined channel with them, and no message asks "is alice
/// online?". A DM focus with nothing joined would wait forever.
/// @requirement AC-202
#[test]
fn a_dm_focus_with_no_channels_gets_a_discovery_channel() {
    let flags = DaemonFlags {
        initial_focus: Some("alice".into()),
        ..flags_with_host()
    };
    let config = DaemonConfig::resolve(&flags, &Settings::default(), &empty_cache()).unwrap();

    let names: Vec<&str> = config.channels.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["the-hall"],
        "a DM focus needs somewhere to see the person from"
    );
}

/// ...but only when there is nothing else. A named channel is where the
/// person will actually be, and is quieter.
/// @requirement AC-202
#[test]
fn a_dm_focus_with_channels_does_not_get_the_hall() {
    let flags = DaemonFlags {
        channels: vec!["team".into()],
        initial_focus: Some("alice".into()),
        ..flags_with_host()
    };
    let config = DaemonConfig::resolve(&flags, &Settings::default(), &empty_cache()).unwrap();

    let names: Vec<&str> = config.channels.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["team"]);
}

/// @requirement AC-201
#[test]
fn a_bad_channel_or_focus_is_reported_rather_than_ignored() {
    let bad_channel = DaemonFlags {
        channels: vec!["not a name".into()],
        ..flags_with_host()
    };
    assert!(DaemonConfig::resolve(&bad_channel, &Settings::default(), &empty_cache()).is_err());

    let bad_focus = DaemonFlags {
        initial_focus: Some("channel:".into()),
        ..flags_with_host()
    };
    assert!(DaemonConfig::resolve(&bad_focus, &Settings::default(), &empty_cache()).is_err());

    let otp_on_channel = DaemonFlags {
        initial_focus: Some("channel:ops".into()),
        otp: true,
        ..flags_with_host()
    };
    let err =
        DaemonConfig::resolve(&otp_on_channel, &Settings::default(), &empty_cache()).unwrap_err();
    assert!(err.contains("needs a person"), "{err}");
}

/// A daemon writes its resolved configuration back so the *next* bare
/// `aloo --daemon` - the form a service unit runs at boot - reproduces it.
/// @requirement AC-201
#[test]
fn a_resolved_configuration_round_trips_through_the_settings_file() {
    let path = std::env::temp_dir().join(format!(
        "aloo-daemon-persist-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let flags = DaemonFlags {
        host: Some("chat.example".into()),
        port: Some(7979),
        nickname: Some("david".into()),
        server_pwd: Some("hunter2".into()),
        channels: vec!["team,ops:s3cret".into()],
        initial_focus: Some("alice".into()),
        otp: true,
        ..Default::default()
    };
    let config = DaemonConfig::resolve(&flags, &Settings::default(), &empty_cache()).unwrap();
    config.persist(&path).unwrap();

    // A later flag-less start reads it back and resolves the same thing.
    let reloaded = Settings::load_or_create(&path).unwrap();
    let again = DaemonConfig::resolve(&DaemonFlags::default(), &reloaded, &empty_cache()).unwrap();

    assert_eq!(again.host, config.host);
    assert_eq!(again.port, config.port);
    assert_eq!(again.nickname, config.nickname);
    assert_eq!(again.password, config.password);
    assert_eq!(again.ssl, config.ssl);
    assert_eq!(again.channels, config.channels);
    assert_eq!(again.initial_focus, config.initial_focus);

    std::fs::remove_file(&path).ok();
}

/// The escape hatch promised by the `--channels` syntax: a password
/// containing a comma cannot come from the command line, but it survives a
/// settings line, where nothing splits on commas.
/// @requirement AC-202
#[test]
fn a_password_containing_a_comma_survives_the_settings_file() {
    let mut settings = Settings::default();
    settings.daemon_channels = vec!["ops:a,b".into()];

    let config = DaemonConfig::resolve(&flags_with_host(), &settings, &empty_cache()).unwrap();
    assert_eq!(config.channels.len(), 1);
    assert_eq!(config.channels[0].name, "ops");
    assert_eq!(config.channels[0].password.as_deref(), Some("a,b"));
}

// ---- Daemon with no server (docs/PROTOCOL.md 7.1.5) --------------------

fn temp_settings_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "aloo-daemon-noserver-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// `--no-server` is the one start that legitimately has nowhere to
/// connect, so the host requirement must not apply to it.
///
/// @requirement AC-221
#[test]
fn no_server_lifts_the_host_requirement() {
    let flags = DaemonFlags {
        no_server: true,
        nickname: Some("omar".into()),
        ..DaemonFlags::default()
    };
    let config = DaemonConfig::resolve(&flags, &Settings::default(), &empty_cache())
        .expect("--no-server must start with no host anywhere");
    assert!(config.no_server);
}

/// A bare `aloo --daemon` at the next boot has to reproduce the last
/// configuration - which for a serverless daemon means coming back
/// serverless, not failing to start for want of a host it never had.
///
/// @requirement AC-221
#[test]
fn a_serverless_daemon_comes_back_serverless_after_a_restart() {
    let path = temp_settings_path();
    let flags = DaemonFlags {
        no_server: true,
        nickname: Some("omar".into()),
        ..DaemonFlags::default()
    };
    let config = DaemonConfig::resolve(&flags, &Settings::default(), &empty_cache()).unwrap();
    config.persist(&path).unwrap();

    // The next boot passes no flags at all.
    let reloaded = Settings::load_or_create(&path).unwrap();
    let restarted = DaemonConfig::resolve(&DaemonFlags::default(), &reloaded, &empty_cache())
        .expect("a persisted serverless daemon must start again with no flags");
    assert!(
        restarted.no_server,
        "the daemon came back expecting a server it was never given"
    );
    let _ = std::fs::remove_file(&path);
}

/// The hall exists so a DM focus has somewhere to *see* the person from -
/// presence is announced within a shared channel. With no server there is
/// no presence and no hall to join; a serverless peer is found by punching
/// at them, so joining a channel nothing configured would only produce an
/// empty tab that can never fill.
///
/// @requirement AC-221
#[test]
fn a_serverless_dm_focus_does_not_get_a_discovery_channel() {
    let flags = DaemonFlags {
        no_server: true,
        nickname: Some("omar".into()),
        initial_focus: Some("peter".into()),
        ..DaemonFlags::default()
    };
    let config = DaemonConfig::resolve(&flags, &Settings::default(), &empty_cache()).unwrap();
    assert!(
        config.channels.is_empty(),
        "a serverless DM focus needs no channel to discover anyone through, \
         but got {:?}",
        config.channels
    );
}

/// A peer punched directly who shares no channel has still *arrived* - and
/// a DM focus is about the person, not about where they turned up. The
/// chime's channel arm is the only part that needs one, and a peer with
/// none can never be the arrival a focused *channel* was waiting for.
///
/// This is the shape of an OTP pair configured only for each other
/// (docs/PROTOCOL.md §7.1.5, §16): no channel between them at all.
///
/// @requirement AC-221
#[test]
fn a_dm_focus_is_about_the_person_even_with_no_channel_between_them() {
    use aloo::client::tui::ui::CurrentFocus;

    let peer = aloo::proto::UserId(1);
    let plan = DaemonPlan::new(
        Vec::new(),
        Some(DaemonFocus::Dm {
            nickname: "alice".into(),
            otp: true,
        }),
    );
    // The focus fires for the person whether or not a channel is named.
    assert!(plan.is_focus_event("alice", None));
    assert!(plan.is_focus_event("alice", Some("team")));
    assert!(!plan.is_focus_event("bob", None));

    // ...and the OTP session a `--otp` daemon exists to propose is offered
    // for them, which is what a DM-only pair would otherwise never get.
    assert!(plan.should_invite_otp("alice", false));

    // The chime still rings for a focused DM peer arriving from nowhere.
    assert!(DaemonPlan::should_play_joined_chime(
        true,
        false,
        &CurrentFocus::Dm(peer),
        peer,
        None,
        false,
    ));
    // But a focused *channel* is never satisfied by a peer who arrived in
    // no channel at all.
    assert!(!DaemonPlan::should_play_joined_chime(
        true,
        false,
        &CurrentFocus::Channel("team".into()),
        peer,
        None,
        false,
    ));
}
