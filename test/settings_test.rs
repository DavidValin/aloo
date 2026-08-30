use aloo::settings::{
    DEFAULT_BIND, DEFAULT_DIRECT_PUNCH_PORT, DEFAULT_GLOBAL_PTT_SHORTCUT, DEFAULT_PORT,
    DEFAULT_SERVER_SSL_FULLCHAIN, DEFAULT_SERVER_SSL_PRIVKEY, DIRECT_PUNCH_PORT_MAX,
    DIRECT_PUNCH_PORT_MIN, DirectPunchTarget, EchoDucking, PunchFrequency, Settings,
    default_path,
};
use std::path::PathBuf;

fn temp_settings_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "aloo-settings-test-{}-{}",
        std::process::id(),
        fastrand_seed()
    ))
}

fn fastrand_seed() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// @requirement AC-088
#[test]
fn default_path_resolves_under_the_aloo_dir() {
    assert!(default_path().ends_with("settings"));
}

/// @requirement AC-088
#[test]
fn missing_file_is_created_with_documented_defaults() {
    let path = temp_settings_path();
    assert!(!path.exists());

    let settings =
        Settings::load_or_create(&path).expect("first run should create the file, not error");
    assert!(settings.global_ptt_enabled);
    assert_eq!(settings.global_ptt_shortcut, DEFAULT_GLOBAL_PTT_SHORTCUT);
    assert_eq!(settings.server_bind, DEFAULT_BIND);
    assert_eq!(settings.server_port, DEFAULT_PORT);
    assert!(!settings.server_ssl);
    assert!(!settings.server_allow_registration);
    assert!(
        path.is_file(),
        "load_or_create must write the defaults to disk immediately, not just in memory"
    );

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("global_ptt_enabled=on"));
    assert!(contents.contains(&format!(
        "global_ptt_shortcut={DEFAULT_GLOBAL_PTT_SHORTCUT}"
    )));
    assert!(contents.contains(&format!("server_bind={DEFAULT_BIND}")));
    assert!(contents.contains(&format!("server_port={DEFAULT_PORT}")));
    assert!(contents.contains("server_ssl=off"));
    assert!(contents.contains("server_allow_registration=off"));
    assert!(contents.contains("voice_echo_ducking=auto"));
    // `auto` alone doesn't reveal that the other two states exist, so the
    // scaffold has to name them.
    assert!(contents.contains("# voice_echo_ducking: auto (decide from the audio), on, off"));

    std::fs::remove_file(&path).ok();
}

/// @requirement AC-396
#[test]
fn echo_ducking_decides_for_itself_by_default_and_can_be_forced_either_way() {
    let path = temp_settings_path();
    // Auto by default: whether the microphone can hear the speakers is
    // something the app observes better than the user can state it.
    assert_eq!(Settings::default().voice_echo_ducking, EchoDucking::Auto);
    assert_eq!(
        Settings::load_or_create(&path).unwrap().voice_echo_ducking,
        EchoDucking::Auto
    );

    for (written, expected) in [
        ("auto", EchoDucking::Auto),
        ("AUTO", EchoDucking::Auto),
        ("on", EchoDucking::On),
        ("true", EchoDucking::On),
        ("yes", EchoDucking::On),
        ("1", EchoDucking::On),
        ("off", EchoDucking::Off),
        ("false", EchoDucking::Off),
        ("no", EchoDucking::Off),
        ("0", EchoDucking::Off),
        // An unreadable value lands on the default, and the default is the
        // one that works it out for itself - not silently "off", which
        // would leak echo to everyone else in the call.
        ("sometimes", EchoDucking::Auto),
        ("", EchoDucking::Auto),
    ] {
        std::fs::write(&path, format!("voice_echo_ducking={written}\n")).unwrap();
        assert_eq!(
            Settings::load_or_create(&path).unwrap().voice_echo_ducking,
            expected,
            "voice_echo_ducking={written}"
        );
    }

    // And each state survives a save/load round trip as itself.
    for mode in [EchoDucking::Auto, EchoDucking::On, EchoDucking::Off] {
        let saved = Settings {
            voice_echo_ducking: mode,
            ..Settings::default()
        };
        saved.save(&path).unwrap();
        assert_eq!(Settings::load_or_create(&path).unwrap(), saved);
    }

    std::fs::remove_file(&path).ok();
}

/// @requirement AC-088
#[test]
fn round_trips_through_save_and_load() {
    let path = temp_settings_path();
    let saved = Settings {
        global_ptt_enabled: false,
        global_ptt_shortcut: "shift+alt+KeyV".to_string(),
        server_bind: "127.0.0.1".to_string(),
        server_port: 9999,
        ..Settings::default()
    };
    saved.save(&path).expect("save should succeed");

    let loaded = Settings::load_or_create(&path)
        .expect("an existing file should just be loaded, not recreated");
    assert_eq!(loaded, saved);

    std::fs::remove_file(&path).ok();
}

/// Every server key is in the file from the first run, unset ones with an
/// empty value, so an operator finds them already named.
/// @requirement TB-241
#[test]
fn server_ssl_registration_and_smtp_keys_are_written_even_when_unset() {
    let path = temp_settings_path();
    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.server_ssl_fullchain, DEFAULT_SERVER_SSL_FULLCHAIN);
    assert_eq!(settings.server_ssl_privkey, DEFAULT_SERVER_SSL_PRIVKEY);
    assert_eq!(settings.server_smtp_host, None);
    assert_eq!(settings.server_smtp_port, None);

    let contents = std::fs::read_to_string(&path).unwrap();
    for line in [
        "server_ssl=off",
        &format!("server_ssl_fullchain={DEFAULT_SERVER_SSL_FULLCHAIN}"),
        &format!("server_ssl_privkey={DEFAULT_SERVER_SSL_PRIVKEY}"),
        "server_allow_registration=off",
        "server_smtp_host=",
        "server_smtp_port=",
        "server_smtp_username=",
        "server_smtp_password=",
    ] {
        assert!(contents.contains(line), "missing {line:?} in:\n{contents}");
    }
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-241
#[test]
fn server_ssl_registration_and_smtp_keys_round_trip() {
    let path = temp_settings_path();
    let saved = Settings {
        server_ssl: true,
        server_ssl_fullchain: "/etc/letsencrypt/live/chat/fullchain.pem".to_string(),
        server_ssl_privkey: "/etc/letsencrypt/live/chat/privkey.pem".to_string(),
        server_allow_registration: true,
        server_smtp_host: Some("smtp.example.com".to_string()),
        server_smtp_port: Some(587),
        server_smtp_username: Some("aloo@example.com".to_string()),
        server_smtp_password: Some("s3cret".to_string()),
        ..Settings::default()
    };
    saved.save(&path).unwrap();
    let loaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(loaded, saved);
    std::fs::remove_file(&path).ok();
}

/// `on`/`true`/`yes`/`1` all switch a server flag on.
/// @requirement TB-241
#[test]
fn server_switches_accept_every_documented_spelling() {
    let path = temp_settings_path();
    for spelling in ["on", "true", "yes", "1"] {
        std::fs::write(
            &path,
            format!("server_ssl={spelling}\nserver_allow_registration={spelling}\n"),
        )
        .unwrap();
        let settings = Settings::load_or_create(&path).unwrap();
        assert!(settings.server_ssl, "server_ssl={spelling}");
        assert!(settings.server_allow_registration, "server_allow_registration={spelling}");
    }
    std::fs::write(&path, "server_ssl=off\nserver_smtp_port=0\n").unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert!(!settings.server_ssl);
    assert_eq!(settings.server_smtp_port, None, "port 0 is not a port");
    std::fs::remove_file(&path).ok();
}

/// `server_allow_create_public_channels` defaults on (matches the
/// pre-existing behavior for any server that never sets it) and is
/// always written, even unset.
///
/// @requirement AC-337
#[test]
fn server_allow_create_public_channels_defaults_on_and_is_always_written() {
    let path = temp_settings_path();
    let settings = Settings::load_or_create(&path).unwrap();
    assert!(settings.server_allow_create_public_channels);
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("server_allow_create_public_channels=on"));
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-337
#[test]
fn server_allow_create_public_channels_round_trips_off() {
    let path = temp_settings_path();
    let saved = Settings {
        server_allow_create_public_channels: false,
        ..Settings::default()
    };
    saved.save(&path).unwrap();
    let loaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(loaded, saved);
    assert!(!loaded.server_allow_create_public_channels);
    std::fs::remove_file(&path).ok();
}

/// `ChannelDeletionPeriod::parse` accepts every documented spelling and
/// canonicalizes to days on save; unset (the default) round-trips as
/// `None`, meaning the inactivity sweep never runs.
///
/// @requirement AC-350
#[test]
fn server_channel_deletion_unactivity_period_parses_and_round_trips() {
    use aloo::settings::ChannelDeletionPeriod;

    assert_eq!(
        ChannelDeletionPeriod::parse("30days").unwrap().as_duration(),
        std::time::Duration::from_secs(30 * 24 * 60 * 60)
    );
    assert_eq!(
        ChannelDeletionPeriod::parse("2weeks").unwrap().as_duration(),
        std::time::Duration::from_secs(14 * 24 * 60 * 60)
    );
    assert_eq!(
        ChannelDeletionPeriod::parse("1month").unwrap().as_duration(),
        std::time::Duration::from_secs(30 * 24 * 60 * 60)
    );
    assert!(ChannelDeletionPeriod::parse("0days").is_err());
    assert!(ChannelDeletionPeriod::parse("garbage").is_err());

    let path = temp_settings_path();
    let saved = Settings {
        server_channel_deletion_unactivity_period: Some(ChannelDeletionPeriod::parse("1month").unwrap()),
        ..Settings::default()
    };
    saved.save(&path).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        contents.contains("server_channel_deletion_unactivity_period=30days"),
        "a saved '1month' should canonicalize to days, numerically identical: {contents}"
    );
    let loaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(loaded, saved);
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-350
#[test]
fn server_channel_deletion_unactivity_period_defaults_to_no_sweep() {
    let path = temp_settings_path();
    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.server_channel_deletion_unactivity_period, None);
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("server_channel_deletion_unactivity_period="));
    std::fs::remove_file(&path).ok();
}

/// `server_superadmin` is one repeated line per admin, like `muted_voice` -
/// never the bracketed-list form - and an unregistrable value is skipped
/// the same way `daemon_nickname` already is.
///
/// @requirement AC-344
#[test]
fn server_superadmin_is_one_line_per_admin_and_skips_unregistrable_values() {
    let path = temp_settings_path();
    std::fs::write(
        &path,
        "server_superadmin=alice\nserver_superadmin=bob\nserver_superadmin=not a nickname\n",
    )
    .unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(
        settings.server_superadmin,
        ["alice", "bob"].into_iter().map(String::from).collect()
    );
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-344
#[test]
fn server_superadmin_round_trips_in_sorted_order() {
    let path = temp_settings_path();
    let saved = Settings {
        server_superadmin: ["carol", "alice", "bob"].into_iter().map(String::from).collect(),
        ..Settings::default()
    };
    saved.save(&path).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    let alice_at = contents.find("server_superadmin=alice").unwrap();
    let bob_at = contents.find("server_superadmin=bob").unwrap();
    let carol_at = contents.find("server_superadmin=carol").unwrap();
    assert!(
        alice_at < bob_at && bob_at < carol_at,
        "a BTreeSet should write in sorted order: {contents}"
    );
    let loaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(loaded, saved);
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-135
#[test]
fn load_skips_unparseable_or_unknown_lines_and_keeps_the_rest() {
    let path = temp_settings_path();
    std::fs::write(
        &path,
        "global_ptt_enabled=false\n\
         # a comment\n\
         some_future_key=some_future_value\n\
         not a key value line at all\n\
         server_port=not_a_number\n\
         global_ptt_shortcut=ctrl+shift+KeyM\n",
    )
    .unwrap();

    let settings = Settings::load_or_create(&path)
        .expect("malformed/unknown lines must not fail the whole load");
    assert_eq!(
        settings.server_port, DEFAULT_PORT,
        "an unparseable server_port must keep the default"
    );
    assert!(!settings.global_ptt_enabled);
    assert_eq!(settings.global_ptt_shortcut, "ctrl+shift+KeyM");

    std::fs::remove_file(&path).ok();
}

/// @requirement TB-135
#[test]
fn an_empty_shortcut_value_is_ignored_in_favor_of_the_default() {
    let path = temp_settings_path();
    std::fs::write(&path, "global_ptt_shortcut=\n").unwrap();

    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.global_ptt_shortcut, DEFAULT_GLOBAL_PTT_SHORTCUT);

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// The three sound switches (`docs/SPEC.md` "Settings"): all on out of the
// box, since each one silences something a user asked for by using the
// feature it belongs to.
// ---------------------------------------------------------------------

/// @requirement AC-402
#[test]
fn the_three_sound_switches_default_on_and_are_always_written() {
    let path = temp_settings_path();
    let settings = Settings::load_or_create(&path).unwrap();
    assert!(settings.voice_autoplay);
    assert!(settings.roger_beep);
    assert!(settings.sound_notifications);
    let contents = std::fs::read_to_string(&path).unwrap();
    for line in ["voice_autoplay=on", "roger_beep=on", "sound_notifications=on"] {
        assert!(contents.contains(line), "missing {line:?} in:\n{contents}");
    }
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-402
#[test]
fn the_three_sound_switches_round_trip_off() {
    let path = temp_settings_path();
    let saved = Settings {
        voice_autoplay: false,
        roger_beep: false,
        sound_notifications: false,
        ..Settings::default()
    };
    saved.save(&path).unwrap();
    let loaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(loaded, saved);
    std::fs::remove_file(&path).ok();
}

/// Each one is its own switch: turning one off says nothing about the
/// other two, which is the whole reason there are three of them.
/// @requirement AC-402
#[test]
fn each_sound_switch_is_read_independently() {
    let path = temp_settings_path();
    std::fs::write(&path, "roger_beep=off\n").unwrap();
    let loaded = Settings::load_or_create(&path).unwrap();
    assert!(!loaded.roger_beep);
    assert!(loaded.voice_autoplay, "the other two keep their defaults");
    assert!(loaded.sound_notifications);
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-355
#[test]
fn autosave_messages_defaults_off_and_is_always_written() {
    let path = temp_settings_path();
    let settings = Settings::load_or_create(&path).unwrap();
    assert!(!settings.autosave_messages);
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("autosave_messages=off"));
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-355
#[test]
fn autosave_messages_round_trips_on() {
    let path = temp_settings_path();
    let saved = Settings {
        autosave_messages: true,
        ..Settings::default()
    };
    saved.save(&path).unwrap();
    let loaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(loaded, saved);
    assert!(loaded.autosave_messages);
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-406
#[test]
fn queue_send_messages_defaults_on_and_is_always_written() {
    let path = temp_settings_path();
    let settings = Settings::load_or_create(&path).unwrap();
    assert!(settings.queue_send_messages);
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        contents.contains("queue_send_messages=on"),
        "the first-run scaffold must name it: {contents}"
    );
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-406
#[test]
fn queue_send_messages_round_trips_off() {
    let path = temp_settings_path();
    let saved = Settings {
        queue_send_messages: false,
        ..Settings::default()
    };
    saved.save(&path).unwrap();
    let loaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(loaded, saved);
    assert!(!loaded.queue_send_messages);
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-359
#[test]
fn resume_from_log_defaults_off_and_is_always_written() {
    let path = temp_settings_path();
    let settings = Settings::load_or_create(&path).unwrap();
    assert!(!settings.resume_from_log);
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("resume_from_log=off"));
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-359
#[test]
fn resume_from_log_round_trips_on() {
    let path = temp_settings_path();
    let saved = Settings {
        resume_from_log: true,
        ..Settings::default()
    };
    saved.save(&path).unwrap();
    let loaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(loaded, saved);
    assert!(loaded.resume_from_log);
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// The scaffold `load_or_create` writes for a machine's very first run:
// two `#`-commented sections, client options then server options.
// ---------------------------------------------------------------------

/// @requirement AC-356
#[test]
fn the_first_run_scaffold_is_split_into_client_and_server_sections_in_order() {
    let path = temp_settings_path();
    Settings::load_or_create(&path).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();

    let client_at = contents.find("# client options").expect("missing client section header");
    let server_at = contents.find("# server options").expect("missing server section header");
    assert!(client_at < server_at, "client options must come first: {contents}");

    // Every client-side key appears before the server section starts...
    for key in [
        "global_ptt_enabled=",
        "autosave_messages=",
        "resume_from_log=",
        "daemon_host=",
        "connect_using_ssl=",
    ] {
        let at = contents.find(key).unwrap_or_else(|| panic!("missing {key:?} in:\n{contents}"));
        assert!(at < server_at, "{key:?} should be in the client section: {contents}");
    }
    // ...and every server-side key appears after it starts.
    for key in ["server_bind=", "server_ssl=", "server_allow_create_public_channels="] {
        let at = contents.find(key).unwrap_or_else(|| panic!("missing {key:?} in:\n{contents}"));
        assert!(at > server_at, "{key:?} should be in the server section: {contents}");
    }
    std::fs::remove_file(&path).ok();
}

/// Every accumulating (one-line-per-entry) setting - which has nothing
/// real to pre-populate on a fresh file - still shows up as a commented
/// example, so a user editing the file by hand can discover its syntax
/// without reading the docs. Commented means inert: reloading the freshly
/// scaffolded file must not actually populate any of them.
/// @requirement AC-356
#[test]
fn the_scaffold_shows_every_accumulating_key_as_a_commented_example_that_never_loads() {
    let path = temp_settings_path();
    let settings = Settings::load_or_create(&path).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();

    for example in [
        "# muted_voice=somenickname",
        "# daemon_channel=otherchannel",
        "# direct_punch_to=alice,alicehost.com,every_1m",
        "# direct_punch_to=bob,bobhost.com:[18000,19000,21000],every_1m",
        "# direct_punch_channel=the-hall",
        "# server_superadmin=somenickname",
    ] {
        assert!(
            contents.contains(example),
            "missing commented example {example:?} in:\n{contents}"
        );
    }
    assert!(settings.muted_voice.is_empty());
    assert!(settings.daemon_channels.is_empty());
    assert!(settings.direct_punch_to.is_empty());
    assert!(settings.direct_punch_channels.is_empty());
    assert!(settings.server_superadmin.is_empty());
    std::fs::remove_file(&path).ok();
}

/// A blank line separates the two sections - not just the header comment.
/// @requirement AC-356
#[test]
fn a_blank_line_separates_the_client_and_server_sections() {
    let path = temp_settings_path();
    Settings::load_or_create(&path).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        contents.contains("\n\n# server options"),
        "expected a blank line right before the server section header: {contents}"
    );
    std::fs::remove_file(&path).ok();
}

/// The first-run file is assembled from two tables that share no text:
/// `SCAFFOLD_LAYOUT` names the keys and the comment lines, `scalar_fields`
/// supplies every value - which is what stops a key from being scaffolded
/// in one spelling and saved in another. This locks the result of putting
/// them together, byte for byte, so a key added to one table and not the
/// other cannot pass unnoticed. (A layout entry naming a key
/// `scalar_fields` doesn't manage panics outright, which every test here
/// that calls `load_or_create` already exercises.)
///
/// Adding a setting is expected to change this text - deliberately, in
/// the same commit that adds it.
/// @requirement AC-356
#[test]
fn the_first_run_scaffold_is_written_exactly_like_this() {
    let path = temp_settings_path();
    Settings::load_or_create(&path).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).ok();
    assert_eq!(contents, EXPECTED_FIRST_RUN_SCAFFOLD);
}

/// Every line `Settings::load_or_create` writes on a machine's very first
/// run - see `the_first_run_scaffold_is_written_exactly_like_this`.
const EXPECTED_FIRST_RUN_SCAFFOLD: &str = "\
# client options\n\
# -----------------------------------------\n\
global_ptt_enabled=on\n\
global_ptt_shortcut=ctrl+alt+p\n\
# voice_echo_ducking: auto (decide from the audio), on, off\n\
voice_echo_ducking=auto\n\
voice_autoplay=on\n\
roger_beep=on\n\
sound_notifications=on\n\
autosave_messages=off\n\
resume_from_log=off\n\
queue_send_messages=on\n\
daemon_host=\n\
daemon_port=\n\
daemon_nickname=\n\
daemon_server_password=\n\
daemon_my_key_pub=\n\
daemon_my_key_priv=\n\
daemon_initial_focus=\n\
# daemon_channel=otherchannel\n\
daemon_otp=off\n\
daemon_no_server=off\n\
direct_punch=off\n\
direct_punch_port=7879\n\
# direct_punch_to=alice,alicehost.com,every_1m\n\
# direct_punch_to=bob,bobhost.com:[18000,19000,21000],every_1m\n\
# direct_punch_channel=the-hall\n\
noip_when_no_server_and_direct_punch_is_active=off\n\
noip_hostname=\n\
noip_username=\n\
noip_password=\n\
connect_host=\n\
connect_nickname=\n\
connect_port=\n\
connect_using_ssl=off\n\
connect_ssl_ca=\n\
otp_binary_path=\n\
otp_keypair_size_mb=1\n\
otp_low_key_warn_pct=10\n\
otp_status_poll_interval=20\n\
# muted_voice=somenickname\n\
\n\
# server options\n\
# -----------------------------------------\n\
server_bind=0.0.0.0\n\
server_port=7878\n\
server_ssl=off\n\
server_ssl_fullchain=~/.aloo/certs/fullchain.pem\n\
server_ssl_privkey=~/.aloo/certs/privkey.pem\n\
server_allow_registration=off\n\
server_smtp_host=\n\
server_smtp_port=\n\
server_smtp_username=\n\
server_smtp_password=\n\
server_allow_create_public_channels=on\n\
server_channel_deletion_unactivity_period=\n\
# server_superadmin=somenickname\n";

/// The scaffold is only ever *written* once, on first run - but a
/// mid-session write (`save`/`update`, used by every ordinary action)
/// patches that file's own lines in place rather than regenerating it, so
/// its section comments, blank lines and key order survive every
/// ordinary save (`/mute-voice`, `remember_connection`, `--server`
/// recording its bind/port, ...) instead of being flattened away the
/// first time any of them runs.
/// @requirement AC-356
#[test]
fn an_ordinary_save_after_the_first_run_preserves_the_scaffolds_comments_and_order() {
    let path = temp_settings_path();
    Settings::load_or_create(&path).unwrap();
    let before = std::fs::read_to_string(&path).unwrap();

    Settings::update(&path, |s| s.global_ptt_enabled = false).unwrap();
    let after = std::fs::read_to_string(&path).unwrap();

    assert!(
        after.contains("# client options") && after.contains("# server options"),
        "an ordinary update must not strip the scaffold's section comments: {after}"
    );
    assert!(
        after.contains("\n\n# server options"),
        "the blank line between sections must survive too: {after}"
    );
    // Every line is byte-identical to the scaffold except the one whose
    // value actually changed - patched in place, not regenerated.
    let before_lines: Vec<&str> = before.lines().collect();
    let after_lines: Vec<&str> = after.lines().collect();
    assert_eq!(
        before_lines.len(),
        after_lines.len(),
        "no line should be added or removed by this edit: before={before:?} after={after:?}"
    );
    let changed: Vec<(&str, &str)> = before_lines
        .into_iter()
        .zip(after_lines)
        .filter(|(b, a)| b != a)
        .collect();
    assert_eq!(
        changed,
        vec![("global_ptt_enabled=on", "global_ptt_enabled=off")],
        "only the edited key's line should differ: before={before:?} after={after:?}"
    );
    std::fs::remove_file(&path).ok();
}

/// The exact sequence a real machine goes through: `--server` starts
/// (recording its resolved bind/port, `run_server`'s own `settings.save`),
/// then later a daemon connects and records a real `daemon_host` in what
/// the scaffold pre-wrote as a blank placeholder line. Both writes must
/// land as in-place edits of their own existing line - not appended
/// duplicates, and not a reason to lose the file's structure - which is
/// what an operator hand-editing `server_superadmin`/`server_ssl_*`
/// between those two writes needs to survive.
/// @requirement AC-356
#[test]
fn server_start_then_a_daemon_connect_both_patch_in_place_on_the_scaffold() {
    let path = temp_settings_path();
    Settings::load_or_create(&path).unwrap();

    // Mirrors `main.rs::run_server`: load, resolve bind/port, save.
    Settings::update(&path, |s| {
        s.server_bind = "203.0.113.5".to_string();
        s.server_port = 6667;
    })
    .unwrap();
    // An operator hand-edits the file in between, exactly the kind of
    // edit this whole feature exists to protect.
    {
        let mut contents = std::fs::read_to_string(&path).unwrap();
        contents = contents.replace("server_allow_registration=off", "server_allow_registration=on");
        std::fs::write(&path, contents).unwrap();
    }

    // Mirrors a daemon start recording its resolved keybundle/host.
    Settings::update(&path, |s| {
        s.daemon_host = Some("chat.example.com".to_string());
    })
    .unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        contents.contains("# client options") && contents.contains("# server options"),
        "structure must still be there after both writes: {contents}"
    );
    assert_eq!(
        contents.matches("daemon_host=").count(),
        1,
        "the placeholder line must be reused, not duplicated: {contents}"
    );
    assert!(contents.contains("daemon_host=chat.example.com"), "{contents}");
    assert!(
        contents.contains("server_allow_registration=on"),
        "the hand-edit between the two writes must survive: {contents}"
    );

    let reloaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(reloaded.server_bind, "203.0.113.5");
    assert_eq!(reloaded.server_port, 6667);
    assert!(reloaded.server_allow_registration);
    assert_eq!(reloaded.daemon_host.as_deref(), Some("chat.example.com"));

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// muted_voice (`/mute-voice`, docs/SPEC.md Functionality #15)
// ---------------------------------------------------------------------

/// @requirement TB-213
#[test]
fn muted_voice_round_trips_as_one_line_per_nickname() {
    let path = temp_settings_path();
    let mut settings = Settings::default();
    settings.muted_voice.insert("alice".to_string());
    settings.muted_voice.insert("bob".to_string());
    settings.save(&path).unwrap();

    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(
        raw.contains("muted_voice=alice\n") && raw.contains("muted_voice=bob\n"),
        "each nickname gets its own line, never one joined value: {raw}"
    );

    let reloaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(reloaded.muted_voice, settings.muted_voice);

    std::fs::remove_file(&path).ok();
}

/// A nickname rejects only whitespace, so a comma is legal inside one -
/// which is exactly why this is not a comma-separated value.
/// @requirement TB-213
#[test]
fn a_nickname_containing_a_comma_survives_a_round_trip() {
    let path = temp_settings_path();
    let mut settings = Settings::default();
    settings.muted_voice.insert("a,b".to_string());
    settings.save(&path).unwrap();

    let reloaded = Settings::load_or_create(&path).unwrap();
    assert!(
        reloaded.muted_voice.contains("a,b"),
        "a comma inside a nickname must not split it: {:?}",
        reloaded.muted_voice
    );
    assert_eq!(reloaded.muted_voice.len(), 1);

    std::fs::remove_file(&path).ok();
}

/// @requirement TB-213
#[test]
fn muted_voice_entries_are_written_in_sorted_order() {
    let path = temp_settings_path();
    let mut settings = Settings::default();
    for name in ["zoe", "alice", "bob"] {
        settings.muted_voice.insert(name.to_string());
    }
    settings.save(&path).unwrap();

    let raw = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = raw
        .lines()
        .filter(|l| l.starts_with("muted_voice="))
        .collect();
    assert_eq!(
        lines,
        vec!["muted_voice=alice", "muted_voice=bob", "muted_voice=zoe"],
        "a stable order is what keeps the file from churning between saves"
    );

    std::fs::remove_file(&path).ok();
}

/// @requirement TB-213
#[test]
fn an_empty_or_unstorable_muted_voice_line_is_skipped() {
    let path = temp_settings_path();
    std::fs::write(&path, "muted_voice=\nmuted_voice=alice\n").unwrap();

    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.muted_voice.len(), 1);
    assert!(settings.muted_voice.contains("alice"));

    std::fs::remove_file(&path).ok();
}

/// The whole reason `update_muted_voice` exists: `~/.aloo/settings` is now
/// written *during* a session, so a mute must never carry this process's
/// stale view of every other key back to disk.
/// @requirement TB-214
#[test]
fn update_muted_voice_preserves_keys_written_by_another_process() {
    let path = temp_settings_path();

    // This process's view of the file, loaded early.
    let mut mine = Settings::default();
    mine.server_port = 7878;
    mine.save(&path).unwrap();

    // Another process (an `aloo --server` start) rewrites it meanwhile.
    let mut theirs = Settings::load_or_create(&path).unwrap();
    theirs.server_port = 9999;
    theirs.server_smtp_password = Some("hunter2".to_string());
    theirs.save(&path).unwrap();

    // Our mute must not revert any of that.
    Settings::update_muted_voice(&path, |set| {
        set.insert("alice".to_string());
    })
    .unwrap();

    let after = Settings::load_or_create(&path).unwrap();
    assert_eq!(
        after.server_port, 9999,
        "a mute must not roll back another writer's port"
    );
    assert_eq!(after.server_smtp_password.as_deref(), Some("hunter2"));
    assert!(after.muted_voice.contains("alice"));

    std::fs::remove_file(&path).ok();
}

/// @requirement TB-214
#[test]
fn update_muted_voice_creates_the_file_when_missing() {
    let path = temp_settings_path();
    assert!(!path.exists());

    let stored = Settings::update_muted_voice(&path, |set| {
        set.insert("alice".to_string());
    })
    .expect("a first mute on a fresh machine must work, not error");

    assert!(stored.contains("alice"));
    assert!(
        Settings::load_or_create(&path).unwrap().muted_voice.contains("alice"),
        "the returned set must be what actually landed on disk"
    );

    std::fs::remove_file(&path).ok();
}

/// @requirement TB-214
#[test]
fn update_muted_voice_removes_an_entry_too() {
    let path = temp_settings_path();
    Settings::update_muted_voice(&path, |set| {
        set.insert("alice".to_string());
        set.insert("bob".to_string());
    })
    .unwrap();

    let stored = Settings::update_muted_voice(&path, |set| {
        set.remove("alice");
    })
    .unwrap();

    assert!(!stored.contains("alice"));
    assert!(stored.contains("bob"));

    std::fs::remove_file(&path).ok();
}

// ---- Serverless direct punch (docs/PROTOCOL.md 7.1.5) -------------------

/// @requirement AC-212
#[test]
fn direct_punch_is_off_and_targetless_unless_the_file_turns_it_on() {
    let settings = Settings::load_or_create(&temp_settings_path()).unwrap();
    assert!(!settings.direct_punch);
    assert!(settings.direct_punch_to.is_empty());
    assert_eq!(settings.direct_punch_ports, [DEFAULT_DIRECT_PUNCH_PORT]);
}

/// @requirement AC-212
#[test]
fn direct_punch_on_reads_one_target_per_line() {
    let path = temp_settings_path();
    std::fs::write(
        &path,
        "direct_punch=on\n\
         direct_punch_to=bob,bobpublic.com,every_1min\n\
         direct_punch_to=marco,marcohost.com,every_1h\n",
    )
    .unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert!(settings.direct_punch);
    assert!(settings.direct_punch_invalid.is_empty());
    let names: Vec<&str> = settings
        .direct_punch_to
        .iter()
        .map(|t| t.nickname.as_str())
        .collect();
    assert_eq!(names, vec!["bob", "marco"]);
    assert_eq!(settings.direct_punch_to[0].host, "bobpublic.com");
    assert_eq!(settings.direct_punch_to[0].frequency.minutes(), 1);
    assert_eq!(settings.direct_punch_to[1].frequency.minutes(), 60);
    // No port in the line means the well-known one both sides assume.
    assert_eq!(settings.direct_punch_to[0].ports, [DEFAULT_DIRECT_PUNCH_PORT]);
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-287
#[test]
fn has_direct_punch_configured_is_false_by_default() {
    let settings = Settings::load_or_create(&temp_settings_path()).unwrap();
    assert!(!settings.has_direct_punch_configured());
}

/// @requirement AC-287
#[test]
fn has_direct_punch_configured_is_false_with_targets_but_the_switch_off() {
    let path = temp_settings_path();
    std::fs::write(&path, "direct_punch_to=bob,bobpublic.com,every_1m\n").unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert!(!settings.direct_punch);
    assert!(!settings.direct_punch_to.is_empty());
    assert!(!settings.has_direct_punch_configured());
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-287
#[test]
fn has_direct_punch_configured_is_false_with_the_switch_on_but_no_targets() {
    let path = temp_settings_path();
    std::fs::write(&path, "direct_punch=on\n").unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert!(!settings.has_direct_punch_configured());
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-287
#[test]
fn has_direct_punch_configured_is_true_with_the_switch_on_and_a_target() {
    let path = temp_settings_path();
    std::fs::write(
        &path,
        "direct_punch=on\ndirect_punch_to=bob,bobpublic.com,every_1m\n",
    )
    .unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert!(settings.has_direct_punch_configured());
    let _ = std::fs::remove_file(&path);
}

/// A NAT that rewrites the source port makes one agreed number
/// insufficient - which port arrives is the router's choice - so a line may
/// name several and have all of them probed together.
/// @requirement AC-434
#[test]
fn a_target_host_may_name_several_ports_probed_together() {
    for (value, host, ports) in [
        (
            "bob,203.0.113.9:[18000,19000,21000],every_5m",
            "203.0.113.9",
            vec![18000u16, 19000, 21000],
        ),
        // The space people naturally type after a comma.
        ("bob,bobpublic.com:[18000, 19000],every_5m", "bobpublic.com", vec![18000, 19000]),
        // A bracketed IPv6 host and a bracketed port list together: the
        // field split must not confuse one bracket for the other.
        ("bob,[2001:db8::1]:[18000,19000],every_5m", "2001:db8::1", vec![18000, 19000]),
        // A one-element list is just the single-port form.
        ("bob,bobpublic.com:[19000],every_5m", "bobpublic.com", vec![19000]),
    ] {
        let target = DirectPunchTarget::parse(value).unwrap_or_else(|e| panic!("{value:?}: {e}"));
        assert_eq!(target.host, host, "{value:?}");
        assert_eq!(target.ports, ports, "{value:?}");
    }
}

/// Asking for the same probe twice only costs a datagram.
/// @requirement AC-434
#[test]
fn a_repeated_port_is_probed_only_once() {
    let target =
        DirectPunchTarget::parse("bob,bobpublic.com:[19000,18000,19000],every_5m").unwrap();
    assert_eq!(target.ports, [19000, 18000], "order is the line's, repeats collapse");
}

/// @requirement AC-435
#[test]
fn a_port_outside_the_allowed_range_is_refused_with_the_range_in_the_reason() {
    for value in [
        "bob,203.0.113.9:9000,every_5m",
        "bob,203.0.113.9:65535,every_5m",
        "bob,203.0.113.9:[18000,70000],every_5m",
        "bob,203.0.113.9:0,every_5m",
    ] {
        let message = DirectPunchTarget::parse(value)
            .expect_err(&format!("{value:?} names a port outside the range"));
        assert!(
            message.contains(&DIRECT_PUNCH_PORT_MIN.to_string())
                && message.contains(&DIRECT_PUNCH_PORT_MAX.to_string()),
            "{value:?}: the reason must name the range, got {message:?}"
        );
    }
}

/// A line that names no port is spelled by leaving the port off, not by
/// naming an empty list of them.
/// @requirement AC-435
#[test]
fn an_empty_port_list_is_refused() {
    let message = DirectPunchTarget::parse("bob,203.0.113.9:[],every_5m")
        .expect_err("an empty list names no port");
    assert!(message.contains("no port"), "unhelpful reason: {message:?}");
    let message = DirectPunchTarget::parse("bob,203.0.113.9:[ ],every_5m")
        .expect_err("whitespace is still no port");
    assert!(message.contains("no port"), "unhelpful reason: {message:?}");
}

/// The default sits outside the accepted range on purpose, so writing it
/// back explicitly would produce a line that no longer parses.
/// Being reachable on several ports means binding several, since what a
/// peer can reach you on is the set of ports you send *from*.
/// @requirement AC-438
#[test]
fn direct_punch_port_takes_a_list_of_local_ports() {
    let path = temp_settings_path();
    std::fs::write(&path, "direct_punch=on\ndirect_punch_port=18000, 19000,21000\n").unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.direct_punch_ports, [18000, 19000, 21000]);

    // As forgiving as the single-value form always was: an unusable entry
    // is skipped, and nothing usable at all leaves the default alone.
    std::fs::write(&path, "direct_punch_port=18000,nonsense,0,18000,19000\n").unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.direct_punch_ports, [18000, 19000], "repeats collapse too");

    std::fs::write(&path, "direct_punch_port=nonsense\n").unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.direct_punch_ports, [DEFAULT_DIRECT_PUNCH_PORT]);
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-435
#[test]
fn the_implicit_default_port_round_trips_as_no_port_at_all() {
    let target = DirectPunchTarget::parse("bob,bobpublic.com,every_5m").unwrap();
    assert_eq!(target.ports, [DEFAULT_DIRECT_PUNCH_PORT]);
    let written = target.to_setting_value();
    assert_eq!(written, "bob,bobpublic.com,every_5m");
    assert_eq!(DirectPunchTarget::parse(&written).unwrap(), target);

    // And the two written shapes round-trip too.
    for value in [
        "bob,bobpublic.com:19000,every_5m",
        "bob,bobpublic.com:[18000,19000,21000],every_5m",
        "bob+laptop,[2001:db8::1]:[18000,19000],every_1h",
    ] {
        let target = DirectPunchTarget::parse(value).unwrap_or_else(|e| panic!("{value:?}: {e}"));
        assert_eq!(target.to_setting_value(), value, "round trip must be exact");
    }
}

/// @requirement AC-212
#[test]
fn a_target_host_may_be_ipv4_ipv6_or_a_name_and_may_carry_its_own_port() {
    for (value, host, ports) in [
        ("bob,203.0.113.9,every_5m", "203.0.113.9", vec![DEFAULT_DIRECT_PUNCH_PORT]),
        ("bob,203.0.113.9:19000,every_5m", "203.0.113.9", vec![19000]),
        ("bob,2001:db8::1,every_5m", "2001:db8::1", vec![DEFAULT_DIRECT_PUNCH_PORT]),
        ("bob,[2001:db8::1]:19000,every_5m", "2001:db8::1", vec![19000]),
        (
            "bob,bob-public.example.com,every_5m",
            "bob-public.example.com",
            vec![DEFAULT_DIRECT_PUNCH_PORT],
        ),
        ("bob,bobpublic.com:19000,every_5m", "bobpublic.com", vec![19000]),
    ] {
        let target = DirectPunchTarget::parse(value).unwrap_or_else(|e| panic!("{value:?}: {e}"));
        assert_eq!(target.host, host, "{value:?}");
        assert_eq!(target.ports, ports, "{value:?}");
    }
}

/// @requirement AC-212
#[test]
fn every_documented_frequency_parses_and_nothing_else_does() {
    for minutes in aloo::settings::PUNCH_FREQUENCIES {
        let spelling = if minutes == 60 {
            "every_1h".to_string()
        } else {
            format!("every_{minutes}m")
        };
        assert_eq!(
            PunchFrequency::parse(&spelling).unwrap().minutes(),
            minutes,
            "{spelling}"
        );
    }
    // `every_1min` is the same thing spelled the way the settings file's
    // own example spells it.
    assert_eq!(PunchFrequency::parse("every_1min").unwrap().minutes(), 1);
    for bad in [
        "", "every_2m", "every_0m", "every_90m", "every_2h", "every_1s", "every_m", "every_",
        "1m", "1h", "m", "1", "sometimes",
    ] {
        assert!(
            PunchFrequency::parse(bad).is_err(),
            "{bad:?} should not be an accepted frequency"
        );
    }
}

/// @requirement AC-213
#[test]
fn a_malformed_target_is_reported_rather_than_silently_dropped() {
    let path = temp_settings_path();
    std::fs::write(
        &path,
        "direct_punch=on\n\
         direct_punch_to=bob,bobpublic.com,every_1m\n\
         direct_punch_to=carol,carolhost.com,every_3m\n\
         direct_punch_to=dave,not a host,every_1h\n\
         direct_punch_to=justanickname\n\
         direct_punch_to=,nohost.com,every_1h\n",
    )
    .unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    // The good line still loads - one bad line never costs the others.
    assert_eq!(settings.direct_punch_to.len(), 1);
    assert_eq!(settings.direct_punch_to[0].nickname, "bob");
    let bad: Vec<&str> = settings
        .direct_punch_invalid
        .iter()
        .map(|(line, _)| line.as_str())
        .collect();
    assert_eq!(
        bad,
        vec![
            "carol,carolhost.com,every_3m",
            "dave,not a host,every_1h",
            "justanickname",
            ",nohost.com,every_1h",
        ]
    );
    // Each one says why, so a typo is fixable without guessing.
    for (_, reason) in &settings.direct_punch_invalid {
        assert!(!reason.is_empty());
    }
    let _ = std::fs::remove_file(&path);
}

/// A `+<device_id>` suffix on the nickname field (device-pinning plan §5a)
/// is split off into its own field, leaving the bare nickname untouched.
///
/// @requirement AC-320
#[test]
fn a_plus_suffix_on_the_nickname_names_a_specific_device() {
    let target = DirectPunchTarget::parse("bob+phone,bobpublic.com,every_1m").unwrap();
    assert_eq!(target.nickname, "bob");
    assert_eq!(target.device_id.as_deref(), Some("phone"));
}

/// A line with no `+` is unaffected by the suffix syntax existing at all -
/// device_id is simply `None`, exactly as every line behaved before this
/// plan.
///
/// @requirement AC-320
#[test]
fn a_target_with_no_device_suffix_parses_with_no_device_id() {
    let target = DirectPunchTarget::parse("bob,bobpublic.com,every_1m").unwrap();
    assert_eq!(target.nickname, "bob");
    assert_eq!(target.device_id, None);
}

/// `target_key` is what two lines for the same nickname but different
/// devices must never collide on: nickname alone when unsuffixed
/// (identical to every line's only identity before this field existed),
/// `nickname+device_id` when suffixed.
///
/// @requirement AC-320
#[test]
fn target_key_is_nickname_alone_when_unsuffixed_and_qualified_when_suffixed() {
    let plain = DirectPunchTarget::parse("bob,bobpublic.com,every_1m").unwrap();
    assert_eq!(plain.target_key(), "bob");
    let phone = DirectPunchTarget::parse("bob+phone,bobpublic.com,every_1m").unwrap();
    assert_eq!(phone.target_key(), "bob+phone");
    let laptop = DirectPunchTarget::parse("bob+laptop,bobpublic.com,every_1m").unwrap();
    assert_ne!(phone.target_key(), laptop.target_key());
}

/// An empty device id (`bob+,host,every_1m`) is refused rather than
/// silently becoming the reserved "unbound" sentinel `IdStore` uses
/// internally for a device id (`idstore::DeviceEntry`) - a settings line is
/// never how that sentinel is meant to be reached.
///
/// @requirement AC-320
#[test]
fn an_empty_device_suffix_is_refused() {
    assert!(DirectPunchTarget::parse("bob+,bobpublic.com,every_1m").is_err());
}

/// The device id half of the field gets the same tab/newline injection
/// guard the nickname half already has (`validation::is_storable`) - a
/// settings line is user-editable text, and a delimiter smuggled through
/// either half could otherwise inject a record into a tab-delimited store
/// downstream (`idstore`).
///
/// @requirement AC-320
#[test]
fn a_device_suffix_containing_a_tab_or_newline_is_refused() {
    assert!(DirectPunchTarget::parse("bob+pho\tne,bobpublic.com,every_1m").is_err());
    assert!(DirectPunchTarget::parse("bob+pho\nne,bobpublic.com,every_1m").is_err());
}

/// The nickname half gets the same `nickname_is_registrable` rule the
/// server enforces, not just `is_storable` - a hand-edited settings file
/// cannot name a serverless peer with a nickname the registry would never
/// accept.
/// @requirement TB-251
#[test]
fn a_direct_punch_to_nickname_must_be_registrable() {
    assert!(DirectPunchTarget::parse("not a nickname,bobpublic.com,every_1m").is_err());
    assert!(DirectPunchTarget::parse("way-too-long-a-nickname,bobpublic.com,every_1m").is_err());
    assert!(DirectPunchTarget::parse("has_under,bobpublic.com,every_1m").is_ok());
}

/// `to_setting_value` round-trips the device suffix losslessly, the same
/// property the nickname/host/port/frequency fields already have.
///
/// @requirement AC-320
#[test]
fn a_device_suffixed_target_round_trips_through_to_setting_value() {
    let target = DirectPunchTarget::parse("bob+phone,bobpublic.com:19000,every_5m").unwrap();
    let reparsed = DirectPunchTarget::parse(&target.to_setting_value()).unwrap();
    assert_eq!(reparsed, target);
}

/// @requirement AC-212
#[test]
fn direct_punch_settings_survive_a_save_and_load_round_trip() {
    let path = temp_settings_path();
    let settings = Settings {
        direct_punch: true,
        direct_punch_ports: vec![9100, 19000],
        direct_punch_to: vec![
            DirectPunchTarget::parse("bob,bobpublic.com,every_1m").unwrap(),
            DirectPunchTarget::parse("marco,[2001:db8::1]:19000,every_1h").unwrap(),
            DirectPunchTarget::parse("nina,ninahost.com:[18000,19000,21000],every_5m").unwrap(),
        ],
        ..Settings::default()
    };
    settings.save(&path).unwrap();

    let reloaded = Settings::load_or_create(&path).unwrap();
    assert!(reloaded.direct_punch);
    assert_eq!(reloaded.direct_punch_ports, [9100, 19000]);
    assert_eq!(reloaded.direct_punch_to, settings.direct_punch_to);
    assert!(reloaded.direct_punch_invalid.is_empty());
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-217
#[test]
fn direct_punch_channels_are_read_one_per_line_and_validated() {
    let path = temp_settings_path();
    std::fs::write(
        &path,
        "direct_punch=on\n\
         direct_punch_channel=general\n\
         direct_punch_channel=dev\n\
         direct_punch_channel=general\n\
         direct_punch_channel=not a valid name!\n\
         direct_punch_channel=\n",
    )
    .unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    // Duplicates collapse and invalid names are skipped: with no server to
    // reject a bad name, this file is the only thing that can.
    assert_eq!(
        settings.direct_punch_channels,
        vec!["general".to_string(), "dev".to_string()]
    );

    // File order is preserved through a round trip - it is the order the
    // channels are presented in, so it must not churn.
    let reloaded = {
        settings.save(&path).unwrap();
        Settings::load_or_create(&path).unwrap()
    };
    assert_eq!(reloaded.direct_punch_channels, settings.direct_punch_channels);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------
// The last connection made from the connect popup (`connect_*`)
// ---------------------------------------------------------------------

/// A hand-edited settings file cannot set `connect_nickname` to something
/// the server would refuse - the line is simply skipped, leaving the
/// field at its default.
/// @requirement TB-251
#[test]
fn a_settings_file_skips_an_unregistrable_connect_nickname() {
    let path = temp_settings_path();
    std::fs::write(&path, "connect_nickname=not a valid nickname!\n").unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.connect_nickname, None);
    let _ = std::fs::remove_file(&path);
}

/// Same rule for `daemon_nickname`.
/// @requirement TB-251
#[test]
fn a_settings_file_skips_an_unregistrable_daemon_nickname() {
    let path = temp_settings_path();
    std::fs::write(&path, "daemon_nickname=way-too-long-a-nickname\n").unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.daemon_nickname, None);
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-240
#[test]
fn the_last_connection_is_remembered_and_read_back() {
    let path = temp_settings_path();
    Settings::remember_connection(&path, "chat.example.com", 6667, "dave", false)
        .expect("recording a connection must not fail");

    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.connect_host.as_deref(), Some("chat.example.com"));
    assert_eq!(settings.connect_port, Some(6667));
    assert_eq!(settings.connect_nickname.as_deref(), Some("dave"));
    assert!(!settings.connect_using_ssl);

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("connect_nickname=dave"), "{contents}");
    assert!(contents.contains("connect_using_ssl=off"), "{contents}");
    assert!(
        !contents.contains("connect_password"),
        "there is no connect_password key at all: {contents}"
    );
    assert!(contents.contains("connect_host=chat.example.com"), "{contents}");
    assert!(contents.contains("connect_port=6667"), "{contents}");
    let _ = std::fs::remove_file(&path);
}

/// A later connection replaces the earlier one - this is "the last values
/// used", not a history.
/// @requirement AC-240
#[test]
fn a_second_connection_replaces_what_the_first_recorded() {
    let path = temp_settings_path();
    Settings::remember_connection(&path, "first.example.com", 1111, "dave", true).unwrap();
    Settings::remember_connection(&path, "second.example.com", 2222, "erin", false).unwrap();

    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.connect_host.as_deref(), Some("second.example.com"));
    assert_eq!(settings.connect_port, Some(2222));
    assert_eq!(settings.connect_nickname.as_deref(), Some("erin"));
    assert!(!settings.connect_using_ssl, "the second connection was plain");
    let _ = std::fs::remove_file(&path);
}

/// The merging write matters here for the same reason it does for the
/// daemon keys: a daemon may be running and writing this same file while
/// a second `aloo` is being connected in a terminal.
/// @requirement AC-240
#[test]
fn remembering_a_connection_leaves_every_other_key_alone() {
    let path = temp_settings_path();
    let mut settings = Settings {
        server_port: 9999,
        daemon_nickname: Some("daemonname".to_string()),
        ..Settings::default()
    };
    settings.muted_voice.insert("noisy".to_string());
    settings.save(&path).unwrap();

    Settings::remember_connection(&path, "chat.example.com", 6667, "dave", false).unwrap();

    let reloaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(reloaded.server_port, 9999);
    assert_eq!(reloaded.daemon_nickname.as_deref(), Some("daemonname"));
    assert!(reloaded.muted_voice.contains("noisy"));
    assert_eq!(reloaded.connect_nickname.as_deref(), Some("dave"));
    let _ = std::fs::remove_file(&path);
}

/// A `--no-server` start has no host to record, and the empty string it
/// stands in for is not one - recording it would leave the next start
/// resolving a host that is not a host.
/// @requirement AC-240
#[test]
fn a_connection_with_no_host_leaves_the_recorded_host_alone() {
    let path = temp_settings_path();
    Settings::remember_connection(&path, "chat.example.com", 6667, "dave", false).unwrap();
    Settings::remember_connection(&path, "", 6667, "dave", false).unwrap();

    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(settings.connect_host.as_deref(), Some("chat.example.com"));
    let _ = std::fs::remove_file(&path);
}

/// Every switch in the file is written `on`/`off`, and every one of them
/// still reads the `true`/`false` a file written before they were
/// normalized holds - so upgrading never silently changes a setting.
/// @requirement AC-416
#[test]
fn every_switch_is_written_on_or_off_and_still_reads_the_old_spelling() {
    let path = temp_settings_path();
    Settings::load_or_create(&path).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        assert!(
            !matches!(value, "true" | "false"),
            "{key} is a switch written the old way: {line:?}"
        );
    }
    std::fs::remove_file(&path).ok();

    // A file from before the normalization still turns things off.
    let old = temp_settings_path();
    std::fs::write(&old, "global_ptt_enabled=false\ndaemon_otp=true\n").unwrap();
    let loaded = Settings::load_or_create(&old).unwrap();
    assert!(!loaded.global_ptt_enabled, "`false` must still switch it off");
    assert!(loaded.daemon_otp, "`true` must still switch it on");
    std::fs::remove_file(&old).ok();

    // ...and so does the new one.
    let new = temp_settings_path();
    std::fs::write(&new, "global_ptt_enabled=off\ndaemon_otp=on\n").unwrap();
    let loaded = Settings::load_or_create(&new).unwrap();
    assert!(!loaded.global_ptt_enabled);
    assert!(loaded.daemon_otp);
    std::fs::remove_file(&new).ok();
}
