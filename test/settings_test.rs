use aloo::settings::{
    DEFAULT_BIND, DEFAULT_DIRECT_PUNCH_PORT, DEFAULT_GLOBAL_PTT_SHORTCUT, DEFAULT_PORT,
    DirectPunchTarget, PunchFrequency, ServerAuth, Settings, default_path,
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
    assert_eq!(settings.server_auth, ServerAuth::None);
    assert!(
        path.is_file(),
        "load_or_create must write the defaults to disk immediately, not just in memory"
    );

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("global_ptt_enabled=true"));
    assert!(contents.contains(&format!(
        "global_ptt_shortcut={DEFAULT_GLOBAL_PTT_SHORTCUT}"
    )));
    assert!(contents.contains(&format!("server_bind={DEFAULT_BIND}")));
    assert!(contents.contains(&format!("server_port={DEFAULT_PORT}")));
    assert!(contents.contains("server_auth_type=none"));

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
        server_auth: ServerAuth::None,
        ..Settings::default()
    };
    saved.save(&path).expect("save should succeed");

    let loaded = Settings::load_or_create(&path)
        .expect("an existing file should just be loaded, not recreated");
    assert_eq!(loaded, saved);

    std::fs::remove_file(&path).ok();
}

/// @requirement AC-094
#[test]
fn round_trips_password_auth_through_save_and_load() {
    let path = temp_settings_path();
    let saved = Settings {
        server_auth: ServerAuth::Password("hunter2".to_string()),
        ..Settings::default()
    };
    saved.save(&path).unwrap();

    let loaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(
        loaded.server_auth,
        ServerAuth::Password("hunter2".to_string())
    );

    std::fs::remove_file(&path).ok();
}

/// @requirement AC-094
#[test]
fn round_trips_rsa_auth_through_save_and_load() {
    let path = temp_settings_path();
    let saved = Settings {
        server_auth: ServerAuth::Rsa(PathBuf::from("/tmp/server_key")),
        ..Settings::default()
    };
    saved.save(&path).unwrap();

    let loaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(
        loaded.server_auth,
        ServerAuth::Rsa(PathBuf::from("/tmp/server_key"))
    );

    std::fs::remove_file(&path).ok();
}

/// @requirement TB-138
#[test]
fn a_malformed_server_auth_type_with_no_matching_value_falls_back_to_none() {
    let path = temp_settings_path();
    std::fs::write(&path, "server_auth_type=password\n").unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(
        settings.server_auth,
        ServerAuth::None,
        "a password type with no password line must not panic or half-apply"
    );

    std::fs::write(&path, "server_auth_type=rsa\n").unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    assert_eq!(
        settings.server_auth,
        ServerAuth::None,
        "an rsa type with no keyfile line must not panic or half-apply"
    );

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
    theirs.server_auth = ServerAuth::Password("hunter2".to_string());
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
    assert_eq!(after.server_auth, ServerAuth::Password("hunter2".to_string()));
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
    assert_eq!(settings.direct_punch_port, DEFAULT_DIRECT_PUNCH_PORT);
}

/// @requirement AC-212
#[test]
fn direct_punch_on_reads_one_target_per_line() {
    let path = temp_settings_path();
    std::fs::write(
        &path,
        "direct_punch=on\n\
         direct_punch_to=bob,bobpublic.com,1min\n\
         direct_punch_to=marco,marcohost.com,1h\n",
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
    assert_eq!(settings.direct_punch_to[0].port, DEFAULT_DIRECT_PUNCH_PORT);
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-212
#[test]
fn a_target_host_may_be_ipv4_ipv6_or_a_name_and_may_carry_its_own_port() {
    for (value, host, port) in [
        ("bob,203.0.113.9,5m", "203.0.113.9", DEFAULT_DIRECT_PUNCH_PORT),
        ("bob,203.0.113.9:9000,5m", "203.0.113.9", 9000),
        ("bob,2001:db8::1,5m", "2001:db8::1", DEFAULT_DIRECT_PUNCH_PORT),
        ("bob,[2001:db8::1]:9000,5m", "2001:db8::1", 9000),
        ("bob,bob-public.example.com,5m", "bob-public.example.com", DEFAULT_DIRECT_PUNCH_PORT),
        ("bob,bobpublic.com:9000,5m", "bobpublic.com", 9000),
    ] {
        let target = DirectPunchTarget::parse(value).unwrap_or_else(|e| panic!("{value:?}: {e}"));
        assert_eq!(target.host, host, "{value:?}");
        assert_eq!(target.port, port, "{value:?}");
    }
}

/// @requirement AC-212
#[test]
fn every_documented_frequency_parses_and_nothing_else_does() {
    for minutes in aloo::settings::PUNCH_FREQUENCIES {
        let spelling = if minutes == 60 {
            "1h".to_string()
        } else {
            format!("{minutes}m")
        };
        assert_eq!(
            PunchFrequency::parse(&spelling).unwrap().minutes(),
            minutes,
            "{spelling}"
        );
    }
    // `1min` is the same thing spelled the way the settings file's own
    // example spells it.
    assert_eq!(PunchFrequency::parse("1min").unwrap().minutes(), 1);
    for bad in ["", "2m", "0m", "90m", "2h", "1s", "m", "1", "sometimes"] {
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
         direct_punch_to=bob,bobpublic.com,1m\n\
         direct_punch_to=carol,carolhost.com,3m\n\
         direct_punch_to=dave,not a host,1h\n\
         direct_punch_to=justanickname\n\
         direct_punch_to=,nohost.com,1h\n",
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
            "carol,carolhost.com,3m",
            "dave,not a host,1h",
            "justanickname",
            ",nohost.com,1h",
        ]
    );
    // Each one says why, so a typo is fixable without guessing.
    for (_, reason) in &settings.direct_punch_invalid {
        assert!(!reason.is_empty());
    }
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-212
#[test]
fn direct_punch_settings_survive_a_save_and_load_round_trip() {
    let path = temp_settings_path();
    let settings = Settings {
        direct_punch: true,
        direct_punch_port: 9100,
        direct_punch_to: vec![
            DirectPunchTarget::parse("bob,bobpublic.com,1m").unwrap(),
            DirectPunchTarget::parse("marco,[2001:db8::1]:9000,1h").unwrap(),
        ],
        ..Settings::default()
    };
    settings.save(&path).unwrap();

    let reloaded = Settings::load_or_create(&path).unwrap();
    assert!(reloaded.direct_punch);
    assert_eq!(reloaded.direct_punch_port, 9100);
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
