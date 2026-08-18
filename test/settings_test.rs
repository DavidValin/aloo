use aloo::settings::{
    DEFAULT_BIND, DEFAULT_GLOBAL_PTT_SHORTCUT, DEFAULT_PORT, ServerAuth, Settings, default_path,
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
