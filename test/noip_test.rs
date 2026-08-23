//! The optional No-IP dynamic DNS updater (`docs/PROTOCOL.md` §7.1.5's
//! "No-IP updates"): the settings that configure it, the pure scheduling
//! math that decides when it fires, and the request it builds and the
//! response it reads. The live socket to `dynupdate.no-ip.com` itself is
//! not exercised here - the same trade-off `server::users_registry`'s SMTP
//! client makes, for the same reason (see `docs/TESTING.md`).

use std::time::Duration;

use aloo::client::noip::{
    NOIP_GAP_LONG, NOIP_GAP_SHORT, NOIP_SECOND_OF_MINUTE, NoipConfig, build_request,
    parse_response, seconds_until_next_noip_mark,
};
use aloo::settings::Settings;

fn temp_settings_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("aloo-noip-test-{}.settings", std::process::id()))
}

/// @requirement AC-272
#[test]
fn noip_settings_default_off_and_empty() {
    let settings = Settings::default();
    assert!(!settings.noip_when_no_server_and_direct_punch_is_active);
    assert_eq!(settings.noip_hostname, "");
    assert_eq!(settings.noip_username, "");
    assert_eq!(settings.noip_password, "");
}

/// @requirement AC-272
#[test]
fn noip_settings_round_trip_through_save_and_load() {
    let path = temp_settings_path();
    let settings = Settings {
        noip_when_no_server_and_direct_punch_is_active: true,
        noip_hostname: "myhouse.ddns.example".to_string(),
        noip_username: "dave".to_string(),
        noip_password: "hunter2".to_string(),
        ..Settings::default()
    };
    settings.save(&path).unwrap();

    let reloaded = Settings::load_or_create(&path).unwrap();
    assert!(reloaded.noip_when_no_server_and_direct_punch_is_active);
    assert_eq!(reloaded.noip_hostname, "myhouse.ddns.example");
    assert_eq!(reloaded.noip_username, "dave");
    assert_eq!(reloaded.noip_password, "hunter2");
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-272, TB-245
#[test]
fn noip_config_from_settings_requires_all_three_fields() {
    let mut settings = Settings::default();
    assert!(NoipConfig::from_settings(&settings).is_none());

    settings.noip_hostname = "myhouse.ddns.example".to_string();
    assert!(NoipConfig::from_settings(&settings).is_none());

    settings.noip_username = "dave".to_string();
    assert!(NoipConfig::from_settings(&settings).is_none());

    settings.noip_password = "hunter2".to_string();
    let config = NoipConfig::from_settings(&settings).expect("all three set");
    assert_eq!(config.hostname, "myhouse.ddns.example");
    assert_eq!(config.username, "dave");
    assert_eq!(config.password, "hunter2");
}

/// @requirement TB-246
#[test]
fn seconds_until_next_noip_mark_computes_the_gap_to_the_next_mark() {
    for (second_of_minute, expected) in [
        (0, NOIP_SECOND_OF_MINUTE),
        (49, 1),
        (50, 60),
        (51, 59),
        (59, 51),
    ] {
        assert_eq!(
            seconds_until_next_noip_mark(second_of_minute),
            expected,
            "at second {second_of_minute}"
        );
    }
}

/// @requirement TB-246
#[test]
fn the_two_gaps_average_five_and_a_half_minutes_and_stay_on_the_mark() {
    assert_eq!((NOIP_GAP_SHORT + NOIP_GAP_LONG) / 2, Duration::from_secs(330));
    // Both are whole multiples of a minute, which is what keeps a fire
    // landing on NOIP_SECOND_OF_MINUTE forever regardless of which gap
    // came before it - only the minute changes, never the second.
    assert_eq!(NOIP_GAP_SHORT.as_secs() % 60, 0);
    assert_eq!(NOIP_GAP_LONG.as_secs() % 60, 0);
}

fn config() -> NoipConfig {
    NoipConfig {
        hostname: "myhouse.ddns.example".to_string(),
        username: "dave".to_string(),
        password: "hunter2".to_string(),
    }
}

/// @requirement AC-274
#[test]
fn build_request_carries_the_hostname_and_the_basic_auth_header() {
    let request = build_request(&config());
    assert!(request.starts_with("GET /nic/update?hostname=myhouse.ddns.example HTTP/1.1\r\n"));
    assert!(request.contains("Host: dynupdate.no-ip.com\r\n"));
    // Basic auth is base64("dave:hunter2") - checked against an
    // independently computed value rather than the crate's own encoder,
    // so a bug shared between the two would not hide itself.
    assert!(request.contains("Authorization: Basic ZGF2ZTpodW50ZXIy\r\n"));
    assert!(request.ends_with("\r\n\r\n"));
}

/// @requirement AC-274
#[test]
fn parse_response_returns_the_trimmed_body_on_200() {
    let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\ngood 203.0.113.9\r\n";
    assert_eq!(parse_response(raw).unwrap(), "good 203.0.113.9");
}

/// @requirement AC-274
#[test]
fn parse_response_rejects_a_non_200_status() {
    let raw = "HTTP/1.1 401 Unauthorized\r\n\r\nbadauth";
    assert!(parse_response(raw).is_err());
}

/// @requirement AC-274
#[test]
fn parse_response_rejects_an_empty_response() {
    assert!(parse_response("").is_err());
}
