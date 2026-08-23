//! Tests for `src/server/activation.rs`: the tiny hand-rolled HTTP parsing,
//! the per-IP attempt limiter, and `handle`'s decision table
//! (docs/PROTOCOL.md §5.3).

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use aloo::server::activation::{
    ATTEMPT_WINDOW, Admission, AttemptLimiter, BAN_DURATION, MAX_ATTEMPTS_PER_HOUR, handle,
    parse_request, percent_decode,
};
use aloo::server::users_registry::UsersRegistry;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

fn temp_registry(tag: &str) -> UsersRegistry {
    let dir = std::env::temp_dir().join(format!(
        "aloo-activation-test-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    UsersRegistry::open_with_iterations(dir, 10).unwrap()
}

// ---------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------

/// @requirement TB-243
#[test]
fn parse_request_reads_the_method_path_and_decoded_query() {
    let req = parse_request("GET /activate?nickname=al%20ice&code=123 HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/activate");
    assert_eq!(req.param("nickname"), Some("al ice"));
    assert_eq!(req.param("code"), Some("123"));
    assert_eq!(req.param("missing"), None);
}

/// @requirement TB-243
#[test]
fn parse_request_rejects_a_line_with_no_method_or_target() {
    assert!(parse_request("").is_none());
    assert!(parse_request("justoneword\r\n").is_none());
}

/// @requirement TB-243
#[test]
fn percent_decode_handles_plus_and_hex_escapes_and_keeps_invalid_ones_literal() {
    assert_eq!(percent_decode("a+b"), "a b");
    assert_eq!(percent_decode("100%25"), "100%");
    assert_eq!(percent_decode("%zz"), "%zz");
    assert_eq!(percent_decode("trailing%2"), "trailing%2");
}

// ---------------------------------------------------------------------
// The attempt limiter
// ---------------------------------------------------------------------

/// @requirement AC-266
#[test]
fn the_eleventh_attempt_within_an_hour_is_banned() {
    let mut limiter = AttemptLimiter::new();
    let now = Instant::now();
    for _ in 0..MAX_ATTEMPTS_PER_HOUR {
        assert_eq!(limiter.note_attempt(IP, now), Admission::Allowed);
    }
    assert_eq!(limiter.note_attempt(IP, now), Admission::Banned);
    assert!(limiter.is_banned(IP, now));
}

/// @requirement AC-266
#[test]
fn a_ban_lasts_the_full_day_and_then_lifts() {
    let mut limiter = AttemptLimiter::new();
    let now = Instant::now();
    for _ in 0..=MAX_ATTEMPTS_PER_HOUR {
        limiter.note_attempt(IP, now);
    }
    assert!(limiter.is_banned(IP, now + BAN_DURATION - Duration::from_secs(1)));
    assert!(!limiter.is_banned(IP, now + BAN_DURATION + Duration::from_secs(1)));
    // Once it lifts, a fresh run of attempts is judged on its own merits.
    let later = now + BAN_DURATION + Duration::from_secs(1);
    assert_eq!(limiter.note_attempt(IP, later), Admission::Allowed);
}

/// The window itself restarts once `ATTEMPT_WINDOW` has passed with no
/// ban tripped - a slow trickle of wrong guesses spread over days is not
/// the same threat as a burst.
/// @requirement AC-266
#[test]
fn the_window_restarts_once_it_has_fully_elapsed() {
    let mut limiter = AttemptLimiter::new();
    let now = Instant::now();
    for _ in 0..MAX_ATTEMPTS_PER_HOUR {
        limiter.note_attempt(IP, now);
    }
    let later = now + ATTEMPT_WINDOW + Duration::from_secs(1);
    assert_eq!(
        limiter.note_attempt(IP, later),
        Admission::Allowed,
        "a fresh window resets the count"
    );
}

/// Two different addresses never share a bucket.
/// @requirement AC-266
#[test]
fn the_limiter_is_scoped_per_address() {
    let mut limiter = AttemptLimiter::new();
    let now = Instant::now();
    let other = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    for _ in 0..=MAX_ATTEMPTS_PER_HOUR {
        limiter.note_attempt(IP, now);
    }
    assert!(limiter.is_banned(IP, now));
    assert!(!limiter.is_banned(other, now));
    assert_eq!(limiter.note_attempt(other, now), Admission::Allowed);
}

// ---------------------------------------------------------------------
// handle: the decision table
// ---------------------------------------------------------------------

/// @requirement AC-263
#[test]
fn a_bare_get_with_no_query_shows_the_form_and_costs_no_attempt() {
    let registry = temp_registry("bare-form");
    let mut limiter = AttemptLimiter::new();
    let req = parse_request("GET /activate HTTP/1.1\r\n\r\n").unwrap();
    let now = Instant::now();
    for _ in 0..(MAX_ATTEMPTS_PER_HOUR * 2) {
        let response = handle(&registry, &mut limiter, IP, &req, 0, now);
        assert_eq!(response.status, 200);
        assert!(response.body.contains("<form"));
    }
    assert!(!limiter.is_banned(IP, now), "an empty form view is never an attempt");
}

/// @requirement AC-263
#[test]
fn wrong_path_and_wrong_method_are_reported_without_touching_the_limiter() {
    let registry = temp_registry("wrong-path");
    let mut limiter = AttemptLimiter::new();
    let now = Instant::now();

    let req = parse_request("GET /nope HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!(handle(&registry, &mut limiter, IP, &req, 0, now).status, 404);

    let req = parse_request("POST /activate?nickname=alice&code=123456789012 HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!(handle(&registry, &mut limiter, IP, &req, 0, now).status, 405);
    assert!(!limiter.is_banned(IP, now));
}

/// @requirement AC-263, AC-265
#[test]
fn a_correct_code_activates_and_a_wrong_one_says_so() {
    let registry = temp_registry("activate-http");
    let registration = registry.register("alice", "pw", "alice@example.com", 0).unwrap();
    let mut limiter = AttemptLimiter::new();
    let now = Instant::now();

    let wrong = parse_request("GET /activate?nickname=alice&code=000000000000 HTTP/1.1\r\n\r\n").unwrap();
    let response = handle(&registry, &mut limiter, IP, &wrong, 0, now);
    assert_eq!(response.status, 400);
    assert!(registry.pending_activation("alice").is_some());

    let right = parse_request(&format!(
        "GET /activate?nickname=alice&code={} HTTP/1.1\r\n\r\n",
        registration.code
    ))
    .unwrap();
    let response = handle(&registry, &mut limiter, IP, &right, 0, now);
    assert_eq!(response.status, 200);
    assert!(response.body.contains("activated"), "{}", response.body);
    assert!(registry.pending_activation("alice").is_none());
}

/// An address that keeps submitting wrong codes gets banned by this
/// endpoint's own limiter, independent of any login the same address
/// might also attempt.
/// @requirement AC-266
#[test]
fn repeated_wrong_codes_from_one_address_trip_the_endpoints_own_ban() {
    let registry = temp_registry("ban-http");
    registry.register("alice", "pw", "alice@example.com", 0).unwrap();
    let mut limiter = AttemptLimiter::new();
    let now = Instant::now();
    let req = parse_request("GET /activate?nickname=alice&code=000000000000 HTTP/1.1\r\n\r\n").unwrap();

    for _ in 0..MAX_ATTEMPTS_PER_HOUR {
        assert_eq!(handle(&registry, &mut limiter, IP, &req, 0, now).status, 400);
    }
    let banned = handle(&registry, &mut limiter, IP, &req, 0, now);
    assert_eq!(banned.status, 429);
    assert!(banned.body.contains("day"), "{}", banned.body);
}

/// A `to_bytes` response is a well-formed status line plus a
/// `Content-Length` matching the body, so any client reading it can find
/// the end of the message.
/// @requirement TB-243
#[test]
fn to_bytes_carries_a_correct_content_length() {
    let registry = temp_registry("to-bytes");
    let mut limiter = AttemptLimiter::new();
    let req = parse_request("GET /activate HTTP/1.1\r\n\r\n").unwrap();
    let response = handle(&registry, &mut limiter, IP, &req, 0, Instant::now());
    let bytes = response.to_bytes();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    let expected = format!("Content-Length: {}\r\n", response.body.len());
    assert!(text.contains(&expected), "{text}");
    assert!(text.ends_with(&response.body));
}
