//! The IP ban list (`client::ip_ban`): pure timing logic and persistence,
//! with no network involved - `test/direct_punch_test.rs` covers the
//! `on_direct_ping` gate that actually consults it.

use std::net::IpAddr;

use aloo::client::ip_ban::{BanOutcome, IpBanList};

fn addr() -> IpAddr {
    "203.0.113.5".parse().unwrap()
}

fn temp_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "aloo-ip-ban-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// @requirement AC-280
#[test]
fn three_failures_spanning_two_minutes_within_the_window_bans_the_ip() {
    let path = temp_path();
    let mut list = IpBanList::new_empty(path.clone());
    let ip = addr();
    let base = 1_000_000u64;
    assert_eq!(list.record_failed_check(ip, base), BanOutcome::NotYet);
    assert_eq!(list.record_failed_check(ip, base + 60), BanOutcome::NotYet);
    assert_eq!(list.record_failed_check(ip, base + 61), BanOutcome::Banned);
    assert!(list.is_banned(ip));
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-280
#[test]
fn three_failures_inside_one_minute_do_not_ban() {
    let path = temp_path();
    let mut list = IpBanList::new_empty(path.clone());
    let ip = addr();
    let base = 1_000_000u64;
    assert_eq!(list.record_failed_check(ip, base), BanOutcome::NotYet);
    assert_eq!(list.record_failed_check(ip, base + 1), BanOutcome::NotYet);
    assert_eq!(list.record_failed_check(ip, base + 2), BanOutcome::NotYet);
    assert!(!list.is_banned(ip));
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-280
#[test]
fn failures_older_than_the_rolling_window_are_pruned_and_do_not_count() {
    let path = temp_path();
    let mut list = IpBanList::new_empty(path.clone());
    let ip = addr();
    let base = 1_000_000u64;
    const TEN_HOURS: u64 = 10 * 60 * 60;
    assert_eq!(list.record_failed_check(ip, base), BanOutcome::NotYet);
    assert_eq!(
        list.record_failed_check(ip, base + 60),
        BanOutcome::NotYet
    );
    // Both of the above are now more than 10 hours in the past.
    let later = base + TEN_HOURS + 120;
    assert_eq!(list.record_failed_check(ip, later), BanOutcome::NotYet);
    assert!(!list.is_banned(ip));
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-280, AC-281
#[test]
fn an_already_banned_ip_stays_banned_and_is_not_recounted() {
    let path = temp_path();
    let mut list = IpBanList::new_empty(path.clone());
    let ip = addr();
    let base = 1_000_000u64;
    list.record_failed_check(ip, base);
    list.record_failed_check(ip, base + 60);
    assert_eq!(list.record_failed_check(ip, base + 61), BanOutcome::Banned);
    // Calling again immediately (as if a check somehow still ran) reports
    // the same outcome without needing a fresh set of strikes.
    assert_eq!(list.record_failed_check(ip, base + 62), BanOutcome::Banned);
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-282
#[test]
fn a_banned_ip_stays_banned_across_a_reload() {
    let path = temp_path();
    let ip = addr();
    {
        let mut list = IpBanList::new_empty(path.clone());
        let base = 1_000_000u64;
        list.record_failed_check(ip, base);
        list.record_failed_check(ip, base + 60);
        assert_eq!(list.record_failed_check(ip, base + 61), BanOutcome::Banned);
    }
    let reloaded = IpBanList::load(&path).unwrap();
    assert!(reloaded.is_banned(ip));
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-282
#[test]
fn the_header_line_reports_the_running_count_and_is_recomputed_on_every_ban() {
    let path = temp_path();
    let mut list = IpBanList::new_empty(path.clone());
    let base = 1_000_000u64;
    for ip in ["203.0.113.5", "203.0.113.6"] {
        let ip: IpAddr = ip.parse().unwrap();
        list.record_failed_check(ip, base);
        list.record_failed_check(ip, base + 60);
        list.record_failed_check(ip, base + 61);
    }
    assert_eq!(list.ban_count(), 2);
    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(contents.lines().next(), Some("2 banned"));
    let _ = std::fs::remove_file(&path);
}

/// @requirement TB-248
#[test]
fn a_hand_edited_removal_of_an_entry_is_trusted_over_a_stale_header() {
    let path = temp_path();
    // A header claiming one ban, but no entry lines beneath it - exactly
    // what a hand edit that deleted the one entry line but forgot the
    // header would leave behind.
    std::fs::write(&path, "1 banned\n").unwrap();
    let list = IpBanList::load(&path).unwrap();
    assert!(!list.is_banned(addr()));
    assert_eq!(list.ban_count(), 0);
    let _ = std::fs::remove_file(&path);
}

/// @requirement TB-248
#[test]
fn an_unparseable_ban_line_is_skipped_rather_than_failing_the_whole_load() {
    let path = temp_path();
    std::fs::write(
        &path,
        "1 banned\n\
         2026-08-24T00:00:00Z\t203.0.113.5\trepeated unproven direct-punch checks\n\
         not a valid line at all\n\
         2026-08-24T00:00:00Z\tnot-an-ip\tsome reason\n",
    )
    .unwrap();
    let list = IpBanList::load(&path).unwrap();
    assert!(list.is_banned(addr()));
    assert_eq!(list.ban_count(), 1);
    let _ = std::fs::remove_file(&path);
}

/// @requirement AC-282
#[test]
fn loading_a_missing_file_starts_empty_rather_than_erroring() {
    let path = temp_path();
    let _ = std::fs::remove_file(&path);
    let list = IpBanList::load(&path).unwrap();
    assert_eq!(list.ban_count(), 0);
    assert!(!list.is_banned(addr()));
}
