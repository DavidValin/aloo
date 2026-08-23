//! The permanent, on-disk IP ban list for the unknown-nickname direct-punch
//! flow (US-046, `client::ip_ban`) - driven directly against the real type,
//! since it needs no network at all to prove.

use cucumber::{given, then, when};

use aloo::client::ip_ban::{BanOutcome, IpBanList};

use crate::world::AlooWorld;

/// The one address these scenarios call "a source", unless a scenario
/// explicitly involves two.
fn source_ip() -> std::net::IpAddr {
    "203.0.113.5".parse().unwrap()
}

fn other_source_ip() -> std::net::IpAddr {
    "203.0.113.6".parse().unwrap()
}

/// An arbitrary but fixed base timestamp, so "a minute apart"/"ten hours
/// ago" are exact rather than dependent on when the suite happens to run.
const BASE: u64 = 2_000_000_000;
const TEN_HOURS: u64 = 10 * 60 * 60;

fn temp_ban_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "aloo-bdd-ip-ban-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn bans_mut(w: &mut AlooWorld) -> &mut IpBanList {
    w.ip_bans.as_mut().expect("no ban list open for this scenario")
}

#[given("a fresh ban list")]
async fn fresh_ban_list(w: &mut AlooWorld) {
    let path = temp_ban_path();
    w.temp_files.push(path.clone());
    w.ip_bans_path = Some(path.clone());
    w.ip_bans = Some(IpBanList::new_empty(path));
}

#[given("a ban list file with one good line and one unparseable line")]
async fn hand_written_file(w: &mut AlooWorld) {
    let path = temp_ban_path();
    w.temp_files.push(path.clone());
    std::fs::write(
        &path,
        format!(
            "1 banned\n\
             2026-08-24T00:00:00Z\t{}\trepeated unproven direct-punch checks\n\
             this line is not a valid record at all\n",
            source_ip()
        ),
    )
    .unwrap();
    w.ip_bans_path = Some(path.clone());
    w.ip_bans = Some(IpBanList::load(&path).unwrap());
}

#[when("a source has two genuine failed checks a minute apart")]
async fn two_failures_a_minute_apart(w: &mut AlooWorld) {
    let ip = source_ip();
    bans_mut(w).record_failed_check(ip, BASE);
    bans_mut(w).record_failed_check(ip, BASE + 60);
}

#[when("that same source has one more genuine failed check right after")]
async fn one_more_failure_right_after(w: &mut AlooWorld) {
    bans_mut(w).record_failed_check(source_ip(), BASE + 61);
}

#[when("a source has three genuine failed checks all within the same minute")]
async fn three_failures_same_minute(w: &mut AlooWorld) {
    let ip = source_ip();
    let b = bans_mut(w);
    b.record_failed_check(ip, BASE);
    b.record_failed_check(ip, BASE + 1);
    b.record_failed_check(ip, BASE + 2);
}

#[when("a source had two genuine failed checks over ten hours ago")]
async fn two_failures_long_ago(w: &mut AlooWorld) {
    let ip = source_ip();
    let b = bans_mut(w);
    b.record_failed_check(ip, BASE);
    b.record_failed_check(ip, BASE + 60);
}

#[when("that same source has one genuine failed check now")]
async fn one_failure_now(w: &mut AlooWorld) {
    bans_mut(w).record_failed_check(source_ip(), BASE + TEN_HOURS + 120);
}

#[given("a source is already banned")]
#[given("a source has just been banned")]
async fn source_already_banned(w: &mut AlooWorld) {
    let ip = source_ip();
    let b = bans_mut(w);
    b.record_failed_check(ip, BASE);
    b.record_failed_check(ip, BASE + 60);
    let outcome = b.record_failed_check(ip, BASE + 61);
    assert_eq!(outcome, BanOutcome::Banned, "setup should have banned it");
}

#[when("that source is asked for one more failed check")]
async fn one_more_check_after_banned(w: &mut AlooWorld) {
    bans_mut(w).record_failed_check(source_ip(), BASE + 3600);
}

#[then("no fresh strike is counted against it")]
async fn no_fresh_strike(w: &mut AlooWorld) {
    // Still exactly one ban on file - an already-banned ip's further
    // checks neither add a second ban nor touch the strike count.
    assert_eq!(bans_mut(w).ban_count(), 1);
}

#[when("two different sources are each banned")]
async fn two_sources_banned(w: &mut AlooWorld) {
    for ip in [source_ip(), other_source_ip()] {
        let b = bans_mut(w);
        b.record_failed_check(ip, BASE);
        b.record_failed_check(ip, BASE + 60);
        b.record_failed_check(ip, BASE + 61);
    }
}

#[when("the ban list is reloaded from disk")]
async fn reload_from_disk(w: &mut AlooWorld) {
    let path = w.ip_bans_path.clone().expect("no ban list path recorded");
    w.ip_bans = Some(IpBanList::load(&path).unwrap());
}

#[when("that source's line is deleted from the file by hand")]
async fn delete_line_by_hand(w: &mut AlooWorld) {
    let path = w.ip_bans_path.clone().expect("no ban list path recorded");
    let contents = std::fs::read_to_string(&path).unwrap();
    let ip = source_ip().to_string();
    let kept: String = contents
        .lines()
        .filter(|line| !line.contains(&ip))
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(&path, kept).unwrap();
}

#[then("that source is banned")]
async fn source_is_banned(w: &mut AlooWorld) {
    assert!(bans_mut(w).is_banned(source_ip()));
}

#[then("that source is not banned")]
async fn source_is_not_banned(w: &mut AlooWorld) {
    assert!(!bans_mut(w).is_banned(source_ip()));
}

#[then("that source is still banned")]
async fn source_still_banned(w: &mut AlooWorld) {
    assert!(bans_mut(w).is_banned(source_ip()));
}

#[then("that source is no longer banned")]
async fn source_no_longer_banned(w: &mut AlooWorld) {
    assert!(!bans_mut(w).is_banned(source_ip()));
}

#[then("the source named on the good line is still banned")]
async fn good_line_source_banned(w: &mut AlooWorld) {
    assert!(bans_mut(w).is_banned(source_ip()));
}

#[then(expr = "the ban list file's header reads {string}")]
async fn header_reads(w: &mut AlooWorld, expected: String) {
    let path = w.ip_bans_path.clone().expect("no ban list path recorded");
    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(contents.lines().next(), Some(expected.as_str()));
}
