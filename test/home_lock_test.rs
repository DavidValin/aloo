//! One session per aloo home (`platform::HomeLock`): the guard that stops
//! two aloo processes from writing one `otp_store` and one keychain from two
//! diverging copies of the pad counters.

use aloo::platform::{HomeLock, home_lock_path};

fn scratch(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "aloo-home-lock-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// @requirement AC-441
#[test]
fn a_second_claim_on_the_same_home_is_refused_while_the_first_is_held() {
    let home = scratch("busy");
    let first = HomeLock::acquire(&home)
        .expect("a fresh home is claimable")
        .expect("nobody else holds it");
    assert!(home_lock_path(&home).exists(), "the claim is a file the OS can arbitrate");

    let second = HomeLock::acquire(&home).expect("asking is not an error");
    assert!(second.is_none(), "a second session on the same home is refused");

    // Released with the first session, not by any cleanup step: a killed
    // process never blocks the next start.
    drop(first);
    let again = HomeLock::acquire(&home).expect("asking is not an error");
    assert!(again.is_some(), "the home is claimable again once the holder is gone");
    let _ = std::fs::remove_dir_all(&home);
}

/// @requirement AC-441
#[test]
fn two_different_homes_are_independent() {
    let a = scratch("home-a");
    let b = scratch("home-b");
    let _first = HomeLock::acquire(&a).unwrap().expect("home a");
    let second = HomeLock::acquire(&b).unwrap();
    assert!(
        second.is_some(),
        "ALOO_HOME=<other dir> is exactly how a second, consistent session is meant to run"
    );
    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
}

/// @requirement AC-441
#[test]
fn the_refusal_names_the_home_and_the_way_out() {
    let home = scratch("message");
    let message = HomeLock::busy_message(&home);
    assert!(message.contains(&home.display().to_string()));
    assert!(message.contains("ALOO_HOME="), "the fix is a second home, and the message says so");
    assert!(message.contains("attach"), "or attaching to the running session");
}
