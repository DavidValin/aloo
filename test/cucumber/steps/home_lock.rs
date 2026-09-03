//! One session per aloo home (AC-441): the process-lifetime claim
//! `platform::HomeLock` takes on a home, driven directly - the claim is the
//! whole mechanism, and `main.rs` only ever refuses to start on its answer.

use cucumber::{given, then, when};

use aloo::platform::HomeLock;

use crate::world::AlooWorld;

fn claim(w: &mut AlooWorld, home: &std::path::Path) {
    match HomeLock::acquire(home).expect("asking for a home is never an I/O error here") {
        Some(lock) => {
            w.home_claims.push(Some(lock));
            w.last_home_refusal = None;
        }
        None => {
            w.home_claims.push(None);
            w.last_home_refusal = Some(HomeLock::busy_message(home));
        }
    }
}

#[given(expr = "a session holds the aloo home {string}")]
async fn a_session_holds_the_home(w: &mut AlooWorld, tag: String) {
    let home = w.temp_path(&format!("home-{tag}"));
    claim(w, &home);
    assert!(
        w.home_claims.last().is_some_and(Option::is_some),
        "a fresh home is claimed by the first session"
    );
    w.session_home = Some(home);
}

#[when("another session tries to start against the same home")]
async fn another_session_same_home(w: &mut AlooWorld) {
    let home = w.session_home.clone().expect("a home was claimed first");
    claim(w, &home);
}

#[when("another session starts against a different home")]
async fn another_session_other_home(w: &mut AlooWorld) {
    let other = w.temp_path("home-other");
    claim(w, &other);
}

#[when("that session ends")]
async fn that_session_ends(w: &mut AlooWorld) {
    // The first claim is dropped - which is all a process exit, clean or
    // not, ever does to an advisory lock.
    let first = w.home_claims.remove(0);
    drop(first);
}

#[then("it is refused, naming the home and ALOO_HOME as the way out")]
async fn it_is_refused(w: &mut AlooWorld) {
    assert!(
        w.home_claims.last().is_some_and(Option::is_none),
        "a second session on a held home must not start"
    );
    let message = w.last_home_refusal.clone().expect("the refusal explains itself");
    let home = w.session_home.clone().expect("a home was claimed first");
    assert!(message.contains(&home.display().to_string()), "{message:?}");
    assert!(message.contains("ALOO_HOME="), "{message:?}");
}

#[then("it starts")]
async fn it_starts(w: &mut AlooWorld) {
    assert!(
        w.home_claims.last().is_some_and(Option::is_some),
        "the claim is granted"
    );
}
