//! Where a diagnostic goes (US-042).
//!
//! The sink is a single process-wide switch, which is why the feature file
//! holds one scenario rather than several. These steps also put it back the
//! way they found it: `cargo bdd` runs scenarios concurrently, and one that
//! silenced the sink and walked away would swallow every other scenario's
//! diagnostics for the rest of the run.

use cucumber::{given, then, when};

use aloo::log;

use crate::world::AlooWorld;

#[given("the interface has taken the terminal over")]
async fn terminal_taken_over(_w: &mut AlooWorld) {
    let _ = log::take_collected();
    log::silence();
}

#[when(expr = "a background task warns {string}")]
async fn task_warns(_w: &mut AlooWorld, message: String) {
    aloo::log_warn!("{message}");
}

#[then("nothing is written to the terminal")]
async fn nothing_written(w: &mut AlooWorld) {
    assert!(
        log::is_silenced(),
        "the sink must still be silenced while the interface holds the screen"
    );
    // Held rather than written, which is what having it to replay below
    // proves. Read by content, not by count: production code reached by
    // other scenarios running alongside this one warns through the very
    // same sink.
    w.log_collected = log::take_collected();
    assert!(
        w.log_collected
            .iter()
            .any(|l| l.contains("direct-link UDP receive error")),
        "the warning should have been collected: {:?}",
        w.log_collected
    );
}

#[when("the interface hands the terminal back")]
async fn terminal_handed_back(_w: &mut AlooWorld) {
    log::unsilence();
    // Anything a scenario running alongside this one warned about while
    // the sink was silenced is in the ring too, and is nothing to do with
    // what is being asserted below.
    let _ = log::take_collected();
}

#[then("the warning is written out, prefixed as the app's own")]
async fn warning_written_out(w: &mut AlooWorld) {
    assert!(!log::is_silenced());
    let line = w
        .log_collected
        .iter()
        .find(|l| l.contains("direct-link UDP receive error"))
        .expect("the collected warning");
    assert!(
        line.starts_with(log::PREFIX),
        "a warning must be recognisable as aloo's own: {line:?}"
    );
}

#[then("that warning is not held back")]
async fn warning_not_held(_w: &mut AlooWorld) {
    let collected = log::take_collected();
    assert!(
        !collected
            .iter()
            .any(|l| l.contains("could not read ~/.aloo/settings")),
        "with nobody holding the screen there is nothing to hold back: {collected:?}"
    );
}
