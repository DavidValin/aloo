//! `crate::log` - where a diagnostic goes when a terminal UI may be in the
//! way (`docs/SPEC.md` "Where diagnostics go").
//!
//! The sink is a single process-wide switch, so every assertion about it
//! lives in one test function rather than several: libtest runs the tests
//! in one binary on parallel threads, and two of them flipping that switch
//! at once would prove nothing about either. Everything here is about that
//! one switch, so one test is also all there is to say.

use aloo::log;

/// @requirement AC-244, TB-235
#[test]
fn a_silenced_sink_collects_every_line_and_replays_them_on_the_way_out() {
    // The default: nothing is holding the screen, so nothing is held back.
    assert!(
        !log::is_silenced(),
        "a process that never took the terminal over writes straight out"
    );
    assert!(
        log::take_collected().is_empty(),
        "nothing is collected while the sink is writing out"
    );

    // What `client::tui::terminal::setup` does for as long as ratatui owns
    // the screen.
    log::silence();
    assert!(log::is_silenced());
    aloo::log_warn!("first thing that went wrong");
    aloo::log_warn!("second thing, about {}", "formatting");

    let collected = log::take_collected();
    assert_eq!(
        collected,
        vec![
            format!("{} first thing that went wrong", log::PREFIX),
            format!("{} second thing, about formatting", log::PREFIX),
        ],
        "every silenced line is kept, in order, with the app's own prefix"
    );
    assert!(
        log::take_collected().is_empty(),
        "taking the collected lines empties the ring"
    );

    // A session that warns about the same thing forever must not grow this
    // without bound; the newest lines are the ones worth keeping.
    for i in 0..(log::RING_CAPACITY + 10) {
        aloo::log_warn!("line {i}");
    }
    let collected = log::take_collected();
    assert_eq!(collected.len(), log::RING_CAPACITY);
    assert!(
        collected[0].ends_with("line 10"),
        "the oldest lines are the ones dropped: {:?}",
        collected.first()
    );
    assert!(
        collected[log::RING_CAPACITY - 1].ends_with(&format!("line {}", log::RING_CAPACITY + 9)),
        "the newest line is always kept: {:?}",
        collected.last()
    );

    // `drain` is what `restore` calls once the terminal is genuinely back:
    // it empties the ring, whether or not anyone is reading stderr.
    aloo::log_warn!("something to drain");
    log::drain();
    assert!(
        log::take_collected().is_empty(),
        "draining leaves nothing behind for a second replay"
    );

    // And the inverse of `silence`, so a foreground start after an
    // attached session writes out again.
    log::unsilence();
    assert!(!log::is_silenced());
    aloo::log_warn!("straight to the console");
    assert!(
        log::take_collected().is_empty(),
        "an unsilenced sink collects nothing - it writes"
    );
}
