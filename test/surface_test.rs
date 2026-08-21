//! `crate::client::tui::surface` - where a frame gets drawn, and whether
//! one gets drawn at all.
//!
//! `Surface::Local` is deliberately not exercised here: constructing it
//! requires putting the real process terminal into raw mode and the
//! alternate screen, which a parallel test run cannot do safely (and which
//! would be testing crossterm, not this module). What *is* specific to
//! this module - the detached no-op, and a backend answering for a
//! terminal it cannot query - is covered below.

use aloo::client::tui::surface::{AttachBackend, AttachWriter, Surface, TerminalSize};
use ratatui::backend::Backend;
use ratatui::widgets::{Block, Borders, Paragraph};

fn attach_channel() -> (
    AttachWriter,
    tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (AttachWriter::new(tx), rx)
}

fn draw_something(surface: &mut Surface) {
    surface
        .draw(|f| {
            let widget = Paragraph::new("hello").block(Block::default().borders(Borders::ALL));
            f.render_widget(widget, f.area());
        })
        .expect("drawing must not fail");
}

/// @requirement TB-215
#[test]
fn a_detached_surface_draws_nothing_at_all() {
    let mut surface = Surface::Detached;
    assert!(!surface.is_visible());
    // The point is that this is free, not merely quiet: no panic, no
    // error, and nothing to flush anywhere.
    draw_something(&mut surface);
    draw_something(&mut surface);
}

/// @requirement TB-215
#[test]
fn an_attached_surface_emits_one_message_per_frame() {
    let (writer, mut rx) = attach_channel();
    let mut surface = Surface::Detached;
    surface
        .attach(writer, TerminalSize::new(80, 24))
        .expect("attaching must succeed");
    assert!(surface.is_visible());

    // `attach` clears the viewer's screen before the first frame - that
    // repaint is itself a flush, so drain whatever it produced first.
    let mut before = 0;
    while rx.try_recv().is_ok() {
        before += 1;
    }
    assert!(before > 0, "attaching must repaint the viewer's screen");

    draw_something(&mut surface);
    let frame = rx.try_recv().expect("a drawn frame must be sent");
    assert!(!frame.is_empty());
    assert!(
        rx.try_recv().is_err(),
        "one draw is one message, not one per internal write"
    );
}

/// Detaching drops the terminal, and with it the writer's sender - which
/// is how the IPC side learns the viewer is finished without a separate
/// signal.
/// @requirement TB-215
#[test]
fn detaching_closes_the_frame_channel_and_stops_drawing() {
    let (writer, mut rx) = attach_channel();
    let mut surface = Surface::Detached;
    surface.attach(writer, TerminalSize::new(80, 24)).unwrap();
    while rx.try_recv().is_ok() {}

    surface.detach();
    assert!(!surface.is_visible());
    draw_something(&mut surface);

    assert!(
        matches!(rx.try_recv(), Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)),
        "dropping the attached terminal must close the channel"
    );
}

/// @requirement TB-215
#[test]
fn detaching_a_surface_that_was_never_attached_is_a_no_op() {
    let mut surface = Surface::Detached;
    surface.detach();
    assert!(!surface.is_visible());
}

/// The three questions `CrosstermBackend` answers by asking the operating
/// system about its own stdout - which, in a daemon, is /dev/null.
/// @requirement TB-216
#[test]
fn the_attach_backend_reports_the_size_its_viewer_declared() {
    let (writer, _rx) = attach_channel();
    let mut backend = AttachBackend::new(writer, TerminalSize::new(120, 40));

    let size = backend.size().unwrap();
    assert_eq!((size.width, size.height), (120, 40));
    let window = backend.window_size().unwrap();
    assert_eq!((window.columns_rows.width, window.columns_rows.height), (120, 40));

    backend.set_size(TerminalSize::new(80, 24));
    let size = backend.size().unwrap();
    assert_eq!((size.width, size.height), (80, 24));
}

/// The real implementation writes a Device Status Report and blocks
/// reading the answer from this process's stdin - over a socket there is
/// nobody to answer, so it would hang forever.
/// @requirement TB-216
#[test]
fn the_attach_backend_tracks_the_cursor_instead_of_asking_for_it() {
    let (writer, _rx) = attach_channel();
    let mut backend = AttachBackend::new(writer, TerminalSize::new(80, 24));

    assert_eq!(backend.get_cursor_position().unwrap(), (0, 0).into());
    backend.set_cursor_position((12, 5)).unwrap();
    assert_eq!(backend.get_cursor_position().unwrap(), (12, 5).into());
}

/// A zero dimension means "I do not know" - reported transiently
/// mid-resize, and constantly by a pty nobody has sized. Clamping it to 1
/// would render a *valid* 1x1 frame: one border character on a blank
/// screen, which reads as a broken attach rather than an unknown size.
/// @requirement TB-216
#[test]
fn an_unknown_dimension_falls_back_to_a_usable_terminal_size() {
    use aloo::client::tui::surface::{DEFAULT_COLS, DEFAULT_ROWS};
    let size = TerminalSize::new(0, 0);
    assert_eq!((size.cols, size.rows), (DEFAULT_COLS, DEFAULT_ROWS));

    // Only the unknown half is substituted.
    let size = TerminalSize::new(120, 0);
    assert_eq!((size.cols, size.rows), (120, DEFAULT_ROWS));
    let size = TerminalSize::new(0, 40);
    assert_eq!((size.cols, size.rows), (DEFAULT_COLS, 40));

    // A real size is left exactly alone.
    let size = TerminalSize::new(1, 1);
    assert_eq!((size.cols, size.rows), (1, 1));
}

/// @requirement TB-216
#[test]
fn resizing_an_attached_surface_redraws_at_the_new_size() {
    let (writer, mut rx) = attach_channel();
    let mut surface = Surface::Detached;
    surface.attach(writer, TerminalSize::new(80, 24)).unwrap();
    while rx.try_recv().is_ok() {}

    surface
        .resize(TerminalSize::new(120, 40))
        .expect("resize must succeed");
    draw_something(&mut surface);
    let frame = rx.try_recv().expect("a frame must follow a resize");
    assert!(!frame.is_empty());
}

/// A resize must not be diffed against the buffer laid out for the old
/// size: whatever the old layout put outside the new one would then never
/// be painted over, showing as a half-erased header and torn selectors
/// alongside the frame that is.
///
/// Checked at the level both `Surface` arms share (`Surface::resize` ->
/// `Terminal::resize`), by looking for the erase-display escape that a
/// full repaint has to emit and a diff never does. `Local` cannot be
/// constructed here for the reason this file's own doc comment gives, but
/// it reaches this same call.
/// @requirement TB-234
#[test]
fn a_resize_repaints_every_cell_rather_than_diffing_against_the_old_size() {
    /// `CSI 2 J` - erase the whole display. What `Terminal::resize` emits
    /// through the backend, and nothing an ordinary diffed frame does.
    const ERASE_DISPLAY: &[u8] = b"\x1b[2J";

    let (writer, mut rx) = attach_channel();
    let mut surface = Surface::Detached;
    surface.attach(writer, TerminalSize::new(80, 24)).unwrap();
    draw_something(&mut surface);
    while rx.try_recv().is_ok() {}

    surface.resize(TerminalSize::new(120, 40)).unwrap();
    draw_something(&mut surface);

    let frame = rx.try_recv().expect("a frame must follow a resize");
    assert!(
        frame
            .windows(ERASE_DISPLAY.len())
            .any(|w| w == ERASE_DISPLAY),
        "the first frame after a resize must clear the screen under it"
    );

    // ...and only that one. A resize is a one-off, not a mode.
    while rx.try_recv().is_ok() {}
    draw_something(&mut surface);
    let frame = rx.try_recv().expect("a second frame");
    assert!(
        !frame
            .windows(ERASE_DISPLAY.len())
            .any(|w| w == ERASE_DISPLAY),
        "an ordinary frame after the resize goes back to diffing"
    );
}

/// Resizing a detached surface has no meaning and must not error - a
/// viewer's last resize can arrive just after it detaches.
/// @requirement TB-216
#[test]
fn resizing_a_detached_surface_is_a_no_op() {
    let mut surface = Surface::Detached;
    surface
        .resize(TerminalSize::new(120, 40))
        .expect("must not error");
}

/// The daemon must survive its viewer vanishing at any moment, including
/// between two writes of a single frame.
/// @requirement TB-215
#[test]
fn a_frame_written_after_the_viewer_is_gone_is_dropped_not_an_error() {
    let (writer, rx) = attach_channel();
    let mut surface = Surface::Detached;
    surface.attach(writer, TerminalSize::new(80, 24)).unwrap();
    drop(rx);

    // No panic, no error - the detach is noticed through the IPC task,
    // not through a write error surfacing out of the event loop.
    draw_something(&mut surface);
    draw_something(&mut surface);
}
