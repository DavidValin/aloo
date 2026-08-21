//! Where a frame gets drawn, decoupled from *whether* one gets drawn at
//! all.
//!
//! A plain `Terminal<CrosstermBackend<Stdout>>` cannot express two of the
//! three places a session's frames go (`docs/SPEC.md` "Running in
//! background mode"): a daemon has no terminal at all for most of its
//! life, and a resumed one is drawing to a terminal that belongs to a
//! *different process*.
//!
//! `Surface` covers all three behind one `draw` call, so `session`'s event
//! loop - which redraws at the bottom of every `select!` iteration - needs
//! to know about none of it:
//!
//! - **`Local`** - this process owns the real stdout, and draws to it
//!   directly.
//! - **`Detached`** - a running daemon with nobody watching. `draw` does
//!   nothing at all: no rendering work, no allocation, no diff. This is
//!   the state a daemon spends nearly all its time in, so it has to be
//!   free rather than merely cheap (rendering to a sink would still walk
//!   and diff the whole buffer several times a second).
//! - **`Attached`** - a daemon whose session is being viewed from an
//!   `aloo` running in some terminal. Frames are rendered to ANSI and
//!   handed off as byte blobs for that process to write to its own stdout.
//!
//! Nothing here knows about sockets. `Attached` writes into an ordinary
//! channel (`AttachWriter`), which `client::daemon_ipc` drains - so this
//! module stays testable with a plain receiver, and the transport can
//! change without touching rendering.

use std::io::{self, Stdout, Write};

use ratatui::Terminal;
use ratatui::backend::{Backend, ClearType, CrosstermBackend, WindowSize};
use ratatui::buffer::Cell;
use ratatui::layout::{Position, Size};

use crate::BoxError;

/// What to assume when a terminal cannot say how big it is - the
/// conventional default an 80-column VT100 established and every terminal
/// emulator still opens at.
pub const DEFAULT_COLS: u16 = 80;
pub const DEFAULT_ROWS: u16 = 24;

/// A terminal size, as reported by whoever is actually displaying the
/// frames. Carried explicitly because the process rendering them cannot
/// ask: a daemon's own stdout is `/dev/null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    pub cols: u16,
    pub rows: u16,
}

impl TerminalSize {
    pub fn new(cols: u16, rows: u16) -> Self {
        // A zero dimension means "I do not know", never "one cell wide".
        // Terminals report it transiently mid-resize, and a pty nobody has
        // set a size on (a `script` session, some CI runners) reports 0x0
        // from the moment it opens.
        //
        // Substituting the conventional 80x24 rather than clamping to 1
        // matters more than it looks: a 1x1 frame is *valid* - ratatui
        // renders it happily, and the viewer sees a single border
        // character on an otherwise blank screen, which reads as "attach
        // is broken" rather than as "the size was unknown". Falling back
        // to a real terminal size means the session is usable, and a
        // client that later learns its true size sends a `Resize`.
        Self {
            cols: if cols == 0 { DEFAULT_COLS } else { cols },
            rows: if rows == 0 { DEFAULT_ROWS } else { rows },
        }
    }
}

/// The sink an `Attached` surface renders into: accumulates a frame's ANSI
/// bytes and, on `flush`, hands the whole frame over as one blob.
///
/// One message per frame rather than per write is deliberate. ratatui
/// issues many small writes per draw (a cursor move and a style change per
/// run of cells); forwarding each as its own IPC frame would multiply the
/// message count by a hundred or more for no benefit, and would let a
/// half-drawn frame reach the viewer if the connection dropped mid-render.
/// `Terminal::draw` always ends in a `flush`, so "one message" and "one
/// complete frame" coincide.
#[derive(Debug)]
pub struct AttachWriter {
    buf: Vec<u8>,
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl AttachWriter {
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self {
            buf: Vec::new(),
            tx,
        }
    }
}

impl Write for AttachWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// A send failure means the viewer is gone. Deliberately *not* an
    /// error: the daemon must survive its viewer disconnecting at any
    /// moment, including mid-frame, and the detach is noticed through the
    /// IPC task rather than through a write error surfacing out of a draw
    /// call deep in the event loop.
    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let _ = self.tx.send(std::mem::take(&mut self.buf));
        }
        Ok(())
    }
}

/// `CrosstermBackend` with the three questions it cannot answer for a
/// remote viewer answered from what that viewer reported.
///
/// Everything else delegates unchanged - this is a backend for a real
/// terminal, it just happens to be one at the other end of a socket:
///
/// - **`size`/`window_size`** - `CrosstermBackend` asks the *operating
///   system* about its own stdout. In a daemon that is `/dev/null`, so the
///   answer is either an error or a meaningless default. The attached
///   client sends its real size on attach and on every resize.
/// - **`get_cursor_position`** - the real implementation writes a Device
///   Status Report and blocks reading the reply *from this process's
///   stdin*. Over a socket there is nobody to answer, so it would hang.
///   The position we last set is tracked instead, which is what a
///   `Terminal` actually needs it for.
pub struct AttachBackend {
    inner: CrosstermBackend<AttachWriter>,
    size: TerminalSize,
    cursor: Position,
}

impl AttachBackend {
    pub fn new(writer: AttachWriter, size: TerminalSize) -> Self {
        Self {
            inner: CrosstermBackend::new(writer),
            size,
            cursor: Position::new(0, 0),
        }
    }

    pub fn set_size(&mut self, size: TerminalSize) {
        self.size = size;
    }
}

impl Backend for AttachBackend {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> Result<(), Self::Error>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        self.inner.draw(content)
    }

    fn hide_cursor(&mut self) -> Result<(), Self::Error> {
        self.inner.hide_cursor()
    }

    fn show_cursor(&mut self) -> Result<(), Self::Error> {
        self.inner.show_cursor()
    }

    fn get_cursor_position(&mut self) -> Result<Position, Self::Error> {
        Ok(self.cursor)
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> Result<(), Self::Error> {
        let position = position.into();
        self.cursor = position;
        self.inner.set_cursor_position(position)
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        self.inner.clear()
    }

    fn clear_region(&mut self, clear_type: ClearType) -> Result<(), Self::Error> {
        self.inner.clear_region(clear_type)
    }

    fn size(&self) -> Result<Size, Self::Error> {
        Ok(Size::new(self.size.cols, self.size.rows))
    }

    fn window_size(&mut self) -> Result<WindowSize, Self::Error> {
        // Pixel dimensions are reported as unknown (0x0) rather than
        // guessed: nothing in this app draws images, and the only honest
        // answer for a terminal we are not attached to is that we do not
        // know. `columns_rows` is the part callers actually use.
        Ok(WindowSize {
            columns_rows: Size::new(self.size.cols, self.size.rows),
            pixels: Size::new(0, 0),
        })
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // Disambiguated: `CrosstermBackend` implements both `Backend` and
        // `io::Write`, and only the former's `flush` emits the queued
        // draw commands before flushing the writer under them.
        Backend::flush(&mut self.inner)
    }
}

/// Where this session's frames go right now. See the module doc.
pub enum Surface {
    Local(Terminal<CrosstermBackend<Stdout>>),
    Detached,
    Attached(Box<Terminal<AttachBackend>>),
}

impl Surface {
    /// Renders one frame, or - when nothing is watching - does nothing.
    ///
    /// Takes the same closure `Terminal::draw` does, so a call site reads
    /// as an ordinary draw whichever of the three this is.
    pub fn draw<F>(&mut self, render: F) -> Result<(), BoxError>
    where
        F: FnOnce(&mut ratatui::Frame),
    {
        match self {
            Self::Local(terminal) => {
                terminal.draw(render)?;
            }
            Self::Detached => {}
            Self::Attached(terminal) => {
                terminal.draw(render)?;
            }
        }
        Ok(())
    }

    /// Whether a frame drawn right now would actually be seen. Lets a
    /// caller skip work that only exists to produce something to look at.
    pub fn is_visible(&self) -> bool {
        !matches!(self, Self::Detached)
    }

    /// Starts sending frames to a viewer of `size`, replacing whatever
    /// this surface was.
    ///
    /// The full repaint matters: the attaching client's terminal holds
    /// whatever was on its screen before, and ratatui only ever sends the
    /// *difference* against its own previous buffer. A freshly built
    /// `Terminal` believes the screen is empty, so without clearing it
    /// first the viewer would see this session's frame composited over
    /// their shell's leftovers, with the untouched cells never repainted.
    pub fn attach(&mut self, writer: AttachWriter, size: TerminalSize) -> Result<(), BoxError> {
        let mut terminal = Terminal::new(AttachBackend::new(writer, size))?;
        terminal.clear()?;
        *self = Self::Attached(Box::new(terminal));
        Ok(())
    }

    /// Stops sending frames and goes back to `Detached`. A no-op on a
    /// surface that was not attached - detaching twice (the viewer's
    /// socket dropping just as `/daemon` is typed) must not be an error.
    pub fn detach(&mut self) {
        if matches!(self, Self::Attached(_)) {
            *self = Self::Detached;
        }
    }

    /// Tells this surface its terminal changed size, from either place a
    /// resize is noticed: a `Local` surface's own `Event::Resize`, or the
    /// `Resize` message an attached viewer sends for the terminal it owns.
    /// A no-op only when `Detached` - nothing is being drawn there, and
    /// there is no size to speak of.
    ///
    /// `Terminal::resize` is what discards the stale buffer and clears the
    /// screen under it, so the very next `draw` repaints every cell for
    /// the new dimensions. Without it ratatui keeps diffing against a
    /// buffer laid out for a window that no longer exists: whatever the
    /// old layout put outside the new one is never painted over, leaving
    /// a half-erased header and torn selectors behind the frame that is.
    ///
    /// A `Local` terminal would eventually reach the same place on its own
    /// (`Terminal::draw` autoresizes), but only once it next asks the OS,
    /// and only for the size the OS happens to report then. Acting on the
    /// event makes the repaint the resize's own, immediate consequence.
    pub fn resize(&mut self, size: TerminalSize) -> Result<(), BoxError> {
        let area = ratatui::layout::Rect::new(0, 0, size.cols, size.rows);
        match self {
            Self::Local(terminal) => {
                terminal.resize(area)?;
            }
            Self::Detached => {}
            Self::Attached(terminal) => {
                terminal.backend_mut().set_size(size);
                terminal.resize(area)?;
            }
        }
        Ok(())
    }
}
