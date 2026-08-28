//! The two-button confirmation this app asks every yes-or-no question
//! with: a bordered box over whatever is behind it, a body, and one
//! affirmative button beside one declining button.
//!
//! Every such popup used to carry its own copy of three things - a
//! two-variant focus enum, a `Left`/`Right`/`Tab` toggle written out as a
//! match, and a 50/50 `Layout` split feeding two `render_popup_button`
//! calls. Nine enums and fourteen button rows, all structurally identical;
//! what actually varied between them was only ever the two labels, the
//! button width, and which side starts focused.
//!
//! So that is what this module parametrizes, and nothing else:
//!
//! - [`Confirm`] is the focus state for all of them. `Yes` is whichever
//!   button *does the thing* (Accept, Send file, Delete, END CALL), `No`
//!   the one that declines it (Reject, Discard, Cancel, No). Naming them
//!   by role rather than by wording is what lets one type serve every
//!   popup - the wording lives in [`ConfirmLabels`], beside the question
//!   it belongs to.
//! - [`render_confirm_row`] draws the button pair into a `Rect` a caller
//!   has already laid out. This is the piece every site shares, including
//!   the ones whose body is a list or a multi-line styled block rather
//!   than a paragraph.
//! - [`ConfirmPopup`] draws the whole thing - clear, border, body, button
//!   row - for the sites that are exactly that and nothing more. The body
//!   is a closure, so a caller with something richer than a paragraph to
//!   draw still gets the frame and the buttons for free.
//!
//! **Focus is `Option<Confirm>`**, not `Confirm`. Two existing popups need
//! "neither button is focused" as a real state: the export popup's focus
//! sits on its checkbox list until `Tab`, and the contacts popups store
//! the whole confirmation as `Option`, absent until it is asked for. A
//! `None` here draws both buttons unfocused, which is what those sites
//! already did by gating the comparison.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use super::super::ui::{centered_rect, focus_border_style};

/// Which of a confirmation's two buttons has focus.
///
/// `No` is the `Default` because the app's own convention is that the
/// irreversible half of a question is never one accidental `Enter` away -
/// the three enums this replaces that derived `Default` all defaulted to
/// their declining variant. Popups where proceeding is the common case
/// (a file offer, an OTP invite, `/call` - the user either asked for it
/// themselves or is being asked something they would usually grant) set
/// `Yes` explicitly at the point they open, exactly as they did before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Confirm {
    /// The button that carries the action out.
    Yes,
    /// The button that declines it.
    #[default]
    No,
}

impl Confirm {
    /// The other one. What `Left`/`Right`/`Tab` does in every one of these
    /// popups - there are only two buttons, so all three keys mean the
    /// same thing and none of them can fall off an end.
    pub fn toggled(self) -> Self {
        match self {
            Confirm::Yes => Confirm::No,
            Confirm::No => Confirm::Yes,
        }
    }

    /// `toggled`, in place.
    pub fn toggle(&mut self) {
        *self = self.toggled();
    }

    /// Whether the affirmative button is the focused one - for a caller
    /// that only branches one way and would otherwise write out a `match`
    /// with a dead arm.
    pub fn is_yes(self) -> bool {
        matches!(self, Confirm::Yes)
    }

    /// `Yes` when `yes`, `No` otherwise - for building a focus out of a
    /// condition rather than a branch.
    pub fn from_yes(yes: bool) -> Self {
        if yes { Confirm::Yes } else { Confirm::No }
    }
}

/// What the two buttons say. Held beside the question rather than on
/// [`Confirm`] because the wording is the one thing that genuinely differs
/// between these popups: the same `Yes`/`No` *state* reads as
/// Accept/Reject on an incoming offer, Send file/Discard on an outgoing
/// one, and Delete/Cancel on something destructive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmLabels<'a> {
    pub yes: &'a str,
    pub no: &'a str,
}

impl<'a> ConfirmLabels<'a> {
    pub const fn new(yes: &'a str, no: &'a str) -> Self {
        Self { yes, no }
    }

    /// Answering someone else's request - an incoming file offer, a call
    /// invite, an OTP invitation, an identity review.
    pub const ACCEPT_REJECT: ConfirmLabels<'static> = ConfirmLabels::new("Accept", "Reject");

    /// A plain question the user asked themselves.
    pub const CONFIRM_CANCEL: ConfirmLabels<'static> = ConfirmLabels::new("Confirm", "Cancel");

    /// A question phrased as one, rather than as an action.
    pub const YES_NO: ConfirmLabels<'static> = ConfirmLabels::new("Yes", "No");
}

/// The button width every confirmation in this app draws at, except the
/// three whose affirmative label is long enough to need
/// [`WIDE_BUTTON_WIDTH`] ("Send file", "Delete").
pub const BUTTON_WIDTH: u16 = 16;

/// The wider button the file-send and contacts-delete confirmations use.
pub const WIDE_BUTTON_WIDTH: u16 = 18;

/// One popup button - the affirmative and declining halves of every
/// confirmation, and the standalone `Save` the direct-punch editor draws.
///
/// Same border-vs-fill focus convention as
/// `ui_connect_popup::render_connect_button`: the border (block) always
/// keeps its own plain/yellow-focus style, and only the *inner* area gets
/// the solid highlight fill when focused, via the `Paragraph`'s own
/// `.style()` rather than a separate widget underneath it. `width` is the
/// button's fixed width, centered in `area`.
pub fn render_popup_button(frame: &mut Frame, area: Rect, width: u16, label: &str, focused: bool) {
    let popup = centered_rect(width, 3, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_border_style(focused));
    let text_style = if focused {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::BOLD)
    };
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    frame.render_widget(
        Paragraph::new(label)
            .alignment(ratatui::layout::Alignment::Center)
            .style(text_style),
        inner,
    );
}

/// The affirmative button beside the declining one, filling `area` in two
/// equal halves - for a caller that has already laid out its own popup and
/// only needs the row. [`ConfirmPopup`] is the whole-popup form.
///
/// `focus` of `None` draws both unfocused; see the module doc for the two
/// popups that need that.
pub fn render_confirm_row(
    frame: &mut Frame,
    area: Rect,
    labels: ConfirmLabels<'_>,
    focus: Option<Confirm>,
    button_width: u16,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    render_popup_button(
        frame,
        cols[0],
        button_width,
        labels.yes,
        focus == Some(Confirm::Yes),
    );
    render_popup_button(
        frame,
        cols[1],
        button_width,
        labels.no,
        focus == Some(Confirm::No),
    );
}

/// A whole confirmation popup: cleared background, titled border, a body,
/// and the button row along the bottom.
///
/// Built as a struct rather than a long argument list because the sites
/// differ in six independent ways and most of them want the defaults -
/// `ConfirmPopup { title, labels, focus, ..Default::default() }` is the
/// common call, with `size`/`border_style`/`button_width`/`body_min_height`
/// set only where a popup genuinely differs.
#[derive(Debug, Clone)]
pub struct ConfirmPopup<'a> {
    /// Drawn on the border. Empty means an untitled box.
    pub title: &'a str,
    pub labels: ConfirmLabels<'a>,
    pub focus: Option<Confirm>,
    /// The popup's own `(width, height)`, centered in the area given to
    /// [`render`](ConfirmPopup::render).
    pub size: (u16, u16),
    /// `Some` for a popup that colours its border - the destructive ones
    /// use red. `None` leaves the border at the terminal's default.
    pub border_style: Option<Style>,
    /// The `Constraint::Min` the body row is laid out with. 3 everywhere
    /// but the end-call question, which is a single centered line.
    pub body_min_height: u16,
    pub button_width: u16,
}

impl Default for ConfirmPopup<'_> {
    fn default() -> Self {
        Self {
            title: "",
            labels: ConfirmLabels::CONFIRM_CANCEL,
            focus: None,
            size: (64, 9),
            border_style: None,
            body_min_height: 3,
            button_width: BUTTON_WIDTH,
        }
    }
}

impl ConfirmPopup<'_> {
    /// Draws the popup, calling `body` with the `Rect` above the buttons.
    ///
    /// The body is a closure rather than a string so a caller with a
    /// styled `Line`, a stateful `List` or a multi-line block still gets
    /// the frame and the button row from here - which is what lets every
    /// one of this app's confirmations share it, not only the ones whose
    /// body happens to be one wrapped paragraph. [`render_message`] is the
    /// shorthand for those.
    pub fn render<F>(&self, frame: &mut Frame, area: Rect, body: F)
    where
        F: FnOnce(&mut Frame, Rect),
    {
        let popup = centered_rect(self.size.0, self.size.1, area);
        let mut block = Block::default().borders(Borders::ALL);
        if !self.title.is_empty() {
            block = block.title(self.title.to_string());
        }
        if let Some(style) = self.border_style {
            block = block.border_style(style);
        }
        let inner = block.inner(popup);
        frame.render_widget(Clear, popup);
        frame.render_widget(block, popup);

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(self.body_min_height),
                Constraint::Length(3),
            ])
            .split(inner);

        body(frame, rows[0]);
        render_confirm_row(frame, rows[1], self.labels, self.focus, self.button_width);
    }

    /// [`render`](ConfirmPopup::render) with a wrapped paragraph as the
    /// body - the shape most of these popups have.
    pub fn render_message(&self, frame: &mut Frame, area: Rect, message: &str) {
        self.render(frame, area, |frame, body| {
            frame.render_widget(
                Paragraph::new(message.to_string()).wrap(Wrap { trim: true }),
                body,
            );
        });
    }
}
