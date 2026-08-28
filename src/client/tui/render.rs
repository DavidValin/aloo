//! Drawing the connected screen.
//!
//! Everything here reads a `&UiState` and paints - the whole render half
//! of what `ui.rs` used to hold in one 9,600-line file. Nothing in this
//! module mutates state, decides an action, or touches the network: a
//! function takes a `Frame`, a `Rect` and something to draw, and draws it.
//! That is the seam the split was made on, and the property worth keeping.
//!
//! [`render`] is the entry point - the one function the terminal loop
//! calls per frame. It lays out the screen and dispatches to the popup and
//! panel renderers below it, in the priority order the modal stack
//! demands.
//!
//! Distinct from [`crate::client::tui::widgets`], which holds pieces that
//! know nothing about `UiState` at all. These do.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState,
};

use std::sync::atomic::Ordering;

use crate::proto::UserId;

use super::widgets::confirm_popup::{Confirm, ConfirmLabels, ConfirmPopup};
use super::help::{HELP_POPUP_TITLE, help_rendered_lines, wrap_to_width};
use super::ui::*;

pub fn render(frame: &mut Frame, state: &UiState) {
    let area = frame.area();
    if state.otp_mail.is_some() {
        // The mail view replaces the whole screen (its popups included) -
        // the global popups/notice below still overlay it, same priority
        // order `handle_key` applies.
        super::otp_mail::render_otp_mail_view(frame, area, state);
    } else if let Some(peer_id) = state.active_private_room {
        super::direct_message::render_private_room(frame, area, state, peer_id);
    } else {
        super::channel::render_channel_view(frame, area, state);
    }
    // The focused selector's dropdown, when open: an overlay hanging off
    // the top row over whichever view is behind it - which keeps updating
    // live as Up/Down move the selection - and below every popup.
    if state.selector_dropdown_open {
        super::channel::render_selector_dropdown(frame, area, state);
    }
    if state.mode == Mode::JoinPrivatePopup {
        super::channel::render_join_popup(frame, area, state);
    }
    if state.mode == Mode::ChannelPasswordPopup {
        super::channel::render_channel_password_popup(frame, area, state);
    }
    if state.mode == Mode::ChannelsPopup {
        super::channel::render_channels_popup(frame, area, state);
    }
    if state.mode == Mode::FileSend {
        super::file_send::render_file_send_popup(frame, area, state);
    }
    if state.mode == Mode::Contacts {
        super::contacts::render_contacts_popup(frame, area, state);
    }
    if state.mode == Mode::DirectPunches {
        super::direct_punch_popup::render_direct_punches_popup(frame, area, state);
    }
    if state.mode == Mode::ChannelLockPopup {
        super::channel_lock_popup::render_channel_lock_popup(frame, area, state);
    }
    if state.mode == Mode::ExportPopup {
        super::export_popup::render_export_popup(frame, area, state);
    }
    // One message's delivery details, drawn under the help overlay and
    // every consent popup for the same reason `handle_key` lets those
    // absorb keys first.
    if state.message_info.is_some() {
        render_message_info_popup(frame, area, state);
    }
    // Same tier as message-info above - a staged `.txt` receive's preview.
    if state.file_preview.is_some() {
        render_txt_preview_popup(frame, area, state);
    }
    // Same tier as message-info above - `i`/`/info`'s read-only snapshot.
    if state.user_info.is_some() {
        super::contacts::render_user_info_popup(frame, area, state);
    }
    // Same tier as user-info above - the superadmin `/users` popup.
    if state.users_admin.is_some() {
        super::contacts::render_users_admin_popup(frame, area, state);
    }
    // Drawn last, and independent of `mode`/the private-vs-channel view
    // above, so it overlays whatever's currently showing rather than
    // replacing it - matches `Ctrl+H` working from any view (`handle_key`).
    if state.help_open {
        render_help_popup(frame, area, state);
    }
    // A file offer sits above help but below an identity review, same
    // priority order `handle_key` applies.
    if let Some(offer) = state.file_offer_open() {
        render_file_offer_popup(frame, area, offer, state.file_offer_focus);
    }
    // A call invite is the same tier as a file offer, same reasoning
    // `handle_key` applies.
    if let Some(invite) = state.call_invite_open() {
        render_call_invite_popup(frame, area, invite, state.call_invite_focus);
    }
    // The call modal, whenever it isn't already the whole view above -
    // i.e. a call that has not been minimized away yet. Drawn under the
    // consent popups (which must stay answerable over it) for the same
    // reason `handle_key` lets them absorb keys first.
    if let Some(call) = &state.call
        && !call.minimized
    {
        render_call_modal(frame, area, state, call);
    }
    if let Some(pending) = &state.call_confirm {
        render_call_confirm_popup(frame, area, pending, state.call_confirm_focus);
    }
    if let Some(pending) = &state.channel_command_confirm {
        render_channel_command_confirm_popup(frame, area, pending, state.channel_command_confirm_focus);
    }
    // The OTP popups sit above the file offer, same tier `handle_key` gives
    // them (below only an identity review).
    if let Some(pending) = &state.otp_generate_confirm {
        render_otp_generate_popup(frame, area, pending, state.otp_generate_focus);
    }
    if let Some(pending) = state.otp_size_input_open() {
        render_otp_size_popup(frame, area, pending, state);
    }
    if let Some(progress) = state.otp_keygen_open() {
        render_otp_keygen_popup(frame, area, progress);
    }
    if let Some(invite) = state.otp_invite_open() {
        render_otp_invite_popup(frame, area, invite, state.otp_invite_focus);
    }
    // Drawn just below the identity review, for the same reason it is
    // checked just below it in `handle_key`: impersonation still wins the
    // screen if both are somehow open for different peers at once.
    if let Some(review) = state.unknown_peer_review_open() {
        render_unknown_peer_popup(frame, area, review, state.unknown_peer_review_focus);
    }
    // Drawn last of all - takes priority over even the help overlay, same
    // as it does in `handle_key`, so it's always interactable regardless
    // of what else happened to be open when the mismatch arrived.
    if let Some(review) = state.identity_review_open() {
        render_identity_review_popup(frame, area, review, state.identity_review_focus);
    }
    // Outranks even the identity review, same as in `handle_key`: once
    // the account is deactivated nothing else this session could still do
    // matters, so this is always what's on screen from here on.
    if let Some(reason) = &state.account_deactivated {
        render_account_deactivated_modal(frame, area, reason);
    }
    // The permanent "on a call" indicator (`docs/SPEC.md` "Live voice
    // calls") is drawn in the same top-right corner the status notice
    // uses, just above it - unlike that notice it never auto-clears, so it
    // claims the corner first and pushes the notice down rather than the
    // other way around.
    // Both hang just below the header block rather than inside it - that
    // band is the selectors' own (`docs/SPEC.md` "Connected UI").
    let mut status_notice_y = super::channel::HEADER_ROW_HEIGHT;
    if let Some(call) = &state.call {
        status_notice_y = render_call_banner(frame, area, call, state.own_id);
    }
    // The status notice is a small non-modal banner, not a popup - drawn
    // absolutely last so a session outcome is always visible even over
    // everything above, without ever blocking input the way those do.
    if let Some((message, success)) = &state.status_notice {
        render_status_notice(frame, area, status_notice_y, message, *success);
    }
}

/// The Accept/Reject popup for one incoming file offer
/// (`docs/PROTOCOL.md`'s file transfer section) - visual shape mirrors
/// `render_identity_review_popup`, `Accept` focused by default (see
/// `Confirm`'s doc for why the default flips from the identity
/// review's `Reject`-first one).
fn render_file_offer_popup(
    frame: &mut Frame,
    area: Rect,
    offer: &PendingFileOffer,
    focus: Confirm,
) {
    let title = format!("Incoming file from {}", offer.from_name);
    let location = match &offer.channel {
        Some(name) => format!("#{name}"),
        None => "a private message".to_string(),
    };
    let message = format!(
        "{} is sending \"{}\" ({}) via {location}. Do you accept it?",
        offer.from_name,
        offer.filename,
        format_file_size(offer.size)
    );
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::ACCEPT_REJECT,
        focus: Some(focus),
        ..Default::default()
    }
    .render_message(frame, area, &message);
}

/// The Accept/Reject popup for one incoming call invite
/// (`docs/PROTOCOL.md` "Live voice calls") - visual shape mirrors
/// `render_file_offer_popup` exactly, same `Accept`-first default.
fn render_call_invite_popup(
    frame: &mut Frame,
    area: Rect,
    invite: &PendingCallInvite,
    focus: Confirm,
) {
    let title = format!("Voice call incoming from {}", invite.from_name);
    let location = match &invite.channel {
        Some(name) => format!("#{name}"),
        None => "a private message".to_string(),
    };
    let message = format!(
        "{} is calling via {location}. Do you accept?",
        invite.from_name
    );
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::ACCEPT_REJECT,
        focus: Some(focus),
        ..Default::default()
    }
    .render_message(frame, area, &message);
}

fn render_otp_generate_popup(
    frame: &mut Frame,
    area: Rect,
    pending: &PendingOtpGenerate,
    focus: Confirm,
) {
    let label = pending.purpose.label();
    let title = format!("Start an {label}");

    let retry_command = match pending.purpose {
        crate::crypto::otp::OtpPurpose::Live => "/otp",
        crate::crypto::otp::OtpPurpose::Mail => "/new-otp-mail-key",
    };
    let message = format!(
        "No {label} found for {}. Generate one now and share it automatically \
         over the encrypted pq_hybrid channel? Alternatively, run the 'otp' \
         command yourself and place the keys under ~/.aloo/otp/.keychain/, \
         then try {retry_command} again.",
        pending.peer_name
    );
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::ACCEPT_REJECT,
        focus: Some(focus),
        size: (64, 11),
        body_min_height: 6,
        ..Default::default()
    }
    .render_message(frame, area, &message);
}

fn render_otp_invite_popup(
    frame: &mut Frame,
    area: Rect,
    invite: &PendingOtpInvite,
    focus: Confirm,
) {
    let purpose = crate::crypto::otp::OtpPurpose::of_contact_name(&invite.contact_name);
    let label = purpose.label();
    let title = format!("{label} request from {}", invite.from_name);

    // The size, when there is one (a fresh-key invitation, not a bare
    // resume request), is exactly what the sender chose in their own size
    // prompt - shown so this decision isn't made sight-unseen (see
    // `PendingOtpInvite::pad_size_mb`'s doc).
    let size_clause = match invite.pad_size_mb {
        Some(mb) => format!(" using a fresh {mb}MB pad"),
        None => String::new(),
    };
    // The trailing clause differs by purpose too, not just the verb: a
    // live session genuinely layers the pad on top of pq_hybrid for every
    // message afterward, but a mail key never layers onto anything - it's
    // its own, separate delivery mechanism (`/mail`), so describing it as
    // "layered on top of pq_hybrid" would misdescribe what accepting it
    // actually does.
    let message = match purpose {
        crate::crypto::otp::OtpPurpose::Live => format!(
            "{} wants to start an OTP session with you{size_clause}, layered on top of \
             pq_hybrid for extra secrecy. Accept it?",
            invite.from_name
        ),
        crate::crypto::otp::OtpPurpose::Mail => format!(
            "{} wants to exchange an OTP mail key with you{size_clause}. Accept it?",
            invite.from_name
        ),
    };
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::ACCEPT_REJECT,
        focus: Some(focus),
        ..Default::default()
    }
    .render_message(frame, area, &message);
}

/// Follows `render_otp_generate_popup`'s Accept - asks how large a pad to
/// generate (MB per key, `crypto::otp::OTP_SIZE_MB_MIN..=OTP_SIZE_MB_MAX`),
/// same shape as `channel::render_channel_password_popup`'s text-entry
/// popup (a live input line, an error line only when there's an error to
/// show).
fn render_otp_size_popup(
    frame: &mut Frame,
    area: Rect,
    pending: &PendingOtpGenerate,
    state: &UiState,
) {
    let has_error = state.otp_size_error.is_some();
    let popup = centered_rect(64, if has_error { 8 } else { 7 }, area);
    let block = Block::default()
        .title(format!(
            "{} pad size for {} (MB per key)",
            pending.purpose.label(),
            pending.peer_name
        ))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let mut constraints = vec![Constraint::Min(3), Constraint::Length(1)];
    if has_error {
        constraints.push(Constraint::Length(1));
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    // The estimate is the whole reason a ceiling is no longer imposed
    // here: any size can be delivered, but a large one takes real time and
    // that is the user's call to make knowingly rather than ours to refuse.
    let estimate = state
        .otp_size_text
        .parse::<u32>()
        .ok()
        .filter(|mb| crate::crypto::otp::otp_size_mb_in_range(*mb))
        .map(|mb| {
            format!(
                " {} MB per key is {} to send over the link once generated.",
                mb,
                crate::client::otp::transfer_estimate_text(mb)
            )
        })
        .unwrap_or_default();
    let message = format!(
        "Choose a size between {} and {} MB, then press Enter. \
         Esc cancels the whole session.{estimate}",
        crate::crypto::otp::OTP_SIZE_MB_MIN,
        crate::crypto::otp::OTP_SIZE_MB_MAX
    );
    frame.render_widget(
        Paragraph::new(message).wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );
    frame.render_widget(
        Paragraph::new(format!("> {}", state.otp_size_text)),
        rows[1],
    );
    if let Some(err) = &state.otp_size_error {
        frame.render_widget(
            Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)),
            rows[2],
        );
    }
}

/// How wide the keygen popup's progress bar is drawn, in cells.
const KEYGEN_BAR_CELLS: usize = 40;

/// Follows `render_otp_size_popup`'s Enter - the pad is now genuinely
/// being generated (`client::otp::confirm_generate`'s background task), so
/// this shows a live spinner and progress bar until it finishes.
///
/// Absorbs input without offering any action (see `handle_key`): there is
/// nothing to decide and nothing safe to cancel mid-generation. Its whole
/// job is to make a long wait legible - at the sizes now allowed, a pad can
/// take minutes, and a silent frozen screen is the failure mode this
/// replaces.
fn render_otp_keygen_popup(frame: &mut Frame, area: Rect, progress: &OtpKeygenProgress) {
    let popup = centered_rect(64, 8, area);
    let label = progress.purpose.label();
    let (title, what, reassurance) = match progress.phase {
        OtpPadPhase::Generating => (
            format!("Generating an {label} pad for {}", progress.peer_name),
            format!(
                "{}MB per key ({}MB of true randomness in total)",
                progress.size_mb,
                progress.size_mb as u64 * 2
            ),
            "Generating and sharing happen once - the pad is then reused for every message \
             with this contact until it runs out.",
        ),
        OtpPadPhase::Sending => (
            format!("Sending the {label} pad to {}", progress.peer_name),
            format!(
                "{}MB per key, both halves ({}MB over the link)",
                progress.size_mb,
                progress.size_mb as u64 * 2
            ),
            "They are asked to accept only once the whole pad has arrived and both sides \
             agree it matches - so their prompt appears when this finishes, not before.",
        ),
        OtpPadPhase::Receiving => (
            format!("Receiving an {label} pad from {}", progress.peer_name),
            format!(
                "{}MB per key, both halves ({}MB over the link)",
                progress.size_mb,
                progress.size_mb as u64 * 2
            ),
            "Nothing is installed yet. Once it has all arrived and matches what they sent, \
             you will be asked whether to accept it.",
        ),
    };
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // spinner + what is happening
            Constraint::Length(1), // bar
            Constraint::Min(1),    // reassurance
        ])
        .split(inner);

    let spinner = SPINNER_FRAMES[progress.frame % SPINNER_FRAMES.len()];
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{spinner} "),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(what),
        ]))
        .wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );

    let filled = (progress.fraction() * KEYGEN_BAR_CELLS as f64).round() as usize;
    let filled = filled.min(KEYGEN_BAR_CELLS);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("\u{2588}".repeat(filled), Style::default().fg(Color::Green)),
            Span::styled(
                "\u{2591}".repeat(KEYGEN_BAR_CELLS - filled),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(format!("  {}%", progress.percent())),
        ])),
        rows[1],
    );

    frame.render_widget(
        Paragraph::new(reassurance)
            .style(Style::default().fg(Color::DarkGray))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        rows[2],
    );
}

/// A small, non-modal one-line banner in the top-right corner reporting the
/// most recent OTP session outcome (green on success, red otherwise) - see
/// `UiState::status_notice`'s field doc for why this exists as its own
/// always-rendered surface. `y` is where the permanent call banner (drawn
/// just above this one, when there is a call) leaves off -
/// `render_call_banner`'s return value, or `1` when there is none.
fn render_status_notice(frame: &mut Frame, area: Rect, y: u16, message: &str, success: bool) {
    let width = (message.len() as u16 + 4).min(area.width);
    let rect = Rect {
        x: area.width.saturating_sub(width),
        y,
        width,
        height: 3,
    };
    let color = if success { Color::Green } else { Color::Red };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    frame.render_widget(
        Paragraph::new(message)
            .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        inner,
    );
}

/// The permanent, always-visible top-right "on a call" indicator
/// (`docs/SPEC.md` "Live voice calls") - unlike `render_status_notice`,
/// never auto-clears while `state.call` is `Some`. Always red regardless of
/// mute state: the red means "a call is live", not "something went wrong"
/// the way `render_status_notice`'s red does. Returns the height it
/// occupied (including its top margin) so `render` can draw the status
/// notice just below it instead of overlapping.
/// How wide one voice meter is, in cells - `LEVEL_BAR_CELLS` filled
/// blocks at 100, none at 0. Narrow on purpose: it sits at the end of a
/// roster row that already carries a name and up to three labels.
const LEVEL_BAR_CELLS: usize = 10;

/// One participant's live voice meter (`CallMember::level`) as a bar of
/// block characters - the "audio bar with the voice levels from the user"
/// `docs/SPEC.md` "Live voice calls" puts next to every roster row.
fn level_bar(level: u8) -> String {
    let filled = (level as usize * LEVEL_BAR_CELLS)
        .div_ceil(100)
        .min(LEVEL_BAR_CELLS);
    format!(
        "{}{}",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(LEVEL_BAR_CELLS - filled)
    )
}

/// The `> ` / `  ` selection marker every roster row opens with.
const CALL_MARKER_COL: usize = 2;

/// The gap between the name column and the label column. Four columns
/// rather than one: on the row whose name fills the whole column the two
/// would otherwise touch, and a long nickname running straight into
/// `IN CALL` reads as one string rather than as two columns.
const CALL_COL_GAP: usize = 4;

/// The narrowest gap ever left between the labels and the voice meter that
/// ends the row. Wider than `CALL_COL_GAP` because the meter is right
/// aligned and the labels are not: on the widest row in the list these two
/// columns are all that separates them, and one space there reads as one
/// run of text rather than two columns.
const CALL_LEVEL_GAP: usize = 2;

/// A call roster's two measured column widths - the third column, the
/// voice meter, is `LEVEL_BAR_CELLS` wide and always sits flush against
/// the modal's right edge.
///
/// Both are measured from the roster actually on screen rather than fixed
/// at the widest they could ever be (a 10-character nickname carrying both
/// ` (you)` and ` (host)`, a `REJECTED MUTED` label pair). A call is
/// usually two or three people with short names and one label each, so
/// the worst case is mostly blank columns down the middle of every row.
/// Measuring makes the modal as narrow as the call in it allows, and -
/// because both figures are taken across the *whole* list, not per row -
/// keeps all three columns lined up down it (`docs/SPEC.md` "Live voice
/// calls").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallColumns {
    pub name: usize,
    pub label: usize,
}

impl CallColumns {
    /// Measures both columns across `call`'s whole roster.
    pub fn measure(call: &CallUiState, own_id: Option<UserId>) -> Self {
        let name = call
            .members
            .iter()
            .map(|m| display_width(&call_member_name(m, call.host, own_id)) as usize)
            .max()
            .unwrap_or(0);
        let label = call
            .members
            .iter()
            .map(|m| {
                call_member_labels(m)
                    .iter()
                    .map(|s| display_width(&s.content) as usize)
                    .sum()
            })
            .max()
            .unwrap_or(0);
        Self { name, label }
    }

    /// How many columns one roster row needs end to end: marker, name,
    /// gap, labels, the gap before the meter, and the meter itself.
    pub fn row_width(self) -> usize {
        CALL_MARKER_COL + self.name + CALL_COL_GAP + self.label + CALL_LEVEL_GAP + LEVEL_BAR_CELLS
    }
}

/// The roster labels one member's row carries, already coloured
/// (`docs/SPEC.md` "Live voice calls"): `IN CALL` green / `INVITED`
/// yellow / `REJECTED` grey for where they stand, then `MUTED` red if
/// they cannot currently be heard - whether they muted themselves or the
/// host did. The host is not labelled here - their row is named
/// `<nickname> (host)` instead (`call_member_name`).
fn call_member_labels(member: &CallMember) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let (text, color) = match member.state {
        CallMemberState::InCall => ("IN CALL", Color::Green),
        CallMemberState::Invited => ("INVITED", Color::Yellow),
        CallMemberState::Rejected => ("REJECTED", Color::DarkGray),
    };
    spans.push(Span::styled(text, Style::default().fg(color)));
    // One label for either kind of silence - the roster answers "can this
    // person be heard right now", and both answers are no. Which of the
    // two it is only matters for who may lift it (`CallMember::host_muted`
    // vs `self_muted`), not for reading the row.
    if member.host_muted || member.self_muted {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            "MUTED",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    spans
}

/// How a roster row names one member: their nickname, marked `(you)` for
/// ourselves and `(host)` for whoever started the call - the host carries
/// no separate label of its own (`docs/SPEC.md` "Live voice calls").
fn call_member_name(member: &CallMember, host: UserId, own_id: Option<UserId>) -> String {
    let mut name = member.name.clone();
    if Some(member.id) == own_id {
        name.push_str(" (you)");
    }
    if member.id == host {
        name.push_str(" (host)");
    }
    name
}

/// Pads `spans` out to `width` display columns with one trailing blank
/// span, leaving it alone if it is already at least that wide - what keeps
/// a column of variable-length labels from shifting whatever follows it.
fn pad_to(spans: &mut Vec<Span<'static>>, width: usize) {
    let used: usize = spans
        .iter()
        .map(|s| display_width(&s.content) as usize)
        .sum();
    if used < width {
        spans.push(Span::raw(" ".repeat(width - used)));
    }
}

/// The call modal (`docs/SPEC.md` "Live voice calls"): live duration on
/// top in yellow, the scrollable roster below it - host first, everyone
/// else after - each row labelled and metered, and the END CALL button at
/// the bottom.
///
/// `area` is the space the modal may use, not the modal: it sizes itself
/// to the call in it (`call_modal_rect`) and centers in what it was given,
/// so a three-person call on a wide terminal is a small box rather than a
/// fixed slab of mostly-blank columns.
pub(crate) fn render_call_modal(
    frame: &mut Frame,
    area: Rect,
    state: &UiState,
    call: &CallUiState,
) {
    let title = match &call.channel {
        Some(name) => format!("Call \u{2014} #{name}"),
        None => "Call".to_string(),
    };
    let columns = CallColumns::measure(call, state.own_id);
    let hint = call_modal_hint(call, state.own_id);
    let area = call_modal_rect(call, &title, &hint, columns, area);
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let inner = block.inner(area);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(3),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            call.duration_label(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )))
        .alignment(ratatui::layout::Alignment::Center),
        rows[0],
    );

    // The roster scrolls rather than truncating - the selection is always
    // kept in view, the same "follow the cursor" scrolling the message log
    // and the /channels directory already use.
    let visible = rows[1].height as usize;
    let scroll = if visible == 0 || call.selected < visible {
        0
    } else {
        call.selected + 1 - visible
    };
    let lines: Vec<Line> = call
        .members
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(idx, member)| {
            let mut spans = vec![Span::styled(
                if idx == call.selected { "> " } else { "  " },
                Style::default().fg(Color::Yellow),
            )];
            let is_us = Some(member.id) == state.own_id;
            let name = call_member_name(member, call.host, state.own_id);
            let name_col = columns.name;
            spans.push(Span::styled(
                format!("{name:<name_col$}"),
                if idx == call.selected {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ));
            spans.push(Span::raw(" ".repeat(CALL_COL_GAP)));
            let mut labels = call_member_labels(member);
            pad_to(&mut labels, columns.label);
            spans.extend(labels);
            // Our own row meters what we are actually sending: muting
            // ourselves (`m` on our own row) stops that at the source, so
            // the bar must read empty rather than keep twitching along
            // with a microphone nobody hears.
            let level = if is_us && call.muted { 0 } else { member.level };
            // Flush right against the modal's inner edge, whatever the
            // two measured columns before it came to - so the meters read
            // as one column of their own rather than tracking the ragged
            // right edge of the labels.
            let used = CALL_MARKER_COL + name_col + CALL_COL_GAP + columns.label;
            let gap = (inner.width as usize)
                .saturating_sub(used + LEVEL_BAR_CELLS)
                .max(CALL_LEVEL_GAP);
            spans.push(Span::raw(" ".repeat(gap)));
            spans.push(Span::styled(
                level_bar(level),
                Style::default().fg(Color::Green),
            ));
            Line::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), rows[1]);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            hint,
            Style::default().fg(Color::DarkGray),
        ))),
        rows[2],
    );
    render_popup_button(frame, rows[3], CALL_END_BUTTON_WIDTH, "END CALL", true);

    if let Some(picker) = &call.invite_picker {
        render_call_invite_picker(frame, area, picker);
    }
    if let Some(focus) = call.end_confirm {
        render_end_call_confirm_popup(frame, area, focus);
    }
}

/// What END CALL asks before it leaves a call
/// (`CallUiState::end_confirm`). Drawn over the modal it was pressed on,
/// like the invite picker, so the roster it is about stays in view.
fn render_end_call_confirm_popup(frame: &mut Frame, area: Rect, focus: Confirm) {
    // The one confirmation whose question is centered rather than
    // left-aligned, so it renders its own body rather than using
    // `render_message`.
    ConfirmPopup {
        title: END_CALL_CONFIRM_TITLE,
        labels: ConfirmLabels::new("END CALL", "Cancel"),
        focus: Some(focus),
        size: (48, 6),
        border_style: Some(Style::default().fg(Color::Red)),
        body_min_height: 1,
        ..Default::default()
    }
    .render(frame, area, |frame, body| {
        frame.render_widget(
            Paragraph::new(END_CALL_CONFIRM_QUESTION)
                .wrap(ratatui::widgets::Wrap { trim: true })
                .alignment(ratatui::layout::Alignment::Center),
            body,
        );
    });
}

/// The confirmation's title and question, named so a test reads the same
/// strings the popup draws.
pub const END_CALL_CONFIRM_TITLE: &str = "Leave this call?";
pub const END_CALL_CONFIRM_QUESTION: &str = "Leaving is immediate and cannot be undone.";

/// The width of the modal's own END CALL button, which is also a floor on
/// how narrow the modal may get - a button clipped in half reads as a
/// rendering fault rather than as a small window.
const CALL_END_BUTTON_WIDTH: u16 = 14;

/// The key line under the roster. The host's two extra keys are only shown
/// to the host, since only they do anything for anyone else.
fn call_modal_hint(call: &CallUiState, own_id: Option<UserId>) -> String {
    let host_hint = if call.we_are_host(own_id) {
        "  m: mute  i: invite"
    } else {
        ""
    };
    format!("Esc: minimize{host_hint}")
}

/// The rectangle the call modal actually occupies inside `area`: as narrow
/// and as short as its own contents allow, centered, and never larger than
/// what it was given.
///
/// Width is the widest thing that has to fit on one line - a roster row
/// (`CallColumns::row_width`), the key hint, the title in its border, or
/// the END CALL button. Height is one row per participant plus the fixed
/// furniture around them (duration, hint, button, borders), so a two-person
/// call is a small box and a twelve-person one grows until it runs out of
/// screen, at which point the roster scrolls inside it as it already did.
pub(crate) fn call_modal_rect(
    call: &CallUiState,
    title: &str,
    hint: &str,
    columns: CallColumns,
    area: Rect,
) -> Rect {
    let content = columns
        .row_width()
        .max(display_width(hint) as usize)
        .max(display_width(title) as usize)
        .max(CALL_END_BUTTON_WIDTH as usize);
    let width = (content as u16).saturating_add(2);
    // 1 duration + roster + 1 hint + 3 button + 2 borders. The roster
    // floors at one row: a modal with no room for even one participant
    // would be a border around nothing.
    let height = (call.members.len().max(1) as u16).saturating_add(7);
    centered_rect(width, height, area)
}

/// The host-only invite picker, drawn over the modal it was opened from.
fn render_call_invite_picker(frame: &mut Frame, area: Rect, picker: &CallInvitePicker) {
    let height = (picker.candidates.len() as u16 + 2).clamp(3, area.height);
    let popup = centered_rect(40, height, area);
    let block = Block::default()
        .title("Invite to call")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let visible = inner.height as usize;
    let scroll = if visible == 0 || picker.selected < visible {
        0
    } else {
        picker.selected + 1 - visible
    };
    let lines: Vec<Line> = picker
        .candidates
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(idx, (_, name))| {
            let style = if idx == picker.selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Line::from(Span::styled(format!("  {name}"), style))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The `/call` confirmation (`docs/SPEC.md` "Live voice calls") - nothing
/// is rung until it is answered, and the number of people it is about to
/// ring is spelled out in yellow.
fn render_call_confirm_popup(
    frame: &mut Frame,
    area: Rect,
    pending: &PendingCallConfirm,
    focus: Confirm,
) {
    let where_clause = match &pending.target {
        CallTarget::Channel { channel } => format!("in #{channel}"),
        CallTarget::Direct { .. } => "in this private room".to_string(),
    };
    let plural = if pending.invitee_count == 1 {
        "user"
    } else {
        "users"
    };
    // The invitee count is highlighted, so this is a styled `Line` rather
    // than the plain message `render_message` takes.
    ConfirmPopup {
        title: "Start a call",
        labels: ConfirmLabels::new("Call", "Cancel"),
        focus: Some(focus),
        size: (60, 9),
        ..Default::default()
    }
    .render(frame, area, |frame, body| {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::raw("This will invite "),
                Span::styled(
                    format!("{} {plural}", pending.invitee_count),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(" {where_clause} to a live call. Go ahead?")),
            ]))
            .wrap(ratatui::widgets::Wrap { trim: true }),
            body,
        );
    });
}

/// `/delete-channel`/`/assign-admin`'s confirmation - a red-bordered
/// mirror of `render_call_confirm_popup`, generic over `pending.question`
/// rather than building the sentence itself, since the two commands ask
/// two different questions over the same Confirm/Cancel shape.
fn render_channel_command_confirm_popup(
    frame: &mut Frame,
    area: Rect,
    pending: &ChannelCommandConfirm,
    focus: Confirm,
) {
    ConfirmPopup {
        title: pending.title,
        labels: ConfirmLabels::CONFIRM_CANCEL,
        focus: Some(focus),
        size: (60, 9),
        border_style: Some(Style::default().fg(Color::Red)),
        ..Default::default()
    }
    .render_message(frame, area, pending.question.as_str());
}

fn render_call_banner(
    frame: &mut Frame,
    area: Rect,
    call: &CallUiState,
    own_id: Option<UserId>,
) -> u16 {
    let where_clause = match &call.channel {
        Some(name) => format!(" in #{name}"),
        None => String::new(),
    };
    let mute_clause = if call.muted { " \u{1F507} muted" } else { "" };
    // The plain record-circle glyph, not a multicolour emoji - its colour
    // is entirely the `Style` painted below, never fixed in the character.
    let message = format!(
        "\u{23FA} On a call{where_clause} ({} connected){mute_clause}",
        call.connected_count(own_id)
    );
    let width = (message.chars().count() as u16 + 4).min(area.width);
    let rect = Rect {
        x: area.width.saturating_sub(width),
        y: super::channel::HEADER_ROW_HEIGHT,
        width,
        height: 3,
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    frame.render_widget(
        Paragraph::new(message)
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        inner,
    );
    rect.y + rect.height
}

/// Renders the label the UI shows on a finalized voice message block, e.g.
/// `voice (12sec)`. A non-zero duration under one second still rounds up
/// to `1sec` so a short clip is never shown as `0sec`.
pub fn format_duration_label(duration_ms: u32) -> String {
    let secs = if duration_ms == 0 {
        0
    } else {
        (duration_ms as f64 / 1000.0).ceil() as u32
    };
    format!("voice ({secs}sec)")
}

/// Renders a byte count as a short human-readable size, e.g. `842 B`,
/// `128.0 KB`, `4.2 MB`, `1.10 GB` - used only for the file-offer popup and
/// in-progress log rows, so this doesn't need to handle anything past GB.
pub(crate) fn format_file_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{bytes} B")
    } else if b < MB {
        format!("{:.1} KB", b / KB)
    } else if b < GB {
        format!("{:.1} MB", b / MB)
    } else {
        format!("{:.2} GB", b / GB)
    }
}

/// A fixed-width ASCII progress bar, e.g. `[####------]`, for an
/// in-progress file transfer's log row.
fn progress_bar(pct: u32) -> String {
    const WIDTH: u32 = 10;
    let filled = (pct.min(100) * WIDTH / 100) as usize;
    format!(
        "[{}{}]",
        "#".repeat(filled),
        "-".repeat(WIDTH as usize - filled)
    )
}

/// The Accept/Reject popup for one peer's identity mismatch
/// (`docs/PROTOCOL.md` §12) - auto-opened by `push_identity_review`,
/// re-openable via Enter on a red sidebar entry. Visual style matches the
/// help popup (bordered box, centered) and the connect popup's single
/// button (`ui_connect_popup::render_connect_button`): a plain border, a
/// solid-fill interior when focused.
fn render_identity_review_popup(
    frame: &mut Frame,
    area: Rect,
    review: &IdentityReview,
    focus: Confirm,
) {
    let title = format!("Identity review: {}", review.nickname);
    // Taller than the other single-button popups (64x9): the message now
    // also carries the last-known vs. new address/device id
    // (docs/PROTOCOL.md §12.7), several lines longer than the original
    // one-line fingerprint warning.
    let mut lines = vec![Line::from(review.message.as_str())];
    if review.status == IdentityStatus::Rejected {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "(previously rejected - messaging with them is blocked)",
            Style::default().fg(Color::Red),
        )));
    }
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::ACCEPT_REJECT,
        focus: Some(focus),
        size: (70, 13),
        ..Default::default()
    }
    .render(frame, area, |frame, body| {
        frame.render_widget(
            Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: true }),
            body,
        );
    });
}

/// The Yes/No popup for a `direct_punch_to` nickname with no pinned key
/// that just sent proof of an identity (`docs/PROTOCOL.md` §7.1.5) -
/// opened by `push_unknown_peer_review`. Same visual style as
/// `render_identity_review_popup`; the wording switches on `review.stage`,
/// since this is two sequential questions about the same review rather
/// than a case-specific message the caller pre-formats.
fn render_unknown_peer_popup(
    frame: &mut Frame,
    area: Rect,
    review: &UnknownPeerReview,
    focus: Confirm,
) {
    let title = format!("Unknown direct connection: {}", review.requested_nickname);
    let message = match &review.stage {
        UnknownPeerStage::Initial => format!(
            "A connection was received directly to your public ip from an unknown \
             nickname (\"{}\"). Do you want to check which of your local keys \
             matches this request?",
            review.requested_nickname
        ),
        UnknownPeerStage::ConfirmMatch {
            matched_nickname, ..
        } => format!(
            "I found that the request from {} matches your local key for {}. \
             Do you want to use {}'s key to talk to {}?",
            review.requested_nickname, matched_nickname, matched_nickname, review.requested_nickname
        ),
    };
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::YES_NO,
        focus: Some(focus),
        size: (70, 11),
        ..Default::default()
    }
    .render_message(frame, area, &message);
}

/// The `<nickname><separator> ` a user-content row opens with. On a row
/// whose delivery is tracked the separator is `DELIVERY_ARROW`, coloured
/// by how far the message has got (`docs/SPEC.md` "Delivery
/// acknowledgments"); on every other row it is the plain `:` this app has
/// always used. Shared by text, voice and file rows so one message kind
/// can never disagree with another about where the indicator lives.
fn sender_prefix(entry: &LogEntry) -> Vec<Span<'static>> {
    match entry.delivery_status() {
        Some(status) => vec![
            Span::raw(format!("{} ", entry.from_name)),
            Span::styled(
                DELIVERY_ARROW,
                Style::default()
                    .fg(status.color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ],
        None => vec![Span::raw(format!("{}{PLAIN_SEPARATOR} ", entry.from_name))],
    }
}

/// Every `http://`/`https://` URL in `text`, as byte ranges - shared by
/// message rendering (underlines each one) and Ctrl+O (opens one). A link
/// is a whitespace-delimited token starting with one of those schemes, so
/// no regex is needed: `split_whitespace`'s tokens are relocated by
/// scanning forward from where the last one ended, since it doesn't hand
/// back byte offsets itself.
pub(crate) fn find_urls(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut from = 0;
    for token in text.split_whitespace() {
        let Some(rel) = text[from..].find(token) else {
            continue;
        };
        let start = from + rel;
        let end = start + token.len();
        from = end;
        if token.starts_with("http://") || token.starts_with("https://") {
            out.push(start..end);
        }
    }
    out
}

/// Appends `text` to `spans`, with every link `find_urls` finds in it
/// rendered blue and underlined instead of the surrounding plain text.
fn push_text_with_links(spans: &mut Vec<Span<'static>>, text: &str) {
    let mut pos = 0;
    for range in find_urls(text) {
        if range.start > pos {
            spans.push(Span::raw(text[pos..range.start].to_string()));
        }
        spans.push(Span::styled(
            text[range.clone()].to_string(),
            Style::default().fg(Color::Blue).add_modifier(Modifier::UNDERLINED),
        ));
        pos = range.end;
    }
    if pos < text.len() {
        spans.push(Span::raw(text[pos..].to_string()));
    }
}

pub(crate) fn render_messages(
    frame: &mut Frame,
    area: Rect,
    state: &UiState,
    dm_peer: Option<UserId>,
) {
    let title = if let Some(id) = dm_peer {
        state
            .known_users
            .get(&id)
            // The same tag they carry in the user list and on the DM
            // selector (`UiState::encryption_tag`), so one person is not
            // labelled two different ways on one screen.
            .map(|u| {
                format!(
                    "Private: {} {}",
                    u.name,
                    state.encryption_tag(id, u.key_mode)
                )
            })
            .unwrap_or_else(|| "Private".to_string())
    } else {
        // The channel's own name, `🔒`-prefixed for a private one, the
        // same convention the (unbordered) header selector already uses
        // (`channel_label`) - plus its admin, when it has one (never
        // `the-hall`, whose `admin` is always `None`).
        match state.channels.get(state.selected_channel) {
            Some(c) => {
                let base = channel_label(c.kind, &c.name);
                match &c.admin {
                    Some(admin) => format!("{base} (admin: {admin})"),
                    None => base,
                }
            }
            None => "Messages".to_string(),
        }
    };
    let border_style = focus_border_style(state.focus == Focus::Messages);
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let log: &[LogEntry] = if let Some(peer) = dm_peer {
        state
            .private_rooms
            .get(&peer)
            .map(|r| r.log.as_slice())
            .unwrap_or(&[])
    } else {
        state
            .channels
            .get(state.selected_channel)
            .map(|c| c.log.as_slice())
            .unwrap_or(&[])
    };

    // An empty conversation with no server behind it is a conversation
    // waiting on a punch, not an idle one: nothing is going to arrive from
    // a roster or a presence notice to explain the silence, so it is said
    // here (see `channel::WAITING_FOR_DIRECT_PEERS`). Only while the peer
    // is genuinely not reachable yet - once a link is up, an empty log
    // means exactly what it always did.
    if log.is_empty() && state.serverless {
        let reachable = match dm_peer {
            Some(peer) => state.link_status_of(peer) == crate::client::p2p::LinkStatus::Active,
            None => state
                .channels
                .get(state.selected_channel)
                .is_some_and(|c| !c.members.is_empty()),
        };
        if !reachable {
            frame.render_widget(
                Paragraph::new(super::channel::WAITING_FOR_DIRECT_PEERS)
                    .style(Style::default().fg(Color::DarkGray))
                    .wrap(ratatui::widgets::Wrap { trim: true }),
                inner,
            );
            return;
        }
    }

    let items: Vec<ListItem> = log
        .iter()
        .map(|entry| {
            // One `LogEntry` is always exactly one selectable `ListItem`,
            // however many visual rows its content takes - a multiline
            // paste (`MessageBody::Text` containing `\n`) renders as
            // several rows of the *same* message, not several messages:
            // Up/Down still moves one log entry at a time (`ListState`
            // selects by item, not by rendered row) and `i` still opens
            // the details of the one entry under the cursor regardless of
            // which of its rows that is.
            let mut lines: Vec<Line<'static>> = match &entry.body {
                MessageBody::Text(text) => {
                    let mut physical_lines: Vec<Line<'static>> = text
                        .split('\n')
                        .map(|part| {
                            let mut spans = Vec::new();
                            push_text_with_links(&mut spans, part);
                            Line::from(spans)
                        })
                        .collect();
                    // The sender prefix belongs on the first row only.
                    if let Some(first) = physical_lines.first_mut() {
                        let mut prefix = sender_prefix(entry);
                        prefix.append(&mut first.spans);
                        first.spans = prefix;
                    }
                    physical_lines
                }
                MessageBody::Voice { duration_ms, .. } => {
                    let label = format_duration_label(*duration_ms);
                    let mut spans = sender_prefix(entry);
                    spans.push(Span::styled(
                        format!("\u{1F534} {label}"),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ));
                    // A received voice message nobody has actually heard
                    // yet - never autoplayed (muted, trust-gated, or this
                    // wasn't the focused channel/DM when it arrived) and
                    // never manually replayed either (`handle_messages_key`'s
                    // Enter, which is the only other place `listened` is
                    // ever set). Right-padded to the row's own width so the
                    // marker lands flush with the right edge.
                    if !entry.outgoing && !entry.listened {
                        const NOT_LISTENED: &str = "not listened";
                        let used: u16 = spans.iter().map(|s| display_width(s.content.as_ref())).sum();
                        let marker_width = display_width(NOT_LISTENED);
                        let pad = inner.width.saturating_sub(used + marker_width);
                        if pad > 0 {
                            spans.push(Span::raw(" ".repeat(pad as usize)));
                        }
                        spans.push(Span::styled(
                            NOT_LISTENED,
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        ));
                    }
                    vec![Line::from(spans)]
                }
                // A `resume_from_log` history row nobody has asked to hear
                // yet - dimmed rather than the solid red `Voice` circle,
                // to read at a glance as "not loaded" rather than "not
                // listened" (no marker either: `listened` is always `true`
                // here, see `export::parse_log_entry`'s doc for why).
                MessageBody::VoiceOnDisk { duration_ms, wav_path } => {
                    let label = format_duration_label(*duration_ms);
                    let mut spans = sender_prefix(entry);
                    let hint = if wav_path.is_some() {
                        "(Enter to load)"
                    } else {
                        "(no audio saved)"
                    };
                    spans.push(Span::styled(
                        format!("\u{25CB} {label} {hint}"),
                        Style::default().fg(Color::DarkGray),
                    ));
                    vec![Line::from(spans)]
                }
                MessageBody::VoiceStreaming { .. } => {
                    let dot = if state.blink_on { "\u{23FA}" } else { " " };
                    let mut spans = sender_prefix(entry);
                    spans.push(Span::styled(
                        format!("{dot} voice (streaming...)"),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ));
                    vec![Line::from(spans)]
                }
                MessageBody::File {
                    filename,
                    total,
                    status,
                    ..
                } => {
                    let mut spans = sender_prefix(entry);
                    match status {
                        FileTransferStatus::Pending => spans.push(Span::styled(
                            format!("\u{1F4CE} {filename} (waiting for accept...)"),
                            Style::default().fg(Color::Cyan),
                        )),
                        FileTransferStatus::InProgress { bytes } => {
                            let pct = if *total == 0 {
                                100
                            } else {
                                ((*bytes as f64 / *total as f64) * 100.0).clamp(0.0, 100.0) as u32
                            };
                            spans.push(Span::styled(
                                format!("\u{1F4CE} {filename} {} {pct}%", progress_bar(pct)),
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ));
                        }
                        FileTransferStatus::Completed => spans.push(Span::styled(
                            format!("\u{1F4CE} {filename}"),
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        )),
                        FileTransferStatus::Received { .. } => spans.push(Span::styled(
                            format!("\u{1F4CE} {filename} (Enter: preview)"),
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        )),
                        FileTransferStatus::Rejected => spans.push(Span::styled(
                            format!("\u{1F4CE} {filename} (rejected)"),
                            Style::default().fg(Color::DarkGray),
                        )),
                        FileTransferStatus::Failed => spans.push(Span::styled(
                            format!("\u{1F4CE} {filename} (failed)"),
                            Style::default().fg(Color::Red),
                        )),
                    }
                    vec![Line::from(spans)]
                }
                MessageBody::System(text) => vec![Line::from(Span::styled(
                    text.clone(),
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                ))],
                MessageBody::Presence(text) => vec![Line::from(Span::styled(
                    text.clone(),
                    Style::default().fg(Color::Yellow),
                ))],
            };
            // A message that reached nobody is struck through: it is not
            // waiting on anybody's acknowledgement, because it was never
            // addressed to anybody (`docs/SPEC.md` "Delivery
            // acknowledgments"). Applied before the pad prefix below,
            // so a combining overlay never lands on that emoji. Every row
            // of a multiline message is struck through together, since
            // they are all the one message that reached nobody.
            if entry.reached_nobody() {
                for line in lines.iter_mut() {
                    for span in line.spans.iter_mut() {
                        span.content = strike_through(&span.content).into();
                    }
                }
            }
            // The tag reflects what actually protected THIS message
            // (`entry.crypto`, stamped once at push time by
            // `UiState::message_crypto`), never the room's current live
            // OTP session state - a message sent under OTP keeps its key
            // icon in the log even after `/endotp` ends the session, since
            // ending the session changes nothing about how that message
            // was actually encrypted. Only the first row carries it - one
            // tag per message, not one per row.
            if matches!(entry.crypto, Some(MessageCrypto::Otp { .. }))
                && !matches!(
                    entry.body,
                    MessageBody::System(_) | MessageBody::Presence(_)
                )
            {
                if let Some(first) = lines.first_mut() {
                    first.spans.insert(0, Span::raw(format!("{OTP_ICON} ")));
                }
            }
            // A row whose async send turned out to have failed
            // (`UiState::mark_dm_message_failed`) is shown in red, same as
            // every other "this needs your attention" red the app already
            // uses - a failed send must never look identical to a
            // delivered one. Every row of a multiline message gets it, so
            // a failed send is never half-red.
            if entry.failed {
                for line in lines.iter_mut() {
                    line.style = Style::default().fg(Color::Red);
                }
            }
            ListItem::new(Text::from(lines))
        })
        .collect();

    // `highlight_style` only shows while this pane actually has focus
    // (matching the old per-item behavior); `ListState` is what makes the
    // log genuinely scrollable - ratatui computes whatever offset is
    // needed to keep `message_selected` on screen, rather than always
    // starting the view at the oldest message and cutting off anything
    // that doesn't fit.
    let highlight_style = if state.focus == Focus::Messages {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    // The rightmost column is given up to the scrollbar, but only while the
    // log actually overflows - an unscrollable pane shouldn't lose a column
    // of text to a bar that would be full-height anyway.
    let visible = inner.height as usize;
    // Cached for `UiState::history_chunk_size` - key-handling code (Up/
    // PageUp/Home, tab switches) never sees a `Frame`/`Rect` of its own.
    state.last_messages_area_height.store(inner.height, Ordering::Relaxed);
    let overflows = log.len() > visible && inner.width > 1;
    let list_area = if overflows {
        Rect {
            width: inner.width - 1,
            ..inner
        }
    } else {
        inner
    };

    let list = List::new(items).highlight_style(highlight_style);
    let mut list_state = ListState::default();
    if !log.is_empty() {
        list_state.select(Some(state.message_selected.min(log.len() - 1)));
    }
    frame.render_stateful_widget(list, list_area, &mut list_state);

    if overflows {
        // Read after the list has rendered: the offset that keeps the
        // selection on screen is ratatui's to compute, so the thumb tracks
        // the viewport itself rather than a guess made from the selection.
        // ratatui counts `content_length` in scroll *positions*, not items:
        // the last one shows the final viewport-worth of entries, so with
        // `log.len()` passed straight in the thumb would stop a step short
        // of the bottom of its track on the newest message.
        let mut scrollbar_state = ScrollbarState::new(log.len() - visible + 1)
            .viewport_content_length(visible)
            .position(list_state.offset());
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_symbol(Some("\u{2591}"))
                .thumb_symbol("\u{2588}")
                .track_style(Style::default().fg(Color::DarkGray))
                .thumb_style(Style::default().fg(Color::Gray)),
            Rect {
                x: inner.right() - 1,
                width: 1,
                ..inner
            },
            &mut scrollbar_state,
        );
    }
}

/// Packs a `Rect` into one `u64` (16 bits per field, `x`/`y`/`width`/
/// `height` from the high end down) - what lets a rendered position be
/// recorded in a plain `AtomicU64` field (`Sync`-friendly, unlike `Cell`;
/// see `UiState::last_input_bar_area`'s doc) rather than four separate
/// `AtomicU16`s.
pub(crate) fn pack_rect(r: Rect) -> u64 {
    ((r.x as u64) << 48) | ((r.y as u64) << 32) | ((r.width as u64) << 16) | (r.height as u64)
}

/// `pack_rect`'s inverse.
pub(crate) fn unpack_rect(v: u64) -> Rect {
    Rect {
        x: (v >> 48) as u16,
        y: (v >> 32) as u16,
        width: (v >> 16) as u16,
        height: v as u16,
    }
}

/// Whether `(x, y)` falls inside `r` - `u64::MAX`'s unpacked sentinel
/// (`{65535, 65535, 65535, 65535}`, before any frame has stored a real
/// area, or one this session's terminal will never actually be) contains
/// nothing a real click can ever land on, so callers need no separate
/// "not drawn yet" check.
pub(crate) fn rect_contains(r: Rect, x: u16, y: u16) -> bool {
    x >= r.x && x < r.x.saturating_add(r.width) && y >= r.y && y < r.y.saturating_add(r.height)
}

pub(crate) fn render_input_bar(frame: &mut Frame, area: Rect, state: &UiState) {
    state.last_input_bar_area.store(pack_rect(area), Ordering::Relaxed);
    let dm_peer_offline = state.active_dm_peer_offline();
    let dm_peer_trust_gated = state.active_dm_peer_trust_gated();
    let title = if state.recording {
        "Recording..."
    } else {
        "Message"
    };
    let border_style = if state.recording {
        Style::default().fg(Color::Red)
    } else {
        focus_border_style(state.focus == Focus::Input)
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);
    let inner = block.inner(area);

    // A Pending/Rejected identity (docs/PROTOCOL.md §12) always replaces
    // whatever's in `input` with a clear, red notice - nothing typed there
    // can ever be submitted (`handle_input_key` refuses it outright). An
    // offline DM peer gets the same red placeholder only while `input` is
    // actually empty: typing is no longer blocked for that case alone
    // (`/endotp` must still be composable and submitted while a peer is
    // unreachable - `handle_input_key`'s doc), so the moment there's
    // something typed, show it rather than hiding it behind a fixed notice
    // the user would otherwise be typing blind past.
    // The pad marks the bar it is typed into, not just the rows it has
    // already protected: while a session is open, everything sent from
    // here goes under it (`docs/PROTOCOL.md` §16.2 - there is no way to
    // send that person a plain message meanwhile), and this says so at the
    // moment it matters rather than only afterwards. Shown even over the
    // placeholders below, since it is a fact about the room rather than
    // about what is currently typed.
    let pad_prefix = state
        .active_private_room
        .is_some_and(|peer| state.is_otp_active(peer))
        .then(|| format!("{OTP_ICON} "));

    let mut spans = if dm_peer_trust_gated {
        vec![Span::styled(
            "(identity not verified)",
            Style::default().fg(Color::Red),
        )]
    } else if dm_peer_offline && state.input.is_empty() {
        vec![Span::styled(
            "(user offline)",
            Style::default().fg(Color::Red),
        )]
    } else {
        vec![Span::raw(state.input.as_str())]
    };
    if let Some(prefix) = &pad_prefix {
        spans.insert(
            0,
            Span::styled(prefix.clone(), Style::default().fg(OTP_TAG_COLOR)),
        );
    }
    if state.recording {
        let dot = if state.blink_on { "\u{23FA}" } else { " " };
        spans.push(Span::styled(
            format!(" {dot} recording..."),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);

    // Only show a blinking cursor here when this bar is actually focused,
    // nothing else (e.g. the join-channel popup) is drawn on top of it, and
    // there's actually text to edit (not one of the placeholders above).
    if state.focus == Focus::Input
        && state.mode == Mode::Normal
        && !dm_peer_trust_gated
        && (!dm_peer_offline || !state.input.is_empty())
    {
        // Past the pad marker, when there is one - the cursor belongs
        // where the next character will actually land.
        let offset = pad_prefix.as_deref().map(display_width).unwrap_or(0)
            + state.input.chars().count() as u16;
        let cursor_x = inner.x + offset.min(inner.width.saturating_sub(1));
        frame.set_cursor_position((cursor_x, inner.y));
    }
}

/// Border style shared by every bordered region: yellow while it holds
/// focus, so it's obvious at a glance which one keystrokes go to; the
/// input bar overrides this with red while actively recording.
pub(crate) fn focus_border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    }
}

/// Terminal cell width of `s`, correcting `.chars().count()` for the
/// 2-cell-wide emoji this help text uses (\u{1F512}/\u{1F6A8}) - every other
/// How many terminal cells `s` takes up, measured exactly the way ratatui
/// measures it when laying the same text out. Anything sized from this and
/// the text drawn into it therefore agree by construction, however many
/// double-width emoji are in the string - which a `chars().count()` would
/// not, and which every column this app aligns depends on (the call
/// roster, the help overlay's two columns, the details popup).
/// Minimum space kept between a nickname and its status column when the
/// popup is sized, so the two never touch.
const GAP_COLUMNS: usize = 2;

pub(crate) fn display_width(s: &str) -> u16 {
    Span::raw(s).width() as u16
}

/// What the info popup calls the time a row carries, per direction: a row
/// this client sent was sent then, a row that arrived was received then,
/// and claiming otherwise would put words in the sender's mouth.
pub const SENT_AT_LABEL: &str = "sent_at";
pub const RECEIVED_AT_LABEL: &str = "received_at";

/// What the info popup says on a row that tracks no delivery at all - an
/// incoming message, a presence notice, or an outgoing row that is not a
/// text message.
pub const NO_DELIVERY_INFO: &str = "no delivery information for this message";

/// The labels down the info popup's encryption block, in the order they
/// appear. The three `Key *` ones are the OTP layer's alone
/// (`MessageCrypto::Otp`) - which sequence of the pad this message was,
/// where in the pad its key bytes started, and which key file they came
/// out of (`docs/PROTOCOL.md` §16).
pub const ENCRYPTION_LABEL: &str = "encryption";
pub const KEY_LABEL: &str = "key";
pub const KEY_SEQ_LABEL: &str = "key_seq";
pub const KEY_OFFSET_LABEL: &str = "key_offset";
pub const KEY_FILE_LABEL: &str = "key_file";

/// What stands in for a key id on a channel send, which is sealed once per
/// member with that member's own key - there is no single key to name.
pub const KEY_PER_RECIPIENT: &str = "one per recipient";

/// What the popup says on a row this client wrote itself - a presence
/// notice, or the app's own narration of an OTP handshake. Nothing about
/// those lines travelled, so there is no encryption to report.
pub const NO_CRYPTO_INFO: &str = "not an encrypted message";

/// The encryption block for one row, as `(label, value)` pairs in display
/// order. Split out from the rendering so the popup can size itself off
/// the same lines it is about to draw, and so a test can read what a row
/// reports without going through a frame.
pub fn crypto_lines(crypto: Option<&MessageCrypto>) -> Vec<(&'static str, String)> {
    let Some(crypto) = crypto else {
        return vec![(ENCRYPTION_LABEL, NO_CRYPTO_INFO.to_string())];
    };
    let mut lines = vec![(ENCRYPTION_LABEL, crypto.method_label().to_string())];
    match crypto {
        MessageCrypto::Envelope { key_id, .. } => {
            lines.push((
                KEY_LABEL,
                key_id
                    .clone()
                    .unwrap_or_else(|| KEY_PER_RECIPIENT.to_string()),
            ));
        }
        MessageCrypto::Otp {
            seq,
            offset,
            key_path,
            ..
        } => {
            lines.push((KEY_SEQ_LABEL, seq.to_string()));
            lines.push((KEY_OFFSET_LABEL, offset.to_string()));
            lines.push((KEY_FILE_LABEL, key_path.clone()));
        }
    }
    lines
}

/// One message's details: when it happened, and - for a message this
/// client sent - every user it was sent to with that user's own delivery
/// state (`docs/SPEC.md` "Delivery acknowledgments"). Opened with `i` on
/// the message log and closed with `i` or Esc. Reads the row live rather
/// than from a snapshot, so a recipient acknowledging while it is open
/// turns their line green under the cursor.
fn render_message_info_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(index) = state.message_info else {
        return;
    };
    let Some(entry) = state.current_log().get(index) else {
        return;
    };

    let time_label = if entry.outgoing {
        SENT_AT_LABEL
    } else {
        RECEIVED_AT_LABEL
    };
    let time_line = format!("{time_label}: {}", entry.sent_at);
    let recipients: &[DeliveryRecipient] = entry
        .delivery
        .as_ref()
        .map(|d| d.recipients.as_slice())
        .unwrap_or_default();

    // How this row's content was protected (`MessageCrypto`), as a block
    // of `label: value` lines with the values in one column - the same
    // shape the OTP session header uses for the same figures.
    let crypto = crypto_lines(entry.crypto.as_ref());
    let crypto_label_width = crypto.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    let crypto_rendered: Vec<String> = crypto
        .iter()
        .map(|(label, value)| format!("{label:<crypto_label_width$}  {value}"))
        .collect();

    // Every status column is the same width, so the words line up under
    // each other however uneven the nicknames are; the names column is
    // sized by the longest name so nothing is truncated that fits.
    let status_width = [
        UNDELIVERED_LABEL,
        DELIVERED_LABEL,
        LISTENED_LABEL,
        SAVED_LABEL,
    ]
    .iter()
    .map(|l| l.len())
    .max()
    .unwrap_or(0)
        + DELIVERY_ARROW.len()
        + 1;
    let name_width = recipients
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(0);
    let content_width = (name_width + GAP_COLUMNS + status_width)
        .max(time_line.chars().count())
        .max(NO_DELIVERY_INFO.len())
        .max(
            crypto_rendered
                .iter()
                .map(|l| l.chars().count())
                .max()
                .unwrap_or(0),
        );
    let max_allowed = (area.width as u32 * 9 / 10) as u16;
    let popup_width = ((content_width + 4) as u16).min(max_allowed);
    // The time line, a blank, the encryption block, a blank, then one line
    // per recipient - or the single "nothing to report" line, which is why
    // that part floors at one rather than sizing straight off
    // `recipients.len()`.
    let body_lines = 3 + crypto_rendered.len() + recipients.len().max(1);
    let popup_height = ((body_lines + 2) as u16).min((area.height as u32 * 9 / 10) as u16);
    let popup = centered_rect(popup_width, popup_height, area);

    let block = Block::default()
        .title("Message details (i / Esc to close)")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let mut lines = vec![
        Line::from(Span::styled(
            time_line,
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    for line in &crypto_rendered {
        lines.push(Line::from(Span::styled(
            line.clone(),
            Style::default().fg(Color::Cyan),
        )));
    }
    lines.push(Line::from(""));
    if recipients.is_empty() {
        lines.push(Line::from(Span::styled(
            NO_DELIVERY_INFO,
            Style::default().fg(Color::DarkGray),
        )));
    }
    for recipient in recipients {
        let (label, color) = recipient_label(recipient, &entry.body);
        // The status is right-aligned against the popup's own inner width,
        // so it stays flush with the right edge rather than with whatever
        // the longest nickname happened to be. Same arrow, same colour, as
        // the log row this popup was opened from.
        let status = format!("{DELIVERY_ARROW} {label}");
        let used = recipient.name.chars().count() + status.len();
        let pad = (inner.width as usize).saturating_sub(used).max(1);
        lines.push(Line::from(vec![
            Span::raw(recipient.name.clone()),
            Span::raw(" ".repeat(pad)),
            Span::styled(
                status,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

/// A staged `.txt` receive's content, read-only and scrollable
/// (`UiState::file_preview`, opened by `Enter` on a
/// `FileTransferStatus::Received` row). Modeled directly on
/// `render_help_popup` below: the whole frame rather than a centered box
/// (plenty of terminals are narrower than one real line of typed text),
/// a stored scroll offset clamped against the actual rendered height here
/// rather than in `handle_key` (which has no reason to know the terminal
/// size), and a bottom hint line rather than a separate status bar.
fn render_txt_preview_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(preview) = state.file_preview.as_ref() else {
        return;
    };
    let popup = area;
    let block = Block::default()
        .title(format!("Preview: {}", preview.filename))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let width = inner.width as usize;
    let mut lines: Vec<Line<'static>> = Vec::new();
    for line in preview.content.split('\n') {
        if line.is_empty() {
            lines.push(Line::from(""));
            continue;
        }
        for chunk in wrap_to_width(line, width) {
            lines.push(Line::from(chunk));
        }
    }
    if preview.truncated {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "--- preview truncated - the saved file will still be complete ---",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::ITALIC),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "d: save   Esc: close",
        Style::default().fg(Color::DarkGray),
    )));

    let visible_rows = inner.height as usize;
    let max_scroll = lines.len().saturating_sub(visible_rows);
    let scroll = preview.scroll.min(max_scroll);

    frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), inner);
}

fn render_help_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    // The whole screen, from the row above the header down through the
    // compose bar (`docs/SPEC.md` Functionality #7). Help is the one
    // overlay nothing behind it can usefully be read alongside: it is a
    // page to read, several screens long on a small terminal, and every
    // column it does not take is a column its key table has to wrap in.
    // Taking the frame outright also means the widest line is clipped
    // only by a terminal genuinely too narrow for it.
    let popup = area;
    let block = Block::default()
        .title(HELP_POPUP_TITLE)
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    // Both the number of lines the text comes to and how many of them fit
    // depend on the terminal size at render time, which `UiState` has no
    // reason to know - so the scroll offset stored in state is clamped
    // precisely here rather than in `handle_key` (which only loosely
    // clamps against `help_total_lines`). This is what actually makes the
    // content scrollable rather than just truncated: without it, a
    // terminal shorter than the full help text would permanently hide
    // everything past the bottom of the popup.
    let lines = help_rendered_lines(inner.width);
    let visible_rows = inner.height as usize;
    let max_scroll = lines.len().saturating_sub(visible_rows);
    let scroll = state.help_scroll.min(max_scroll);

    frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), inner);
}

/// The full-screen, red-bordered takeover shown once a superadmin's
/// `/deactivate` lands against this account. Structural copy of
/// `render_help_popup` - the only other place this codebase takes
/// `frame.area()` directly rather than `centered_rect`, for the same
/// reason: nothing behind it should be readable, or in this case even
/// visible, once it's up. Escape is the only key `handle_key`'s matching
/// top-priority tier answers, which ends the whole session - there is
/// nothing to "return to" underneath, unlike `help_open`.
fn render_account_deactivated_modal(frame: &mut Frame, area: Rect, reason: &str) {
    let popup = area;
    let block = Block::default()
        .title("Account deactivated")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let text = format!("Your account has been deactivated (\"{reason}\")\n\nPress ESCAPE to close aloo");
    let paragraph = Paragraph::new(text)
        .style(Style::default().fg(Color::Red))
        .alignment(Alignment::Center)
        .wrap(ratatui::widgets::Wrap { trim: true });
    // Vertically centered within the bordered area, the same way a small
    // confirm popup centers itself in its own box - just at the scale of
    // the whole screen here.
    let centered = Rect {
        y: inner.y + inner.height / 3,
        height: inner.height.saturating_sub(inner.height / 3),
        ..inner
    };
    frame.render_widget(paragraph, centered);
}

pub(crate) fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

/// Shared by `ui_connect_popup`'s key-file picker and `file_send`'s
/// send-a-file browser - the same generic, fs-backed directory browser
/// (`FileBrowserState`), just titled differently for whichever popup is
/// currently using it (`"Select file"` there, `"Send file"` here).
///
/// Uses `ListState` rather than a fixed style-per-item (same fix as
/// `render_messages`' `list_state`): without it, `List` always starts
/// drawing at entry 0 and simply clips whatever doesn't fit, so selecting
/// past the bottom of the visible area moved `browser.selected` but never
/// scrolled the view to show it - `ListState` makes ratatui compute
/// whatever offset keeps the selected entry on screen.
pub(crate) fn render_file_browser(
    frame: &mut Frame,
    area: Rect,
    browser: &crate::client::file_browser::FileBrowserState,
    title_prefix: &str,
) {
    let popup = centered_rect(60, 20, area);
    let title = format!("{title_prefix} - {}", browser.current_dir.display());
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let items: Vec<ListItem> = browser
        .entries
        .iter()
        .map(|e| {
            ListItem::new(if e.is_dir {
                format!("{}/", e.name)
            } else {
                e.name.clone()
            })
        })
        .collect();
    let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut list_state = ListState::default();
    if !browser.entries.is_empty() {
        list_state.select(Some(browser.selected.min(browser.entries.len() - 1)));
    }
    frame.render_stateful_widget(list, inner, &mut list_state);
}
