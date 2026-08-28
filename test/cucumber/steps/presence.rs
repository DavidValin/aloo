//! Who is present, who has gone, and the help overlay
//! (US-012, US-013, US-014, US-016).

use crossterm::event::{KeyCode, KeyModifiers};
use cucumber::{given, then, when};
use ratatui::style::Color;

use aloo::client::p2p::LinkStatus;
use aloo::client::tui::channel::HEADER_ROW_HEIGHT;
use aloo::client::tui::ui::{Focus, HELP_POPUP_TITLE, LogEntry, MessageBody};
use aloo::proto::{KeyMode, UserId};

use crate::steps::ui_common::{id_for, press_key};
use crate::support::{
    appears_before, find_text_start, find_text_start_below, ui_buffer, ui_rows, ui_rows_wide,
};
use crate::world::AlooWorld;

// ---------------------------------------------------------------------
// Encryption tags (US-012)
// ---------------------------------------------------------------------

#[then(expr = "{word}'s tag is shown after their name")]
async fn tag_after(w: &mut AlooWorld, name: String) {
    let rows = ui_rows_wide(w.ui_ref());
    // One scheme, so one tag - the assertion is about where it sits, not
    // about which of several it is.
    let tag = "PQH";
    assert!(
        appears_before(&rows, &name, tag),
        "every tag trails the name as an annotation on it - expected {name}'s {tag} tag after their name: {rows:?}"
    );
}

#[then(expr = "the private room title reads {string} with the pq_hybrid tag after the name")]
async fn room_title_tag(w: &mut AlooWorld, title: String) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        rows.iter().any(|r| r.contains(&title)),
        "expected the title to lead with the name: {rows:?}"
    );
    assert!(
        appears_before(&rows, "bob", "PQH"),
        "the peer's tag belongs after their name in the title too: {rows:?}"
    );
}

// ---------------------------------------------------------------------
// Offline users (US-013)
// ---------------------------------------------------------------------

#[when(expr = "{word} goes offline")]
#[given(expr = "{word} has gone offline")]
async fn goes_offline(w: &mut AlooWorld, name: String) {
    w.ui_mut().on_user_offline(UserId(id_for(&name)));
}

#[then(expr = "{word} is still listed in the channel")]
async fn still_listed(w: &mut AlooWorld, name: String) {
    let state = w.ui_ref();
    let id = UserId(id_for(&name));
    assert!(
        state.channels[0].members.iter().any(|m| m.id == id),
        "someone I have history with stays listed rather than vanishing"
    );
    assert!(
        state.offline.contains(&id),
        "and is still tracked as offline"
    );
}

#[then(expr = "{word} is dropped from the channel list")]
async fn dropped(w: &mut AlooWorld, name: String) {
    let state = w.ui_ref();
    let id = UserId(id_for(&name));
    assert!(
        !state.channels[0].members.iter().any(|m| m.id == id),
        "with no history to keep them around for, they are removed like an explicit leave"
    );
    assert!(
        state.offline.contains(&id),
        "but they are still remembered as offline"
    );
}

/// Green in the sidebar means "a direct link to this person is up"
/// (AC-135), not merely "they are connected to the server" - so a scenario
/// that asserts green has to establish one first.
#[given(expr = "I have a direct connection to {word}")]
async fn have_direct_connection(w: &mut AlooWorld, name: String) {
    w.ui_mut()
        .set_link_status(UserId(id_for(&name)), LinkStatus::Active);
}

#[given(expr = "the direct connection to {word} has been lost")]
#[when(expr = "the direct connection to {word} is lost")]
async fn direct_connection_lost(w: &mut AlooWorld, name: String) {
    w.ui_mut()
        .set_link_status(UserId(id_for(&name)), LinkStatus::Lost);
}

#[then(expr = "{word}'s name is shown in {word}")]
async fn name_colour(w: &mut AlooWorld, name: String, colour: String) {
    let expected = match colour.as_str() {
        "green" => Color::Green,
        "gray" => Color::DarkGray,
        "red" => Color::Red,
        other => panic!("unknown colour {other:?} - expected green/gray/red"),
    };
    let buffer = ui_buffer(w.ui_ref(), 160, 30);
    let (x, y) = find_text_start(&buffer, &name);
    assert_eq!(
        buffer[(x, y)].fg,
        expected,
        "{name} should be rendered {colour} for their direct-link state"
    );
}

#[then(expr = "{word}'s name is shown in gray, whatever their/his/her link was last doing")]
async fn name_gray_despite_link(w: &mut AlooWorld, name: String) {
    let buffer = ui_buffer(w.ui_ref(), 160, 30);
    let (x, y) = find_text_start_below(&buffer, &name, HEADER_ROW_HEIGHT);
    assert_eq!(
        buffer[(x, y)].fg,
        Color::DarkGray,
        "a closed connection outranks whatever {name}'s link was last doing"
    );
}

/// The top row's DM selector names one person, and an open room is the one
/// view with no user list of its own - so it carries the same colour their
/// name has in the sidebar (AC-229).
#[then(expr = "the DM selector shows {word} in {word}")]
async fn dm_selector_colour(w: &mut AlooWorld, name: String, colour: String) {
    let expected = match colour.as_str() {
        "green" => Color::Green,
        "red" => Color::Red,
        "yellow" => Color::Yellow,
        "gray" => Color::DarkGray,
        other => panic!("unknown colour {other:?}"),
    };
    let buffer = ui_buffer(w.ui_ref(), 160, 30);
    // The header row's own copy of the name, not the sidebar's.
    let (x, y) = find_text_start(&buffer, &name);
    assert!(
        (y as usize) < HEADER_ROW_HEIGHT as usize,
        "the first {name} on screen should be the one on the DM selector"
    );
    assert_eq!(
        buffer[(x, y)].fg,
        expected,
        "the DM selector should show {name} in {colour}"
    );
}

#[then("every room listed in the DM dropdown carries its peer's reachability")]
async fn dm_dropdown_carries_presence(w: &mut AlooWorld) {
    let entries = w.ui_ref().selector_dropdown_entries();
    assert!(
        !entries.is_empty(),
        "the dropdown lists every open room except the one named - there should be one"
    );
    for entry in entries {
        assert!(
            entry.presence.is_some(),
            "a DM row names a person and must carry their presence: {:?}",
            entry.label
        );
    }
}

#[then(expr = "{word} is rendered in gray while {word} stays green")]
async fn gray_vs_green(w: &mut AlooWorld, offline: String, online: String) {
    let buffer = ui_buffer(w.ui_ref(), 160, 30);
    let (ox, oy) = find_text_start_below(&buffer, &offline, HEADER_ROW_HEIGHT);
    assert_eq!(
        buffer[(ox, oy)].fg,
        Color::DarkGray,
        "an offline member should be rendered in soft gray"
    );
    let (nx, ny) = find_text_start_below(&buffer, &online, HEADER_ROW_HEIGHT);
    assert_eq!(
        buffer[(nx, ny)].fg,
        Color::Green,
        "a still-connected member should stay green"
    );
}

#[then(expr = "the private room holds only {int} message(s)")]
async fn room_message_count(w: &mut AlooWorld, n: usize) {
    let state = w.ui_ref();
    let id = state.active_private_room.expect("no private room open");
    assert_eq!(
        state.private_rooms[&id].log.len(),
        n,
        "nothing of mine should have been sent to an offline peer"
    );
}

#[then("the compose bar shows an offline notice in red")]
async fn offline_notice(w: &mut AlooWorld) {
    let buffer = ui_buffer(w.ui_ref(), 100, 15);
    let (x, y) = find_text_start(&buffer, "(user offline)");
    assert_eq!(
        buffer[(x, y)].fg,
        Color::Red,
        "the offline notice should be red"
    );
}

#[then(expr = "{word} stays offline even if a join for them arrives again")]
async fn offline_is_permanent(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    let info = crate::steps::ui_common::user_with_mode(
        id_for(&name),
        &name,
        aloo::proto::KeyMode::PqHybrid,
    );
    w.ui_mut().on_user_joined("general", info);
    assert!(
        w.ui_ref().offline.contains(&id),
        "a UserId is never reused, so nothing should ever move one back to online"
    );
}

// ---------------------------------------------------------------------
// Presence notices in the log: join/left/disconnected (US-034)
// ---------------------------------------------------------------------

/// A genuine live join, distinct from `member_present` above
/// (`{word} is in the channel with me`, which seeds the channel's starting
/// roster without producing a notice) - this is the one that goes through
/// `UiState::on_user_joined` and so does log a yellow "joined" line.
#[when(expr = "{word} joins the channel with me")]
async fn member_joins_live(w: &mut AlooWorld, name: String) {
    let info = crate::steps::ui_common::user_with_mode(id_for(&name), &name, KeyMode::PqHybrid);
    w.ui_mut().on_user_joined("general", info);
}

#[when(expr = "{word} leaves the channel")]
async fn member_leaves(w: &mut AlooWorld, name: String) {
    w.ui_mut().on_user_left("general", UserId(id_for(&name)));
}

fn assert_presence_suffix(entry: Option<&LogEntry>, suffix: &str) {
    let entry = entry
        .unwrap_or_else(|| panic!("expected a presence notice ending {suffix:?}, log is empty"));
    match &entry.body {
        MessageBody::Presence(text) => assert!(
            text.ends_with(suffix),
            "expected the presence notice to end with {suffix:?}, got {text:?}"
        ),
        other => panic!("expected a Presence entry ending {suffix:?}, got {other:?}"),
    }
}

#[then(expr = "the channel log ends with the presence notice {string}")]
async fn channel_log_ends_with_presence(w: &mut AlooWorld, suffix: String) {
    assert_presence_suffix(w.ui_ref().channels[0].log.last(), &suffix);
}

#[then("no presence notice appears in the channel log")]
async fn no_presence_notice(w: &mut AlooWorld) {
    assert!(
        w.ui_ref().channels[0].log.is_empty(),
        "expected no presence notice from the membership snapshot, got {:?}",
        w.ui_ref().channels[0].log
    );
}

#[then(expr = "{word}'s private room ends with the presence notice {string}")]
async fn private_room_ends_with_presence(w: &mut AlooWorld, name: String, suffix: String) {
    let id = UserId(id_for(&name));
    let entry = w.ui_ref().private_rooms.get(&id).and_then(|r| r.log.last());
    assert_presence_suffix(entry, &suffix);
}

// ---------------------------------------------------------------------
// Help overlay (US-014)
// ---------------------------------------------------------------------

#[then("the help overlay is open")]
async fn help_open(w: &mut AlooWorld) {
    assert!(w.ui_ref().help_open, "Ctrl+H should open the help overlay");
}

#[then("the help overlay is closed")]
async fn help_closed(w: &mut AlooWorld) {
    assert!(!w.ui_ref().help_open, "Ctrl+H again should close it");
}

#[then("the help overlay explains private channels, voice, files and the tags")]
async fn help_content(w: &mut AlooWorld) {
    let rows = ui_rows(w.ui_ref());
    for (needle, what) in [
        ("Help", "a help popup title"),
        ("Ctrl+J", "how to join a hidden channel"),
    ] {
        assert!(
            rows.iter().any(|r| r.contains(needle)),
            "expected {what}: {rows:?}"
        );
    }
    // Past the first screenful now that the two selectors, the log's
    // scroll keys and `/mute-voice` all have their own lines above them -
    // reached the same way the sections below are.
    let rows = scroll_help_until(w, "Space");
    assert!(
        rows.iter().any(|r| r.contains("Space")),
        "expected how to send a voice message: {rows:?}"
    );
    let rows = scroll_help_until(w, "/file");
    assert!(
        rows.iter().any(|r| r.contains("/file")),
        "expected how to send a file: {rows:?}"
    );
}

/// The encryption tags and the "Contacts & Keys" section are both far
/// enough down the (now longer) help text that a typical terminal does not
/// show them without scrolling - see `docs/SPEC.md` Functionality #7's
/// scrollable overlay. Each is scrolled to independently (PageDown,
/// incrementally) rather than assuming a single End-scroll screenful
/// contains both - exactly how far apart they land shifts whenever
/// `HELP_BODY` changes.
#[then("scrolling to the bottom reveals contacts and keys")]
async fn help_content_scrolled(w: &mut AlooWorld) {
    let rows = scroll_help_until(w, "PQH");
    assert!(
        rows.iter().any(|r| r.contains("PQH")),
        "expected the encryption tags explained: {rows:?}"
    );
    let rows = scroll_help_until(w, "Contacts & Keys");
    assert!(
        rows.iter().any(|r| r.contains("Contacts & Keys")),
        "expected the contacts and keys section: {rows:?}"
    );
}

/// Presses PageDown until `text` appears on screen or the scroll position
/// stops advancing (hit bottom) - see `help_content_scrolled`'s doc.
fn scroll_help_until(w: &mut AlooWorld, text: &str) -> Vec<String> {
    let mut rows = ui_rows(w.ui_ref());
    for _ in 0..40 {
        if rows.iter().any(|r| r.contains(text)) {
            break;
        }
        let before = w.ui_ref().help_scroll();
        press_key(w, KeyCode::PageDown, KeyModifiers::NONE);
        if w.ui_ref().help_scroll() == before {
            break;
        }
        rows = ui_rows(w.ui_ref());
    }
    rows
}

#[then("the help hint sits at the top right")]
async fn help_hint(w: &mut AlooWorld) {
    let rows = ui_rows(w.ui_ref());
    assert!(
        rows.iter()
            .any(|r| r.contains("Ctrl+H") && r.contains("Help")),
        "the hint should always be there as a reminder: {rows:?}"
    );
}

#[then("my typing does not reach the compose bar")]
async fn typing_absorbed(w: &mut AlooWorld) {
    assert!(
        w.ui_ref().input.is_empty(),
        "help absorbs every other key while it is open"
    );
}

#[then(expr = "focus is still on the {word}")]
async fn focus_unchanged(w: &mut AlooWorld, area: String) {
    let expected = match area.as_str() {
        "sidebar" => Focus::Sidebar,
        "log" | "messages" => Focus::Messages,
        "compose" | "input" => Focus::Input,
        other => panic!("unknown focus target {other:?}"),
    };
    assert_eq!(
        w.ui_ref().focus,
        expected,
        "no navigation should happen underneath the overlay"
    );
}

#[then("the private room underneath is untouched")]
async fn room_untouched(w: &mut AlooWorld) {
    assert_eq!(
        w.ui_ref().active_private_room,
        Some(UserId(2)),
        "Esc must not fall through to closing the room while help is open"
    );
}

/// The pq_hybrid encryption line now sits below the fold on the first
/// screen (the help text has grown since this was written) - scrolls to it
/// first, same precedent as `help_content_scrolled`. Rendered wide (via
/// `ui_rows_wide`) so the line's width comfortably clears the popup's own
/// 90%-of-terminal cap. Scrolls incrementally (PageDown) rather than
/// jumping straight to End: exactly how far down this line sits shifts
/// whenever `HELP_BODY` grows elsewhere, so a fixed "scroll all the way,
/// then check" no longer reliably lands on a screenful containing it.
///
/// One line at a time rather than a page at a time, for the same reason
/// taken one step further: a page jump can step *over* the screenful the
/// line is on, which is exactly what happened once `HELP_BODY` grew past
/// a certain length. Bounded by the scroll position no longer moving, so
/// it still terminates at the bottom whatever the text does next.
#[then("the help popup shows its longest line unclipped")]
async fn help_unclipped(w: &mut AlooWorld) {
    let tail =
        "the only scheme there is: ML-DSA-87+RSA4096/ML-KEM-1024+RSA4096/AES-256-GCM, loaded from a file";
    // Back to the top first: the step before this one scrolls looking for
    // its own lines, and scrolling only ever goes down from wherever it
    // left off - so without this the scan can start already past the line
    // it is looking for.
    press_key(w, KeyCode::Home, KeyModifiers::NONE);
    let mut rows = ui_rows_wide(w.ui_ref());
    let mut seen = rows.clone();
    while !seen.iter().any(|r| r.contains(tail)) {
        let before = w.ui_ref().help_scroll();
        press_key(w, KeyCode::Down, KeyModifiers::NONE);
        if w.ui_ref().help_scroll() == before {
            break;
        }
        rows = ui_rows_wide(w.ui_ref());
        seen.extend(rows.iter().cloned());
    }
    // Every row seen on the way down, not just the last screenful: which
    // screenful this line lands on moves whenever `HELP_BODY` grows, and
    // what is being proven is that it renders in full *somewhere*, not
    // where it happens to sit today.
    let rows = seen;
    assert!(
        rows.iter().any(|r| r.contains(tail)),
        "expected the longest help line in full: {rows:?}"
    );
}

#[then("the help popup covers the whole screen, the compose bar included")]
async fn help_covers_the_whole_screen(w: &mut AlooWorld) {
    // Smaller than the help text needs, so nothing but the frame itself
    // can be deciding the overlay's size here.
    let (width, height) = (60u16, 20u16);
    let buffer = ui_buffer(w.ui_ref(), width, height);
    let rows = crate::support::rows_of(&buffer);
    let row_chars: Vec<Vec<char>> = rows.iter().map(|r| r.chars().collect()).collect();

    assert_eq!(
        row_chars[0][0], '\u{250C}',
        "the overlay's top-left corner sits at the very top left, above the header: {rows:?}"
    );
    assert!(
        rows[0].contains(HELP_POPUP_TITLE),
        "the overlay's own title row is the frame's first row: {rows:?}"
    );
    assert_eq!(
        row_chars[0][width as usize - 1],
        '\u{2510}',
        "the overlay runs to the last column: {rows:?}"
    );
    assert_eq!(
        row_chars[height as usize - 1][0],
        '\u{2514}',
        "the overlay runs down to the last row, so the compose bar is covered: {rows:?}"
    );
}

#[given("the help overlay is open")]
async fn given_help_open(w: &mut AlooWorld) {
    w.ui_mut().help_open = true;
}

#[then("the help overlay is scrolled down")]
async fn help_scrolled_down(w: &mut AlooWorld) {
    assert!(
        w.ui_ref().help_scroll() > 0,
        "End should have scrolled past the top"
    );
}

#[then("the help overlay is scrolled to the top")]
async fn help_scrolled_to_top(w: &mut AlooWorld) {
    assert!(w.ui_ref().help_open, "should have reopened");
    assert_eq!(
        w.ui_ref().help_scroll(),
        0,
        "reopening must not resume wherever it was left last time"
    );
}

// ---------------------------------------------------------------------
// Focus (US-016)
// ---------------------------------------------------------------------

#[then(expr = "focus moves to the {word}")]
async fn focus_moves_to(w: &mut AlooWorld, area: String) {
    let expected = match area.as_str() {
        "sidebar" => Focus::Sidebar,
        "log" | "messages" => Focus::Messages,
        "compose" | "input" => Focus::Input,
        other => panic!("unknown focus target {other:?}"),
    };
    assert_eq!(w.ui_ref().focus, expected);
}

#[then(expr = "the selected user is at position {int}")]
async fn sidebar_position(w: &mut AlooWorld, index: usize) {
    assert_eq!(w.ui_ref().sidebar_selected, index, "sidebar selection");
}

// ---------------------------------------------------------------------
// Where the tags sit in the user list (AC-245)
// ---------------------------------------------------------------------

/// The user list's own rows, inside its border - so a column figure is a
/// column of the sidebar rather than of the screen.
fn user_list_rows(w: &AlooWorld) -> Vec<String> {
    crate::support::popup_body(&ui_buffer(w.ui_ref(), 100, 14), "Users")
}

#[then("every tag in the user list ends on the sidebar's right edge")]
async fn tags_flush_right(w: &mut AlooWorld) {
    let rows = user_list_rows(w);
    let tagged: Vec<&String> = rows
        .iter()
        .filter(|r| r.contains("PWD") || r.contains("PQH") || r.contains("PLAIN"))
        .collect();
    assert!(!tagged.is_empty(), "expected tagged rows: {rows:?}");
    for row in tagged {
        let chars: Vec<char> = row.chars().collect();
        let last = chars
            .iter()
            .rposition(|c| !c.is_whitespace())
            .expect("a tag on this row");
        assert_eq!(
            last + 1,
            chars.len(),
            "the tag runs to the sidebar's right edge: {row:?}"
        );
    }
}

#[then("every nickname still starts on its left")]
async fn names_flush_left(w: &mut AlooWorld) {
    let rows = user_list_rows(w);
    for name in ["dan", "frank"] {
        let row = rows
            .iter()
            .find(|r| r.contains(name))
            .unwrap_or_else(|| panic!("no row for {name}: {rows:?}"));
        assert!(
            row.starts_with(name),
            "the person stays on the left: {row:?}"
        );
    }
}

// ---------------------------------------------------------------------
// A peer who reconnects (AC-248)
// ---------------------------------------------------------------------

/// The fresh `UserId` a reconnecting peer arrives under - deliberately not
/// `id_for(name)`, since the whole point is that the server never hands
/// the same one out twice.
const RECONNECTED_ID: u64 = 9_001;

#[when(expr = "{word} reconnects under a new id")]
async fn reconnects(w: &mut AlooWorld, name: String) {
    let info = crate::steps::ui_common::user_with_mode(
        RECONNECTED_ID,
        &name,
        aloo::proto::KeyMode::PqHybrid,
    );
    w.ui_mut().on_user_joined("general", info);
}

#[then(expr = "{word} is listed once in the channel")]
async fn listed_once(w: &mut AlooWorld, name: String) {
    let state = w.ui_ref();
    let listed = state.channels[state.selected_channel]
        .members
        .iter()
        .filter(|m| m.name == name)
        .count();
    assert_eq!(listed, 1, "expected one {name}, not one per connection");
}

#[then(expr = "the private room with {word} still holds {string}")]
async fn room_still_holds(w: &mut AlooWorld, name: String, text: String) {
    let state = w.ui_ref();
    let room = state
        .private_rooms
        .get(&UserId(RECONNECTED_ID))
        .unwrap_or_else(|| panic!("no room under {name}'s new id: {:?}", state.dm_order));
    assert!(
        room.log
            .iter()
            .any(|e| matches!(&e.body, MessageBody::Text(t) if *t == text)),
        "the conversation continues in the same room: {:?}",
        room.log.len()
    );
}

#[then(expr = "{word} is no longer offline")]
async fn no_longer_offline(w: &mut AlooWorld, name: String) {
    let state = w.ui_ref();
    assert!(!state.offline.contains(&UserId(RECONNECTED_ID)));
    assert!(
        !state.offline.contains(&UserId(id_for(&name))),
        "the id they are no longer known by is cleared too"
    );
}
