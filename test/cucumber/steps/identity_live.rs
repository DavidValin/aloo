//! Live, real-socket coverage for the device-pinning identity algorithm
//! (device-pinning plan §2) - two real `run_daemon_session`s talking to a
//! real server over real loopback TCP/UDP, driving `check_identity`,
//! `finalize_identity_pin` and the `AcceptIdentity` handler exactly as a
//! genuine user's session would, rather than the `UiState`-only
//! simulation `steps/identity.rs`'s scenarios use.
//!
//! This is the harness `daemon_session_test.rs` already proved for a
//! serverless (`direct_punch_to`) pair, reused here server-mediated
//! instead - which is what makes it fast enough for the ordinary
//! `cargo bdd` run: a server-introduced P2P link punches over loopback
//! the moment both sides learn of each other (§7.1), with no wall-clock
//! slot grid to wait out the way §7.1.5's serverless scheduling needs.
//!
//! Closes docs/TESTING.md's "device id/last-seen-address orchestration"
//! and "AcceptIdentity's network-facing side effects" rows for real,
//! rather than leaving them as documented, structurally-argued gaps.

use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use cucumber::{given, then, when};

use aloo::client::connect::{ConnectRequest, MyKeySelection, connect_with_reconnect};
use aloo::client::daemon::{DaemonChannel, DaemonPlan};
use aloo::client::idstore::IdStore;
use aloo::client::session::{SessionInput, run_daemon_session};
use aloo::client::tui::surface::{AttachWriter, Surface, TerminalSize};

use crate::world::AlooWorld;

// ---------------------------------------------------------------------
// Real key material and id_store paths, on disk, one per scenario run
// ---------------------------------------------------------------------

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-cucumber-identity-live-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A real, file-backed `pq_hybrid` identity for `nickname` - `variant`
/// distinguishes a second, genuinely different identity for the *same*
/// nickname (a rotated or impersonating key), since a plain reconnect
/// under the ordinary identity must reuse the same files every time -
/// stable for the life of the whole test *process* (keyed on
/// `nickname`+`variant`+pid only, no per-call timestamp, and generated
/// once then reused - not `scratch_dir`'s per-call fresh directory),
/// exactly `steps/reconnect.rs::scenario_keybundle`'s own caching
/// reasoning: a caller that resolves `("bob", "own")` twice, once to
/// start bob's real session and once to compute what its public key
/// *should* be for an assertion, must get back the identical bundle both
/// times.
fn keybundle(nickname: &str, variant: &str) -> MyKeySelection {
    let dir = std::env::temp_dir().join(format!(
        "aloo-cucumber-identity-live-keys-{}-{nickname}-{variant}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let file_pub = dir.join("id.pub");
    let file_priv = dir.join("id.priv");
    if !file_pub.exists() {
        let (public, private) =
            aloo::crypto::pq::generate_bundle_with_bits(1024).expect("scenario keygen");
        aloo::crypto::pq::save_private_bundle(&private, &file_priv).expect("save private");
        aloo::crypto::pq::save_public_bundle(&public, &file_pub).expect("save public");
    }
    MyKeySelection { file_pub, file_priv }
}

fn password_for(nickname: &str) -> String {
    format!("live-pw-{nickname}")
}

fn ensure_registered(w: &mut AlooWorld, nickname: &str) {
    let users = w.server_users.as_ref().expect("no server running - `a server that anyone may connect to` first");
    if !users.is_registered(nickname) {
        users.register_manual(nickname, &password_for(nickname)).unwrap();
    }
}

// ---------------------------------------------------------------------
// The live session handle
// ---------------------------------------------------------------------

/// One real `run_daemon_session`, with the handles a scenario drives it
/// through - the cucumber-world counterpart of `daemon_session_test.rs`'s
/// `Running`.
pub struct LiveDaemon {
    pub(crate) input_tx: tokio::sync::mpsc::UnboundedSender<SessionInput>,
    frames: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    handle: tokio::task::JoinHandle<()>,
    screen: String,
    /// Where this session's id_store lives on disk - reloaded fresh once
    /// the session ends, to inspect exactly what it persisted, never
    /// trusted from the in-memory value the session started with.
    id_store_path: PathBuf,
    /// Whose private room this session currently has open, so a second
    /// send into the same room does not re-navigate - and so a stale
    /// "Private: x" left in the transcript from an earlier room can never
    /// be mistaken for the room being open now.
    open_room: Option<String>,
}

impl LiveDaemon {
    /// Reads frames until the screen says `needle`, or gives up - driven
    /// by what actually arrives rather than a settle delay, the same
    /// reasoning `daemon_session_test.rs::Running::wait_for` documents.
    async fn wait_for(&mut self, needle: &str, within: Duration) -> bool {
        let needle = squash(needle);
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if squash(&self.screen).contains(&needle) {
                return true;
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            match tokio::time::timeout(left, self.frames.recv()).await {
                Ok(Some(bytes)) => {
                    self.screen.push_str(&strip_ansi(&String::from_utf8_lossy(&bytes)));
                }
                _ => return squash(&self.screen).contains(&needle),
            }
        }
    }

    /// Types `text` one keystroke at a time, exactly as a person would -
    /// the compose bar has a per-keystroke filter, so a bulk insert
    /// would not be the same thing.
    fn type_text(&self, text: &str) {
        for c in text.chars() {
            self.key(KeyCode::Char(c));
        }
    }

    /// Whether the screen has ever shown `needle` - a plain look at what
    /// has already arrived, for asserting something is *absent*.
    fn has_shown(&self, needle: &str) -> bool {
        squash(&self.screen).contains(&squash(needle))
    }

    /// Ends the session without reading anything back - "this person
    /// goes offline", which is what the server sees when a client stops.
    async fn stop(self) {
        drop(self.input_tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
    }

    fn key(&self, code: KeyCode) {
        let _ = self.input_tx.send(SessionInput::Key(Event::Key(KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        })));
    }

    /// Ends the session and reloads its id_store fresh from disk - never
    /// the in-memory value it started with, since the whole point is
    /// checking what `check_identity`/`finalize_identity_pin`/
    /// `AcceptIdentity` actually persisted while it ran.
    async fn end(self) -> IdStore {
        let path = self.id_store_path.clone();
        drop(self.input_tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
        IdStore::load(&path).expect("id_store should still load once the session has ended")
    }
}

fn squash(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace() && !"│─┌┐└┘├┤┬┴┼".contains(*c)).collect()
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\u{7}' {
                        break;
                    }
                    if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Starts a real daemon session, joined to `channel`, with a viewer
/// already attached so what it draws is readable straight off `frames` -
/// `daemon_session_test.rs::start`'s exact shape, server-mediated
/// (`connect_with_reconnect`) rather than serverless.
async fn start_daemon(
    w: &mut AlooWorld,
    nickname: &str,
    my_key: MyKeySelection,
    id_store: IdStore,
    channel: &str,
) {
    let addr = w.addr.expect("no server running");
    ensure_registered(w, nickname);
    let id_store_path = id_store.path().to_path_buf();
    let request = ConnectRequest {
        host: addr.ip().to_string(),
        port: addr.port(),
        ssl: false,
        ssl_ca: None,
        nickname: nickname.to_string(),
        password: password_for(nickname),
        my_key,
        activation_code: None,
    };
    // Retried, not assumed: a nickname is freed when the server notices
    // that connection has gone, which is not instantaneous, so somebody
    // coming straight back after leaving can genuinely race it and be
    // told the name is taken. That is the server behaving correctly, and
    // waiting it out is the harness's business.
    let mut attempt = connect_with_reconnect(&request).await;
    for _ in 0..40 {
        if attempt.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        attempt = connect_with_reconnect(&request).await;
    }
    let (events, sink, you, identity, server_addr) =
        attempt.expect("the connection should succeed once the old one has been reaped");

    let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel();
    let (frame_tx, frames) = tokio::sync::mpsc::unbounded_channel();
    let plan = DaemonPlan::new(
        vec![DaemonChannel { name: channel.to_string(), password: None }],
        None,
    );
    let name = nickname.to_string();
    let handle = tokio::spawn(async move {
        let mut surface = Surface::Detached;
        let _ = run_daemon_session(
            &mut surface,
            Some(events),
            sink,
            name,
            you,
            identity,
            id_store,
            None,
            Some(server_addr),
            input_rx,
            plan,
            "test-server_0".to_string(),
        )
        .await;
    });
    // A viewer attaches, exactly as `aloo` does on a real attach - without
    // this there is nothing to read the review popup or the member list
    // off at all.
    input_tx
        .send(SessionInput::Attached {
            writer: AttachWriter::new(frame_tx),
            size: TerminalSize { cols: 160, rows: 40 },
        })
        .expect("session should be accepting input");

    w.daemons.insert(
        nickname.to_string(),
        LiveDaemon {
            input_tx,
            frames,
            handle,
            screen: String::new(),
            id_store_path,
            open_room: None,
        },
    );
}

fn daemon_of<'w>(w: &'w mut AlooWorld, nickname: &str) -> &'w mut LiveDaemon {
    w.daemons.get_mut(nickname).unwrap_or_else(|| panic!("{nickname} has no live daemon session"))
}

// ---------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------

#[given(expr = "{word} joins the server for real, into {string}")]
#[when(expr = "{word} joins the server for real, into {string}")]
async fn joins_for_real(w: &mut AlooWorld, nickname: String, channel: String) {
    let my_key = keybundle(&nickname, "own");
    let id_store = IdStore::new_empty(scratch_dir(&format!("idstore-{nickname}")).join("ids_store"));
    start_daemon(w, &nickname, my_key, id_store, &channel).await;
}

/// Seeds `holder`'s id_store with a *different*, genuinely distinct
/// identity for `nickname` before `holder`'s session ever starts, filed
/// under `device_id` - so `nickname`'s real, actual identity connecting
/// afterward is a genuine mismatch against it, exactly table row 2/6's
/// starting state, not simulated.
#[given(expr = "{word} already has {word} pinned under device {string} to a different key")]
async fn pinned_under_a_different_key(
    w: &mut AlooWorld,
    holder: String,
    nickname: String,
    device_id: String,
) {
    let old_identity = keybundle(&nickname, "old");
    let old_der = aloo::client::connect::resolve_my_keypair(&old_identity)
        .expect("old identity should resolve")
        .public_der;
    let path = scratch_dir(&format!("idstore-{holder}")).join("ids_store");
    let mut store = IdStore::new_empty(path);
    store.pin_new_device(&nickname, &device_id, &old_der, aloo::client::idstore::Trust::Tofu);
    store.set_key_mode(&nickname, &device_id, aloo::proto::KeyMode::PqHybrid);
    store.save().expect("seed the pre-existing pin");
    w.pending_id_store.insert(holder, (store.path().to_path_buf(), device_id));
}

/// Starts `holder`'s session with the id_store `pinned_under_a_different_key`
/// just seeded on disk, rather than an empty one.
#[given(expr = "{word} joins the server for real, into {string}, with that pin in place")]
async fn joins_with_seeded_pin(w: &mut AlooWorld, holder: String, channel: String) {
    let (path, _device_id) = w
        .pending_id_store
        .remove(&holder)
        .unwrap_or_else(|| panic!("no seeded pin for {holder} - call the seeding step first"));
    let id_store = IdStore::load(&path).expect("the seeded store should still load");
    let my_key = keybundle(&holder, "own");
    start_daemon(w, &holder, my_key, id_store, &channel).await;
}

#[then(expr = "{word}'s screen shows an identity review naming {word} within {int} seconds")]
async fn shows_identity_review(w: &mut AlooWorld, holder: String, subject: String, seconds: u64) {
    let daemon = daemon_of(w, &holder);
    let found = daemon
        .wait_for(&format!("Identity review: {subject}"), Duration::from_secs(seconds))
        .await;
    assert!(found, "{holder} never showed an identity review for {subject}: {}", daemon.screen);
}

/// Confirms the review's default focus (`Reject`), same as
/// `daemon_session_test.rs`'s screen-driven assertions - Tab moves focus
/// to `Accept`, Enter confirms it.
#[when(expr = "{word} accepts the pending identity review")]
async fn accepts_pending_review(w: &mut AlooWorld, holder: String) {
    let daemon = daemon_of(w, &holder);
    daemon.key(KeyCode::Tab);
    daemon.key(KeyCode::Enter);
}

#[given(expr = "{word}'s screen shows {string} within {int} seconds")]
#[then(expr = "{word}'s screen shows {string} within {int} seconds")]
async fn screen_shows(w: &mut AlooWorld, holder: String, needle: String, seconds: u64) {
    let daemon = daemon_of(w, &holder);
    let found = daemon.wait_for(&needle, Duration::from_secs(seconds)).await;
    assert!(found, "{holder} never showed {needle:?}: {}", daemon.screen);
}

/// Order is the queue's whole contract, and the screen is where it is
/// finally observable: the row written first must sit above the row
/// written second. Reads the screen the previous `shows ... within` step
/// already waited for, so both are known to be on it.
#[then(expr = "{word}'s screen shows {string} above {string}")]
async fn screen_shows_above(w: &mut AlooWorld, holder: String, first: String, second: String) {
    let daemon = daemon_of(w, &holder);
    let screen = daemon.screen.clone();
    let above = screen
        .find(&first)
        .unwrap_or_else(|| panic!("{holder} never showed {first:?}: {screen}"));
    let below = screen
        .find(&second)
        .unwrap_or_else(|| panic!("{holder} never showed {second:?}: {screen}"));
    assert!(
        above < below,
        "{first:?} was written first and must be shown above {second:?}: {screen}"
    );
}

/// Ends every live daemon session this scenario started and hands back
/// each one's freshly-reloaded, on-disk id_store for the `Then` steps
/// below to inspect.
async fn end_all(w: &mut AlooWorld) {
    let names: Vec<String> = w.daemons.keys().cloned().collect();
    for name in names {
        let daemon = w.daemons.remove(&name).unwrap();
        let store = daemon.end().await;
        w.ended_id_stores.insert(name, store);
    }
}

#[then(expr = "{word}'s on-disk identity store pins {word} to {word}'s newly connected key, under a new device")]
async fn pins_the_new_key(w: &mut AlooWorld, holder: String, subject: String, subject2: String) {
    assert_eq!(subject, subject2, "scenario wiring: the same subject named twice");
    end_all(w).await;
    let store = w.ended_id_stores.get(&holder).expect("session was never ended");
    let new_identity = keybundle(&subject, "own");
    let new_der = aloo::client::connect::resolve_my_keypair(&new_identity)
        .expect("new identity should resolve")
        .public_der;
    // The real device_id `subject`'s own live session actually announces
    // - the same ambient `~/.aloo/d_id` every live session in this run
    // reads (`client::device_id::load_or_create`), keyed to `subject`'s
    // own nickname - not the arbitrary label the pre-existing pin was
    // seeded under: `Accept` files the new key under whichever device the
    // connection actually announced, additively, never reusing the old
    // device's own entry.
    let real_device_id = aloo::client::device_id::load_or_create(
        &aloo::client::device_id::default_path(),
        &subject,
    )
    .expect("this process's own device id should resolve");
    assert_eq!(
        store.get_for_device(&subject, &real_device_id),
        Some(new_der.as_slice()),
        "{holder}'s on-disk store should pin {subject}'s real, newly-connected key under the device that actually connected"
    );
    assert!(
        store.devices_of(&subject).count() >= 2,
        "the old, pre-existing pin must still be there too - additive, never replaced (device-pinning plan §2)"
    );
}

#[then(expr = "{word}'s on-disk identity store records {word}'s last-seen address")]
async fn records_last_seen(w: &mut AlooWorld, holder: String, subject: String) {
    // Both sides are already members of the same channel by the time this
    // step runs (`{word} joins the server for real` already waited for
    // that), but the direct P2P link and its `DeviceIdAnnounce` are a
    // second, independent step behind it - `maybe_resolve_p2p_identity_data`
    // only records anything once *both* have completed
    // (`docs/PROTOCOL.md` §12.7). Over real loopback that is normally
    // sub-second; polled - reading a fresh, independent `IdStore::load`
    // off the same path while the session is still running, never the
    // session's own in-memory copy - rather than a single fixed wait, so
    // this is no slower than it has to be, and the session is only ever
    // torn down once, after the condition is already met or timed out.
    let path = w
        .daemons
        .get(&holder)
        .expect(&format!("{holder} has no live daemon session"))
        .id_store_path
        .clone();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if IdStore::load(&path).is_ok_and(|s| s.last_addr(&subject).is_some()) {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            end_all(w).await;
            panic!(
                "{holder}'s on-disk store never recorded an address for {subject} - \
                 their direct link never reached Active in time"
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    end_all(w).await;
    let store = w.ended_id_stores.get(&holder).expect("session was never ended");
    assert!(store.last_addr(&subject).is_some());
}

// ---------------------------------------------------------------------
// Live coverage for the durable send queue (US-064)
// ---------------------------------------------------------------------

/// Ends one side's session for real - the server sees the connection go,
/// frees the nickname, and tells everyone else. This is "they went
/// offline", not a simulation of it.
#[when(expr = "{word} goes offline for real")]
#[given(expr = "{word} has gone offline for real")]
async fn goes_offline_for_real(w: &mut AlooWorld, nickname: String) {
    let daemon = w
        .daemons
        .remove(&nickname)
        .unwrap_or_else(|| panic!("{nickname} has no live daemon session"));
    daemon.stop().await;
    // Their departure has to have *reached* the other side before a send
    // to them means anything: until it does, that side still holds a
    // live link to them and the message goes out over it into nothing.
    // Asserted rather than merely waited on - a silent timeout here made
    // a queueing test pass through a path that never queued.
    for other in w.daemons.keys().cloned().collect::<Vec<_>>() {
        let holder = daemon_of(w, &other);
        let seen = holder
            .wait_for(&format!("{nickname} disconnected"), Duration::from_secs(40))
            .await;
        assert!(
            seen,
            "{other} never learned that {nickname} had gone - nothing after this would \
             be testing what it claims to"
        );
    }
}

/// Opens `subject`'s private room and sends one message, driving the real
/// compose bar - the whole point being that this is the path a user
/// takes, refusals and all.
#[given(expr = "{word} sends {word} the private message {string} for real")]
#[when(expr = "{word} sends {word} the private message {string} for real")]
async fn sends_private_for_real(
    w: &mut AlooWorld,
    sender: String,
    subject: String,
    text: String,
) {
    open_room_for_real(w, &sender, &subject).await;
    let daemon = daemon_of(w, &sender);
    daemon.type_text(&text);
    daemon.key(KeyCode::Enter);
    // Give the session a moment to actually process the send before the
    // scenario asserts on what it produced.
    let _ = daemon.wait_for(&text, Duration::from_secs(5)).await;
}

/// Opens `subject`'s private room from `holder`'s sidebar, exactly as a
/// person does: onto the sidebar, then Enter on a row, walking down until
/// one of them actually opens a room.
///
/// Walked rather than counted because the sidebar is sorted by nickname,
/// so which row is whose depends on the names a scenario chose - and
/// Enter on your own row is a no-op, which is precisely the case this has
/// to step past. A private room draws no member sidebar, so a frame
/// arriving without one is what says a room genuinely opened.
async fn open_room_for_real(w: &mut AlooWorld, holder: &str, subject: &str) {
    if daemon_of(w, holder).open_room.as_deref() == Some(subject) {
        return;
    }
    // The room's own pane title, which nothing else on screen draws -
    // a positive signal, unlike "the member sidebar is gone", which any
    // partial redraw (a CPU figure ticking over) satisfies by accident.
    let title = format!("Private: {subject}");
    daemon_of(w, holder).key(KeyCode::Tab);
    for _ in 0..6 {
        daemon_of(w, holder).key(KeyCode::Enter);
        if daemon_of(w, holder)
            .wait_for(&title, Duration::from_secs(2))
            .await
        {
            daemon_of(w, holder).open_room = Some(subject.to_string());
            return;
        }
        daemon_of(w, holder).key(KeyCode::Down);
    }
    panic!(
        "{holder} could not open a private room with {subject}: {}",
        daemon_of(w, holder).screen
    );
}

#[given(expr = "{word} opens the private room with {word} for real")]
#[when(expr = "{word} opens the private room with {word} for real")]
async fn opens_room_for_real(w: &mut AlooWorld, holder: String, subject: String) {
    open_room_for_real(w, &holder, &subject).await;
}

#[then(expr = "{word}'s screen never showed {string}")]
async fn screen_never_showed(w: &mut AlooWorld, holder: String, needle: String) {
    let daemon = daemon_of(w, &holder);
    assert!(
        !daemon.has_shown(&needle),
        "{holder}'s screen should never have shown {needle:?}: {}",
        daemon.screen
    );
}

/// Reconnects somebody who went offline, with the same nickname - which
/// the server gives a brand-new `UserId`, the case a queue keyed by
/// nickname exists to survive.
#[when(expr = "{word} comes back for real, into {string}")]
async fn comes_back_for_real(w: &mut AlooWorld, nickname: String, channel: String) {
    let my_key = keybundle(&nickname, "own");
    let id_store = IdStore::new_empty(scratch_dir(&format!("idstore-{nickname}-again")).join("ids_store"));
    start_daemon(w, &nickname, my_key, id_store, &channel).await;
}

#[then(expr = "dump {word}'s screen")]
async fn dump_screen(w: &mut AlooWorld, holder: String) {
    let daemon = daemon_of(w, &holder);
    let _ = daemon.wait_for("~~never~~", Duration::from_millis(400)).await;
    eprintln!("=== {holder} ===\n{}\n=== end ===", daemon.screen);
}

/// What this session actually wrote to its own queue - read off disk,
/// beside its `id_store`, never from memory.
#[then(expr = "{word} has {int} message held for {word}")]
#[then(expr = "{word} has {int} messages held for {word}")]
async fn holds_queued_for(w: &mut AlooWorld, holder: String, count: usize, subject: String) {
    let dir = aloo::client::outbox::dir_beside(daemon_of(w, &holder).id_store_path.as_path());
    // Queueing is what the session does *after* the send returns - the
    // transport raises "could not deliver this" and the session loop
    // acts on it - so this waits for the write rather than assuming it
    // has already happened.
    let mut held = 0;
    for _ in 0..40 {
        held = aloo::client::outbox::Outbox::load(&dir).len_for(&subject);
        if held == count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("{holder} should be holding {count} message(s) for {subject} in {dir:?}, holds {held}");
}
