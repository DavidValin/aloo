//! End-to-end tests for a daemon session running with **no server at all**
//! (`aloo --daemon --no-server`, `docs/PROTOCOL.md` §7.1.5).
//!
//! Everything else under `session.rs` needs a live server socket and is
//! therefore only covered indirectly (see `docs/TESTING.md`'s known
//! coverage gaps). A serverless session is the exception, and the reason is
//! the whole point of the mode: there is no control connection to stand up,
//! no rendezvous to answer, and - as a daemon - no terminal either. What is
//! left is drivable in-process:
//!
//! - the control channel is `control::NullSink`, and the reader is `None`;
//! - the "terminal" is `SessionInput::Attached`, which hands the session an
//!   `AttachWriter` - a plain channel of rendered bytes, so what a viewer
//!   would see is readable straight off a receiver;
//! - dropping the input sender ends the loop cleanly.
//!
//! So these drive the real `run_daemon_session`, with real settings on
//! disk, and assert on what someone attaching a terminal actually sees.
//!
//! Identity is the one real cost: a `pq_hybrid` bundle carries an RSA
//! signing key. The bundles here use a small modulus (`TEST_BITS`) and are
//! generated once for the whole file, the same trade every other test that
//! needs real key material makes - nothing here asserts key size.

/// Modulus for the scenario bundles - see `shared_home`.
const TEST_BITS: usize = 1024;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use aloo::client::daemon::{DaemonChannel, DaemonFocus, DaemonPlan};
use aloo::client::session::{SessionInput, run_daemon_session};
use aloo::client::tui::surface::{AttachWriter, Surface, TerminalSize};
use aloo::control::NullSink;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// One temp `ALOO_HOME` for the whole file, with a `pq_hybrid` bundle
/// generated once inside it.
///
/// `ALOO_HOME` is process-global, so every test here shares this one
/// directory and the tests are serialised (see `SERIAL`) rather than each
/// mutating the environment underneath the others.
fn shared_home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "aloo-daemon-session-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // A small modulus, the same reason `identity_continuity_test` and
        // `voice_stream_test` use one: nothing here asserts key *size*,
        // and a real RSA-4096 keygen is what puts a dozen other tests
        // behind `cargo slow`. Generated once and shared by every test.
        for who in ["alice", "bob"] {
            let (public, private) = aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS)
                .expect("generating a pq_hybrid bundle");
            aloo::crypto::pq::save_private_bundle(&private, &dir.join(format!("{who}.priv")))
                .unwrap();
            aloo::crypto::pq::save_public_bundle(&public, &dir.join(format!("{who}.pub"))).unwrap();
        }
        unsafe { std::env::set_var("ALOO_HOME", &dir) };
        dir
    })
}

/// Tests here mutate one shared `ALOO_HOME` and a settings file inside it,
/// so they run one at a time. An async mutex rather than `std`'s: the
/// guard is held across awaits for the whole of a test.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn write_settings(home: &Path, body: &str) {
    let mut f = std::fs::File::create(home.join("settings")).unwrap();
    f.write_all(body.as_bytes()).unwrap();
}

fn my_key(home: &Path, who: &str) -> aloo::client::connect::MyKeySelection {
    aloo::client::connect::MyKeySelection {
        file_pub: home.join(format!("{who}.pub")),
        file_priv: home.join(format!("{who}.priv")),
    }
}

/// The DER a peer's identity is pinned under - exactly what a server would
/// have relayed as `UserInfo::public_key_der`.
fn public_der(home: &Path, who: &str) -> Vec<u8> {
    aloo::client::connect::resolve_my_keypair(&my_key(home, who))
        .unwrap()
        .public_der
}

/// A free UDP port, released immediately so the session under test can
/// bind it. Racy in principle, fine in practice and the ordinary way to
/// pick one.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One running session, with the handles a test drives it through.
struct Running {
    input_tx: tokio::sync::mpsc::UnboundedSender<SessionInput>,
    frames: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    handle: tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    screen: String,
}

impl Running {
    /// Reads frames until the screen says `needle`, or gives up. Driven by
    /// what is actually on screen rather than by a settle delay: the
    /// session redraws every tick, so it never goes quiet to wait for.
    ///
    /// Matched with whitespace removed from both sides. A terminal backend
    /// only writes the cells that changed and moves the cursor over the
    /// rest, so a run of spaces usually never reaches the byte stream at
    /// all - `alice: hello there` arrives as `alice:hellothere`. Comparing
    /// literally would fail on rendering, not on behaviour.
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
                    self.screen
                        .push_str(&strip_ansi(&String::from_utf8_lossy(&bytes)));
                }
                _ => return squash(&self.screen).contains(&needle),
            }
        }
    }

    /// Types `text` into the compose bar and presses Enter, as a person
    /// at an attached terminal would. Focus starts on the compose bar.
    fn send_text(&self, text: &str) {
        for c in text.chars() {
            self.key(KeyCode::Char(c));
        }
        self.key(KeyCode::Enter);
    }

    fn key(&self, code: KeyCode) {
        let _ = self.input_tx.send(SessionInput::Key(Event::Key(KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        })));
    }

    async fn end(self) {
        drop(self.input_tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
    }
}

/// Starts a serverless daemon session with a viewer already attached, so
/// what it draws is readable straight off `frames`.
fn start(
    nickname: &str,
    key_owner: &str,
    id_store: aloo::client::idstore::IdStore,
    plan: DaemonPlan,
) -> Running {
    let home = shared_home();
    let identity =
        aloo::client::connect::resolve_my_keypair(&my_key(home, key_owner)).expect("identity");

    let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel::<SessionInput>();
    let (frame_tx, frames) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let you = aloo::client::p2p::direct_peer_id(nickname);
    let name = nickname.to_string();
    let handle = tokio::spawn(async move {
        let mut surface = Surface::Detached;
        run_daemon_session(
            &mut surface,
            // No server: no reader, nothing to write to, no rendezvous.
            None,
            NullSink,
            name,
            you,
            identity,
            id_store,
            None,
            None,
            input_rx,
            plan,
        )
        .await
    });

    // Someone opens a terminal on it, exactly as `aloo` does when attaching.
    input_tx
        .send(SessionInput::Attached {
            writer: AttachWriter::new(frame_tx),
            size: TerminalSize {
                cols: 160,
                rows: 40,
            },
        })
        .expect("session should be accepting input");

    Running {
        input_tx,
        frames,
        handle,
        screen: String::new(),
    }
}

/// The single-session helper: start, wait for `needle`, hand back the
/// screen, end the session.
async fn attach_until(plan: DaemonPlan, needle: &str) -> String {
    let home = shared_home();
    let mut run = start(
        "omar",
        "alice",
        aloo::client::idstore::IdStore::new_empty(home.join("id_store_omar")),
        plan,
    );
    let found = run.wait_for(needle, Duration::from_secs(10)).await;
    let screen = run.screen.clone();
    run.end().await;
    assert!(found, "never saw {needle:?} on screen: {screen}");
    screen
}

/// Everything but whitespace - see `Running::wait_for`.
fn squash(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Drops CSI/OSC escape sequences, leaving the characters a person would
/// actually read on the screen.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.next() {
            // CSI: parameters, then a final byte in @..~
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            // OSC: runs to BEL or ST
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

/// `aloo --daemon --no-server --focus peter` with `direct_punch_channel=team`:
/// the channel from settings is there, the configured peer is nowhere yet,
/// and the screen says so instead of sitting blank.
///
/// @requirement AC-221, AC-220
#[tokio::test]
async fn a_serverless_daemon_shows_its_configured_channel_and_waits_for_peers() {
    let _guard = SERIAL.lock().await;
    let home = shared_home();
    write_settings(
        home,
        "direct_punch=on\n\
         direct_punch_port=0\n\
         direct_punch_channel=team\n\
         direct_punch_to=peter,127.0.0.1:65001,every_1m\n",
    );

    let screen = attach_until(
        DaemonPlan::new(
            Vec::new(),
            Some(DaemonFocus::Dm {
                nickname: "peter".into(),
                otp: false,
            }),
        ),
        // The channel named in direct_punch_channel is the one this client
        // is in, so it must be on screen.
        "team",
    )
    .await;

    assert!(
        screen.contains("Waiting for other users"),
        "nobody has punched in yet, and nothing else will explain the \
         silence: {screen}"
    );
    // Nothing invented a channel to discover the focused peer through -
    // there is no presence to watch for without a server.
    assert!(
        !screen.contains("the-hall"),
        "a serverless DM focus must not be given a discovery channel: {screen}"
    );
}

/// The channels a daemon was *asked* to join are joined at startup, not off
/// a `ChannelList` that will never arrive - otherwise `--channel` is
/// silently ignored on the one start where nobody is watching.
///
/// @requirement AC-221
#[tokio::test]
async fn a_serverless_daemon_joins_the_channel_it_was_given() {
    let _guard = SERIAL.lock().await;
    let home = shared_home();
    write_settings(
        home,
        "direct_punch=on\n\
         direct_punch_port=0\n\
         direct_punch_channel=team\n",
    );

    // `--channel team` must actually be joined with no server.
    attach_until(
        DaemonPlan::new(
            vec![DaemonChannel {
                name: "team".into(),
                password: None,
            }],
            None,
        ),
        "team",
    )
    .await;
}

/// A channel nothing configured cannot be joined without a server, and the
/// refusal says so rather than the join quietly going nowhere.
///
/// @requirement AC-219
#[tokio::test]
async fn a_channel_that_is_not_configured_is_refused_with_a_reason() {
    let _guard = SERIAL.lock().await;
    let home = shared_home();
    write_settings(home, "direct_punch=on\ndirect_punch_port=0\n");

    // The refusal must name what would fix it.
    attach_until(
        DaemonPlan::new(
            vec![DaemonChannel {
                name: "elsewhere".into(),
                password: None,
            }],
            None,
        ),
        "direct_punch_channel",
    )
    .await;
}

/// Two whole serverless sessions, in one process, punching a link to each
/// other and each ending up with the other listed in the channel they both
/// declared - the end-to-end shape of §7.1.5 with nothing simulated:
/// real sockets, real hole punching on the shared slot grid, a real sealed
/// `ChannelPresence` opened against a real pinned identity, and the result
/// read off what each side actually renders.
///
/// Two sessions share one `ALOO_HOME`, which would normally mean sharing
/// one settings file too - and they need different ports and different
/// peers. They can still each have their own, because settings are read
/// exactly once, at session start: alice is started and waited for (her
/// first frame proves she has read them), and only then is the file
/// rewritten for bob.
///
/// `#[ignore]`: the slot grid is wall-clock (§7.1.5 step 1), and the
/// shortest one steps once a minute, so this waits for a real minute
/// boundary. That is the same trade `heartbeat_timeout`'s scenario
/// documents - the mechanics are covered fast elsewhere, and what this
/// adds is that they compose.
///
/// Confirmed to be able to fail: with alice's pin for bob removed, she
/// punches the link exactly as before and then refuses to register him,
/// leaving the waiting line up and failing this test. The negative case is
/// not kept as a test of its own - `only_a_pinned_pq_hybrid_identity_can_
/// become_an_addressable_peer` proves the same rule in microseconds - but
/// it is what says this one is asserting something real.
///
/// @requirement AC-214, AC-215, AC-195, AC-196, AC-100
#[tokio::test]
#[ignore = "waits for a real wall-clock slot boundary - run by `cargo slow`"]
async fn two_serverless_sessions_punch_to_each_other_and_each_registers_the_other() {
    let _guard = SERIAL.lock().await;
    let home = shared_home();

    let (alice_port, bob_port) = (free_udp_port(), free_udp_port());
    assert_ne!(alice_port, bob_port);

    // Each has met the other before, so each holds the other's key. That
    // pin is the only thing that will let either believe a nickname.
    let mut alice_store = aloo::client::idstore::IdStore::new_empty(home.join("id_store_alice"));
    alice_store.check_and_pin("bob", &public_der(home, "bob"));
    let mut bob_store = aloo::client::idstore::IdStore::new_empty(home.join("id_store_bob"));
    bob_store.check_and_pin("alice", &public_der(home, "alice"));

    // Both grids restart at the same o'clock, so both fire at the next
    // minute boundary. Started just before one, rather than waiting a whole
    // step for the one after.
    let to_boundary = 60
        - (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            % 60);
    if to_boundary > 3 {
        tokio::time::sleep(Duration::from_secs(to_boundary - 3)).await;
    }

    let settings_for = |port: u16, peer: &str, peer_port: u16| {
        format!(
            "direct_punch=on\n\
             direct_punch_port={port}\n\
             direct_punch_channel=team\n\
             direct_punch_to={peer},127.0.0.1:{peer_port},every_1m\n"
        )
    };

    write_settings(home, &settings_for(alice_port, "bob", bob_port));
    let mut alice = start(
        "alice",
        "alice",
        alice_store,
        DaemonPlan::new(Vec::new(), None),
    );
    // Her first frame is proof the settings above have been read, so the
    // file is free to be rewritten for bob.
    assert!(
        alice.wait_for("team", Duration::from_secs(10)).await,
        "alice should be in the channel she declared: {}",
        alice.screen
    );

    write_settings(home, &settings_for(bob_port, "alice", alice_port));
    let mut bob = start("bob", "bob", bob_store, DaemonPlan::new(Vec::new(), None));

    // From here nothing is driven: the two sessions punch on their own
    // schedule, exchange a sealed ChannelPresence, and place each other.
    let punch_window = Duration::from_secs(75);
    let saw_bob = alice.wait_for("bob", punch_window).await;
    let saw_alice = bob.wait_for("alice", punch_window).await;

    // The link is up and each knows who the other is - so an ordinary
    // channel message must now travel over it, with no server anywhere.
    let delivered = if saw_bob && saw_alice {
        alice.send_text("hello over the punch");
        bob.wait_for("hello over the punch", Duration::from_secs(15))
            .await
    } else {
        false
    };

    let (alice_screen, bob_screen) = (alice.screen.clone(), bob.screen.clone());
    alice.end().await;
    bob.end().await;

    assert!(
        saw_bob,
        "alice never registered bob - punched, authenticated and placed in \
         the channel they both declared: {alice_screen}"
    );
    assert!(saw_alice, "bob never registered alice: {bob_screen}");
    // Registered as a real member, with the encryption tag every other
    // member carries - not merely a name that happened to be drawn.
    assert!(
        squash(&alice_screen).contains(&squash("bob 🛡️ PQH")),
        "bob should be listed as an ordinary pq_hybrid member: {alice_screen}"
    );
    assert!(
        delivered,
        "the whole point of the link: an ordinary channel message must reach \
         bob over it with no server involved: {bob_screen}"
    );
}
