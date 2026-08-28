//! Tests for the connect-popup field cache (`~/.aloo/.cache`) and the
//! `pq_hybrid` auto-generation it enables (`docs/PROTOCOL.md` §13.9). Pure
//! file/logic, no live socket - unlike the rest of `connect.rs`, which
//! needs one (`docs/TESTING.md`'s exception list).

use std::path::PathBuf;

use aloo::client::connect::MyKeySelection;
use aloo::client::connect::{
    ConnectCache, cache_path, fresh_pq_hybrid_paths_in, prefill_connect_defaults,
    random_prefix, resolve_my_keypair, run_with_processing_screen,
};
use aloo::client::tui::surface::Surface;
use aloo::client::tui::ui_connect_popup::ConnectPopupState;
use aloo::settings::Settings;

fn temp_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "aloo-connect-test-{label}-{}-{}",
        std::process::id(),
        fastrand_seed()
    ))
}

fn fastrand_seed() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

// ---------------------------------------------------------------------
// ConnectCache
// ---------------------------------------------------------------------

/// @requirement TB-132
#[test]
fn connect_cache_load_of_a_missing_file_is_empty_not_an_error() {
    let path = temp_path("missing");
    let cache = ConnectCache::load(&path).expect("missing file should not be an error");
    assert_eq!(cache.most_recent(), None);
}

/// @requirement AC-087
#[test]
fn connect_cache_round_trips_through_save_and_load() {
    let path = temp_path("roundtrip");
    {
        let mut cache = ConnectCache::new_empty(path.clone());
        cache.record(
            "chat.example.com",
            6667,
            "/home/me/.aloo/ab12.pub",
            "/home/me/.aloo/ab12.priv",
        );
        cache.save().expect("save should succeed");
    }
    {
        let cache = ConnectCache::load(&path).expect("load should succeed");
        assert_eq!(
            cache.most_recent(),
            Some((
                "chat.example.com",
                6667,
                "/home/me/.aloo/ab12.pub",
                "/home/me/.aloo/ab12.priv"
            ))
        );
    }
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-132
#[test]
fn connect_cache_record_moves_an_existing_pair_to_most_recent() {
    let path = temp_path("reorder");
    let mut cache = ConnectCache::new_empty(path);
    cache.record("alice.example.com", 1, "/a.pub", "/a.priv");
    cache.record("bob.example.com", 2, "/b.pub", "/b.priv");
    assert_eq!(
        cache.most_recent(),
        Some(("bob.example.com", 2, "/b.pub", "/b.priv"))
    );

    // Re-recording the first pair (with new file values) must move it back
    // to "most recent", not just sit duplicated behind bob's entry.
    cache.record("alice.example.com", 1, "/a2.pub", "/a2.priv");
    assert_eq!(
        cache.most_recent(),
        Some(("alice.example.com", 1, "/a2.pub", "/a2.priv"))
    );
}

/// @requirement TB-132
#[test]
fn connect_cache_load_skips_malformed_lines() {
    let path = temp_path("malformed");
    std::fs::write(
        &path,
        "alice.example.com\t6667\t/a.pub\t/a.priv\n\
         not-enough-fields\n\
         bob.example.com\tnot-a-port\t/b.pub\t/b.priv\n\
         carol.example.com\t9999\t/c.pub\t/c.priv\n",
    )
    .unwrap();
    let cache = ConnectCache::load(&path).expect("a partially-corrupt file should still load");
    // The last *validly parsed* line is carol's - the malformed lines in
    // between are skipped entirely, not counted as entries at all.
    assert_eq!(
        cache.most_recent(),
        Some(("carol.example.com", 9999, "/c.pub", "/c.priv"))
    );
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-132
#[test]
fn connect_cache_record_rejects_fields_containing_the_delimiter() {
    let path = temp_path("delimiter");
    let mut cache = ConnectCache::new_empty(path);
    cache.record("evil\thost", 1, "/a.pub", "/a.priv");
    assert_eq!(
        cache.most_recent(),
        None,
        "a host containing a tab must never be stored"
    );
    cache.record("host", 1, "/a\n.pub", "/a.priv");
    assert_eq!(
        cache.most_recent(),
        None,
        "a path containing a newline must never be stored"
    );
}

/// @requirement TB-132
#[test]
fn connect_cache_save_creates_missing_parent_directories() {
    let dir = temp_path("dir");
    let path = dir.join("nested").join(".cache");
    let mut cache = ConnectCache::new_empty(path.clone());
    cache.record("host", 1, "/a.pub", "/a.priv");
    cache.save().expect("save should create parent dirs");
    assert!(path.is_file());
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement TB-132
#[test]
fn cache_path_always_resolves_under_the_dot_aloo_home_directory() {
    let path = cache_path();
    assert_eq!(path.file_name(), Some(std::ffi::OsStr::new(".cache")));
    assert_eq!(
        path.parent().and_then(|p| p.file_name()),
        Some(std::ffi::OsStr::new(".aloo")),
        "the cache must always live under ~/.aloo, never a local/cwd file: {path:?}"
    );
}

// ---------------------------------------------------------------------
// random_prefix / fresh_pq_hybrid_paths_in
// ---------------------------------------------------------------------

/// @requirement AC-085
#[test]
fn random_prefix_is_four_lowercase_alphanumeric_characters() {
    let prefix = random_prefix();
    assert_eq!(prefix.chars().count(), 4);
    assert!(
        prefix
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "expected only lowercase letters/digits, got {prefix:?}"
    );
}

/// @requirement AC-085
#[test]
fn fresh_pq_hybrid_paths_in_produces_a_pub_and_priv_pair_under_the_given_directory() {
    let dir = temp_path("fresh-dir");
    let (file_pub, file_priv) = fresh_pq_hybrid_paths_in(&dir);
    assert_eq!(file_pub.parent(), Some(dir.as_path()));
    assert_eq!(file_priv.parent(), Some(dir.as_path()));
    assert_eq!(file_pub.extension(), Some(std::ffi::OsStr::new("pub")));
    assert_eq!(file_priv.extension(), Some(std::ffi::OsStr::new("priv")));
    // Same random prefix on both halves of the pair.
    assert_eq!(file_pub.file_stem(), file_priv.file_stem());
    assert!(
        !file_pub.exists() && !file_priv.exists(),
        "neither file should be created yet"
    );
}

/// @requirement TB-133
#[test]
fn fresh_pq_hybrid_paths_in_avoids_an_existing_colliding_prefix() {
    let dir = temp_path("collide-dir");
    std::fs::create_dir_all(&dir).unwrap();
    // Force a collision on whatever prefix comes out first by pre-creating
    // every file the function could possibly try, for a tiny alphabet
    // slice - instead, more simply: call the function once to learn a
    // real prefix, then pre-create *that exact* pair, and confirm a
    // second call never returns the same, now-taken, pair.
    let (first_pub, first_priv) = fresh_pq_hybrid_paths_in(&dir);
    std::fs::write(&first_pub, b"taken").unwrap();
    std::fs::write(&first_priv, b"taken").unwrap();

    let (second_pub, second_priv) = fresh_pq_hybrid_paths_in(&dir);
    assert_ne!(
        second_pub, first_pub,
        "must not reuse a prefix whose files already exist"
    );
    assert_ne!(second_priv, first_priv);
    assert!(!second_pub.exists() && !second_priv.exists());

    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------
// prefill_connect_defaults
// ---------------------------------------------------------------------

/// @requirement AC-085
#[test]
fn prefill_connect_defaults_assigns_a_fresh_location_when_the_cache_is_empty() {
    let dir = temp_path("prefill-empty-dir");
    let cache = ConnectCache::new_empty(temp_path("prefill-empty-cache"));
    let mut popup = ConnectPopupState::new();
    let original_host = popup.host.clone();

    prefill_connect_defaults(&mut popup, &Settings::default(), &cache, &dir);

    assert_eq!(
        popup.host, original_host,
        "host is left alone when there's nothing to restore"
    );
    assert!(!popup.my_key.file_pub.is_empty());
    assert!(!popup.my_key.file_priv.is_empty());
    assert!(PathBuf::from(&popup.my_key.file_pub).starts_with(&dir));
    assert!(PathBuf::from(&popup.my_key.file_priv).starts_with(&dir));
}

/// @requirement AC-087
#[test]
fn prefill_connect_defaults_restores_the_most_recent_cache_entry() {
    let dir = temp_path("prefill-hit-dir");
    let mut cache = ConnectCache::new_empty(temp_path("prefill-hit-cache"));
    cache.record(
        "chat.example.com",
        6667,
        "/keys/ab12.pub",
        "/keys/ab12.priv",
    );
    let mut popup = ConnectPopupState::new();

    prefill_connect_defaults(&mut popup, &Settings::default(), &cache, &dir);

    assert_eq!(popup.host, "chat.example.com");
    assert_eq!(popup.port, "6667");
    assert_eq!(popup.my_key.file_pub, "/keys/ab12.pub");
    assert_eq!(popup.my_key.file_priv, "/keys/ab12.priv");
}

// ---------------------------------------------------------------------
// resolve_my_keypair - auto-generation (real keygen, #[ignore]d)
// ---------------------------------------------------------------------

/// Two halves that both exist but come from different keybundles are
/// refused rather than connected with.
///
/// `ensure_bundle_at` only guards the half-*missing* case (TB-134), so
/// nothing before this caught a crossed pair - and a crossed pair has no
/// local symptom at all: it signs every send, rotation and identity card
/// with a key no peer can verify against.
/// @requirement TB-284
#[test]
#[ignore = "real ML-DSA-87/ML-KEM-1024/RSA-4096 x2 keygen, several seconds - run with cargo slow"]
fn resolve_my_keypair_refuses_a_mismatched_pair() {
    let dir = temp_path("resolve-mismatched-dir");
    std::fs::create_dir_all(&dir).unwrap();
    let file_pub = dir.join("crossed.pub");
    let file_priv = dir.join("crossed.priv");

    // Two independent bundles; keep A's private half beside B's public one.
    let (pub_a, priv_a) = aloo::crypto::pq::generate_bundle().unwrap();
    let (pub_b, _priv_b) = aloo::crypto::pq::generate_bundle().unwrap();
    aloo::crypto::pq::save_private_bundle(&priv_a, &file_priv).unwrap();
    aloo::crypto::pq::save_public_bundle(&pub_b, &file_pub).unwrap();
    assert_ne!(
        aloo::crypto::pq::bundle_fingerprint(&pub_a).unwrap(),
        aloo::crypto::pq::bundle_fingerprint(&pub_b).unwrap()
    );

    // `let ... else` rather than `expect_err`: `ResolvedIdentity` carries a
    // private bundle and deliberately does not implement `Debug`, so the
    // Ok half must never be formatted.
    let Err(err) = resolve_my_keypair(&MyKeySelection {
        file_pub: file_pub.clone(),
        file_priv: file_priv.clone(),
    }) else {
        panic!("a mismatched pair must not resolve");
    };
    let message = err.to_string();
    assert!(
        message.contains("not two halves of the same keybundle"),
        "the refusal must say what is actually wrong, got: {message}"
    );
    assert!(
        message.contains(&file_priv.display().to_string())
            && message.contains(&file_pub.display().to_string()),
        "and name both files, got: {message}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-086
#[test]
#[ignore = "real ML-DSA-87/ML-KEM-1024/RSA-4096 x2 keygen, several seconds - run with cargo slow"]
fn resolve_my_keypair_autogenerates_a_missing_pq_hybrid_bundle() {
    let dir = temp_path("resolve-autogen-dir");
    let file_pub = dir.join("gen.pub");
    let file_priv = dir.join("gen.priv");
    assert!(!file_pub.exists() && !file_priv.exists());

    let sel = MyKeySelection {
        file_pub: file_pub.clone(),
        file_priv: file_priv.clone(),
    };
    let identity = resolve_my_keypair(&sel).expect("should autogenerate and load successfully");

    assert!(
        aloo::crypto::pq::fingerprint_of_encoded(&identity.public_der).is_some(),
        "the loaded identity's public half is a real keybundle"
    );
    assert!(
        file_pub.is_file(),
        "the public bundle should now exist on disk"
    );
    assert!(
        file_priv.is_file(),
        "the private bundle should now exist on disk"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------
// Which resolved address the client connects to
// ---------------------------------------------------------------------

/// The reason this preference exists is the UDP rendezvous riding the same
/// host and port, not the TCP connection: a dual-stack server behind
/// Docker's default port publishing answers STUN over IPv6 with the bridge's
/// own address, which is unusable as a reflexive candidate and costs
/// cross-network punching entirely.
///
/// @requirement TB-205
#[test]
fn a_host_with_both_families_resolves_to_its_ipv4_address() {
    use aloo::client::connect::prefer_ipv4;
    let addrs = vec![
        "[2001:db8::1]:7878".parse().unwrap(),
        "203.0.113.5:7878".parse().unwrap(),
    ];
    assert_eq!(
        prefer_ipv4(&addrs),
        Some("203.0.113.5:7878".parse().unwrap()),
        "IPv4 must win even when the resolver returned the AAAA record first"
    );
}

/// @requirement TB-205
#[test]
fn an_ipv6_only_host_still_resolves() {
    use aloo::client::connect::prefer_ipv4;
    let addrs: Vec<std::net::SocketAddr> = vec!["[2001:db8::1]:7878".parse().unwrap()];
    assert_eq!(
        prefer_ipv4(&addrs),
        Some("[2001:db8::1]:7878".parse().unwrap()),
        "preferring IPv4 must never become requiring it - an AAAA-only host is reachable"
    );
}

/// Order inside a family is the resolver's to decide (round-robin, RFC 6724
/// sorting), so the preference must reorder families without disturbing it.
///
/// @requirement TB-205
#[test]
fn resolver_order_within_ipv4_is_preserved() {
    use aloo::client::connect::prefer_ipv4;
    let addrs = vec![
        "[2001:db8::1]:7878".parse().unwrap(),
        "203.0.113.5:7878".parse().unwrap(),
        "198.51.100.9:7878".parse().unwrap(),
    ];
    assert_eq!(
        prefer_ipv4(&addrs),
        Some("203.0.113.5:7878".parse().unwrap()),
        "the first IPv4 record the resolver returned is the one to use"
    );
}

/// An empty list is a resolution failure, which the caller turns into a
/// "no addresses for host:port" error rather than connecting to something.
///
/// @requirement TB-205
#[test]
fn a_host_that_resolves_to_nothing_yields_no_address() {
    use aloo::client::connect::prefer_ipv4;
    assert_eq!(prefer_ipv4(&[]), None);
}

/// The nickname has nowhere else to live: `.cache` is keyed by
/// `(host, port)` and holds key files only, so it has no slot for the one
/// field that is about the person rather than the server. Without
/// `connect_nickname` every fresh start would propose `$USER` however
/// often someone connected as somebody else.
/// @requirement AC-240
#[test]
fn prefill_connect_defaults_restores_the_last_nickname_from_settings() {
    let dir = temp_path("prefill-nick-dir");
    let cache = ConnectCache::new_empty(temp_path("prefill-nick-cache"));
    let settings = Settings {
        connect_host: Some("chat.example.com".to_string()),
        connect_port: Some(6667),
        connect_nickname: Some("dave".to_string()),
        ..Settings::default()
    };
    let mut popup = ConnectPopupState::new();

    prefill_connect_defaults(&mut popup, &settings, &cache, &dir);

    assert_eq!(popup.nickname, "dave");
    assert_eq!(popup.host, "chat.example.com");
    assert_eq!(popup.port, "6667");
}

/// Two stores answer the same question about the host and port, and the
/// hand-editable one wins: `connect_host` is a deliberate answer, the
/// cache is the older and less specific record. The keybundle paths still
/// come from the cache, which is the only store that has them.
/// @requirement AC-240
#[test]
fn settings_beat_the_cache_for_host_and_port_but_not_for_the_keybundle() {
    let dir = temp_path("prefill-precedence-dir");
    let mut cache = ConnectCache::new_empty(temp_path("prefill-precedence-cache"));
    cache.record(
        "cached.example.com",
        1111,
        "/keys/ab12.pub",
        "/keys/ab12.priv",
    );
    let settings = Settings {
        connect_host: Some("settings.example.com".to_string()),
        connect_port: Some(2222),
        ..Settings::default()
    };
    let mut popup = ConnectPopupState::new();

    prefill_connect_defaults(&mut popup, &settings, &cache, &dir);

    assert_eq!(popup.host, "settings.example.com");
    assert_eq!(popup.port, "2222");
    assert_eq!(popup.my_key.file_pub, "/keys/ab12.pub");
    assert_eq!(popup.my_key.file_priv, "/keys/ab12.priv");
}

/// Nothing recorded yet, so whatever the caller already put in the popup
/// (`$USER`) stands.
/// @requirement AC-240
#[test]
fn an_empty_settings_file_leaves_the_proposed_nickname_alone() {
    let dir = temp_path("prefill-nonick-dir");
    let cache = ConnectCache::new_empty(temp_path("prefill-nonick-cache"));
    let mut popup = ConnectPopupState::new();
    popup.nickname = "whoami".to_string();

    prefill_connect_defaults(&mut popup, &Settings::default(), &cache, &dir);

    assert_eq!(popup.nickname, "whoami");
}

// ---------------------------------------------------------------------
// run_with_processing_screen: keeps the screen animating (instead of
// frozen on the popup's last frame) while a Connect/Register attempt is
// actually in flight. Generic over any future - no live socket needed to
// exercise the screen-driving/return-value behavior itself, so this
// stays within this file's "no live socket" scope even though it lives
// in `connect.rs` alongside the socket-touching code that calls it.
// ---------------------------------------------------------------------

/// The wrapper must hand back exactly what the wrapped future resolved
/// to - it only changes what's on screen while waiting, never the
/// outcome.
/// @requirement AC-371
#[tokio::test]
async fn run_with_processing_screen_returns_the_futures_own_output() {
    let mut surface = Surface::Detached;
    let result = run_with_processing_screen(&mut surface, async { 42 }, "connecting...").await;
    assert_eq!(result, 42);
}

/// Proves it actually waits for the future rather than racing ahead of
/// it: a future that takes noticeably longer than one animation tick
/// must still make the wrapper take at least that long.
/// @requirement AC-371
#[tokio::test]
async fn run_with_processing_screen_waits_for_a_slow_future() {
    let mut surface = Surface::Detached;
    let started = std::time::Instant::now();
    run_with_processing_screen(
        &mut surface,
        tokio::time::sleep(std::time::Duration::from_millis(250)),
        "connecting...",
    )
    .await;
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(250),
        "must not return before the wrapped future actually resolves"
    );
}

/// A `Detached` surface (a daemon with nobody watching, `Surface`'s own
/// doc) makes every `draw` a no-op - the wrapper must not care, and must
/// neither panic nor hang.
/// @requirement AC-371
#[tokio::test]
async fn run_with_processing_screen_tolerates_a_detached_surface() {
    let mut surface = Surface::Detached;
    let result = run_with_processing_screen(&mut surface, async { "done" }, "one moment...").await;
    assert_eq!(result, "done");
}

/// `run_with_processing_screen` only ever gets a chance to poll its own
/// redraw+sleep branch at a genuine `.await` suspension point inside the
/// wrapped future - it cannot preempt a long *synchronous* stretch with
/// no such point in it (the shape `resolve_my_keypair`'s auto-keygen has,
/// `connect_and_handshake`'s own doc). Proven by racing an independent
/// `tokio::spawn`'d ticker against two shapes of the same 200ms of
/// synchronous work: left in-task, it starves the ticker (and would
/// starve the animation exactly the same way); moved off-task via
/// `spawn_blocking` - `connect_and_handshake`'s own handling of
/// `resolve_my_keypair` - the ticker keeps advancing throughout.
/// @requirement AC-373
#[tokio::test]
async fn a_long_synchronous_stretch_must_be_moved_off_task_or_it_still_freezes() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    async fn ticks_during<T>(fut: impl std::future::Future<Output = T>) -> u32 {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                c.fetch_add(1, Ordering::Relaxed);
            }
        });
        let mut surface = Surface::Detached;
        run_with_processing_screen(&mut surface, fut, "connecting...").await;
        ticker.abort();
        counter.load(Ordering::Relaxed)
    }

    let unmoved = ticks_during(async {
        std::thread::sleep(std::time::Duration::from_millis(200));
    })
    .await;

    let moved = ticks_during(async {
        tokio::task::spawn_blocking(|| std::thread::sleep(std::time::Duration::from_millis(200)))
            .await
            .unwrap();
    })
    .await;

    assert!(
        moved > unmoved,
        "moving synchronous work off-task via spawn_blocking must let other tokio tasks \
         keep making progress while it runs; unmoved={unmoved} moved={moved}"
    );
}
