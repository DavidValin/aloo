//! Tests for the connect-popup field cache (`~/.aloo/.cache`) and the
//! `pq_hybrid` auto-generation it enables (`docs/PROTOCOL.md` §13.9). Pure
//! file/logic, no live socket - unlike the rest of `connect.rs`, which
//! needs one (`docs/TESTING.md`'s exception list).

use std::path::PathBuf;

use aloo::client::connect::{
    ConnectCache, ResolvedIdentity, cache_path, fresh_pq_hybrid_paths_in, prefill_connect_defaults,
    random_prefix, resolve_my_keypair,
};
use aloo::client::connect::MyKeySelection;
use aloo::client::tui::ui_connect_popup::{ConnectPopupState, MyKeyType};

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

    prefill_connect_defaults(&mut popup, &cache, &dir);

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

    prefill_connect_defaults(&mut popup, &cache, &dir);

    assert_eq!(popup.host, "chat.example.com");
    assert_eq!(popup.port, "6667");
    assert_eq!(popup.my_key.key_type, MyKeyType::PqHybrid);
    assert_eq!(popup.my_key.file_pub, "/keys/ab12.pub");
    assert_eq!(popup.my_key.file_priv, "/keys/ab12.priv");
}

// ---------------------------------------------------------------------
// resolve_my_keypair - auto-generation (real keygen, #[ignore]d)
// ---------------------------------------------------------------------

/// @requirement AC-086
#[test]
#[ignore = "real ML-DSA-87/ML-KEM-1024/RSA-4096 x2 keygen, several seconds - run with cargo slow"]
fn resolve_my_keypair_autogenerates_a_missing_pq_hybrid_bundle() {
    let dir = temp_path("resolve-autogen-dir");
    let file_pub = dir.join("gen.pub");
    let file_priv = dir.join("gen.priv");
    assert!(!file_pub.exists() && !file_priv.exists());

    let sel = MyKeySelection::PqHybrid {
        file_pub: file_pub.clone(),
        file_priv: file_priv.clone(),
    };
    let (identity, key_mode) =
        resolve_my_keypair(&sel).expect("should autogenerate and load successfully");

    assert_eq!(key_mode, aloo::proto::KeyMode::PqHybrid);
    assert!(matches!(identity, ResolvedIdentity::Pq { .. }));
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
