//! Tests for `src/server/federation`: the directory's ownership/conflict
//! bookkeeping on its own, and a real PQ-hybrid-authenticated peer link
//! between two in-process servers proving the handshake, the initial
//! directory snapshot, and incremental gossip all actually work end to
//! end (docs/PROTOCOL.md's federation section).

#[path = "server_common.rs"]
mod server_common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aloo::control::{ControlEndpoint, ControlReader, ControlWriter};
use aloo::proto::{ChannelInfo, ChannelJoinRejection, ChannelKind, ClientMessage, ServerMessage};
use aloo::server::federation::directory::{FederationDirectory, Ownership};
use aloo::server::federation::handshake::{self, FederationTrust, HandshakeError};
use aloo::server::federation::proto::{FederatedChannelInfo, FederationMessage};
use aloo::server::federation::{self, FederationConfig};
use aloo::settings::FederationPeerConfig;

/// Small RSA modulus for test keygen - matches the `TEST_BITS` convention
/// every other PQ-hybrid test in this suite uses
/// (`crypto::pq::generate_bundle_with_bits`'s doc): the PQ halves
/// (ML-DSA-87/ML-KEM-1024) are always the real parameter sets, only the
/// classical RSA hedge shrinks, and only for tests that never assert on it.
const TEST_BITS: usize = 1024;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-federation-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------
// FederationDirectory - pure bookkeeping, no sockets.
// ---------------------------------------------------------------------

/// @requirement TB-305
#[test]
fn a_fresh_directory_knows_nothing() {
    let dir = FederationDirectory::open(temp_dir("fresh")).unwrap();
    assert!(dir.owner_of_nickname("alice").is_none());
    assert!(dir.owner_of_channel("general").is_none());
}

/// @requirement AC-475
#[test]
fn a_locally_registered_nickname_is_registrable_only_here() {
    let mut dir = FederationDirectory::open(temp_dir("local-register")).unwrap();
    dir.record_local_nickname("alice".to_string(), "serverA").unwrap();
    assert_eq!(
        dir.owner_of_nickname("alice"),
        Some(&Ownership::Owned("serverA".to_string()))
    );
    assert!(dir.is_registrable_here("alice", "serverA").is_ok());
    let err = dir.is_registrable_here("alice", "serverB").unwrap_err();
    assert!(err.contains("serverA"), "{err}");
}

/// A nickname's ownership survives a restart - `record_local_nickname`
/// persists, unlike a channel.
/// @requirement TB-305
#[test]
fn nickname_ownership_persists_across_a_reopen() {
    let path = temp_dir("persist");
    {
        let mut dir = FederationDirectory::open(path.clone()).unwrap();
        dir.record_local_nickname("alice".to_string(), "serverA").unwrap();
    }
    let reopened = FederationDirectory::open(path).unwrap();
    assert_eq!(
        reopened.owner_of_nickname("alice"),
        Some(&Ownership::Owned("serverA".to_string()))
    );
}

/// An unreadable-but-present directory file is an error, never an empty
/// start. This file is the only record of which nicknames the federation
/// has already handed out, so quietly starting empty is the exact failure
/// it exists to prevent: another server then registers a name this one
/// already owns, with no conflict detected on the forgetful side. (A file
/// that simply isn't there yet is an ordinary first run, and does start
/// empty - asserted here too, so the two cases can't be conflated again.)
/// @requirement TB-313
#[test]
fn a_present_but_unreadable_directory_refuses_to_start_empty() {
    let path = temp_dir("unreadable");
    assert!(
        FederationDirectory::open(path.clone()).is_ok(),
        "a directory with no file yet is an ordinary first run"
    );

    // A directory where the nicknames file is itself a directory: present,
    // and impossible to read as a file.
    let blocked = temp_dir("unreadable-blocked");
    std::fs::create_dir_all(blocked.join("nicknames")).unwrap();
    assert!(
        FederationDirectory::open(blocked).is_err(),
        "a present-but-unreadable directory must not silently start empty"
    );
}

/// Every write replaces the file atomically, so a crash can never leave a
/// half-written directory - the tail of which would be nicknames silently
/// freed for another server to claim.
/// @requirement TB-313
#[test]
fn the_directory_is_never_left_half_written() {
    let path = temp_dir("atomic");
    let mut dir = FederationDirectory::open(path.clone()).unwrap();
    dir.record_local_nickname("alice".to_string(), "serverA").unwrap();
    dir.record_local_nickname("bob".to_string(), "serverA").unwrap();

    // Nothing is left behind beside the real file: a temporary that
    // survived would mean a write that wasn't a rename.
    let leftovers: Vec<String> = std::fs::read_dir(&path)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != "nicknames")
        .collect();
    assert!(leftovers.is_empty(), "unexpected files beside the directory: {leftovers:?}");
}

/// A decommissioned peer's claims are released only when an operator says
/// so, and releasing them leaves any *other* server's claim on a shared
/// name intact.
/// @requirement TB-313
#[test]
fn forgetting_a_peer_releases_only_that_peers_claims() {
    let mut dir = FederationDirectory::open(temp_dir("forget-owner")).unwrap();
    dir.merge_remote_nickname("alice".to_string(), "gone".to_string()).unwrap();
    dir.merge_remote_nickname("bob".to_string(), "staying".to_string()).unwrap();
    // A name both of them claimed - an unresolved conflict.
    dir.merge_remote_nickname("carol".to_string(), "gone".to_string()).unwrap();
    dir.merge_remote_nickname("carol".to_string(), "staying".to_string()).unwrap();

    let freed = dir.forget_owner("gone").unwrap();
    assert_eq!(freed, 2, "alice and carol were both claimed by the departing server");
    assert!(dir.owner_of_nickname("alice").is_none(), "freed for anyone to register");
    assert_eq!(
        dir.owner_of_nickname("bob"),
        Some(&Ownership::Owned("staying".to_string())),
        "another server's claim is untouched"
    );
    assert_eq!(
        dir.owner_of_nickname("carol"),
        Some(&Ownership::Owned("staying".to_string())),
        "a shared name resolves to whoever is left, not to nobody"
    );
}

/// Two servers claiming the same nickname (a bootstrap collision, or an
/// unresolved race) become `Conflicted` rather than one silently winning
/// - and a conflicted name is refused for any *new* registration.
/// @requirement AC-477
#[test]
fn a_nickname_claimed_by_two_servers_becomes_conflicted() {
    let mut dir = FederationDirectory::open(temp_dir("conflict")).unwrap();
    dir.merge_remote_nickname("alice".to_string(), "serverA".to_string()).unwrap();
    dir.merge_remote_nickname("alice".to_string(), "serverB".to_string()).unwrap();
    assert_eq!(
        dir.owner_of_nickname("alice"),
        Some(&Ownership::Conflicted(vec!["serverA".to_string(), "serverB".to_string()]))
    );
    let err = dir.is_registrable_here("alice", "serverC").unwrap_err();
    assert!(err.contains("multiple federated servers"), "{err}");
}

/// The same server re-announcing a nickname it already owns (e.g. two
/// gossip messages racing, or a snapshot re-stating a live gossip
/// message) is a no-op, never a conflict with itself.
/// @requirement TB-305
#[test]
fn re_announcing_the_same_owner_is_not_a_conflict() {
    let mut dir = FederationDirectory::open(temp_dir("same-owner")).unwrap();
    dir.merge_remote_nickname("alice".to_string(), "serverA".to_string()).unwrap();
    dir.merge_remote_nickname("alice".to_string(), "serverA".to_string()).unwrap();
    assert_eq!(
        dir.owner_of_nickname("alice"),
        Some(&Ownership::Owned("serverA".to_string()))
    );
}

/// A channel conflict has no automatic resolution: `owner_of_channel`
/// goes back to `None` (neither claimant is *the* routable owner) rather
/// than one being arbitrarily chosen, and `channel_is_conflicted` tells
/// that apart from a genuinely unknown name - a third server must be
/// refused a fresh creation of the same name, not allowed to add yet
/// another conflicting claim on top.
/// @requirement AC-477
#[test]
fn a_channel_claimed_by_two_servers_is_removed_from_the_directory() {
    let mut dir = FederationDirectory::open(temp_dir("chan-conflict")).unwrap();
    dir.merge_remote_channel(FederatedChannelInfo {
        name: "general".to_string(),
        kind: ChannelKind::Public,
        owner: "serverA".to_string(),
    });
    assert!(dir.owner_of_channel("general").is_some());
    assert!(!dir.channel_is_conflicted("general"));
    dir.merge_remote_channel(FederatedChannelInfo {
        name: "general".to_string(),
        kind: ChannelKind::Public,
        owner: "serverB".to_string(),
    });
    assert!(dir.owner_of_channel("general").is_none());
    assert!(dir.channel_is_conflicted("general"));
    assert!(!dir.channel_is_conflicted("never-heard-of-this-one"));
}

/// The race `record_local_nickname`/`record_local_channel` must close in
/// *both* directions: a peer's claim arriving first, then this server's
/// own registration arriving second, must become `Conflicted` exactly as
/// readily as the reverse order does - never silently overwritten by
/// whichever side happened to record last.
/// @requirement AC-477, TB-307
#[test]
fn a_local_registration_after_a_peers_claim_already_arrived_becomes_conflicted() {
    let mut nick_dir = FederationDirectory::open(temp_dir("race-nick")).unwrap();
    nick_dir.merge_remote_nickname("alice".to_string(), "serverB".to_string()).unwrap();
    nick_dir.record_local_nickname("alice".to_string(), "serverA").unwrap();
    assert_eq!(
        nick_dir.owner_of_nickname("alice"),
        Some(&Ownership::Conflicted(vec!["serverB".to_string(), "serverA".to_string()]))
    );

    let mut chan_dir = FederationDirectory::open(temp_dir("race-chan")).unwrap();
    chan_dir.merge_remote_channel(FederatedChannelInfo {
        name: "general".to_string(),
        kind: ChannelKind::Public,
        owner: "serverB".to_string(),
    });
    chan_dir.record_local_channel(FederatedChannelInfo {
        name: "general".to_string(),
        kind: ChannelKind::Public,
        owner: "serverA".to_string(),
    });
    assert!(chan_dir.owner_of_channel("general").is_none());
    assert!(chan_dir.channel_is_conflicted("general"));
}

/// `remove_nickname`/`remove_channel` only ever drop the one claimant
/// named: removing a stale/non-claimant owner is a no-op, and removing
/// one side of a real conflict downgrades it back to a clean `Owned` for
/// whichever side remains rather than clearing the whole entry.
/// @requirement AC-477, TB-307
#[test]
fn removing_one_side_of_a_conflict_restores_a_clean_owner_for_the_other() {
    let mut nick_dir = FederationDirectory::open(temp_dir("resolve-nick")).unwrap();
    nick_dir.merge_remote_nickname("alice".to_string(), "serverA".to_string()).unwrap();
    nick_dir.merge_remote_nickname("alice".to_string(), "serverB".to_string()).unwrap();
    nick_dir.remove_nickname("alice", "not-a-claimant").unwrap();
    assert!(
        matches!(nick_dir.owner_of_nickname("alice"), Some(Ownership::Conflicted(_))),
        "a stale owner name must not touch a real conflict"
    );
    nick_dir.remove_nickname("alice", "serverA").unwrap();
    assert_eq!(nick_dir.owner_of_nickname("alice"), Some(&Ownership::Owned("serverB".to_string())));
    nick_dir.remove_nickname("alice", "serverB").unwrap();
    assert!(nick_dir.owner_of_nickname("alice").is_none());

    let mut chan_dir = FederationDirectory::open(temp_dir("resolve-chan")).unwrap();
    chan_dir.merge_remote_channel(FederatedChannelInfo {
        name: "general".to_string(),
        kind: ChannelKind::Public,
        owner: "serverA".to_string(),
    });
    chan_dir.merge_remote_channel(FederatedChannelInfo {
        name: "general".to_string(),
        kind: ChannelKind::Public,
        owner: "serverB".to_string(),
    });
    assert!(chan_dir.channel_is_conflicted("general"));
    chan_dir.remove_channel("general", "serverA");
    assert_eq!(
        chan_dir.owner_of_channel("general"),
        Some(&FederatedChannelInfo {
            name: "general".to_string(),
            kind: ChannelKind::Public,
            owner: "serverB".to_string(),
        })
    );
    assert!(!chan_dir.channel_is_conflicted("general"));
}

/// Removing a clean (non-conflicted) owner's claim clears the entry
/// entirely; naming a different owner than the real one is a no-op.
/// @requirement AC-477, TB-307
#[test]
fn removing_a_clean_owner_clears_the_entry_and_a_wrong_owner_is_a_no_op() {
    let mut nick_dir = FederationDirectory::open(temp_dir("clean-remove-nick")).unwrap();
    nick_dir.merge_remote_nickname("alice".to_string(), "serverA".to_string()).unwrap();
    nick_dir.remove_nickname("alice", "serverB").unwrap();
    assert_eq!(nick_dir.owner_of_nickname("alice"), Some(&Ownership::Owned("serverA".to_string())));
    nick_dir.remove_nickname("alice", "serverA").unwrap();
    assert!(nick_dir.owner_of_nickname("alice").is_none());

    let mut chan_dir = FederationDirectory::open(temp_dir("clean-remove-chan")).unwrap();
    chan_dir.merge_remote_channel(FederatedChannelInfo {
        name: "general".to_string(),
        kind: ChannelKind::Public,
        owner: "serverA".to_string(),
    });
    chan_dir.remove_channel("general", "serverB");
    assert!(chan_dir.owner_of_channel("general").is_some(), "naming the wrong owner must not remove it");
    chan_dir.remove_channel("general", "serverA");
    assert!(chan_dir.owner_of_channel("general").is_none());
}

/// A conflicted nickname's snapshot re-announces every claimant, so a peer
/// merging it reconstructs the same conflict rather than losing one side.
/// @requirement TB-305
#[test]
fn a_snapshot_of_a_conflicted_nickname_names_every_claimant() {
    let mut dir = FederationDirectory::open(temp_dir("snapshot-conflict")).unwrap();
    dir.merge_remote_nickname("alice".to_string(), "serverA".to_string()).unwrap();
    dir.merge_remote_nickname("alice".to_string(), "serverB".to_string()).unwrap();
    let (nicknames, _channels) = dir.snapshot();
    let owners: Vec<&str> = nicknames
        .iter()
        .filter(|(name, _)| name == "alice")
        .map(|(_, owner)| owner.as_str())
        .collect();
    assert_eq!(owners.len(), 2, "{nicknames:?}");
    assert!(owners.contains(&"serverA"));
    assert!(owners.contains(&"serverB"));
}

// ---------------------------------------------------------------------
// A real PQ-hybrid-authenticated peer link between two in-process servers.
// ---------------------------------------------------------------------

/// A fresh federation identity, written to `<dir>/identity.pub` (what a
/// peer's `FederationPeerConfig::public_key_path` points at) - returns the
/// private bundle directly, since `FederationConfig::new` takes it in
/// memory rather than reading it back off disk itself.
fn write_identity(dir: &std::path::Path) -> (aloo::crypto::pq::PqPrivateBundle, PathBuf) {
    let (public, private) = aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).unwrap();
    let pub_path = dir.join("identity.pub");
    aloo::crypto::pq::save_public_bundle(&public, &pub_path).unwrap();
    (private, pub_path)
}

/// Binds an ephemeral listener and returns it alongside its address -
/// `federation::serve` takes the listener directly (the same split
/// `crate::server::serve` gives the client-facing listener), so nothing
/// here races a `:0` bind against a later re-bind of the same port.
async fn bind_ephemeral() -> (tokio::net::TcpListener, std::net::SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

/// A `FederationContext` around an otherwise-empty `Registry`/`MailStore`
/// - what a test that only cares about the directory/gossip mechanics
/// (not join-proxying or mail relay) wires a link up with, since
/// `federation::serve`/`run_peer_link` need one regardless.
fn test_federation_context(config: Arc<FederationConfig>) -> federation::FederationContext {
    federation::FederationContext {
        config,
        registry: Arc::new(tokio::sync::Mutex::new(aloo::server::Registry::new())),
        senders: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        mail_store: Arc::new(aloo::server::mail::MailStore::open(temp_dir("mail-scratch")).unwrap()),
    }
}

/// Two servers, each configured with the other as its only federation
/// peer: `serverA` already has `alice` registered before the link comes
/// up (so `serverB` must learn her from the initial `DirectorySnapshot`,
/// not gossip), and gains `bob` after the link is up (so `serverB` must
/// learn him from live `NicknameRegistered` gossip instead).
/// @requirement AC-478, TB-304, TB-305
#[tokio::test]
async fn a_peer_link_exchanges_a_snapshot_then_gossips_incrementally() {
    let (listener_a, addr_a) = bind_ephemeral().await;
    let (listener_b, addr_b) = bind_ephemeral().await;
    let dir_a = temp_dir("link-a");
    let dir_b = temp_dir("link-b");
    let (identity_a, pub_a) = write_identity(&dir_a);
    let (identity_b, pub_b) = write_identity(&dir_b);

    let mut directory_a = FederationDirectory::open(dir_a.join("directory")).unwrap();
    directory_a.record_local_nickname("alice".to_string(), "serverA").unwrap();

    let config_a = Arc::new(
        FederationConfig::new(
            "serverA".to_string(),
            addr_a,
            addr_a.to_string(),
            None,
            identity_a,
            vec![FederationPeerConfig {
                peer_id: "serverB".to_string(),
                host: "127.0.0.1".to_string(),
                port: addr_b.port(),
                public_key_path: pub_b.display().to_string(),
            }],
            directory_a,
        )
        .unwrap(),
    );
    let config_b = Arc::new(
        FederationConfig::new(
            "serverB".to_string(),
            addr_b,
            addr_b.to_string(),
            None,
            identity_b,
            vec![FederationPeerConfig {
                peer_id: "serverA".to_string(),
                host: "127.0.0.1".to_string(),
                port: addr_a.port(),
                public_key_path: pub_a.display().to_string(),
            }],
            FederationDirectory::open(dir_b.join("directory")).unwrap(),
        )
        .unwrap(),
    );

    tokio::spawn(federation::serve(listener_a, test_federation_context(config_a.clone())));
    tokio::spawn(federation::serve(listener_b, test_federation_context(config_b.clone())));

    // The snapshot: `serverB` learns `alice` without any gossip message
    // ever naming her, purely from the `DirectorySnapshot` sent right
    // after `Hello`.
    wait_until(Duration::from_secs(5), || async {
        matches!(
            config_b.directory.lock().await.owner_of_nickname("alice"),
            Some(Ownership::Owned(owner)) if owner == "serverA"
        )
    })
    .await;

    // Gossip: registered on `serverA` *after* the link is already up.
    config_a
        .directory
        .lock()
        .await
        .record_local_nickname("bob".to_string(), "serverA")
        .unwrap();
    federation::broadcast(
        &config_a,
        FederationMessage::NicknameRegistered {
            nickname: "bob".to_string(),
            owner: "serverA".to_string(),
        },
        federation::event::NICKS_GOSSIP,
    )
    .await;

    wait_until(Duration::from_secs(5), || async {
        matches!(
            config_b.directory.lock().await.owner_of_nickname("bob"),
            Some(Ownership::Owned(owner)) if owner == "serverA"
        )
    })
    .await;
}

// ---------------------------------------------------------------------
// The handshake's own trust decisions, in isolation - no directory, no
// gossip, just the two messages `handshake::handshake` exchanges.
// ---------------------------------------------------------------------

/// Runs `handshake::handshake` for both ends of a loopback TCP connection
/// concurrently (each side write-then-reads, so this can never deadlock),
/// returning each side's own result.
async fn run_handshake_pair(
    trust_a: FederationTrust<'_>,
    trust_b: FederationTrust<'_>,
) -> (
    Result<handshake::PeerAnnouncement, HandshakeError>,
    Result<handshake::PeerAnnouncement, HandshakeError>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // `tokio::join!` rather than two spawned tasks: `FederationTrust`
    // borrows (it is never itself `'static`), and joining two futures on
    // the current task needs no such bound.
    let (accept_conn, dial_conn) = tokio::join!(
        async { listener.accept().await.unwrap().0 },
        tokio::net::TcpStream::connect(addr),
    );
    let dial_conn = dial_conn.unwrap();

    let (accept_rd, accept_wr) = tokio::io::split(accept_conn);
    let mut accept_rd = ControlReader::new(accept_rd);
    let mut accept_wr = ControlWriter::new(accept_wr);
    let (dial_rd, dial_wr) = tokio::io::split(dial_conn);
    let mut dial_rd = ControlReader::new(dial_rd);
    let mut dial_wr = ControlWriter::new(dial_wr);

    tokio::join!(
        handshake::handshake(&mut accept_rd, &mut accept_wr, &trust_a, "127.0.0.1:0", None),
        handshake::handshake(&mut dial_rd, &mut dial_wr, &trust_b, "127.0.0.1:0", None),
    )
}

/// A connection claiming an id the accepting side has no pinned key for at
/// all is refused before any signature is even checked - the closed-set
/// property that replaces mTLS's root-of-trust check.
/// @requirement TB-304
#[tokio::test]
async fn a_handshake_is_refused_when_the_connecting_side_claims_an_unconfigured_peer_id() {
    let (identity_a, _pub_a) = write_identity(&temp_dir("unknown-peer-a"));
    let (_identity_b, pub_b) = write_identity(&temp_dir("unknown-peer-b"));
    let (identity_stranger, _pub_stranger) = write_identity(&temp_dir("unknown-peer-stranger"));
    let public_b = aloo::crypto::pq::load_public_bundle(&pub_b).unwrap();

    let trust_a = FederationTrust {
        self_id: "serverA",
        own_identity: &identity_a,
        peers: &[("serverB".to_string(), public_b)],
    };
    let trust_stranger =
        FederationTrust { self_id: "stranger", own_identity: &identity_stranger, peers: &[] };

    let (accept_result, _dial_result) = run_handshake_pair(trust_a, trust_stranger).await;
    assert!(
        matches!(accept_result, Err(HandshakeError::UnknownPeer(ref id)) if id == "stranger"),
        "{accept_result:?}"
    );
}

/// A connection claiming a *known* id, but signing with a different
/// private key than the one pinned for it, is refused just the same -
/// unlike the mTLS design this replaces, `self_id` can never be claimed
/// without the matching private key (docs/SECURITY.md).
/// @requirement TB-304
#[tokio::test]
async fn a_handshake_is_refused_when_the_signature_does_not_match_the_pinned_key_for_the_claimed_id() {
    let (identity_a, pub_a) = write_identity(&temp_dir("spoof-a"));
    let (_real_identity_b, pub_b) = write_identity(&temp_dir("spoof-b-real"));
    let (impostor_identity, _pub_impostor) = write_identity(&temp_dir("spoof-b-impostor"));
    let public_a = aloo::crypto::pq::load_public_bundle(&pub_a).unwrap();
    let public_b = aloo::crypto::pq::load_public_bundle(&pub_b).unwrap();

    let trust_a = FederationTrust {
        self_id: "serverA",
        own_identity: &identity_a,
        peers: &[("serverB".to_string(), public_b)],
    };
    // Claims to be "serverB" (a peer `trust_a` does trust), but signs with
    // a private key different from the one pinned for that id. Pins A's
    // *real* key itself, so this side gets past its own unknown-peer check
    // and actually sends its (invalid) `KeyExchange` rather than bailing
    // out before `trust_a` ever gets to verify it.
    let trust_impostor = FederationTrust {
        self_id: "serverB",
        own_identity: &impostor_identity,
        peers: &[("serverA".to_string(), public_a)],
    };

    let (accept_result, _dial_result) = run_handshake_pair(trust_a, trust_impostor).await;
    assert!(
        matches!(accept_result, Err(HandshakeError::AuthenticationFailed(ref id)) if id == "serverB"),
        "{accept_result:?}"
    );
}

// ---------------------------------------------------------------------
// End to end over the wire: a single server whose federation directory
// already knows a nickname belongs elsewhere - no live peer link needed
// for either of these, since both checks are pure local-directory
// lookups (see `federation_login_precheck`/`register_account` in
// `src/server/mod.rs`).
// ---------------------------------------------------------------------

/// A `FederationConfig` for a lone server with no reachable peers - all
/// that `federation_login_precheck`/registration's federation check need
/// is the directory itself, so nothing here has to actually link.
fn lone_federation_config(self_id: &str, directory: FederationDirectory) -> FederationConfig {
    let dir = temp_dir(self_id);
    let (identity, _own_pub) = write_identity(&dir);
    // A distinct identity for the never-dialed peer entry: `FederationConfig::new`
    // loads every configured peer's public key eagerly, so this file has to
    // exist and be a valid bundle even though nothing here ever links to it.
    let unused_peer_dir = dir.join("peer-serverA-unused");
    std::fs::create_dir_all(&unused_peer_dir).unwrap();
    let (_unused_peer_private, peer_pub) = write_identity(&unused_peer_dir);
    FederationConfig::new(
        self_id.to_string(),
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".to_string(),
        None,
        identity,
        vec![FederationPeerConfig {
            peer_id: "serverA".to_string(),
            host: "127.0.0.1".to_string(),
            port: 1, // never dialed by either test below
            public_key_path: peer_pub.display().to_string(),
        }],
        directory,
    )
    .unwrap()
}

/// @requirement AC-476
#[tokio::test]
async fn a_login_for_a_nickname_owned_by_a_peer_is_redirected_over_the_wire() {
    let mut directory = FederationDirectory::open(temp_dir("redirect-login-dir")).unwrap();
    directory.merge_remote_nickname("alice".to_string(), "serverA".to_string()).unwrap();
    let options = server_common::test_options("fed-redirect-login")
        .with_federation(lone_federation_config("serverB", directory));
    let server = server_common::TestServer::spawn(options).await;

    let mut stream = server.connect().await;
    let result = server_common::login(&mut stream, "alice", "whatever-password").await;
    let ServerMessage::AuthResult { ok: false, reason: Some(reason), .. } = result else {
        panic!("expected a refusal naming the peer server, got {result:?}");
    };
    assert!(reason.contains("federated server"), "{reason}");
    // That peer has never linked here, so it has never announced a
    // client-facing address - the refusal names the *server*, and must
    // not invent an address. Naming `server_federation_peer`'s own
    // host:port would be actively wrong: that is the server-to-server
    // port, which no client ever speaks to.
    assert!(reason.contains("serverA"), "{reason}");
    assert!(
        !reason.contains(":1"),
        "the federation port must never be handed to a client: {reason}"
    );
}

/// The same directory state, but for `Register` instead of `Auth`: the
/// nickname is refused before it is ever written locally.
/// @requirement AC-475
#[tokio::test]
async fn registration_is_refused_for_a_nickname_owned_by_a_peer_over_the_wire() {
    let mut directory = FederationDirectory::open(temp_dir("redirect-register-dir")).unwrap();
    directory.merge_remote_nickname("alice".to_string(), "serverA".to_string()).unwrap();
    let options = server_common::test_options("fed-redirect-register")
        .with_registration(Some(aloo::server::users_registry::SmtpConfig {
            host: "127.0.0.1".to_string(),
            port: 1, // never dialed - the federation check refuses first
            username: String::new(),
            password: String::new(),
        }))
        .with_federation(lone_federation_config("serverB", directory));
    let server = server_common::TestServer::spawn(options).await;

    let mut stream = server.connect().await;
    stream.client_handshake().await.unwrap().unwrap();
    stream
        .send(&ClientMessage::Register {
            nickname: "alice".into(),
            password: "pw".into(),
            email: "alice@example.com".into(),
        })
        .await
        .unwrap();
    let result: ServerMessage = stream.recv().await.unwrap().unwrap();
    let ServerMessage::RegisterResult { ok: false, reason: Some(reason) } = result else {
        panic!("expected a refusal naming the peer server, got {result:?}");
    };
    assert!(reason.contains("serverA"), "{reason}");
    assert!(!server.options.users.is_registered("alice"));
}

/// Polls `condition` every 20ms until it is true, panicking if `timeout`
/// passes first - the same shape a live-socket wait needs whenever the
/// thing being waited for happens on another task with no single event to
/// block on directly.
async fn wait_until<F, Fut>(timeout: Duration, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if condition().await {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("condition did not become true within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------
// End to end over the wire: two real, client-facing federated servers -
// private-channel join proxying and cross-server OTP mail relay.
// ---------------------------------------------------------------------

/// Binds an ephemeral port and immediately releases it - the same
/// "picked and released first, dialled while closed" tolerance
/// `server_common::TestServer::spawn_at`'s own doc describes, used here so
/// each server's federation config can name the *other*'s port before
/// either server exists yet.
async fn reserve_port() -> u16 {
    tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Two real, client-facing servers ("serverA"/"serverB"), each federated
/// with the other and each running the ordinary client-connection
/// listener (`server_common::TestServer`) - what every test below drives
/// entirely over the wire, exactly as a real client and a real pair of
/// federated deployments would.
async fn spawn_federated_pair(tag: &str) -> (server_common::TestServer, server_common::TestServer) {
    spawn_federated_pair_with(tag, |o| o, |o| o).await
}

/// `spawn_federated_pair`, letting a test adjust either side's
/// `ServerOptions` (e.g. naming a superadmin) before it spawns - after
/// spawning is too late, since `TestServer::spawn` hands the actually-running
/// task a clone of what it was given and keeps the pre-clone value in the
/// `TestServer` it returns, so mutating `server.options` afterward changes
/// nothing the running server itself sees.
async fn spawn_federated_pair_with(
    tag: &str,
    configure_a: impl FnOnce(aloo::server::ServerOptions) -> aloo::server::ServerOptions,
    configure_b: impl FnOnce(aloo::server::ServerOptions) -> aloo::server::ServerOptions,
) -> (server_common::TestServer, server_common::TestServer) {
    let dir_a = temp_dir(&format!("{tag}-a"));
    let dir_b = temp_dir(&format!("{tag}-b"));
    let (identity_a, pub_a) = write_identity(&dir_a);
    let (identity_b, pub_b) = write_identity(&dir_b);
    let fed_port_a = reserve_port().await;
    let fed_port_b = reserve_port().await;

    // A marker nickname, seeded directly into A's directory before
    // either server starts, so its arrival in B's directory (checked via
    // `wait_until` below) is unambiguous proof the link, the PQ-hybrid
    // handshake, and the initial `DirectorySnapshot` are all genuinely up
    // - not just that some other test left something behind.
    let mut directory_a = FederationDirectory::open(dir_a.join("directory")).unwrap();
    directory_a.record_local_nickname("linkcheck".to_string(), "serverA").unwrap();

    let config_a = FederationConfig::new(
        "serverA".to_string(),
        format!("127.0.0.1:{fed_port_a}").parse().unwrap(),
        format!("127.0.0.1:{fed_port_a}"),
        None,
            identity_a,
        vec![FederationPeerConfig {
            peer_id: "serverB".to_string(),
            host: "127.0.0.1".to_string(),
            port: fed_port_b,
            public_key_path: pub_b.display().to_string(),
        }],
        directory_a,
    )
    .unwrap();
    let config_b = FederationConfig::new(
        "serverB".to_string(),
        format!("127.0.0.1:{fed_port_b}").parse().unwrap(),
        format!("127.0.0.1:{fed_port_b}"),
        None,
            identity_b,
        vec![FederationPeerConfig {
            peer_id: "serverA".to_string(),
            host: "127.0.0.1".to_string(),
            port: fed_port_a,
            public_key_path: pub_a.display().to_string(),
        }],
        FederationDirectory::open(dir_b.join("directory")).unwrap(),
    )
    .unwrap();

    let options_a = configure_a(server_common::test_options(&format!("{tag}-a")).with_federation(config_a));
    let options_b = configure_b(server_common::test_options(&format!("{tag}-b")).with_federation(config_b));
    let server_a = server_common::TestServer::spawn(options_a).await;
    let server_b = server_common::TestServer::spawn(options_b).await;

    wait_until(Duration::from_secs(5), || async {
        matches!(
            server_b
                .options
                .federation
                .as_ref()
                .unwrap()
                .directory
                .lock()
                .await
                .owner_of_nickname("linkcheck"),
            Some(Ownership::Owned(owner)) if owner == "serverA"
        )
    })
    .await;

    (server_a, server_b)
}

/// Three real, client-facing federated servers in a star: `hub` (whose id
/// sorts first, so it is the one that dials out to each leaf - see
/// `dial_peer`) configured with both `leafA` and `leafB` as peers, while
/// `leafA` and `leafB` are only ever configured with `hub` - they never
/// link to each other directly at all. What
/// `a_third_servers_member_sees_presence_relayed_through_the_hub` uses to
/// prove `ChannelMemberJoined`/`ChannelMemberLeft` gossip reaches a server
/// with no direct link to the one that actually granted the join - only a
/// shared home server in common.
async fn spawn_federated_star(
    tag: &str,
) -> (server_common::TestServer, server_common::TestServer, server_common::TestServer) {
    let dir_hub = temp_dir(&format!("{tag}-hub"));
    let dir_a = temp_dir(&format!("{tag}-leafa"));
    let dir_b = temp_dir(&format!("{tag}-leafb"));
    let (identity_hub, pub_hub) = write_identity(&dir_hub);
    let (identity_a, pub_a) = write_identity(&dir_a);
    let (identity_b, pub_b) = write_identity(&dir_b);
    let port_hub = reserve_port().await;
    let port_a = reserve_port().await;
    let port_b = reserve_port().await;

    let config_hub = FederationConfig::new(
        "hub".to_string(),
        format!("127.0.0.1:{port_hub}").parse().unwrap(),
        format!("127.0.0.1:{port_hub}"),
        None,
            identity_hub,
        vec![
            FederationPeerConfig {
                peer_id: "leafA".to_string(),
                host: "127.0.0.1".to_string(),
                port: port_a,
                public_key_path: pub_a.display().to_string(),
            },
            FederationPeerConfig {
                peer_id: "leafB".to_string(),
                host: "127.0.0.1".to_string(),
                port: port_b,
                public_key_path: pub_b.display().to_string(),
            },
        ],
        FederationDirectory::open(dir_hub.join("directory")).unwrap(),
    )
    .unwrap();
    let config_a = FederationConfig::new(
        "leafA".to_string(),
        format!("127.0.0.1:{port_a}").parse().unwrap(),
        format!("127.0.0.1:{port_a}"),
        None,
            identity_a,
        vec![FederationPeerConfig {
            peer_id: "hub".to_string(),
            host: "127.0.0.1".to_string(),
            port: port_hub,
            public_key_path: pub_hub.display().to_string(),
        }],
        FederationDirectory::open(dir_a.join("directory")).unwrap(),
    )
    .unwrap();
    let config_b = FederationConfig::new(
        "leafB".to_string(),
        format!("127.0.0.1:{port_b}").parse().unwrap(),
        format!("127.0.0.1:{port_b}"),
        None,
            identity_b,
        vec![FederationPeerConfig {
            peer_id: "hub".to_string(),
            host: "127.0.0.1".to_string(),
            port: port_hub,
            public_key_path: pub_hub.display().to_string(),
        }],
        FederationDirectory::open(dir_b.join("directory")).unwrap(),
    )
    .unwrap();

    let hub = server_common::TestServer::spawn(
        server_common::test_options(&format!("{tag}-hub")).with_federation(config_hub),
    )
    .await;
    let leaf_a =
        server_common::TestServer::spawn(server_common::test_options(&format!("{tag}-a")).with_federation(config_a))
            .await;
    let leaf_b =
        server_common::TestServer::spawn(server_common::test_options(&format!("{tag}-b")).with_federation(config_b))
            .await;

    // Both links up: proven by each leaf's directory learning the other
    // exists via the hub's snapshot (never directly - they aren't peers
    // of each other), the same "peer's directory finally agrees" signal
    // `spawn_federated_pair_with` uses for a single link.
    // Re-announced on every poll rather than once up front: gossip is a
    // one-shot to whatever links are live *at that moment*, and with both
    // sides dialing there is no instant at which the harness can know the
    // links have settled. A real server registers nicknames continuously
    // over a long-lived link; a test that announces once into a link that
    // is still coming up is just racing itself.
    wait_until(Duration::from_secs(15), || async {
        federate_nickname(&hub, "hub", "hublink").await;
        let a_knows = matches!(
            leaf_a.options.federation.as_ref().unwrap().directory.lock().await.owner_of_nickname("hublink"),
            Some(Ownership::Owned(owner)) if owner == "hub"
        );
        let b_knows = matches!(
            leaf_b.options.federation.as_ref().unwrap().directory.lock().await.owner_of_nickname("hublink"),
            Some(Ownership::Owned(owner)) if owner == "hub"
        );
        a_knows && b_knows
    })
    .await;

    (hub, leaf_a, leaf_b)
}

/// The whole point of gossiping `ChannelMemberJoined`/`ChannelMemberLeft`
/// to *every* linked peer, not just the one a join-proxy request came
/// from: a server with no direct link at all to the server whose client
/// just joined still learns about it, purely through their shared home
/// server relaying it on. `leafA` and `leafB` are never peers of each
/// other here - only of `hub`, which owns the channel both their clients
/// join.
/// @requirement AC-483, TB-310
#[tokio::test]
async fn a_third_servers_member_sees_presence_relayed_through_the_hub() {
    let (hub, leaf_a, leaf_b) = spawn_federated_star("presence-relay").await;

    let mut alice = hub.connect().await;
    hub.handshake(&mut alice, "alice").await;
    alice
        .send(&ClientMessage::JoinChannel {
            name: "plaza".to_string(),
            kind: ChannelKind::Public,
            password: None,
        })
        .await
        .unwrap();
    assert!(matches!(recv_with_timeout(&mut alice).await, ServerMessage::Joined { .. }));

    // The channel reaches leafB (fully shared list) before leafB has any
    // member in it at all - proof this doesn't depend on leafB having
    // proxied a join first.
    wait_until(Duration::from_secs(5), || async {
        matches!(
            leaf_b.options.federation.as_ref().unwrap().directory.lock().await.owner_of_channel("plaza"),
            Some(info) if info.owner == "hub"
        )
    })
    .await;

    let mut bob = leaf_a.connect().await;
    leaf_a.handshake(&mut bob, "bob").await;
    bob.send(&ClientMessage::JoinChannel {
        name: "plaza".to_string(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();
    // leafA already knew about alice - relayed the same way "plaza"
    // itself was - so bob is told about her before his own `Joined`.
    let alice_presence = recv_with_timeout(&mut bob).await;
    assert!(
        matches!(&alice_presence, ServerMessage::UserJoined { channel, user } if channel == "plaza" && user.name == "alice"),
        "{alice_presence:?}"
    );
    assert!(matches!(recv_with_timeout(&mut bob).await, ServerMessage::Joined { .. }));

    // carol, connected to leafB - which has never linked to leafA at all
    // - joins the same channel and must already see both alice and bob in
    // it (alice relayed the same way "plaza" itself was, bob purely
    // through the hub, since leafB has no link of its own to leafA).
    let mut carol = leaf_b.connect().await;
    leaf_b.handshake(&mut carol, "carol").await;
    carol
        .send(&ClientMessage::JoinChannel {
            name: "plaza".to_string(),
            kind: ChannelKind::Public,
            password: None,
        })
        .await
        .unwrap();
    let mut seen_before_joined = Vec::new();
    loop {
        match recv_with_timeout(&mut carol).await {
            ServerMessage::UserJoined { channel, user } if channel == "plaza" => seen_before_joined.push(user.name),
            ServerMessage::Joined { .. } => break,
            other => panic!("unexpected message while carol joins: {other:?}"),
        }
    }
    seen_before_joined.sort();
    assert_eq!(seen_before_joined, vec!["alice".to_string(), "bob".to_string()]);

    // bob leaving reaches carol the same way, purely relayed through the
    // hub - not because leafA and leafB ever spoke directly.
    bob.send(&ClientMessage::LeaveChannel { name: "plaza".to_string() }).await.unwrap();
    let bob_left = recv_with_timeout(&mut carol).await;
    assert!(
        matches!(&bob_left, ServerMessage::UserLeft { channel, .. } if channel == "plaza"),
        "{bob_left:?}"
    );
}

/// An idle link keeps itself alive. Nothing else would: a link carrying
/// no traffic is indistinguishable from a dead one, so the idle timeout
/// that catches a socket TCP never reports as broken would otherwise tear
/// down every quiet link too. Run here with the timings shortened, so
/// several ping cycles pass in a second rather than a minute and a half.
/// @requirement TB-314
#[tokio::test]
async fn an_idle_link_stays_up_across_several_ping_cycles() {
    let (listener_a, addr_a) = bind_ephemeral().await;
    let (listener_b, addr_b) = bind_ephemeral().await;
    let dir_a = temp_dir("ping-a");
    let dir_b = temp_dir("ping-b");
    let (identity_a, pub_a) = write_identity(&dir_a);
    let (identity_b, pub_b) = write_identity(&dir_b);

    let quick = |config: FederationConfig| {
        config.with_liveness(Duration::from_millis(60), Duration::from_millis(250))
    };
    let config_a = Arc::new(quick(
        FederationConfig::new(
            "serverA".to_string(),
            addr_a,
            addr_a.to_string(),
            None,
            identity_a,
            vec![FederationPeerConfig {
                peer_id: "serverB".to_string(),
                host: "127.0.0.1".to_string(),
                port: addr_b.port(),
                public_key_path: pub_b.display().to_string(),
            }],
            FederationDirectory::open(dir_a.join("directory")).unwrap(),
        )
        .unwrap(),
    ));
    let config_b = Arc::new(quick(
        FederationConfig::new(
            "serverB".to_string(),
            addr_b,
            addr_b.to_string(),
            None,
            identity_b,
            vec![FederationPeerConfig {
                peer_id: "serverA".to_string(),
                host: "127.0.0.1".to_string(),
                port: addr_a.port(),
                public_key_path: pub_a.display().to_string(),
            }],
            FederationDirectory::open(dir_b.join("directory")).unwrap(),
        )
        .unwrap(),
    ));

    tokio::spawn(federation::serve(listener_a, test_federation_context(config_a.clone())));
    tokio::spawn(federation::serve(listener_b, test_federation_context(config_b.clone())));

    wait_until(Duration::from_secs(5), || async {
        config_a.send_to_peer("serverB", FederationMessage::Ping).await
    })
    .await;

    // Well past the idle timeout, several ping intervals over, with no
    // real traffic at all: without the keepalive this link would be gone.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        config_a.send_to_peer("serverB", FederationMessage::Ping).await,
        "an idle link must be kept alive by its own pings, not torn down as silent"
    );
}

/// The tunables around that, checked directly - the relationship between
/// them is the part that matters, and it is easy to break by adjusting one
/// number in isolation.
/// @requirement TB-314
#[test]
fn the_liveness_and_redial_timings_hold_their_invariants() {
    // A single lost ping (or one slow moment) must never be enough to tear
    // down a healthy link.
    assert!(
        federation::FEDERATION_IDLE_TIMEOUT > federation::FEDERATION_PING_INTERVAL * 2,
        "the idle timeout has to allow for more than one missed ping"
    );

    // Backoff climbs, and stops climbing.
    let mut wait = federation::REDIAL_INTERVAL;
    for _ in 0..20 {
        let next = federation::next_redial_wait(wait);
        assert!(next >= wait, "backoff must not go backwards");
        assert!(next <= federation::MAX_REDIAL_INTERVAL, "backoff must respect its ceiling");
        wait = next;
    }
    assert_eq!(wait, federation::MAX_REDIAL_INTERVAL, "backoff should reach the ceiling");

    // Jitter stays near its base and never panics on small values.
    for base in [Duration::ZERO, Duration::from_millis(1), federation::REDIAL_INTERVAL] {
        for _ in 0..50 {
            let jittered = federation::with_jitter(base);
            assert!(
                jittered <= base + base / 2,
                "jitter must stay near its base: {jittered:?} for {base:?}"
            );
        }
    }
}

/// Both servers dial each other, so two connections between one pair can
/// exist at once - and both ends have to converge on the *same* survivor,
/// or each keeps the one it dialed, discards the one it accepted, and the
/// pair is left with two half-alive links and nothing working. Both
/// listeners are already bound here before either `serve` starts, which is
/// precisely the startup shape that makes a simultaneous connect likely.
/// @requirement TB-311
#[tokio::test]
async fn two_servers_dialing_each_other_at_once_converge_on_one_working_link() {
    let (listener_a, addr_a) = bind_ephemeral().await;
    let (listener_b, addr_b) = bind_ephemeral().await;
    let dir_a = temp_dir("both-dial-a");
    let dir_b = temp_dir("both-dial-b");
    let (identity_a, pub_a) = write_identity(&dir_a);
    let (identity_b, pub_b) = write_identity(&dir_b);

    // "zeta" sorts *after* "alpha", so this also covers the case the old
    // "only the lower id dials" rule broke: if only the higher-id server
    // were reachable, that rule left the pair unlinked entirely.
    let config_a = Arc::new(
        FederationConfig::new(
            "alpha".to_string(),
            addr_a,
            addr_a.to_string(),
            None,
            identity_a,
            vec![FederationPeerConfig {
                peer_id: "zeta".to_string(),
                host: "127.0.0.1".to_string(),
                port: addr_b.port(),
                public_key_path: pub_b.display().to_string(),
            }],
            FederationDirectory::open(dir_a.join("directory")).unwrap(),
        )
        .unwrap(),
    );
    let config_b = Arc::new(
        FederationConfig::new(
            "zeta".to_string(),
            addr_b,
            addr_b.to_string(),
            None,
            identity_b,
            vec![FederationPeerConfig {
                peer_id: "alpha".to_string(),
                host: "127.0.0.1".to_string(),
                port: addr_a.port(),
                public_key_path: pub_a.display().to_string(),
            }],
            FederationDirectory::open(dir_b.join("directory")).unwrap(),
        )
        .unwrap(),
    );

    tokio::spawn(federation::serve(listener_a, test_federation_context(config_a.clone())));
    tokio::spawn(federation::serve(listener_b, test_federation_context(config_b.clone())));

    // Gossip has to survive in *both* directions on whichever connection
    // won - a half-alive link shows up as one of these never arriving.
    config_a.directory.lock().await.record_local_nickname("from-alpha".to_string(), "alpha").unwrap();
    config_b.directory.lock().await.record_local_nickname("from-zeta".to_string(), "zeta").unwrap();
    wait_until(Duration::from_secs(10), || async {
        federation::broadcast(
            &config_a,
            FederationMessage::NicknameRegistered {
                nickname: "from-alpha".to_string(),
                owner: "alpha".to_string(),
            },
            federation::event::NICKS_GOSSIP,
        )
        .await;
        federation::broadcast(
            &config_b,
            FederationMessage::NicknameRegistered {
                nickname: "from-zeta".to_string(),
                owner: "zeta".to_string(),
            },
            federation::event::NICKS_GOSSIP,
        )
        .await;
        let a_knows = matches!(
            config_a.directory.lock().await.owner_of_nickname("from-zeta"),
            Some(Ownership::Owned(owner)) if owner == "zeta"
        );
        let b_knows = matches!(
            config_b.directory.lock().await.owner_of_nickname("from-alpha"),
            Some(Ownership::Owned(owner)) if owner == "alpha"
        );
        a_knows && b_knows
    })
    .await;
}

/// Presence gossip is live-only, so a peer that links up *after* people
/// joined has missed every `ChannelMemberJoined` for them. The home server
/// therefore sends a full `ChannelMembership` for each of its channels at
/// link-up, and the receiver replaces what it had with it - which is what
/// makes a late link, and a relink after a drop (which deliberately
/// forgets that peer's members), converge instead of showing a busy
/// channel as empty forever.
/// @requirement AC-483, TB-311
#[tokio::test]
async fn a_peer_linking_up_late_still_learns_who_is_already_in_a_channel() {
    let dir_hub = temp_dir("resync-hub");
    let dir_leaf = temp_dir("resync-leaf");
    let (identity_hub, pub_hub) = write_identity(&dir_hub);
    let (identity_leaf, pub_leaf) = write_identity(&dir_leaf);
    let port_hub = reserve_port().await;
    let port_leaf = reserve_port().await;

    // The hub knows about the leaf; the leaf is started later, so every
    // join below happens with no link up at all.
    let config_hub = FederationConfig::new(
        "hub".to_string(),
        format!("127.0.0.1:{port_hub}").parse().unwrap(),
        format!("127.0.0.1:{port_hub}"),
        None,
            identity_hub,
        vec![FederationPeerConfig {
            peer_id: "leaf".to_string(),
            host: "127.0.0.1".to_string(),
            port: port_leaf,
            public_key_path: pub_leaf.display().to_string(),
        }],
        FederationDirectory::open(dir_hub.join("directory")).unwrap(),
    )
    .unwrap();
    let hub = server_common::TestServer::spawn(
        server_common::test_options("resync-hub").with_federation(config_hub),
    )
    .await;

    let mut alice = hub.connect().await;
    hub.handshake(&mut alice, "alice").await;
    alice
        .send(&ClientMessage::JoinChannel {
            name: "forum".to_string(),
            kind: ChannelKind::Public,
            password: None,
        })
        .await
        .unwrap();
    assert!(matches!(recv_with_timeout(&mut alice).await, ServerMessage::Joined { .. }));

    // Only now does the leaf exist - it never saw alice's join gossip.
    let config_leaf = FederationConfig::new(
        "leaf".to_string(),
        format!("127.0.0.1:{port_leaf}").parse().unwrap(),
        format!("127.0.0.1:{port_leaf}"),
        None,
            identity_leaf,
        vec![FederationPeerConfig {
            peer_id: "hub".to_string(),
            host: "127.0.0.1".to_string(),
            port: port_hub,
            public_key_path: pub_hub.display().to_string(),
        }],
        FederationDirectory::open(dir_leaf.join("directory")).unwrap(),
    )
    .unwrap();
    let leaf = server_common::TestServer::spawn(
        server_common::test_options("resync-leaf").with_federation(config_leaf),
    )
    .await;

    wait_until(Duration::from_secs(15), || async {
        matches!(
            leaf.options.federation.as_ref().unwrap().directory.lock().await.owner_of_channel("forum"),
            Some(info) if info.owner == "hub"
        )
    })
    .await;

    // A client joining on the leaf must see alice, who was already there
    // before the two servers had ever spoken.
    let mut bob = leaf.connect().await;
    leaf.handshake(&mut bob, "bob").await;
    bob.send(&ClientMessage::JoinChannel {
        name: "forum".to_string(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();
    let alice_presence = recv_with_timeout(&mut bob).await;
    assert!(
        matches!(&alice_presence, ServerMessage::UserJoined { channel, user } if channel == "forum" && user.name == "alice"),
        "a late-linking peer must still learn who was already in the channel, got {alice_presence:?}"
    );
}

/// A join-proxy request is answered only by the peer it was actually sent
/// to. Request ids are this server's own counter from 1, so they are
/// entirely predictable: without checking *which* link an answer arrived
/// on, any other linked peer could answer a request never addressed to it
/// and have its verdict believed - a forged `Joined` mirroring a channel
/// it does not own into the requesting server, admitting a client the
/// real owner never checked a password, ban or allowlist for. Here
/// "aaa" asks "bbb" about a channel, and "ccc" (linked to "aaa", but a
/// complete stranger to the request) races an answer in.
/// @requirement TB-312
#[tokio::test]
async fn a_join_proxy_answer_from_a_peer_the_request_never_went_to_is_ignored() {
    let (listener_a, addr_a) = bind_ephemeral().await;
    let (listener_b, addr_b) = bind_ephemeral().await;
    let (listener_c, addr_c) = bind_ephemeral().await;
    let dir_a = temp_dir("forge-a");
    let dir_b = temp_dir("forge-b");
    let dir_c = temp_dir("forge-c");
    let (identity_a, pub_a) = write_identity(&dir_a);
    let (identity_b, pub_b) = write_identity(&dir_b);
    let (identity_c, pub_c) = write_identity(&dir_c);

    // "aaa" sorts first, so it is the one that dials both others.
    let peer = |peer_id: &str, addr: std::net::SocketAddr, key: &PathBuf| FederationPeerConfig {
        peer_id: peer_id.to_string(),
        host: "127.0.0.1".to_string(),
        port: addr.port(),
        public_key_path: key.display().to_string(),
    };
    let mut directory_a = FederationDirectory::open(dir_a.join("directory")).unwrap();
    // "aaa" believes "bbb" owns the channel - so that is the only peer
    // whose answer about it may ever count.
    directory_a.merge_remote_channel(FederatedChannelInfo {
        name: "vault".to_string(),
        kind: ChannelKind::Private,
        owner: "bbb".to_string(),
    });

    let config_a = Arc::new(
        FederationConfig::new(
            "aaa".to_string(),
            addr_a,
            addr_a.to_string(),
            None,
            identity_a,
            vec![peer("bbb", addr_b, &pub_b), peer("ccc", addr_c, &pub_c)],
            directory_a,
        )
        .unwrap(),
    );
    let config_b = Arc::new(
        FederationConfig::new(
            "bbb".to_string(),
            addr_b,
            addr_b.to_string(),
            None,
            identity_b,
            vec![peer("aaa", addr_a, &pub_a)],
            FederationDirectory::open(dir_b.join("directory")).unwrap(),
        )
        .unwrap(),
    );
    let config_c = Arc::new(
        FederationConfig::new(
            "ccc".to_string(),
            addr_c,
            addr_c.to_string(),
            None,
            identity_c,
            vec![peer("aaa", addr_a, &pub_a)],
            FederationDirectory::open(dir_c.join("directory")).unwrap(),
        )
        .unwrap(),
    );

    tokio::spawn(federation::serve(listener_a, test_federation_context(config_a.clone())));
    tokio::spawn(federation::serve(listener_b, test_federation_context(config_b.clone())));
    tokio::spawn(federation::serve(listener_c, test_federation_context(config_c.clone())));

    wait_until(Duration::from_secs(5), || async {
        config_a.send_to_peer("bbb", FederationMessage::NicknameRegistered {
            nickname: "linkcheck".to_string(),
            owner: "aaa".to_string(),
        })
        .await
            && config_a
                .send_to_peer("ccc", FederationMessage::NicknameRegistered {
                    nickname: "linkcheck".to_string(),
                    owner: "aaa".to_string(),
                })
                .await
    })
    .await;

    // "ccc" spams forged grants for the request id "aaa" is about to use
    // (its first, so 1) while the real request is in flight.
    let forger = {
        let config_c = config_c.clone();
        tokio::spawn(async move {
            for _ in 0..200 {
                config_c
                    .send_to_peer(
                        "aaa",
                        FederationMessage::JoinProxyResponse {
                            request_id: 1,
                            outcome: federation::proto::JoinProxyOutcome::Joined {
                                kind: ChannelKind::Private,
                                admin: Some("mallory".to_string()),
                            },
                        },
                    )
                    .await;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    };

    // "bbb" has no such channel, so its real answer is `UnknownChannel` -
    // which is what must decide, however fast the forgery arrives.
    let outcome = config_a
        .request_join_proxy("vault", "bob", Some("s3cret!"), Vec::new(), aloo::proto::KeyMode::PqHybrid)
        .await;
    forger.abort();

    assert!(
        matches!(outcome, Ok(federation::proto::JoinProxyOutcome::UnknownChannel)),
        "only the peer the request went to may answer it, got {outcome:?}"
    );
}

/// A federated member's synthetic `UserId` must stay *below* the top bit,
/// which `client::p2p::direct_peer_id` reserves for the serverless
/// direct-punch ids `is_direct_peer_id` recognises. An id with that bit
/// set is read by every client as "a peer no server has ever heard of",
/// which makes `ensure_link` short-circuit to `Pending` forever: the
/// member would sit permanently "Connecting" and anything sent to them
/// would queue silently, with no error and no timeout. `u64::MAX` itself
/// is doubly wrong - `client::voice_call` uses it as its own "id not
/// known yet" sentinel, and it is exactly what the first federated member
/// a server ever showed used to be handed.
/// @requirement TB-310
#[tokio::test]
async fn a_federated_members_synthetic_id_stays_clear_of_the_clients_reserved_id_space() {
    let (hub, leaf_a, _leaf_b) = spawn_federated_star("id-space").await;

    let mut alice = hub.connect().await;
    hub.handshake(&mut alice, "alice").await;
    alice
        .send(&ClientMessage::JoinChannel {
            name: "atrium".to_string(),
            kind: ChannelKind::Public,
            password: None,
        })
        .await
        .unwrap();
    assert!(matches!(recv_with_timeout(&mut alice).await, ServerMessage::Joined { .. }));

    wait_until(Duration::from_secs(5), || async {
        matches!(
            leaf_a.options.federation.as_ref().unwrap().directory.lock().await.owner_of_channel("atrium"),
            Some(info) if info.owner == "hub"
        )
    })
    .await;

    let mut bob = leaf_a.connect().await;
    leaf_a.handshake(&mut bob, "bob").await;
    bob.send(&ClientMessage::JoinChannel {
        name: "atrium".to_string(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();

    let alice_presence = recv_with_timeout(&mut bob).await;
    let ServerMessage::UserJoined { user, .. } = &alice_presence else {
        panic!("expected bob to be told about alice, got {alice_presence:?}");
    };
    assert_eq!(user.name, "alice");
    assert_eq!(
        user.id.0 & 0x8000_0000_0000_0000,
        0,
        "a federated member's id must leave the top bit clear - {:#x} collides with \
         client::p2p::direct_peer_id's reserved half",
        user.id.0
    );
    assert_ne!(
        user.id.0,
        u64::MAX,
        "u64::MAX is client::voice_call's 'own id unknown' sentinel"
    );
}

/// Records `nickname` as owned by `owner_id` in `server`'s own directory
/// and gossips it to every linked peer - exactly what `register_account`'s
/// wire flow does on a real `Register`, reproduced directly here since
/// the test harness's `ensure_user`/`handshake` register accounts out of
/// band (straight into the local users registry) and so never trigger it.
async fn federate_nickname(server: &server_common::TestServer, owner_id: &str, nickname: &str) {
    let federation = server.options.federation.as_ref().unwrap();
    federation
        .directory
        .lock()
        .await
        .record_local_nickname(nickname.to_string(), owner_id)
        .unwrap();
    federation::broadcast(
        federation,
        FederationMessage::NicknameRegistered {
            nickname: nickname.to_string(),
            owner: owner_id.to_string(),
        },
        federation::event::NICKS_GOSSIP,
    )
    .await;
}

async fn recv_with_timeout(stream: &mut ControlEndpoint<tokio::net::TcpStream>) -> ServerMessage {
    tokio::time::timeout(Duration::from_secs(5), stream.recv())
        .await
        .expect("timed out waiting for a message")
        .unwrap()
        .expect("connection closed while waiting for a message")
}

/// The whole cross-server join-proxy story: a channel created (with a
/// password) on `serverA` is joined, by name, from a client connected to
/// `serverB` - the right password succeeds and correctly reports the
/// home server's admin, and a wrong one is rejected exactly the way a
/// local wrong-password attempt would be, never silently granted.
/// @requirement AC-479, TB-307
#[tokio::test]
async fn a_client_on_one_server_joins_a_private_channel_homed_on_another() {
    let (server_a, server_b) = spawn_federated_pair("join-proxy").await;

    let mut alice = server_a.connect().await;
    server_a.handshake(&mut alice, "alice").await;
    alice
        .send(&ClientMessage::JoinChannel {
            name: "secret".to_string(),
            kind: ChannelKind::Private,
            password: Some("shh".to_string()),
        })
        .await
        .unwrap();
    let created = recv_with_timeout(&mut alice).await;
    assert!(matches!(created, ServerMessage::Joined { .. }), "{created:?}");

    wait_until(Duration::from_secs(5), || async {
        matches!(
            server_b.options.federation.as_ref().unwrap().directory.lock().await.owner_of_channel("secret"),
            Some(info) if info.owner == "serverA"
        )
    })
    .await;

    let mut bob = server_b.connect().await;
    server_b.handshake(&mut bob, "bob").await;
    bob.send(&ClientMessage::JoinChannel {
        name: "secret".to_string(),
        kind: ChannelKind::Private,
        password: Some("shh".to_string()),
    })
    .await
    .unwrap();
    let result = recv_with_timeout(&mut bob).await;
    match result {
        ServerMessage::Joined {
            channel: ChannelInfo { name, kind },
            admin,
        } => {
            assert_eq!(name, "secret");
            assert_eq!(kind, ChannelKind::Private);
            assert_eq!(admin.as_deref(), Some("alice"));
        }
        other => panic!("expected bob to join, got {other:?}"),
    }

    let mut mallory = server_b.connect().await;
    server_b.handshake(&mut mallory, "mallory").await;
    mallory
        .send(&ClientMessage::JoinChannel {
            name: "secret".to_string(),
            kind: ChannelKind::Private,
            password: Some("definitely-wrong".to_string()),
        })
        .await
        .unwrap();
    let rejected = recv_with_timeout(&mut mallory).await;
    assert!(
        matches!(
            rejected,
            ServerMessage::ChannelJoinRejected { kind: ChannelJoinRejection::WrongPassword, .. }
        ),
        "{rejected:?}"
    );
}

/// "Fully shared channel list" (docs/PROTOCOL.md §18.2): a *public*
/// channel created on one federated server is announced live
/// (`ServerMessage::ChannelCreated`) to a client already connected to a
/// *different* server, who never joined it and never even knew its name -
/// the same way a local client already learns about a brand-new local
/// public channel, just across the federation link instead of within one
/// server. A private channel created the same way stays invisible, exactly
/// like a local one would.
/// @requirement AC-482
#[tokio::test]
async fn a_public_channel_created_on_one_server_is_announced_live_to_an_already_connected_client_on_another() {
    let (server_a, server_b) = spawn_federated_pair("shared-list").await;

    // Connected to server B *before* the channel exists anywhere - proof
    // this is a live announcement, not something picked up from a
    // connect-time `ChannelList` snapshot that merely happened to be
    // fresh enough.
    let mut bob = server_b.connect().await;
    server_b.handshake(&mut bob, "bob").await;

    let mut alice = server_a.connect().await;
    server_a.handshake(&mut alice, "alice").await;
    alice
        .send(&ClientMessage::JoinChannel {
            name: "lobby".to_string(),
            kind: ChannelKind::Public,
            password: None,
        })
        .await
        .unwrap();
    let created = recv_with_timeout(&mut alice).await;
    assert!(matches!(created, ServerMessage::Joined { .. }), "{created:?}");

    let announced = recv_with_timeout(&mut bob).await;
    assert!(
        matches!(
            &announced,
            ServerMessage::ChannelCreated { channel: ChannelInfo { name, kind: ChannelKind::Public } }
                if name == "lobby"
        ),
        "{announced:?}"
    );

    // A *private* channel, created the same way, never gets this
    // treatment - it stays reachable only by knowing its name, exactly
    // like a local private channel.
    alice
        .send(&ClientMessage::JoinChannel {
            name: "hideout".to_string(),
            kind: ChannelKind::Private,
            password: Some("shh".to_string()),
        })
        .await
        .unwrap();
    let created = recv_with_timeout(&mut alice).await;
    assert!(matches!(created, ServerMessage::Joined { .. }), "{created:?}");

    wait_until(Duration::from_secs(5), || async {
        matches!(
            server_b.options.federation.as_ref().unwrap().directory.lock().await.owner_of_channel("hideout"),
            Some(info) if info.owner == "serverA"
        )
    })
    .await;
    // The directory (server B's internal bookkeeping) knows "hideout"
    // belongs to serverA by now, but that must never surface as a public
    // listing: a fresh connection to server B gets a `ChannelList` with no
    // trace of it.
    let channels = channel_list_via_fresh_connection(&server_b, "carol").await;
    assert!(
        !channels.iter().any(|c| c.name == "hideout"),
        "a private channel must never appear in another server's public channel list: {channels:?}"
    );
}

/// Connects `nickname` fresh to `server` and returns exactly the
/// `ChannelList` it gets right after the handshake - `TestServer::handshake`
/// only asserts that message's shape, not its content, which is what a
/// "does a channel show up" test actually needs.
async fn channel_list_via_fresh_connection(server: &server_common::TestServer, nickname: &str) -> Vec<ChannelInfo> {
    server.ensure_user(nickname);
    let mut stream = server.connect().await;
    let result = server_common::login(&mut stream, nickname, &server_common::password_for(nickname)).await;
    assert!(matches!(result, ServerMessage::AuthResult { ok: true, .. }), "{result:?}");
    stream
        .send(&ClientMessage::Identify { public_key_der: vec![], key_mode: aloo::proto::KeyMode::PqHybrid })
        .await
        .unwrap();
    let identify: ServerMessage = stream.recv().await.unwrap().unwrap();
    assert!(matches!(identify, ServerMessage::IdentifyResult { ok: true, .. }), "{identify:?}");
    let ServerMessage::ChannelList { channels, .. } = recv_with_timeout(&mut stream).await else {
        panic!("expected a ChannelList right after IdentifyResult");
    };
    channels
}

/// OTP mail uploaded on `serverB`, addressed to a nickname registered and
/// connected on `serverA`, is forwarded there and delivered live; the
/// recipient's ack relays a delivery receipt back to `serverB` so the
/// original sender learns of it too - the whole round trip end to end,
/// with the server never touching anything but the opaque ciphertext and
/// its routing metadata.
/// @requirement AC-480, TB-308
#[tokio::test]
async fn otp_mail_crosses_servers_and_the_receipt_relays_back() {
    let (server_a, server_b) = spawn_federated_pair("mail-relay").await;

    // Real federation registration goes through `register_account`'s wire
    // flow, which the test harness's `ensure_user`/`handshake` bypass
    // (they write straight into the local users registry) - so carol's
    // and dave's ownership is seeded into each directory exactly the way
    // `register_account` itself would, the one piece `forward_mail_if_remote`/
    // `relay_receipt_if_remote` actually key off.
    let mut carol = server_a.connect().await;
    server_a.handshake(&mut carol, "carol").await;
    federate_nickname(&server_a, "serverA", "carol").await;

    let mut dave = server_b.connect().await;
    server_b.handshake(&mut dave, "dave").await;
    federate_nickname(&server_b, "serverB", "dave").await;

    wait_until(Duration::from_secs(5), || async {
        matches!(
            server_b.options.federation.as_ref().unwrap().directory.lock().await.owner_of_nickname("carol"),
            Some(Ownership::Owned(owner)) if owner == "serverA"
        )
    })
    .await;
    wait_until(Duration::from_secs(5), || async {
        matches!(
            server_a.options.federation.as_ref().unwrap().directory.lock().await.owner_of_nickname("dave"),
            Some(Ownership::Owned(owner)) if owner == "serverB"
        )
    })
    .await;

    let mail_id = format!("{:02x}", 7u8).repeat(16);
    dave.send(&ClientMessage::OtpMailSend {
        mail_id: mail_id.clone(),
        to: "carol".to_string(),
        contact_name: "mail-carol".to_string(),
        seq: 1,
        sent_at_utc: 1_700_000_000,
        ciphertext: vec![9, 9, 9],
    })
    .await
    .unwrap();
    let result = recv_with_timeout(&mut dave).await;
    assert!(matches!(result, ServerMessage::OtpMailResult { ok: true, .. }), "{result:?}");

    let deliver = recv_with_timeout(&mut carol).await;
    match deliver {
        ServerMessage::OtpMailDeliver { mail_id: got_id, from, ciphertext, .. } => {
            assert_eq!(got_id, mail_id);
            assert_eq!(from, "dave");
            assert_eq!(ciphertext, vec![9, 9, 9]);
        }
        other => panic!("expected carol to receive the forwarded mail, got {other:?}"),
    }

    carol.send(&ClientMessage::OtpMailAck { mail_id: mail_id.clone() }).await.unwrap();
    let delivered = recv_with_timeout(&mut dave).await;
    assert!(
        matches!(delivered, ServerMessage::OtpMailDelivered { mail_id: ref id } if *id == mail_id),
        "{delivered:?}"
    );
}

// ---------------------------------------------------------------------
// Closing the channel-deletion gap: `/delete-channel` and a superadmin's
// `/remove-account`/`/remove-channel` now gossip the removal, and a peer
// mirroring the deleted channel cleans it up locally too.
// ---------------------------------------------------------------------

/// A channel deleted on its home server stops being routable everywhere
/// in the federation, and a peer that had mirrored it (because one of its
/// own local clients had proxy-joined it) force-deletes its mirror too,
/// notifying that local client exactly as an ordinary local deletion
/// would.
/// @requirement AC-481, AC-483, TB-309
#[tokio::test]
async fn deleting_a_channel_clears_it_from_every_peer_and_force_deletes_a_mirror() {
    let (server_a, server_b) = spawn_federated_pair("delete-channel").await;

    let mut alice = server_a.connect().await;
    server_a.handshake(&mut alice, "alice").await;
    alice
        .send(&ClientMessage::JoinChannel {
            name: "vault".to_string(),
            kind: ChannelKind::Public,
            password: None,
        })
        .await
        .unwrap();
    let _joined = recv_with_timeout(&mut alice).await;

    wait_until(Duration::from_secs(5), || async {
        matches!(
            server_b.options.federation.as_ref().unwrap().directory.lock().await.owner_of_channel("vault"),
            Some(info) if info.owner == "serverA"
        )
    })
    .await;

    let mut bob = server_b.connect().await;
    server_b.handshake(&mut bob, "bob").await;
    bob.send(&ClientMessage::JoinChannel {
        name: "vault".to_string(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();
    // Bob is told about alice - already a member through federation - via
    // a `UserJoined` ahead of his own `Joined`, the same order a local
    // join already tells a joiner about every pre-existing member before
    // confirming the join itself.
    let alice_presence = recv_with_timeout(&mut bob).await;
    assert!(
        matches!(&alice_presence, ServerMessage::UserJoined { channel, user } if channel == "vault" && user.name == "alice"),
        "{alice_presence:?}"
    );
    let joined = recv_with_timeout(&mut bob).await;
    assert!(matches!(joined, ServerMessage::Joined { .. }), "{joined:?}");

    // alice, a genuine local member of "vault" on its home server, was
    // already told about bob's federated join via `UserJoined` (the same
    // fix that told bob about alice above, the other direction).
    let bob_presence = recv_with_timeout(&mut alice).await;
    assert!(
        matches!(&bob_presence, ServerMessage::UserJoined { channel, user } if channel == "vault" && user.name == "bob"),
        "{bob_presence:?}"
    );

    // alice, the channel's own admin, deletes it on its home server.
    alice.send(&ClientMessage::DeleteChannel { name: "vault".to_string() }).await.unwrap();
    let admin_confirmation = recv_with_timeout(&mut alice).await;
    assert!(matches!(admin_confirmation, ServerMessage::ChannelRemoved { .. }), "{admin_confirmation:?}");

    // bob's mirror on server B is force-deleted too, with the same
    // client-facing notice a local deletion would send.
    let bob_notice = recv_with_timeout(&mut bob).await;
    assert!(
        matches!(&bob_notice, ServerMessage::ChannelRemoved { name, .. } if name == "vault"),
        "{bob_notice:?}"
    );

    // The name is free again federation-wide: neither server's directory
    // still claims it.
    wait_until(Duration::from_secs(5), || async {
        server_b.options.federation.as_ref().unwrap().directory.lock().await.owner_of_channel("vault").is_none()
    })
    .await;
    assert!(server_a.options.federation.as_ref().unwrap().directory.lock().await.owner_of_channel("vault").is_none());
}

/// A superadmin removing an account frees that nickname federation-wide -
/// gossiped the same way a channel's removal is - rather than leaving it
/// permanently claimed by a server that no longer has it.
/// @requirement AC-481, TB-309
#[tokio::test]
async fn removing_an_account_frees_the_nickname_federation_wide() {
    let (server_a, server_b) = spawn_federated_pair_with(
        "remove-account",
        |mut o| {
            o.superadmins.insert("admin".to_string());
            o
        },
        |o| o,
    )
    .await;

    let mut admin = server_a.connect().await;
    server_a.handshake(&mut admin, "admin").await;
    let mut carol = server_a.connect().await;
    server_a.handshake(&mut carol, "carol").await;
    federate_nickname(&server_a, "serverA", "carol").await;

    wait_until(Duration::from_secs(5), || async {
        matches!(
            server_b.options.federation.as_ref().unwrap().directory.lock().await.owner_of_nickname("carol"),
            Some(Ownership::Owned(owner)) if owner == "serverA"
        )
    })
    .await;

    admin.send(&ClientMessage::AdminRemoveAccount { nickname: "carol".to_string() }).await.unwrap();

    wait_until(Duration::from_secs(5), || async {
        server_b.options.federation.as_ref().unwrap().directory.lock().await.owner_of_nickname("carol").is_none()
    })
    .await;
    assert!(
        server_a
            .options
            .federation
            .as_ref()
            .unwrap()
            .directory
            .lock()
            .await
            .owner_of_nickname("carol")
            .is_none()
    );
    // Free again: a fresh registration for "carol" would no longer be
    // refused for belonging to server A.
    assert!(
        server_b
            .options
            .federation
            .as_ref()
            .unwrap()
            .directory
            .lock()
            .await
            .is_registrable_here("carol", "serverB")
            .is_ok()
    );
}

/// A channel name already `Conflicted` refuses a *third* server's attempt
/// to create yet another one under the same name, rather than letting the
/// collision grow - it must be resolved, not compounded.
/// @requirement AC-477
#[tokio::test]
async fn a_conflicted_channel_name_refuses_a_fresh_creation_attempt() {
    let (server_a, server_b) = spawn_federated_pair("conflicted-create").await;

    // Simulate an already-discovered conflict between two *other*
    // servers, learned by both A and B via a snapshot/gossip they were
    // both party to.
    for server in [&server_a, &server_b] {
        let federation = server.options.federation.as_ref().unwrap();
        let mut dir = federation.directory.lock().await;
        dir.merge_remote_channel(FederatedChannelInfo {
            name: "contested".to_string(),
            kind: ChannelKind::Public,
            owner: "serverX".to_string(),
        });
        dir.merge_remote_channel(FederatedChannelInfo {
            name: "contested".to_string(),
            kind: ChannelKind::Public,
            owner: "serverY".to_string(),
        });
    }

    let mut carol = server_a.connect().await;
    server_a.handshake(&mut carol, "carol").await;
    carol
        .send(&ClientMessage::JoinChannel {
            name: "contested".to_string(),
            kind: ChannelKind::Public,
            password: None,
        })
        .await
        .unwrap();
    let result = recv_with_timeout(&mut carol).await;
    assert!(
        matches!(result, ServerMessage::ChannelJoinFailed { ref reason, .. } if reason.contains("administrator")),
        "{result:?}"
    );
}
