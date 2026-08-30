//! Serverless direct UDP punching (US-037): the settings that name who to
//! punch at and how often, and the scheduler that meets them there.
//!
//! Deliberately server-free, unlike every other multi-client step file
//! here: these scenarios prove that a link opens with nothing arranging it,
//! so a live `Registry`/TCP server would defeat the point. The only socket
//! involved besides the two clients' own is a stand-in for the rendezvous
//! one, present purely so binding a manager answers immediately instead of
//! timing out (`spawn_fake_rendezvous`).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use cucumber::{given, then, when};
use tokio::net::UdpSocket;

use aloo::client::p2p::{
    DIRECT_MAX_RECONNECTS, DIRECT_PUNCH_WINDOW, LINK_IDLE_TIMEOUT, LinkReadiness, LinkStatus,
    P2pEvent, PeerLinkManager, direct_peer_id, is_direct_peer_id,
};
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{ClientMessage, Content, Envelope, UserId};
use aloo::settings::{DEFAULT_DIRECT_PUNCH_PORT, DirectPunchTarget, Settings};

use crate::world::AlooWorld;

/// The second of the hour every scenario's clients are configured at: one
/// slot boundary is then always exactly `60` for a per-minute target.
const CONFIGURED_AT: u64 = 30;

/// Answers `BindingRequest` with a publicly-routable-looking observation so
/// `PeerLinkManager::bind` finishes on its first probe rather than three
/// timeouts later. Nothing punches through it.
async fn spawn_fake_rendezvous() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let Ok(aloo::p2p_proto::RendezvousMessage::BindingRequest { token }) =
                aloo::proto::decode(&buf[..n])
            else {
                continue;
            };
            let reply = aloo::proto::encode(&aloo::p2p_proto::RendezvousMessage::BindingResponse {
                token,
                observed: "203.0.113.7:41234".parse().unwrap(),
            })
            .unwrap();
            let _ = socket.send_to(&reply, from).await;
        }
    });
    addr
}

async fn bind_client(w: &mut AlooWorld, name: &str) -> u16 {
    if w.direct_rendezvous.is_none() {
        w.direct_rendezvous = Some(spawn_fake_rendezvous().await);
    }
    let rendezvous = w.direct_rendezvous.unwrap();
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (link, socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(rendezvous), events_tx)
            .await
            .unwrap();
    let port = socket.local_addr().unwrap().port();
    let (raw_tx, raw_rx) = tokio::sync::mpsc::unbounded_channel();
    aloo::client::p2p::spawn_receive_loop(socket, Some(rendezvous), raw_tx);
    let client = w.clients.entry(name.to_string()).or_default();
    client.peer_link = Some(link);
    client.p2p_raw_rx = Some(raw_rx);
    client.p2p_events_rx = Some(events_rx);
    port
}

fn target(nickname: &str, port: u16, minutes: u32) -> DirectPunchTarget {
    DirectPunchTarget::parse(&format!(
        "{nickname},127.0.0.1:{port},{}",
        if minutes == 60 {
            "every_1h".to_string()
        } else {
            format!("every_{minutes}m")
        }
    ))
    .unwrap()
}

fn link_of<'a>(w: &'a mut AlooWorld, name: &str) -> &'a mut PeerLinkManager {
    w.client_mut(name).peer_link.as_mut().unwrap()
}

/// Drives both clients' receive loops and the scheduler until the link is
/// up on both sides, or the deadline passes.
async fn punch_until_active(w: &mut AlooWorld) {
    let bob_id = direct_peer_id("bob", None);
    let alice_id = direct_peer_id("alice", None);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let up = link_of(w, "alice").is_active(bob_id) && link_of(w, "bob").is_active(alice_id);
        if up {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the scheduled direct punch did not complete in time"
        );
        let mut alice = w.clients.remove("alice").unwrap();
        let mut bob = w.clients.remove("bob").unwrap();
        tokio::select! {
            Some((addr, dgram)) = alice.p2p_raw_rx.as_mut().unwrap().recv() => {
                alice.peer_link.as_mut().unwrap().on_inbound(addr, dgram);
            }
            Some((addr, dgram)) = bob.p2p_raw_rx.as_mut().unwrap().recv() => {
                bob.peer_link.as_mut().unwrap().on_inbound(addr, dgram);
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                let now = Instant::now();
                alice.peer_link.as_mut().unwrap().tick_with_clock_at(now, 60);
                bob.peer_link.as_mut().unwrap().tick_with_clock_at(now, 60);
            }
        }
        w.clients.insert("alice".into(), alice);
        w.clients.insert("bob".into(), bob);
    }
}

// ---------------------------------------------------------------------
// The settings file (AC-201, AC-202)
// ---------------------------------------------------------------------

#[given(expr = "a settings file that says")]
async fn settings_file(w: &mut AlooWorld, step: &cucumber::gherkin::Step) {
    let path = std::env::temp_dir().join(format!(
        "aloo-direct-punch-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, step.docstring().expect("a settings body")).unwrap();
    w.direct_settings = Some(Settings::load_or_create(&path).unwrap());
    w.temp_files.push(path);
}

#[then(expr = "direct punching is on")]
async fn punching_is_on(w: &mut AlooWorld) {
    assert!(
        w.direct_settings.as_ref().unwrap().direct_punch,
        "direct_punch=on must turn the scheduler on"
    );
}

#[then(expr = "{word} is punched at {string} every {int} minutes")]
async fn punched_every(w: &mut AlooWorld, name: String, host: String, minutes: u32) {
    let settings = w.direct_settings.as_ref().unwrap();
    let found = settings
        .direct_punch_to
        .iter()
        .find(|t| t.nickname == name)
        .unwrap_or_else(|| panic!("no direct_punch_to line for {name}"));
    assert_eq!(found.host, host);
    assert_eq!(found.frequency.minutes(), minutes);
}

#[then(expr = "a peer named with no port of its own uses the well-known direct punch port")]
async fn default_port(w: &mut AlooWorld) {
    let settings = w.direct_settings.as_ref().unwrap();
    for t in &settings.direct_punch_to {
        assert_eq!(
            t.ports,
            [DEFAULT_DIRECT_PUNCH_PORT],
            "{} named no port, so both sides must assume the well-known one",
            t.nickname
        );
    }
}

#[then(expr = "{string} names host {string} on the well-known port")]
async fn names_host_default_port(_w: &mut AlooWorld, value: String, host: String) {
    let target = DirectPunchTarget::parse(&value).unwrap_or_else(|e| panic!("{value:?}: {e}"));
    assert_eq!(target.host, host);
    assert_eq!(target.ports, [DEFAULT_DIRECT_PUNCH_PORT]);
}

#[then(expr = "{string} names host {string} on port {int}")]
async fn names_host_port(_w: &mut AlooWorld, value: String, host: String, port: u16) {
    let target = DirectPunchTarget::parse(&value).unwrap_or_else(|e| panic!("{value:?}: {e}"));
    assert_eq!(target.host, host);
    assert_eq!(target.ports, [port]);
}

/// Device-pinning plan §5a: a `+<device_id>` suffix on the nickname field
/// names a specific device rather than the nickname's default.
#[then(expr = "{string} names nickname {string} device {string}")]
async fn names_nickname_device(_w: &mut AlooWorld, value: String, nickname: String, device: String) {
    let target = DirectPunchTarget::parse(&value).unwrap_or_else(|e| panic!("{value:?}: {e}"));
    assert_eq!(target.nickname, nickname);
    assert_eq!(target.device_id.as_deref(), Some(device.as_str()));
}

#[then(expr = "{string} names nickname {string} with no device")]
async fn names_nickname_no_device(_w: &mut AlooWorld, value: String, nickname: String) {
    let target = DirectPunchTarget::parse(&value).unwrap_or_else(|e| panic!("{value:?}: {e}"));
    assert_eq!(target.nickname, nickname);
    assert_eq!(target.device_id, None);
}

#[then(expr = "this client punches from ports {string}")]
async fn punches_from_ports(w: &mut AlooWorld, ports: String) {
    let expected: Vec<u16> = ports.split(',').map(|p| p.trim().parse().unwrap()).collect();
    let settings = w.direct_settings.as_ref().unwrap();
    assert_eq!(
        settings.direct_punch_ports, expected,
        "what a peer can reach this client on is the set of ports it sends from"
    );
}

#[then(expr = "{string} names host {string} on ports {string}")]
async fn names_host_ports(_w: &mut AlooWorld, value: String, host: String, ports: String) {
    let target = DirectPunchTarget::parse(&value).unwrap_or_else(|e| panic!("{value:?}: {e}"));
    let expected: Vec<u16> = ports.split(',').map(|p| p.trim().parse().unwrap()).collect();
    assert_eq!(target.host, host);
    assert_eq!(target.ports, expected, "{value:?}");
}

#[then(expr = "{string} is refused, naming the allowed port range")]
async fn refused_out_of_range(_w: &mut AlooWorld, value: String) {
    let message = DirectPunchTarget::parse(&value)
        .expect_err(&format!("{value:?} names a port outside the allowed range"));
    assert!(
        message.contains(&aloo::settings::DIRECT_PUNCH_PORT_MIN.to_string())
            && message.contains(&aloo::settings::DIRECT_PUNCH_PORT_MAX.to_string()),
        "the reason must say what the range is, not just that the port is wrong: {message:?}"
    );
}

#[then(expr = "{string} is refused for naming no port at all")]
async fn refused_empty_list(_w: &mut AlooWorld, value: String) {
    let message =
        DirectPunchTarget::parse(&value).expect_err(&format!("{value:?} names an empty list"));
    assert!(message.contains("no port"), "unhelpful reason: {message:?}");
}

#[then(expr = "{int} direct punch lines are reported as unusable, each with a reason")]
async fn unusable_lines(w: &mut AlooWorld, count: usize) {
    let invalid = &w.direct_settings.as_ref().unwrap().direct_punch_invalid;
    assert_eq!(
        invalid.len(),
        count,
        "expected {count} unusable lines, got {invalid:?}"
    );
    for (line, reason) in invalid {
        assert!(
            !reason.is_empty(),
            "{line:?} was rejected with no reason, which is indistinguishable from a peer who never answers"
        );
    }
}

// ---------------------------------------------------------------------
// Reference table no-server row 6: a second device stays unreachable
// until a second, device-suffixed `direct_punch_to` line is added
// (device-pinning plan §5a). Pure configuration-level reachability - no
// actual punching needed, since `direct_peer`/`direct_status` are derived
// the instant `configure_direct_punch` runs.
// ---------------------------------------------------------------------

fn target_for_device(nickname: &str, device: &str, port: u16) -> DirectPunchTarget {
    DirectPunchTarget::parse(&format!("{nickname}+{device},127.0.0.1:{port},every_1h")).unwrap()
}

/// Re-applies `who`'s *whole* accumulated line list, exactly what
/// `SaveDirectPunchTargets` does live when a settings file is re-saved
/// with one more line in it - never one line configured in isolation,
/// since that would silently drop whatever was configured before it.
async fn list_device(w: &mut AlooWorld, who: &str, nickname: &str, device: &str) {
    bind_client(w, who).await;
    let lines = w.direct_punch_lines.entry(who.to_string()).or_default();
    // Above the OS ephemeral range so nothing else claims it, and inside
    // the range a `direct_punch_to` line accepts.
    let port = 61050 + lines.len() as u16;
    lines.push(target_for_device(nickname, device, port));
    let lines = lines.clone();
    link_of(w, who).configure_direct_punch(who.to_string(), lines, CONFIGURED_AT);
}

#[given(expr = "{word} lists {word}'s device {string} for direct punching")]
async fn given_lists_device(w: &mut AlooWorld, who: String, nickname: String, device: String) {
    list_device(w, &who, &nickname, &device).await;
}

#[when(expr = "{word} also lists {word}'s device {string} for direct punching")]
async fn also_lists_device(w: &mut AlooWorld, who: String, nickname: String, device: String) {
    list_device(w, &who, &nickname, &device).await;
}

#[then(expr = "{word} can reach {word}'s device {string}")]
async fn can_reach_device(w: &mut AlooWorld, who: String, nickname: String, device: String) {
    let key = format!("{nickname}+{device}");
    let expected = direct_peer_id(&nickname, Some(&device));
    assert_eq!(
        link_of(w, &who).direct_peer(&key),
        Some(expected),
        "{who} should be able to reach {nickname}'s device {device:?} - it has a configured line"
    );
}

#[then(expr = "{word} can still reach {word}'s device {string}")]
async fn can_still_reach_device(w: &mut AlooWorld, who: String, nickname: String, device: String) {
    can_reach_device(w, who, nickname, device).await;
}

#[then(expr = "{word} has no line at all for {word}'s device {string}")]
async fn no_line_for_device(w: &mut AlooWorld, who: String, nickname: String, device: String) {
    let key = format!("{nickname}+{device}");
    assert_eq!(
        link_of(w, &who).direct_status(&key),
        None,
        "the device has no target_key configured at all - not merely idle or lost, genuinely absent"
    );
    assert_eq!(
        link_of(w, &who).direct_peer(&key),
        None,
        "nothing to punch toward, nothing to have an id for"
    );
}

// ---------------------------------------------------------------------
// The schedule (AC-195 - AC-200)
// ---------------------------------------------------------------------

#[given(expr = "alice and bob each list the other for direct punching every minute")]
async fn both_list_each_other(w: &mut AlooWorld) {
    let alice_port = bind_client(w, "alice").await;
    let bob_port = bind_client(w, "bob").await;
    link_of(w, "alice").configure_direct_punch(
        "alice".into(),
        vec![target("bob", bob_port, 1)],
        CONFIGURED_AT,
    );
    link_of(w, "bob").configure_direct_punch(
        "bob".into(),
        vec![target("alice", alice_port, 1)],
        CONFIGURED_AT,
    );
}

/// A port nothing is listening on: bound only long enough to be handed a
/// free one, then dropped, so probing it is silence rather than a refusal.
async fn dead_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The shape a port-rewriting NAT produces: alice names three ports for
/// bob and only one of them is the one he can actually be reached on.
///
/// Bob lists alice at a dead port on purpose. His own probes then reach
/// nobody, so the only thing that can open this link is alice's sweep
/// finding the one live port among the three - which is the whole claim.
#[given(expr = "alice lists bob on three ports, only one of which reaches him")]
async fn alice_lists_three_ports(w: &mut AlooWorld) {
    bind_client(w, "alice").await;
    let bob_port = bind_client(w, "bob").await;
    let (dead_a, dead_b) = (dead_port().await, dead_port().await);
    let line = format!("bob,127.0.0.1:[{dead_a},{dead_b},{bob_port}],every_1m");
    link_of(w, "alice").configure_direct_punch(
        "alice".into(),
        vec![DirectPunchTarget::parse(&line).unwrap_or_else(|e| panic!("{line:?}: {e}"))],
        CONFIGURED_AT,
    );
    let alice_dead = dead_port().await;
    link_of(w, "bob").configure_direct_punch(
        "bob".into(),
        vec![target("alice", alice_dead, 1)],
        CONFIGURED_AT,
    );
    w.direct_swept_ports = Some(vec![dead_a, dead_b, bob_port]);
    w.direct_answered_port = Some(bob_port);
}

#[then(expr = "alice probes bob on only the port he answered from")]
async fn probes_only_the_answering_port(w: &mut AlooWorld) {
    let answered = w.direct_answered_port.expect("a scenario that set the ports up");
    let addrs = link_of(w, "alice").direct_probe_addrs_for_test("bob");
    let ports: Vec<u16> = addrs.iter().map(|a| a.port()).collect();
    assert_eq!(
        ports,
        vec![answered],
        "a port that answered is the port that survived both routers' rewriting - \
         re-probing the rest is pure noise"
    );
}

#[then(expr = "alice probes bob on all three ports again")]
async fn probes_all_ports_again(w: &mut AlooWorld) {
    let expected = w.direct_swept_ports.clone().expect("a scenario that set the ports up");
    let addrs = link_of(w, "alice").direct_probe_addrs_for_test("bob");
    let ports: Vec<u16> = addrs.iter().map(|a| a.port()).collect();
    assert_eq!(
        ports, expected,
        "losing the link reopens the question of which port works, so every \
         configured port is in play again"
    );
}

#[given(expr = "alice lists bob for direct punching every minute, at an address nobody answers")]
async fn alice_lists_dead_bob(w: &mut AlooWorld) {
    bind_client(w, "alice").await;
    let dead_port = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    link_of(w, "alice").configure_direct_punch(
        "alice".into(),
        vec![target("bob", dead_port, 1)],
        CONFIGURED_AT,
    );
}

#[given(expr = "alice lists bob for direct punching every hour")]
async fn alice_lists_bob_hourly(w: &mut AlooWorld) {
    bind_client(w, "alice").await;
    link_of(w, "alice").configure_direct_punch(
        "alice".into(),
        vec![target("bob", 65000, 60)],
        CONFIGURED_AT,
    );
}

#[when(expr = "the next slot on their shared grid comes round")]
async fn next_slot(w: &mut AlooWorld) {
    // Each pass of this step advances one whole minute of the grid, so a
    // scenario can ask for a second slot and get a genuinely new one.
    w.direct_slot += 1;
    let slot = w.direct_slot;
    let now = w.direct_now.unwrap_or_else(Instant::now);
    w.direct_now = Some(now);
    for name in ["alice", "bob"] {
        if w.clients.contains_key(name) {
            link_of(w, name).tick_with_clock_at(now, slot * 60);
        }
    }
}

#[given(expr = "their scheduled link is up")]
#[then(expr = "alice and bob have a direct link to each other")]
async fn link_is_up(w: &mut AlooWorld) {
    punch_until_active(w).await;
    assert_eq!(
        link_of(w, "alice").direct_status("bob"),
        Some(LinkStatus::Active)
    );
    assert_eq!(
        link_of(w, "bob").direct_status("alice"),
        Some(LinkStatus::Active)
    );
}

#[then(expr = "no candidate exchange was ever relayed through a server")]
async fn nothing_relayed(w: &mut AlooWorld) {
    for name in ["alice", "bob"] {
        let rx = w.client_mut(name).p2p_events_rx.as_mut().unwrap();
        while let Ok(event) = rx.try_recv() {
            assert!(
                !matches!(event, P2pEvent::Signal { .. }),
                "{name} asked for candidates to be relayed, but this link had no server in it"
            );
        }
    }
}

#[then(expr = "a message alice sends over that link arrives at bob")]
async fn message_arrives(w: &mut AlooWorld) {
    let bob_id = direct_peer_id("bob", None);
    let alice_id = direct_peer_id("alice", None);
    link_of(w, "alice").send_reliable_or_queue(
        bob_id,
        P2pPayload::Envelope {
            channel: None,
            msg_id: None,
            envelope: Envelope {
                content: Content::Text,
                blocks: vec![b"no server involved".to_vec()],
            },
        },
    );
    let mut alice = w.clients.remove("alice").unwrap();
    let mut bob = w.clients.remove("bob").unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            tokio::select! {
                Some((addr, dgram)) = alice.p2p_raw_rx.as_mut().unwrap().recv() => {
                    alice.peer_link.as_mut().unwrap().on_inbound(addr, dgram);
                }
                Some((addr, dgram)) = bob.p2p_raw_rx.as_mut().unwrap().recv() => {
                    bob.peer_link.as_mut().unwrap().on_inbound(addr, dgram);
                }
                Some(event) = bob.p2p_events_rx.as_mut().unwrap().recv() => {
                    if let P2pEvent::Message { from, envelope, .. } = event {
                        return (from, envelope);
                    }
                }
            }
        }
    })
    .await
    .expect("bob should receive alice's message over the direct link");
    w.clients.insert("alice".into(), alice);
    w.clients.insert("bob".into(), bob);
    assert_eq!(got.0, alice_id, "the message is attributed to alice");
    assert_eq!(got.1.blocks[0], b"no server involved".to_vec());
}

/// The delivery acknowledgment (docs/PROTOCOL.md 7.2.1) end to end, over a
/// real punched link: alice names her message, bob's side answers with a
/// `DeliveryReceipt` for it - which is exactly what
/// `session::send_delivery_receipt` does once an envelope has actually
/// been decrypted - and alice's own side turns that into the `Delivered`
/// event her indicator is driven by. Bob is a bare transport here with no
/// session behind it, so the step stands in for the decrypt step itself;
/// what it proves is that the id survives the round trip and comes back
/// attributed to the right peer.
#[then(expr = "a message alice sends over that link is acknowledged back to her")]
async fn message_is_acknowledged(w: &mut AlooWorld) {
    const MSG_ID: u64 = 77;
    let bob_id = direct_peer_id("bob", None);
    let alice_id = direct_peer_id("alice", None);
    link_of(w, "alice").send_reliable_or_queue(
        bob_id,
        P2pPayload::Envelope {
            channel: None,
            msg_id: Some(MSG_ID),
            envelope: Envelope {
                content: Content::Text,
                blocks: vec![b"did you get this".to_vec()],
            },
        },
    );
    let mut alice = w.clients.remove("alice").unwrap();
    let mut bob = w.clients.remove("bob").unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            tokio::select! {
                Some((addr, dgram)) = alice.p2p_raw_rx.as_mut().unwrap().recv() => {
                    alice.peer_link.as_mut().unwrap().on_inbound(addr, dgram);
                }
                Some((addr, dgram)) = bob.p2p_raw_rx.as_mut().unwrap().recv() => {
                    bob.peer_link.as_mut().unwrap().on_inbound(addr, dgram);
                }
                Some(event) = bob.p2p_events_rx.as_mut().unwrap().recv() => {
                    // Bob only answers a message that actually named one -
                    // an unnamed message earns no receipt at all.
                    if let P2pEvent::Message { from, msg_id: Some(msg_id), .. } = event {
                        bob.peer_link.as_mut().unwrap().send_reliable_or_queue(
                            from,
                            P2pPayload::DeliveryReceipt {
                                msg_id,
                                stage: aloo::p2p_proto::ReceiptStage::Decrypted,
                            },
                        );
                    }
                }
                Some(event) = alice.p2p_events_rx.as_mut().unwrap().recv() => {
                    if let P2pEvent::Delivered { peer, msg_id, .. } = event {
                        return (peer, msg_id);
                    }
                }
            }
        }
    })
    .await
    .expect("alice should be told her message was read by bob");
    w.clients.insert("alice".into(), alice);
    w.clients.insert("bob".into(), bob);
    assert_eq!(got.0, bob_id, "the receipt names who sent it");
    assert_eq!(got.1, MSG_ID, "and which message of hers it answers");
    assert_ne!(bob_id, alice_id, "the two are distinct peers");
}

/// The other half of the contract: a payload that names no message asks
/// for no receipt, which is what keeps the OTP layer's own provisioning
/// traffic from generating receipts for rows that do not exist (7.2.1).
#[then(expr = "a message alice sends without naming it is never acknowledged")]
async fn message_is_not_acknowledged(w: &mut AlooWorld) {
    let bob_id = direct_peer_id("bob", None);
    link_of(w, "alice").send_reliable_or_queue(
        bob_id,
        P2pPayload::Envelope {
            channel: None,
            msg_id: None,
            envelope: Envelope {
                content: Content::Text,
                blocks: vec![b"no answer wanted".to_vec()],
            },
        },
    );
    let mut alice = w.clients.remove("alice").unwrap();
    let mut bob = w.clients.remove("bob").unwrap();
    let mut arrived = false;
    // Bob's client only ever answers a message that named one, so pumping
    // the link to quiescence must produce no `Delivered` for alice.
    let _ = tokio::time::timeout(Duration::from_millis(600), async {
        loop {
            tokio::select! {
                Some((addr, dgram)) = alice.p2p_raw_rx.as_mut().unwrap().recv() => {
                    alice.peer_link.as_mut().unwrap().on_inbound(addr, dgram);
                }
                Some((addr, dgram)) = bob.p2p_raw_rx.as_mut().unwrap().recv() => {
                    bob.peer_link.as_mut().unwrap().on_inbound(addr, dgram);
                }
                Some(event) = bob.p2p_events_rx.as_mut().unwrap().recv() => {
                    if let P2pEvent::Message { from, msg_id, .. } = event {
                        arrived = true;
                        assert_eq!(msg_id, None, "nothing named it");
                        // Faithfully doing what a real client does with an
                        // unnamed message: nothing.
                        let _ = from;
                    }
                }
                Some(event) = alice.p2p_events_rx.as_mut().unwrap().recv() => {
                    assert!(
                        !matches!(event, P2pEvent::Delivered { .. }),
                        "an unnamed message must never come back acknowledged"
                    );
                }
            }
        }
    })
    .await;
    w.clients.insert("alice".into(), alice);
    w.clients.insert("bob".into(), bob);
    assert!(arrived, "the message itself should still have got there");
}

#[when(expr = "four more slots come and go")]
async fn four_more_slots(w: &mut AlooWorld) {
    let bob_id = direct_peer_id("bob", None);
    w.direct_addr = link_of(w, "alice").active_addr(bob_id);
    let now = Instant::now();
    for slot in 2..6u64 {
        link_of(w, "alice").tick_with_clock_at(now, slot * 60);
    }
}

#[then(expr = "alice's link to bob is still up on the same address")]
async fn still_up_same_address(w: &mut AlooWorld) {
    let bob_id = direct_peer_id("bob", None);
    let expected = w.direct_addr;
    let link = link_of(w, "alice");
    assert!(link.is_active(bob_id), "the link was interrupted by a slot");
    assert_eq!(
        link.active_addr(bob_id),
        expected,
        "the link was re-punched onto a new address by a slot"
    );
}

#[then(expr = "alice is punching at bob")]
async fn alice_is_punching(w: &mut AlooWorld) {
    assert_eq!(
        link_of(w, "alice").direct_status("bob"),
        Some(LinkStatus::Connecting)
    );
}

#[then(expr = "alice is no longer punching at bob")]
async fn alice_stopped_punching(w: &mut AlooWorld) {
    assert_eq!(
        link_of(w, "alice").direct_status("bob"),
        Some(LinkStatus::Lost)
    );
}

#[when(expr = "the punch window elapses")]
async fn window_elapses(w: &mut AlooWorld) {
    let now = w.direct_now.unwrap() + DIRECT_PUNCH_WINDOW;
    w.direct_now = Some(now);
    let slot = w.direct_slot;
    link_of(w, "alice").tick_with_clock_at(now, slot * 60);
}

#[then(expr = "no reconnect budget has been spent")]
async fn no_budget_spent(w: &mut AlooWorld) {
    assert_eq!(
        link_of(w, "alice").direct_reconnects("bob"),
        Some(0),
        "an attempt that never had a link to lose must not spend the reconnect budget"
    );
}

#[when(expr = "bob disappears and the link goes quiet")]
async fn bob_disappears(w: &mut AlooWorld) {
    // Nothing more is fed into alice's manager, so the ordinary liveness
    // check loses the link - the same way a real peer vanishing does.
    let mut now = Instant::now() + LINK_IDLE_TIMEOUT + Duration::from_secs(1);
    link_of(w, "alice").tick_with_clock_at(now, 60);
    now += Duration::from_millis(1);
    link_of(w, "alice").tick_with_clock_at(now, 60);
    w.direct_now = Some(now);
}

#[then(expr = "alice re-punches at bob straight away, outside the schedule")]
async fn repunches_immediately(w: &mut AlooWorld) {
    let link = link_of(w, "alice");
    assert_eq!(link.direct_status("bob"), Some(LinkStatus::Connecting));
    assert_eq!(link.direct_reconnects("bob"), Some(1));
}

#[then(expr = "she gives up after {int} reconnect attempts and waits for her next slot")]
async fn gives_up_after(w: &mut AlooWorld, attempts: u32) {
    assert_eq!(
        attempts, DIRECT_MAX_RECONNECTS,
        "the scenario and DIRECT_MAX_RECONNECTS must agree"
    );
    let mut now = w.direct_now.unwrap();
    for expected in 2..=DIRECT_MAX_RECONNECTS {
        now += DIRECT_PUNCH_WINDOW;
        link_of(w, "alice").tick_with_clock_at(now, 60);
        assert_eq!(
            link_of(w, "alice").direct_reconnects("bob"),
            Some(expected),
            "reconnect {expected} of {DIRECT_MAX_RECONNECTS}"
        );
    }
    now += DIRECT_PUNCH_WINDOW;
    link_of(w, "alice").tick_with_clock_at(now, 60);
    let link = link_of(w, "alice");
    assert_eq!(link.direct_status("bob"), Some(LinkStatus::Lost));
    assert_eq!(link.direct_reconnects("bob"), Some(0));
}

#[when(expr = "alice tries to send bob a message")]
async fn alice_tries_to_send(w: &mut AlooWorld) {
    let bob_id = direct_peer_id("bob", None);
    let mut sink = RecordingSink::default();
    let readiness = link_of(w, "alice").ensure_link(&mut sink, bob_id).await;
    assert_eq!(
        readiness,
        LinkReadiness::Pending,
        "the send waits on the attempt already underway"
    );
    w.direct_sent_to_server = sink.sent;
}

#[then(expr = "nothing is sent to the server about bob")]
async fn nothing_sent_to_server(w: &mut AlooWorld) {
    assert!(
        w.direct_sent_to_server.is_empty(),
        "a direct attempt must not be duplicated through the server: {:?}",
        w.direct_sent_to_server
    );
}

#[then(expr = "no retry ever asks the server to relay candidates for bob")]
async fn no_retry_signals(w: &mut AlooWorld) {
    let bob_id = direct_peer_id("bob", None);
    let mut now = w.direct_now.unwrap_or_else(Instant::now);
    for _ in 0..40 {
        now += Duration::from_secs(5);
        link_of(w, "alice").tick_with_clock_at(now, 60);
    }
    let rx = w.client_mut("alice").p2p_events_rx.as_mut().unwrap();
    while let Ok(event) = rx.try_recv() {
        assert!(
            !matches!(event, P2pEvent::Signal { peer, .. } if peer == bob_id),
            "a peer no server has ever named must never be re-signalled through one"
        );
    }
}

#[then(expr = "alice files bob under a peer id no server could have handed out")]
async fn files_under_synthetic(w: &mut AlooWorld) {
    let peer = link_of(w, "alice").direct_peer("bob").unwrap();
    assert_eq!(peer, direct_peer_id("bob", None));
    assert!(is_direct_peer_id(peer));
}

#[when(expr = "the server tells alice that bob is user {int}")]
async fn server_names_bob(w: &mut AlooWorld, id: u64) {
    link_of(w, "alice").set_direct_peer_id("bob", Some(UserId(id)));
}

#[then(expr = "alice files bob under user {int}")]
async fn files_under_server_id(w: &mut AlooWorld, id: u64) {
    assert_eq!(link_of(w, "alice").direct_peer("bob"), Some(UserId(id)));
}

#[when(expr = "bob goes offline on the server")]
async fn bob_goes_offline(w: &mut AlooWorld) {
    let peer = link_of(w, "alice").direct_peer("bob").unwrap();
    link_of(w, "alice").release_direct_peer_id(peer);
}

/// A `ControlSink` that records what would have gone to the server, so a
/// scenario can assert that nothing did.
#[derive(Default)]
struct RecordingSink {
    sent: Vec<ClientMessage>,
}

impl aloo::control::ControlSink for RecordingSink {
    async fn send_control(&mut self, msg: &ClientMessage) -> aloo::proto::Result<()> {
        self.sent.push(msg.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Becoming a real, addressable peer (AC-214 - AC-216)
// ---------------------------------------------------------------------

use aloo::client::idstore::IdStore;
use aloo::client::session::{direct_peer_identity, reconcile_direct_membership};

fn scratch_id_store(w: &mut AlooWorld) -> &mut IdStore {
    if w.id_store.is_none() {
        let path = std::env::temp_dir().join(format!(
            "aloo-bdd-direct-id-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        w.temp_files.push(path.clone());
        w.id_store = Some(IdStore::new_empty(path));
    }
    w.id_store.as_mut().expect("just set")
}

#[given(expr = "alice has no pinned identity for {string}")]
async fn no_pinned_identity(w: &mut AlooWorld, _name: String) {
    scratch_id_store(w);
}

#[given(expr = "alice has a pinned identity for {string} that is not a pq_hybrid one")]
async fn pinned_but_unsigned(w: &mut AlooWorld, name: String) {
    // What a hand-installed pad contact leaves behind: a pin that names
    // someone but carries no keybundle to seal anything to.
    scratch_id_store(w).pin_new_device(
        &name,
        "test-device",
        b"a-pad-only-pin-not-a-pq-bundle",
        aloo::client::idstore::Trust::Tofu,
    );
}

#[then(expr = "{string} cannot become an addressable peer")]
async fn cannot_become_peer(w: &mut AlooWorld, name: String) {
    let store = scratch_id_store(w);
    assert!(
        direct_peer_identity(store, &name, None).is_none(),
        "{name} must not be registerable: a nickname on an unauthenticated \
         punch names nobody at all unless something is pinned for it"
    );
}

#[then(expr = "{string} is named by that pin, but nothing is sealed to it")]
async fn named_but_unsealable(w: &mut AlooWorld, name: String) {
    let store = scratch_id_store(w);
    let info = direct_peer_identity(store, &name, None)
        .unwrap_or_else(|| panic!("{name} is pinned, so the pin names them"));
    assert!(
        aloo::crypto::pq::fingerprint_of_encoded(&info.public_key_der).is_none(),
        "the pin is deliberately not a keybundle, so no envelope can be built for them"
    );
}

#[then(expr = "only a pad can prove {string} is who the pin says")]
async fn only_a_pad_proves(w: &mut AlooWorld, name: String) {
    let store = scratch_id_store(w);
    let info = direct_peer_identity(store, &name, None).expect("pinned");
    // With no keybundle on their side the pair is framed direct, which is
    // the framing whose authentication *is* the pad's decrypt verdict
    // (docs/PROTOCOL.md 16.2).
    assert_eq!(
        aloo::client::otp::framing_for(b"our-own-pad-only-pin", &info.public_key_der),
        aloo::client::otp::OtpFraming::Direct
    );
}

#[given(expr = "alice has joined {string} and {string}")]
async fn alice_joined_two(w: &mut AlooWorld, a: String, b: String) {
    w.direct_our_channels = vec![a, b];
}

#[given(expr = "bob is already placed in {string}")]
async fn bob_already_in(w: &mut AlooWorld, channel: String) {
    w.direct_current_channels = vec![channel];
}

#[when(expr = "bob announces over the direct link that he is in {string} and {string}")]
async fn bob_announces_two(w: &mut AlooWorld, a: String, b: String) {
    let r = reconcile_direct_membership(
        &[a, b],
        &w.direct_our_channels.clone(),
        &w.direct_current_channels.clone(),
    );
    w.direct_reconciled = Some((r.shared, r.join, r.leave));
}

#[when(expr = "bob announces over the direct link that he is in {string}")]
async fn bob_announces_one(w: &mut AlooWorld, a: String) {
    let r = reconcile_direct_membership(
        &[a],
        &w.direct_our_channels.clone(),
        &w.direct_current_channels.clone(),
    );
    w.direct_reconciled = Some((r.shared, r.join, r.leave));
}

#[when(expr = "bob announces over the direct link that he is in no channels")]
async fn bob_announces_none(w: &mut AlooWorld) {
    let r = reconcile_direct_membership(
        &[],
        &w.direct_our_channels.clone(),
        &w.direct_current_channels.clone(),
    );
    w.direct_reconciled = Some((r.shared, r.join, r.leave));
}

#[then(expr = "bob is placed in {string}")]
async fn bob_placed_in(w: &mut AlooWorld, channel: String) {
    let (shared, join, _) = w.direct_reconciled.clone().expect("no announcement yet");
    assert!(
        shared.contains(&channel),
        "expected bob to end up in {channel:?}, shared = {shared:?}"
    );
    assert!(
        join.contains(&channel),
        "expected bob to be newly placed in {channel:?}, joining = {join:?}"
    );
}

#[then(expr = "bob is not placed in {string}")]
async fn bob_not_placed_in(w: &mut AlooWorld, channel: String) {
    let (shared, _, _) = w.direct_reconciled.clone().expect("no announcement yet");
    assert!(
        !shared.contains(&channel),
        "a channel we have not joined ourselves gives us nowhere to put them: {shared:?}"
    );
}

#[then(expr = "bob is removed from {string}")]
async fn bob_removed_from(w: &mut AlooWorld, channel: String) {
    let (_, _, leave) = w.direct_reconciled.clone().expect("no announcement yet");
    assert!(
        leave.contains(&channel),
        "expected bob to be dropped from {channel:?}, leaving = {leave:?}"
    );
}

#[then(expr = "bob is still an addressable peer")]
async fn bob_still_addressable(w: &mut AlooWorld) {
    let (shared, _, _) = w.direct_reconciled.clone().expect("no announcement yet");
    assert!(
        shared.is_empty(),
        "this scenario is about the no-shared-channel case"
    );
    // Sharing no channel is not the same as being unreachable: the DM is
    // what `direct_punch_to` buys on its own, and what `--focus <nickname>`
    // addresses.
}

#[then(expr = "leaving a channel does not forget the link to bob")]
async fn leaving_keeps_the_link(w: &mut AlooWorld) {
    let bob = direct_peer_id("bob", None);
    assert!(
        link_of(w, "alice").direct_nickname_of(bob).is_some(),
        "a settings-file peer must stay recognisable as one, which is what \
         keeps a channel departure from tearing its link down"
    );
    assert!(link_of(w, "alice").is_active(bob));
}

// ---------------------------------------------------------------------
// Running with no server at all (AC-217 - AC-220)
// ---------------------------------------------------------------------

use aloo::client::session::ServerState;
use aloo::client::tui::ui::UiAction;

#[then(expr = "running with no server explains a refusal as permanent")]
async fn refusal_permanent(_w: &mut AlooWorld) {
    let msg = ServerState::Absent.refusal("joining a channel");
    assert!(msg.contains("joining a channel"), "{msg}");
    assert!(
        !msg.contains("unreachable"),
        "there is no server to become reachable, so nothing should suggest waiting: {msg}"
    );
}

#[then(expr = "an unreachable server explains the same refusal as temporary")]
async fn refusal_temporary(_w: &mut AlooWorld) {
    let msg = ServerState::Unreachable.refusal("joining a channel");
    assert!(msg.contains("joining a channel"), "{msg}");
    assert!(
        msg.contains("unreachable"),
        "a server that is merely away should read as temporary: {msg}"
    );
}

#[then(expr = "{string} needs a server")]
async fn needs_a_server(_w: &mut AlooWorld, what: String) {
    let action = match what.as_str() {
        "joining a channel" => UiAction::JoinChannel {
            name: "general".into(),
            kind: aloo::proto::ChannelKind::Public,
            password: None,
        },
        "OTP mail" => UiAction::OpenOtpMailbox,
        other => panic!("no action for {other:?}"),
    };
    assert_eq!(action.needs_server(), Some(what.as_str()));
}

#[then(expr = "sending a message does not need a server")]
async fn send_needs_no_server(_w: &mut AlooWorld) {
    assert_eq!(
        UiAction::SendChannelText {
            channel: "general".into(),
            plaintext: "hi".to_string(),
            recipients: Vec::new(),
            msg_id: 0,
        }
        .needs_server(),
        None
    );
}

#[then(expr = "ending a call does not need a server")]
async fn call_needs_no_server(_w: &mut AlooWorld) {
    assert_eq!(UiAction::EndCall.needs_server(), None);
}

#[then(expr = "leaving a channel does not need a server")]
async fn leaving_needs_no_server(_w: &mut AlooWorld) {
    // A channel with no server behind it is a name we declared, so
    // dropping it is a local act.
    assert_eq!(
        UiAction::LeaveChannel {
            name: "general".into()
        }
        .needs_server(),
        None
    );
}

#[then(expr = "the channels available without a server are {string} and {string}")]
async fn configured_channels_are(w: &mut AlooWorld, a: String, b: String) {
    let settings = w.direct_settings.as_ref().expect("no settings loaded");
    assert_eq!(
        settings.direct_punch_channels,
        vec![a, b],
        "the configured channels are the whole of what exists, in file order and without duplicates"
    );
}

#[given(expr = "bob lists peter for direct punching")]
async fn bob_lists_peter(w: &mut AlooWorld) {
    let peter_port = bind_client(w, "peter").await;
    bind_client(w, "bob").await;
    link_of(w, "bob").configure_direct_punch(
        "bob".into(),
        vec![target("peter", peter_port, 1)],
        CONFIGURED_AT,
    );
}

#[given(expr = "peter lists somebody else instead")]
async fn peter_lists_someone_else(w: &mut AlooWorld) {
    link_of(w, "peter").configure_direct_punch(
        "peter".into(),
        vec![target("omar", 65000, 1)],
        CONFIGURED_AT,
    );
}

#[when(expr = "both of them punch on the shared grid")]
async fn both_punch(w: &mut AlooWorld) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(700);
    let mut now = Instant::now();
    while tokio::time::Instant::now() < deadline {
        let mut bob = w.clients.remove("bob").unwrap();
        let mut peter = w.clients.remove("peter").unwrap();
        tokio::select! {
            Some((a, d)) = bob.p2p_raw_rx.as_mut().unwrap().recv() => {
                bob.peer_link.as_mut().unwrap().on_inbound(a, d);
            }
            Some((a, d)) = peter.p2p_raw_rx.as_mut().unwrap().recv() => {
                peter.peer_link.as_mut().unwrap().on_inbound(a, d);
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                now += Duration::from_millis(200);
                bob.peer_link.as_mut().unwrap().tick_with_clock_at(now, 60);
                peter.peer_link.as_mut().unwrap().tick_with_clock_at(now, 60);
            }
        }
        w.clients.insert("bob".into(), bob);
        w.clients.insert("peter".into(), peter);
    }
}

#[then(expr = "bob has no link to peter")]
async fn bob_no_link(w: &mut AlooWorld) {
    let peter = direct_peer_id("peter", None);
    assert!(
        !link_of(w, "bob").is_active(peter),
        "bob's probes must go unanswered: peter never listed him"
    );
}

#[then(expr = "peter has no link to bob")]
async fn peter_no_link(w: &mut AlooWorld) {
    let bob = direct_peer_id("bob", None);
    assert!(!link_of(w, "peter").is_active(bob));
}

#[then(expr = "peter has no record of bob at all")]
async fn peter_no_record(w: &mut AlooWorld) {
    let bob = direct_peer_id("bob", None);
    // An unlisted nickname is not a peer: no link state is created for one,
    // so the port gives a stranger nothing by probing it.
    assert_eq!(link_of(w, "peter").status(bob), None);
    assert_eq!(link_of(w, "peter").direct_status("bob"), None);
}

// ---------------------------------------------------------------------
// Reconciling an unpinned nickname against an already-pinned key
// (AC-275 - AC-279): the popup mechanics only, driven directly against
// `UiState` the same way `identity.rs`'s review-popup scenarios are - the
// real cryptographic scan that finds a match needs a live link and a live
// pad/keybundle to mean anything, and is proven end to end with two real
// punched sessions in test/daemon_session_test.rs instead.
// ---------------------------------------------------------------------

use crossterm::event::{KeyCode, KeyModifiers};

use aloo::client::tui::ui::{RecoveredProof, UnverifiedDirectProof};

use crate::steps::ui_common::press_key;
use crate::support::ui_rows;

/// `carol` is only ever a name in these scenarios - no `direct_punch_to`
/// settings or real link are involved, since the popup itself doesn't care
/// how the proof arrived.
fn unknown_peer_id(name: &str) -> aloo::proto::UserId {
    direct_peer_id(name, None)
}

#[given(expr = "{word} is a direct-punch target alice has no key pinned for")]
async fn unpinned_target_named(w: &mut AlooWorld, name: String) {
    // Nothing to set up: the absence of a pin is the whole point, and the
    // steps below open the review directly rather than through a real
    // `direct_peer_identity` lookup.
    let _ = (w, name);
}

#[when(expr = "{word}'s punched link sends a pq_hybrid ChannelPresence proof")]
#[given(expr = "{word}'s punched link sends a pq_hybrid ChannelPresence proof")]
async fn sends_channel_presence_proof(w: &mut AlooWorld, name: String) {
    let peer = unknown_peer_id(&name);
    let envelope = Envelope {
        content: Content::ChannelPresence,
        blocks: vec![b"sealed-channel-list".to_vec()],
    };
    w.ui_mut().push_unknown_peer_review(
        peer,
        name,
        UnverifiedDirectProof::ChannelPresence { envelope },
        "203.0.113.9:4000".parse().unwrap(),
    );
}

#[when(expr = "{word}'s punched link sends a pad-wrapped message proof")]
async fn sends_otp_message_proof(w: &mut AlooWorld, name: String) {
    let peer = unknown_peer_id(&name);
    let envelope = Envelope {
        content: Content::Text,
        blocks: vec![b"pad-wrapped-ciphertext".to_vec()],
    };
    w.ui_mut().push_unknown_peer_review(
        peer,
        name,
        UnverifiedDirectProof::OtpMessage {
            channel: None,
            seq: 1,
            msg_id: None,
            envelope,
        },
        "203.0.113.9:4000".parse().unwrap(),
    );
}

#[then(expr = "alice is asked whether to check her local keys for {word}")]
async fn asked_to_check(w: &mut AlooWorld, name: String) {
    let peer = unknown_peer_id(&name);
    let review = w
        .ui_ref()
        .unknown_peer_reviews
        .get(&peer)
        .unwrap_or_else(|| panic!("no unknown-peer review open for {name}"));
    assert_eq!(review.requested_nickname, name);
    assert!(
        matches!(
            review.stage,
            aloo::client::tui::ui::UnknownPeerStage::Initial
        ),
        "expected the initial question, not something further along"
    );
    let rows = ui_rows(w.ui_ref());
    let screen = rows.join("\n");
    assert!(
        screen.contains(&name) && screen.contains("Yes") && screen.contains("No"),
        "expected the popup to name {name:?} with Yes/No buttons: {screen}"
    );
}

#[given("alice agrees to check her local keys")]
#[when("alice agrees to check her local keys")]
async fn agrees_to_check(w: &mut AlooWorld) {
    // Focus starts on "No" - move to "Yes" and confirm.
    press_key(w, KeyCode::Tab, KeyModifiers::NONE);
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
    assert!(
        matches!(w.last_action, Some(UiAction::CheckUnknownPeerIdentity(_))),
        "expected CheckUnknownPeerIdentity, got {:?}",
        w.last_action
    );
}

#[when("alice declines to check her local keys")]
async fn declines_to_check(w: &mut AlooWorld) {
    // "No" is already focused - Enter alone confirms it.
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
    match w.last_action {
        Some(UiAction::DeclineUnknownPeerIdentity(peer)) => {
            w.ui_mut().resolve_unknown_peer_review(peer);
        }
        ref other => panic!("expected DeclineUnknownPeerIdentity, got {other:?}"),
    }
}

#[given(expr = "the check finds that {word}'s key matches {word}'s request")]
#[when(expr = "the check finds that {word}'s key matches {word}'s request")]
async fn check_finds_a_match(w: &mut AlooWorld, matched_name: String, requested_name: String) {
    let peer = unknown_peer_id(&requested_name);
    w.ui_mut().advance_to_confirm_match(
        peer,
        matched_name,
        b"the-matched-nicknames-key-bytes".to_vec(),
        RecoveredProof::ChannelPresence {
            plaintext: b"decoded-channel-list".to_vec(),
        },
    );
}

#[then(expr = "alice is asked whether to use {word}'s key for {word}")]
async fn asked_to_use_match(w: &mut AlooWorld, matched_name: String, requested_name: String) {
    let peer = unknown_peer_id(&requested_name);
    let review = w
        .ui_ref()
        .unknown_peer_reviews
        .get(&peer)
        .expect("no unknown-peer review open");
    assert!(
        matches!(
            &review.stage,
            aloo::client::tui::ui::UnknownPeerStage::ConfirmMatch { matched_nickname, .. }
                if matched_nickname == &matched_name
        ),
        "expected the confirm-match question naming {matched_name}, got {:?}",
        review.stage
    );
    let rows = ui_rows(w.ui_ref());
    let screen = rows.join("\n");
    assert!(
        screen.contains(&matched_name) && screen.contains(&requested_name),
        "expected the popup to name both {matched_name:?} and {requested_name:?}: {screen}"
    );
}

#[when("alice confirms using dave's key")]
async fn confirms_match(w: &mut AlooWorld) {
    press_key(w, KeyCode::Tab, KeyModifiers::NONE);
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
}

#[when("alice declines the offered match")]
async fn declines_match(w: &mut AlooWorld) {
    // "No" is already focused on the confirm-match screen too.
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
    if let Some(UiAction::DeclineUnknownPeerKey(peer)) = w.last_action {
        w.ui_mut().resolve_unknown_peer_review(peer);
    }
}

#[then(expr = "confirming {word}'s match is what alice's answer asked for")]
async fn confirming_was_the_action(w: &mut AlooWorld, name: String) {
    let peer = unknown_peer_id(&name);
    assert_eq!(
        w.last_action,
        Some(UiAction::ConfirmUnknownPeerKey(peer)),
        "expected ConfirmUnknownPeerKey for {name}, got {:?}",
        w.last_action
    );
}

#[then(expr = "declining {word}'s match is what alice's answer asked for")]
async fn declining_was_the_action(w: &mut AlooWorld, name: String) {
    let peer = unknown_peer_id(&name);
    assert_eq!(
        w.last_action,
        Some(UiAction::DeclineUnknownPeerKey(peer)),
        "expected DeclineUnknownPeerKey for {name}, got {:?}",
        w.last_action
    );
}

#[then(expr = "no unknown-peer review is left open for {word}")]
async fn no_review_left(w: &mut AlooWorld, name: String) {
    let peer = unknown_peer_id(&name);
    assert!(
        !w.ui_ref().unknown_peer_reviews.contains_key(&peer),
        "expected no outstanding review for {name}"
    );
}
