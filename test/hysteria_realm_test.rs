//! The Hysteria Realms rendezvous and punch layer (`docs/PROTOCOL.md`
//! §7.1.5, "Meeting through a rendezvous realm"): the realm URI, the wire
//! formats that mirror `apernet/hysteria`'s `extras/realm` package (the
//! punch packet, STUN binding, the SSE event stream), the one-socket
//! demultiplexer, and a whole rendezvous-and-punch run against a loopback
//! stand-in for the two third parties - a `hysteria-realm-server` and a
//! STUN server - so a punch that follows actually connects rather than
//! being simulated.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aloo::client::hysteria_realm::{
    self as realm, AttemptConfig, Introduction, PunchKind, PunchMeta, RawDatagram, RawTaps,
    RealmAddr, RealmRole, decode_punch, encode_punch, is_stun_message, parse_sse_event,
    parse_stun_binding_response, punch_candidates, role_for, run_attempt, stun_binding_request,
    stun_binding_response,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};

// =====================================================================
// The realm URI (AC-434)
// =====================================================================

/// @requirement AC-434
#[test]
fn a_realm_uri_parses_into_its_parts() {
    let addr = RealmAddr::parse("realm://public@realm.hy2.io/a-long-realm-name").unwrap();
    assert!(addr.tls, "realm:// is HTTPS");
    assert_eq!(addr.token, "public");
    assert_eq!(addr.host, "realm.hy2.io");
    assert_eq!(addr.port, 443, "HTTPS defaults to 443");
    assert_eq!(addr.realm_id, "a-long-realm-name");
    assert_eq!(addr.stun_servers(), realm::DEFAULT_STUN_SERVERS, "the built-in STUN list");
    assert_eq!(addr.uri(), "realm://public@realm.hy2.io/a-long-realm-name");
}

/// @requirement AC-434
#[test]
fn realm_plus_http_is_plain_http_on_port_80() {
    let addr = RealmAddr::parse("realm+http://tok@rv.example/my-realm").unwrap();
    assert!(!addr.tls);
    assert_eq!(addr.port, 80);
    let addr = RealmAddr::parse("realm+http://tok@rv.example:8443/my-realm").unwrap();
    assert_eq!(addr.port, 8443);
}

/// @requirement AC-434
#[test]
fn a_realm_uri_carries_stun_overrides_and_rejects_a_local_port() {
    let addr =
        RealmAddr::parse("realm://t@rv.example/r?stun=stun.a.example:3478&stun=stun.b.example")
            .unwrap();
    assert_eq!(
        addr.stun_servers(),
        vec!["stun.a.example:3478".to_string(), "stun.b.example".to_string()]
    );
    // lport would punch from a port the peer's own line never learns of.
    assert!(RealmAddr::parse("realm://t@rv.example/r?lport=40000").is_err());
}

/// @requirement AC-434
#[test]
fn a_malformed_realm_uri_is_refused() {
    for value in [
        "realm://public@realm.hy2.io/",          // no realm name
        "realm://realm.hy2.io/name",             // no token
        "realm://public@realm.hy2.io/a/b",       // realm is one segment
        "realm://public@/name",                  // no host
        "http://public@realm.hy2.io/name",       // wrong scheme
        "realm://public@realm.hy2.io/name#frag", // fragment
    ] {
        assert!(RealmAddr::parse(value).is_err(), "{value:?} should be refused");
    }
}

/// The discriminator a `direct_punch_to` "where" field is read by.
/// @requirement AC-434
#[test]
fn is_realm_uri_recognises_only_the_two_schemes() {
    assert!(RealmAddr::is_realm_uri("realm://t@h/r"));
    assert!(RealmAddr::is_realm_uri("realm+http://t@h/r"));
    assert!(!RealmAddr::is_realm_uri("bobpublic.com:19000"));
    assert!(!RealmAddr::is_realm_uri("203.0.113.9"));
}

// =====================================================================
// The punch packet (TB-293)
// =====================================================================

/// @requirement TB-293
#[test]
fn a_punch_packet_round_trips_under_its_own_key_only() {
    let meta = PunchMeta::random();
    for kind in [PunchKind::Hello, PunchKind::Ack] {
        let packet = encode_punch(kind, &meta);
        assert_eq!(decode_punch(&packet, &meta), Some(kind), "round trips under its key");
        // A different introduction's key sees only noise.
        let other = PunchMeta::random();
        assert_eq!(decode_punch(&packet, &other), None, "another key decodes nothing");
    }
}

/// The salt makes two encodings of the same packet differ on the wire, so
/// the obfuscation is not a fixed XOR anyone can strip by comparison.
/// @requirement TB-293
#[test]
fn two_encodings_of_one_packet_differ_on_the_wire() {
    let meta = PunchMeta::random();
    let a = encode_punch(PunchKind::Hello, &meta);
    let b = encode_punch(PunchKind::Hello, &meta);
    assert_ne!(a, b, "salt and padding randomise the wire bytes");
    // Both still decode to the same thing.
    assert_eq!(decode_punch(&a, &meta), Some(PunchKind::Hello));
    assert_eq!(decode_punch(&b, &meta), Some(PunchKind::Hello));
}

/// @requirement TB-293
#[test]
fn a_too_short_or_too_long_packet_is_not_a_punch() {
    let meta = PunchMeta::random();
    assert_eq!(decode_punch(&[], &meta), None);
    assert_eq!(decode_punch(&[0u8; 4], &meta), None);
    assert_eq!(decode_punch(&vec![0u8; 4096], &meta), None, "past the padding ceiling");
}

/// A hex-encoded nonce/obfs of the wrong length is refused - the shape a
/// rendezvous introduction is validated against before it is trusted.
/// @requirement TB-293
#[test]
fn punch_metadata_from_hex_checks_the_lengths() {
    let meta = PunchMeta::random();
    assert!(PunchMeta::from_hex(&meta.nonce_hex(), &meta.obfs_hex()).is_ok());
    assert!(PunchMeta::from_hex("00", &meta.obfs_hex()).is_err(), "short nonce");
    assert!(PunchMeta::from_hex(&meta.nonce_hex(), "00").is_err(), "short obfs");
    assert!(PunchMeta::from_hex("zz", &meta.obfs_hex()).is_err(), "not hex");
}

// =====================================================================
// STUN binding (TB-294)
// =====================================================================

/// @requirement TB-294
#[test]
fn a_stun_binding_response_round_trips_for_v4_and_v6() {
    for mapped in [
        "203.0.113.10:62031".parse::<SocketAddr>().unwrap(),
        "[2001:db8::1]:41782".parse::<SocketAddr>().unwrap(),
    ] {
        let (txid, request) = stun_binding_request();
        assert!(is_stun_message(&request), "a request is a STUN message");
        let response = stun_binding_response(&txid, mapped);
        let (got_txid, got_addr) = parse_stun_binding_response(&response).expect("parses");
        assert_eq!(got_txid, txid, "the transaction id is echoed");
        assert_eq!(got_addr, mapped, "the XOR-mapped address round trips");
    }
}

/// None of aloo's own datagrams can pass for a STUN message.
/// @requirement TB-294
#[test]
fn random_bytes_are_not_a_stun_message() {
    assert!(!is_stun_message(b"not stun at all, just some bytes here"));
    assert!(!is_stun_message(&[0xff; 40]), "the magic cookie must match");
    assert!(parse_stun_binding_response(b"nope").is_none());
}

// =====================================================================
// The SSE event stream (TB-295)
// =====================================================================

/// @requirement TB-295
#[test]
fn a_punch_sse_event_is_parsed_and_others_are_skipped() {
    let intro = parse_sse_event("event: punch\ndata: {\"addresses\":[\"203.0.113.10:62031\"],\"nonce\":\"aa\",\"obfs\":\"bb\"}")
        .expect("a punch event parses");
    assert_eq!(intro.addresses, vec!["203.0.113.10:62031".to_string()]);
    assert_eq!(intro.nonce, "aa");
    assert_eq!(intro.obfs, "bb");
    // A heartbeat, and a comment line, carry nothing to punch at.
    assert!(parse_sse_event("event: heartbeat_ack\ndata: {\"ttl\":60}").is_none());
    assert!(parse_sse_event(": keep-alive comment").is_none());
}

// =====================================================================
// Punch candidates (TB-296)
// =====================================================================

/// The socket's own family only, deduplicated, in a stable order.
/// @requirement TB-296
#[test]
fn punch_candidates_keep_the_socket_family_and_dedupe() {
    let peers = [
        "203.0.113.10:62031".parse().unwrap(),
        "203.0.113.10:62031".parse().unwrap(), // a repeat
        "[2001:db8::1]:41782".parse().unwrap(), // wrong family for a v4 socket
        "198.51.100.20:5000".parse().unwrap(),
    ];
    let v4 = punch_candidates(&peers, false);
    assert!(v4.iter().all(|a| a.is_ipv4()), "a v4 socket keeps only v4 candidates");
    assert!(v4.contains(&"203.0.113.10:62031".parse().unwrap()));
    assert!(v4.contains(&"198.51.100.20:5000".parse().unwrap()));
    assert_eq!(
        v4.iter().filter(|a| **a == "203.0.113.10:62031".parse().unwrap()).count(),
        1,
        "a repeat collapses"
    );
}

/// A group of ports close together is a NAT allocating predictably, so a
/// few more past the last are added - Hysteria's symmetric-NAT guess.
/// @requirement TB-296
#[test]
fn punch_candidates_widen_a_predictable_symmetric_nat_group() {
    let peers = [
        "203.0.113.10:50000".parse().unwrap(),
        "203.0.113.10:50002".parse().unwrap(),
    ];
    let widened = punch_candidates(&peers, false);
    let ports: Vec<u16> = widened
        .iter()
        .filter(|a| a.ip().to_string() == "203.0.113.10")
        .map(|a| a.port())
        .collect();
    assert!(ports.contains(&50000) && ports.contains(&50002));
    assert!(ports.contains(&50003), "a few ports past the group are tried too");
    assert!(ports.len() > 2, "the group was widened");
}

// =====================================================================
// Demultiplexing one socket (TB-297)
// =====================================================================

/// @requirement TB-297
#[test]
fn the_tap_separates_stun_and_punch_from_everything_else() {
    let taps = RawTaps::new();
    assert!(taps.is_empty(), "nothing to demux while no attempt runs");
    let (handle, mut rx) = taps.register();
    let from: SocketAddr = "203.0.113.10:62031".parse().unwrap();

    // A STUN reply is recognised from the moment of registration.
    let (txid, _) = stun_binding_request();
    let stun = stun_binding_response(&txid, "198.51.100.20:41782".parse().unwrap());
    assert!(taps.demux(from, &stun), "a STUN reply is taken");
    assert!(matches!(rx.try_recv(), Ok(RawDatagram::Stun { .. })));

    // A punch packet only after the key it is masked under is named.
    let meta = PunchMeta::random();
    let packet = encode_punch(PunchKind::Hello, &meta);
    assert!(!taps.demux(from, &packet), "not yet - no key set");
    handle.set_meta(Some(meta));
    assert!(taps.demux(from, &packet), "now the punch is taken");
    assert!(matches!(rx.try_recv(), Ok(RawDatagram::Punch { kind: PunchKind::Hello, .. })));

    // Anything else is left for aloo's own decoders.
    assert!(!taps.demux(from, b"an ordinary aloo datagram"));

    // Dropping the handle stops the tap.
    drop(handle);
    assert!(taps.is_empty());
    assert!(!taps.demux(from, &stun), "a dropped tap takes nothing");
}

// =====================================================================
// A whole rendezvous-and-punch run (TB-298)
// =====================================================================

/// Role is settled with no message passing: the lower nickname registers.
/// @requirement TB-298
#[test]
fn the_lower_nickname_registers_and_the_other_looks_up() {
    assert_eq!(role_for("alice", "bob"), RealmRole::Registrant);
    assert_eq!(role_for("bob", "alice"), RealmRole::Lookup);
}

/// The end to end: two peers, each with only the other's nickname and a
/// shared realm name, meet through a loopback `hysteria-realm-server`
/// stand-in and a loopback STUN server, punch, and each learns the
/// address the other actually answered from. Nothing but the introduction
/// crosses the rendezvous; the punch itself is real UDP on loopback.
/// @requirement TB-298
#[tokio::test]
async fn two_peers_meet_through_a_realm_and_punch_a_direct_path() {
    let rendezvous = FakeRealmServer::spawn("public").await;
    let stun = FakeStunServer::spawn().await;

    let alice = spawn_peer(&rendezvous, &stun, "alice", "bob").await;
    let bob = spawn_peer(&rendezvous, &stun, "bob", "alice").await;
    let (alice_port, bob_port) = (alice.local_port, bob.local_port);

    let (alice_res, bob_res) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(15), alice.run()),
        tokio::time::timeout(Duration::from_secs(15), bob.run()),
    );
    let alice_peer = alice_res.expect("alice's attempt finished in time").expect("alice punched");
    let bob_peer = bob_res.expect("bob's attempt finished in time").expect("bob punched");

    // Each learned a real loopback address for the other, and it is the
    // address that peer's own socket actually sends from.
    assert!(alice_peer.ip().is_loopback());
    assert!(bob_peer.ip().is_loopback());
    assert_eq!(alice_peer.port(), bob_port, "alice punched through to bob's socket");
    assert_eq!(bob_peer.port(), alice_port, "bob punched through to alice's socket");

    // The rendezvous saw exactly one registration and, because the
    // attempt released it, one deregistration - it does not linger.
    let (regs, deregs) = rendezvous.counts();
    assert_eq!(regs, 1, "exactly the registrant registered");
    assert_eq!(deregs, 1, "the registration was released on success");
}

// ---------------------------------------------------------------------
// One test peer: a UDP socket, its tap, a receive loop, and a realm line.
// ---------------------------------------------------------------------

struct Peer {
    cfg: AttemptConfig,
    taps: RawTaps,
    local_port: u16,
}

impl Peer {
    async fn run(self) -> Result<SocketAddr, String> {
        run_attempt(self.cfg, self.taps).await
    }
}

async fn spawn_peer(
    rendezvous: &FakeRealmServer,
    stun: &FakeStunServer,
    own: &str,
    peer: &str,
) -> Peer {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let local = socket.local_addr().unwrap();
    let taps = RawTaps::new();
    // The receive loop a real session runs: everything the tap recognises
    // it takes, the rest would go to aloo's own decoders (nothing here).
    let loop_socket = socket.clone();
    let loop_taps = taps.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = loop_socket.recv_from(&mut buf).await {
            loop_taps.demux(from, &buf[..n]);
        }
    });
    let uri = format!(
        "realm+http://{}@{}/shared-realm-name?stun={}",
        rendezvous.token, rendezvous.addr, stun.addr
    );
    let realm = RealmAddr::parse(&uri).unwrap_or_else(|e| panic!("{uri:?}: {e}"));
    let cfg = AttemptConfig {
        realm,
        role: role_for(own, peer),
        socket,
        local_addrs: Vec::new(),
        local_is_ipv6: false,
        window: Duration::from_secs(14),
        peer_label: peer.to_string(),
    };
    Peer { cfg, taps, local_port: local.port() }
}

// ---------------------------------------------------------------------
// A loopback STUN server: answers a binding request with the source
// address it saw, which on loopback is the truth, so the punch that
// follows reaches a real socket.
// ---------------------------------------------------------------------

struct FakeStunServer {
    addr: SocketAddr,
}

impl FakeStunServer {
    async fn spawn() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                // A binding request is type 0x0001; its transaction id is
                // bytes 8..20. Echo it, mapping to the real source address.
                if n >= 20 && buf[0] == 0x00 && buf[1] == 0x01 {
                    let mut txid = [0u8; 12];
                    txid.copy_from_slice(&buf[8..20]);
                    let reply = stun_binding_response(&txid, from);
                    let _ = socket.send_to(&reply, from).await;
                }
            }
        });
        Self { addr }
    }
}

// ---------------------------------------------------------------------
// A loopback hysteria-realm-server: the HTTP/1.1 API a realm client
// talks to (register, the SSE event stream, lookup, the registrant's
// answer, deregister).
// ---------------------------------------------------------------------

struct RealmRecord {
    events: Option<mpsc::UnboundedSender<String>>,
    /// Lookups waiting on the registrant's answer, keyed by punch nonce.
    pending: HashMap<String, oneshot::Sender<Vec<String>>>,
}

#[derive(Default)]
struct RealmState {
    realms: HashMap<String, RealmRecord>,
    registrations: usize,
    deregistrations: usize,
}

#[derive(Clone)]
struct FakeRealmServer {
    addr: SocketAddr,
    token: String,
    state: Arc<Mutex<RealmState>>,
}

impl FakeRealmServer {
    async fn spawn(token: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = Self {
            addr,
            token: token.to_string(),
            state: Arc::new(Mutex::new(RealmState::default())),
        };
        let accept = server.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let s = accept.clone();
                tokio::spawn(async move { s.serve(stream).await });
            }
        });
        server
    }

    fn counts(&self) -> (usize, usize) {
        let s = self.state.lock().unwrap();
        (s.registrations, s.deregistrations)
    }

    async fn serve(&self, stream: TcpStream) {
        let mut reader = BufReader::new(stream);
        // Request line.
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).await.unwrap_or(0) == 0 {
            return;
        }
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        // Headers.
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                break;
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            let _ = reader.read_exact(&mut body).await;
        }
        let body = String::from_utf8_lossy(&body).to_string();
        // /v1/{realm}[/sub...]
        let rest = path.strip_prefix("/v1/").unwrap_or("");
        let mut seg = rest.splitn(2, '/');
        let realm_id = seg.next().unwrap_or("").to_string();
        let sub = seg.next().unwrap_or("").to_string();

        match (method.as_str(), sub.as_str()) {
            ("POST", "") => self.register(reader, &realm_id, &body).await,
            ("GET", "events") => self.events(reader, &realm_id).await,
            ("POST", "connect") => self.connect(reader, &realm_id, &body).await,
            ("DELETE", "") => self.deregister(reader, &realm_id).await,
            ("POST", s) if s.starts_with("connects/") => {
                let nonce = s.strip_prefix("connects/").unwrap_or("").to_string();
                self.connect_response(reader, &realm_id, &nonce, &body).await;
            }
            _ => {
                let _ = reply(reader.into_inner(), 404, "").await;
            }
        }
    }

    async fn register(&self, reader: BufReader<TcpStream>, realm_id: &str, _body: &str) {
        let session_id = format!("sess-{realm_id}");
        {
            let mut s = self.state.lock().unwrap();
            s.registrations += 1;
            s.realms.insert(
                realm_id.to_string(),
                RealmRecord { events: None, pending: HashMap::new() },
            );
        }
        let json = format!("{{\"session_id\":\"{session_id}\",\"ttl\":60}}");
        let _ = reply(reader.into_inner(), 200, &json).await;
    }

    async fn events(&self, reader: BufReader<TcpStream>, realm_id: &str) {
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        {
            let mut s = self.state.lock().unwrap();
            if let Some(rec) = s.realms.get_mut(realm_id) {
                rec.events = Some(tx);
            }
        }
        let mut stream = reader.into_inner();
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: keep-alive\r\n\r\n";
        if stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        while let Some(event) = rx.recv().await {
            if stream.write_all(event.as_bytes()).await.is_err() {
                break;
            }
        }
    }

    async fn connect(&self, reader: BufReader<TcpStream>, realm_id: &str, body: &str) {
        let addresses = json_string_array(body, "addresses");
        let nonce = json_string_field(body, "nonce");
        let obfs = json_string_field(body, "obfs");
        let found = {
            let mut s = self.state.lock().unwrap();
            s.realms.get_mut(realm_id).map(|rec| {
                let (done_tx, done_rx) = oneshot::channel();
                rec.pending.insert(nonce.clone(), done_tx);
                (rec.events.clone(), done_rx)
            })
        };
        let Some((event_tx, waiter)) = found else {
            let _ = reply(reader.into_inner(), 400, "{\"error\":\"realm_not_found\"}").await;
            return;
        };
        // Push a punch event to the registrant with the lookup's addresses.
        if let Some(tx) = event_tx {
            let data = format!(
                "{{\"addresses\":{},\"nonce\":\"{}\",\"obfs\":\"{}\"}}",
                json_array(&addresses),
                nonce,
                obfs
            );
            let _ = tx.send(format!("event: punch\ndata: {data}\n\n"));
        }
        // Block until the registrant answers with its own addresses.
        let answer = tokio::time::timeout(Duration::from_secs(10), waiter).await;
        match answer {
            Ok(Ok(server_addrs)) => {
                let json = format!(
                    "{{\"addresses\":{},\"nonce\":\"{}\",\"obfs\":\"{}\"}}",
                    json_array(&server_addrs),
                    nonce,
                    obfs
                );
                let _ = reply(reader.into_inner(), 200, &json).await;
            }
            _ => {
                let _ = reply(reader.into_inner(), 504, "{\"error\":\"timeout\"}").await;
            }
        }
    }

    async fn connect_response(
        &self,
        reader: BufReader<TcpStream>,
        realm_id: &str,
        nonce: &str,
        body: &str,
    ) {
        let addresses = json_string_array(body, "addresses");
        let waiter = {
            let mut s = self.state.lock().unwrap();
            s.realms.get_mut(realm_id).and_then(|rec| rec.pending.remove(nonce))
        };
        if let Some(tx) = waiter {
            let _ = tx.send(addresses);
        }
        let _ = reply(reader.into_inner(), 204, "").await;
    }

    async fn deregister(&self, reader: BufReader<TcpStream>, realm_id: &str) {
        {
            let mut s = self.state.lock().unwrap();
            if s.realms.remove(realm_id).is_some() {
                s.deregistrations += 1;
            }
        }
        let _ = reply(reader.into_inner(), 204, "").await;
    }
}

async fn reply(mut stream: TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        504 => "Gateway Timeout",
        _ => "Unknown",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await
}

// A minimal JSON reader for the flat request bodies this fake handles -
// enough for {"addresses":[...],"nonce":"...","obfs":"..."} without a
// dependency. Not a general parser.
fn json_string_field(body: &str, key: &str) -> String {
    let needle = format!("\"{key}\"");
    let Some(after) = body.split_once(&needle).map(|(_, r)| r) else {
        return String::new();
    };
    let after = after.trim_start_matches([':', ' ']);
    if let Some(rest) = after.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").to_string()
    } else {
        String::new()
    }
}

fn json_string_array(body: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\"");
    let Some(after) = body.split_once(&needle).map(|(_, r)| r) else {
        return Vec::new();
    };
    let Some(start) = after.find('[') else {
        return Vec::new();
    };
    let Some(end) = after[start..].find(']') else {
        return Vec::new();
    };
    after[start + 1..start + end]
        .split(',')
        .filter_map(|s| {
            let s = s.trim().trim_matches('"');
            (!s.is_empty()).then(|| s.to_string())
        })
        .collect()
}

fn json_array(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| format!("\"{s}\"")).collect();
    format!("[{}]", inner.join(","))
}

// Silence unused warnings for the SSE Introduction re-export used only in
// doc positions above.
#[allow(dead_code)]
fn _assert_introduction_shape(i: Introduction) -> Vec<String> {
    i.addresses
}
