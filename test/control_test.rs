//! Tests for the encrypted client↔server control channel
//! (`docs/PROTOCOL.md` §1.3).

use aloo::control::{
    ControlEndpoint, ControlReader, ControlWriter, accept_offer, make_offer, open_accept,
    verify_offer,
};
use aloo::crypto::pq::generate_encryption_keys;
use aloo::crypto::KeyPair;
use aloo::proto::{AuthKind, AuthResponse, ClientMessage, ServerMessage};

const TEST_BITS: usize = 1024;

/// Both sides derive the same directional keys from one exchange.
/// @requirement AC-126
#[tokio::test]
async fn both_sides_agree_on_the_same_keys() {
    let (encap, decap) = generate_encryption_keys();
    let offer = make_offer(encap, None).expect("offer");

    let (accept, client_keys) = accept_offer(&offer).expect("accept");
    let server_keys = open_accept(&decap, &accept).expect("server must recover the secret");

    assert_eq!(
        client_keys.send, server_keys.recv,
        "what the client sends is what the server receives"
    );
    assert_eq!(
        client_keys.recv, server_keys.send,
        "and the other way round"
    );
    assert_ne!(
        client_keys.send, client_keys.recv,
        "the two directions must not share a key, or a frame could be reflected"
    );
}

/// The long-term key only ever *signs* the offer - it never encrypts
/// anything - and the keys that do the encrypting are per connection. So
/// holding a different server's decapsulation keys recovers nothing, which
/// is also why stealing the long-term key later does not open a recording.
/// @requirement AC-126, TB-170
#[tokio::test]
async fn a_different_server_cannot_recover_the_secret() {
    let (encap, _decap) = generate_encryption_keys();
    let (_, other_decap) = generate_encryption_keys();
    let offer = make_offer(encap, None).expect("offer");

    let (accept, _) = accept_offer(&offer).expect("accept");

    // Unwrapping with the wrong keys does not fail loudly - it yields
    // different bytes - so what matters is that the derived keys differ.
    if let Some(wrong) = open_accept(&other_decap, &accept) {
        let (_, client_keys) = accept_offer(&offer).expect("accept");
        assert_ne!(wrong.recv, client_keys.send);
    }
}

/// Once the tunnel is on, what goes on the wire is not the plaintext.
/// @requirement AC-126
#[tokio::test]
async fn frames_are_sealed_once_the_tunnel_is_on() {
    let (encap, decap) = generate_encryption_keys();
    let offer = make_offer(encap, None).expect("offer");
    let (accept, client_keys) = accept_offer(&offer).expect("accept");
    let server_keys = open_accept(&decap, &accept).expect("recover");

    let (client_side, server_side) = tokio::io::duplex(4096);
    let mut wr = ControlWriter::new(client_side);
    let mut rd = ControlReader::new(server_side);

    let secret = ClientMessage::Auth(AuthResponse::Password("hunter2".into()));

    // In the clear first, which is how the handshake itself travels.
    wr.send(&secret).await.expect("send");
    let got: ClientMessage = rd.recv().await.expect("recv").expect("some");
    assert_eq!(got, secret);

    wr.enable(client_keys.send);
    rd.enable(server_keys.recv);
    assert!(wr.is_encrypted());

    wr.send(&secret).await.expect("send");
    let got: ClientMessage = rd.recv().await.expect("recv").expect("some");
    assert_eq!(got, secret, "a sealed frame still round-trips");
}

/// The credential the old plaintext channel exposed must not be findable
/// in the bytes any more.
/// @requirement AC-127
#[tokio::test]
async fn the_password_is_not_recoverable_from_the_sealed_bytes() {
    let (encap, decap) = generate_encryption_keys();
    let offer = make_offer(encap, None).expect("offer");
    let (accept, client_keys) = accept_offer(&offer).expect("accept");
    let _ = open_accept(&decap, &accept).expect("recover");

    let mut wr = ControlWriter::new(Vec::new());
    wr.enable(client_keys.send);
    wr.send(&ClientMessage::Auth(AuthResponse::Password(
        "hunter2-in-the-clear".into(),
    )))
    .await
    .expect("send");
    let buffer = wr.into_inner();

    let needle = b"hunter2-in-the-clear";
    assert!(
        !buffer.windows(needle.len()).any(|w| w == needle),
        "the credential must not appear anywhere in what goes on the wire"
    );
}

/// Two sends under the same key must not produce the same bytes, or the
/// counter is not advancing and a nonce is being reused.
/// @requirement TB-169
#[tokio::test]
async fn repeating_a_message_does_not_repeat_the_ciphertext() {
    let (encap, _) = generate_encryption_keys();
    let offer = make_offer(encap, None).expect("offer");
    let (_, keys) = accept_offer(&offer).expect("accept");

    let mut wr = ControlWriter::new(Vec::new());
    wr.enable(keys.send);

    let msg = ClientMessage::Auth(AuthResponse::None);
    wr.send(&msg).await.expect("send");
    wr.send(&msg).await.expect("send");
    let buffer = wr.into_inner();

    // Two frames of identical plaintext, so they are the same length: the
    // second half must not repeat the first.
    let half = buffer.len() / 2;
    assert_ne!(
        &buffer[..half],
        &buffer[half..],
        "the same message sealed twice must differ, or the nonce repeated"
    );
}

/// A tampered frame is a hard error, never silently skipped.
/// @requirement TB-169
#[tokio::test]
async fn a_tampered_frame_fails_to_authenticate() {
    let (encap, decap) = generate_encryption_keys();
    let offer = make_offer(encap, None).expect("offer");
    let (accept, client_keys) = accept_offer(&offer).expect("accept");
    let server_keys = open_accept(&decap, &accept).expect("recover");

    let mut wr = ControlWriter::new(Vec::new());
    wr.enable(client_keys.send);
    wr.send(&ClientMessage::Auth(AuthResponse::None))
        .await
        .expect("send");
    let mut buffer = wr.into_inner();

    // Flip a byte inside the sealed payload, past the length prefix.
    let last = buffer.len() - 1;
    buffer[last] ^= 0xFF;

    let mut rd = ControlReader::new(&buffer[..]);
    rd.enable(server_keys.recv);
    assert!(
        rd.recv::<ClientMessage>().await.is_err(),
        "a frame that fails its tag must be an error, not a skipped message"
    );
}

// ---------------------------------------------------------------------
// Server authentication
// ---------------------------------------------------------------------

/// @requirement AC-128
#[tokio::test]
async fn a_client_holding_the_server_key_requires_a_valid_signature() {
    let server = KeyPair::generate_with_bits(TEST_BITS).expect("keygen");
    let (encap, _) = generate_encryption_keys();

    let signed = make_offer(encap.clone(), Some(&server.private)).expect("offer");
    assert!(
        verify_offer(&signed, Some(&server.public)),
        "the server's own signature must satisfy a client holding its key"
    );

    let unsigned = make_offer(encap, None).expect("offer");
    assert!(
        !verify_offer(&unsigned, Some(&server.public)),
        "an unsigned offer is exactly what a man in the middle would send"
    );
}

/// @requirement AC-128
#[tokio::test]
async fn an_offer_signed_by_another_key_is_refused() {
    let server = KeyPair::generate_with_bits(TEST_BITS).expect("keygen");
    let impostor = KeyPair::generate_with_bits(TEST_BITS).expect("keygen");
    let (encap, _) = generate_encryption_keys();

    let offer = make_offer(encap, Some(&impostor.private)).expect("offer");
    assert!(!verify_offer(&offer, Some(&server.public)));
}

/// Substituting the keys inside a signed offer breaks the signature - the
/// whole point of signing it.
/// @requirement AC-128
#[tokio::test]
async fn swapping_the_keys_inside_a_signed_offer_is_refused() {
    let server = KeyPair::generate_with_bits(TEST_BITS).expect("keygen");
    let (encap, _) = generate_encryption_keys();
    let (other_encap, _) = generate_encryption_keys();

    let mut offer = make_offer(encap, Some(&server.private)).expect("offer");
    offer.encap = other_encap;

    assert!(
        !verify_offer(&offer, Some(&server.public)),
        "a man in the middle swapping in their own keys must be caught"
    );
}

/// A client with no server key has nothing to check against, and says so
/// by accepting the offer - encrypted, but not authenticated.
/// @requirement AC-128
#[tokio::test]
async fn a_client_without_a_server_key_accepts_any_offer() {
    let (encap, _) = generate_encryption_keys();
    let offer = make_offer(encap, None).expect("offer");

    assert!(
        verify_offer(&offer, None),
        "with nothing to check against, the offer is taken as given - encrypted, \
         but not authenticated, which is the documented limit of this mode"
    );
}

/// The endpoint's handshake helper drives the whole exchange.
/// Exercises the same send path the live client uses, through the
/// `ControlSink` seam that lets a split-stream writer and a sequential
/// endpoint share it.
/// @requirement AC-126, TB-171
#[tokio::test]
async fn the_endpoint_handshake_turns_the_channel_on() {
    let (client_side, server_side) = tokio::io::duplex(8192);
    let (encap, decap) = generate_encryption_keys();
    let offer = make_offer(encap, None).expect("offer");

    let server = tokio::spawn(async move {
        let mut server = ControlEndpoint::new(server_side);
        server
            .send(&ServerMessage::Hello {
                auth: AuthKind::None,
                challenge: None,
                control: offer,
            })
            .await
            .expect("hello");
        let accept: ClientMessage = server.recv().await.expect("recv").expect("some");
        let ClientMessage::SecureChannel(accept) = accept else {
            panic!("expected SecureChannel first");
        };
        server.enable(open_accept(&decap, &accept).expect("recover"));
        let sealed: ClientMessage = server.recv().await.expect("recv").expect("some");
        assert_eq!(sealed, ClientMessage::Auth(AuthResponse::None));
    });

    let mut client = ControlEndpoint::new(client_side);
    let (auth, challenge) = client
        .client_handshake(None)
        .await
        .expect("handshake")
        .expect("some");
    assert_eq!(auth, AuthKind::None);
    assert_eq!(challenge, None);
    // Through the trait, exactly as `channel`/`p2p`/`direct_message` send.
    use aloo::control::ControlSink;
    client
        .send_control(&ClientMessage::Auth(AuthResponse::None))
        .await
        .expect("send");

    server.await.expect("server task");
}
