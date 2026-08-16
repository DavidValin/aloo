//! Steps for the encrypted control channel (US-030).

use aloo::control::{accept_offer, make_offer, open_accept, verify_offer};
use aloo::crypto::KeyPair;
use aloo::crypto::pq::generate_encryption_keys;
use aloo::proto::{AuthResponse, ClientMessage};
use cucumber::{given, then, when};

use crate::world::AlooWorld;

/// Small enough to keep the acceptance layer fast; nothing here asserts
/// anything about RSA key size, only that a signature verifies.
const TEST_BITS: usize = 1024;

// ---------------------------------------------------------------------
// Given
// ---------------------------------------------------------------------

#[given("a server offering an encrypted control channel")]
async fn server_offers_channel(w: &mut AlooWorld) {
    let (encap, decap) = generate_encryption_keys();
    w.control_offer = Some(make_offer(encap, None).expect("offer"));
    w.control_decap = Some(decap);
}

#[given("the client already holds that server's public key")]
async fn client_holds_server_key(w: &mut AlooWorld) {
    w.server_keypair = Some(KeyPair::generate_with_bits(TEST_BITS).expect("keygen"));
}

// ---------------------------------------------------------------------
// When
// ---------------------------------------------------------------------

#[when("a client accepts the offer")]
async fn client_accepts(w: &mut AlooWorld) {
    let offer = w.control_offer.as_ref().expect("no offer");
    let (accept, keys) = accept_offer(offer).expect("accept");
    let decap = w.control_decap.as_ref().expect("no server keys");
    w.server_control_keys = open_accept(decap, &accept);
    w.client_control_keys = Some(keys);
}

#[when(expr = "the client sends the password {string} through the channel")]
async fn client_sends_password(w: &mut AlooWorld, password: String) {
    let keys = w.client_control_keys.as_ref().expect("channel not up");
    let mut wr = aloo::control::ControlWriter::new(Vec::new());
    wr.enable(keys.send);
    wr.send(&ClientMessage::Auth(AuthResponse::Password(password)))
        .await
        .expect("send");
    w.control_bytes = wr.into_inner();
}

#[when("the client sends the same message twice")]
async fn client_sends_twice(w: &mut AlooWorld) {
    let keys = w.client_control_keys.as_ref().expect("channel not up");
    let mut wr = aloo::control::ControlWriter::new(Vec::new());
    wr.enable(keys.send);
    let msg = ClientMessage::Auth(AuthResponse::None);
    wr.send(&msg).await.expect("send");
    wr.send(&msg).await.expect("send");
    w.control_bytes = wr.into_inner();
}

// ---------------------------------------------------------------------
// Then
// ---------------------------------------------------------------------

#[then("both sides hold the same keys")]
async fn both_sides_agree(w: &mut AlooWorld) {
    let client = w.client_control_keys.as_ref().expect("no client keys");
    let server = w
        .server_control_keys
        .as_ref()
        .expect("the server must recover the secret the client transported");
    assert_eq!(client.send, server.recv);
    assert_eq!(client.recv, server.send);
}

#[then("each direction has a key of its own")]
async fn directions_differ(w: &mut AlooWorld) {
    let client = w.client_control_keys.as_ref().expect("no client keys");
    assert_ne!(
        client.send, client.recv,
        "sharing one key between directions would let a frame be reflected back"
    );
}

#[then(expr = "the password cannot be found anywhere in the bytes sent")]
async fn password_not_on_wire(w: &mut AlooWorld) {
    let needle = b"hunter2";
    assert!(!w.control_bytes.is_empty(), "nothing was sent");
    assert!(
        !w.control_bytes.windows(needle.len()).any(|c| c == needle),
        "the credential must not appear in what goes on the wire"
    );
}

#[then("a signed offer from that server is accepted")]
async fn signed_offer_accepted(w: &mut AlooWorld) {
    let server = w.server_keypair.as_ref().expect("no server key");
    let (encap, _) = generate_encryption_keys();
    let offer = make_offer(encap, Some(&server.private)).expect("offer");
    assert!(verify_offer(&offer, Some(&server.public)));
}

#[then("an unsigned offer is refused")]
async fn unsigned_offer_refused(w: &mut AlooWorld) {
    let server = w.server_keypair.as_ref().expect("no server key");
    let (encap, _) = generate_encryption_keys();
    let offer = make_offer(encap, None).expect("offer");
    assert!(
        !verify_offer(&offer, Some(&server.public)),
        "an unsigned offer is what a man in the middle would send"
    );
}

#[then("an offer signed by somebody else is refused")]
async fn wrongly_signed_offer_refused(w: &mut AlooWorld) {
    let server = w.server_keypair.as_ref().expect("no server key");
    let impostor = KeyPair::generate_with_bits(TEST_BITS).expect("keygen");
    let (encap, _) = generate_encryption_keys();
    let offer = make_offer(encap, Some(&impostor.private)).expect("offer");
    assert!(!verify_offer(&offer, Some(&server.public)));
}

#[then("the two sealed frames differ")]
async fn frames_differ(w: &mut AlooWorld) {
    let half = w.control_bytes.len() / 2;
    assert!(half > 0, "nothing was sent");
    assert_ne!(
        &w.control_bytes[..half],
        &w.control_bytes[half..],
        "identical plaintext sealed twice must differ, or a nonce repeated"
    );
}
