//! Encryption and wire-protocol steps (US-008, US-009).

use aloo::crypto::{
    self, decrypt_chunked, encrypt_chunked, max_chunk_len, public_key_to_der,
};
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{
    ChannelInfo, ChannelKind, ClientMessage, Content, Envelope, KeyMode, ServerMessage, UserId,
    UserInfo, decode, encode,
};
use cucumber::{given, then, when};

use crate::world::{AlooWorld, keypair_for};

// ---------------------------------------------------------------------
// Given
// ---------------------------------------------------------------------

#[given(expr = "{word} and {word} each have their own RSA keypair")]
async fn two_keypairs(w: &mut AlooWorld, a: String, b: String) {
    let ka = keypair_for(&a);
    let kb = keypair_for(&b);
    assert_ne!(
        public_key_to_der(&ka.public).unwrap(),
        public_key_to_der(&kb.public).unwrap(),
        "the two users must genuinely hold different keys or the scenario proves nothing"
    );
    w.derived.insert(a, ka);
    w.derived.insert(b, kb);
}

#[given(expr = "{word} has an RSA keypair")]
async fn one_keypair(w: &mut AlooWorld, who: String) {
    w.derived.insert(who.clone(), keypair_for(&who));
}

// ---------------------------------------------------------------------
// When
// ---------------------------------------------------------------------

#[when(expr = "the message {string} is encrypted for {word}")]
async fn encrypt_for(w: &mut AlooWorld, message: String, who: String) {
    let kp = w.derived.get(&who).expect("recipient has no key");
    w.plaintext = message.into_bytes();
    w.blocks = encrypt_chunked(&kp.public, &w.plaintext).expect("encryption should succeed");
}

#[when(expr = "an empty message is encrypted for {word}")]
async fn encrypt_empty(w: &mut AlooWorld, who: String) {
    let kp = w.derived.get(&who).expect("recipient has no key");
    w.plaintext = Vec::new();
    w.blocks = encrypt_chunked(&kp.public, &w.plaintext).expect("encryption should succeed");
}

#[when(expr = "a message spanning more than two RSA blocks is encrypted for {word}")]
async fn encrypt_long(w: &mut AlooWorld, who: String) {
    let kp = w.derived.get(&who).expect("recipient has no key");
    // Deliberately not a round multiple of the block size: a final partial
    // block is where an off-by-one in the split/rejoin would show up.
    let chunk = max_chunk_len(&kp.public);
    w.plaintext = (0..chunk * 2 + 37).map(|i| (i % 256) as u8).collect();
    w.blocks = encrypt_chunked(&kp.public, &w.plaintext).expect("encryption should succeed");
}

// ---------------------------------------------------------------------
// Then
// ---------------------------------------------------------------------

#[then(expr = "{word} reads back exactly what was sent")]
async fn reads_back(w: &mut AlooWorld, who: String) {
    let kp = w.derived.get(&who).expect("recipient has no key");
    let out = decrypt_chunked(&kp.private, &w.blocks)
        .expect("the intended recipient must be able to decrypt");
    assert_eq!(
        out, w.plaintext,
        "decrypted bytes differ from what was encrypted"
    );
}

#[then(expr = "{word} cannot read it at all")]
async fn cannot_read(w: &mut AlooWorld, who: String) {
    let kp = w.derived.get(&who).expect("outsider has no key");
    let result = decrypt_chunked(&kp.private, &w.blocks);
    assert!(
        result.is_err(),
        "a key the message was not encrypted for must not decrypt it"
    );
}

#[then(expr = "it was split into at least {int} separately encrypted blocks")]
async fn split_into(w: &mut AlooWorld, n: usize) {
    assert!(
        w.blocks.len() >= n,
        "expected at least {n} blocks, got {} - a long payload must be split, not truncated",
        w.blocks.len()
    );
}

#[then(expr = "it produced exactly {int} encrypted block")]
async fn exactly_blocks(w: &mut AlooWorld, n: usize) {
    assert_eq!(
        w.blocks.len(),
        n,
        "an empty plaintext must still produce exactly one block, never zero - \
         `blocks` is never empty for a valid envelope"
    );
}

// ---------------------------------------------------------------------
// Wire protocol (US-009)
// ---------------------------------------------------------------------

#[when("every kind of protocol message is written to the wire and read back")]
async fn roundtrip_every_message(w: &mut AlooWorld) {
    // One representative of each shape the protocol can carry, checked
    // individually so a failure names the variant that broke.
    let envelope = Envelope {
        content: Content::Text,
        blocks: vec![vec![9, 9, 9], vec![8, 8]],
    };

    let client: Vec<ClientMessage> = vec![
        ClientMessage::Identify {
            public_key_der: vec![1, 2, 3, 4],
            key_mode: KeyMode::PqHybrid,
        },
        ClientMessage::JoinChannel {
            name: "general".into(),
            kind: ChannelKind::Public,
            password: None,
        },
        ClientMessage::LeaveChannel {
            name: "general".into(),
        },
        ClientMessage::RotateKey {
            to: UserId(3),
            new_public_key_der: vec![1, 2, 3],
            signature: vec![9, 9],
        },
        ClientMessage::RequestPeerLink {
            peer: UserId(7),
            candidates: vec![
                "127.0.0.1:4000".parse().unwrap(),
                "203.0.113.5:4000".parse().unwrap(),
            ],
            link_nonce: 42,
        },
    ];
    for msg in &client {
        let decoded: ClientMessage = decode(&encode(msg).expect("encode")).expect("decode");
        assert_eq!(
            &decoded, msg,
            "client message did not survive the round trip: {msg:?}"
        );
    }

    let server: Vec<ServerMessage> = vec![
        ServerMessage::ChannelList(vec![
            ChannelInfo {
                name: "general".into(),
                kind: ChannelKind::Public,
            },
            ChannelInfo {
                name: "secret-room".into(),
                kind: ChannelKind::Private,
            },
        ]),
        ServerMessage::KeyRotated {
            from: UserId(3),
            new_public_key_der: vec![1, 2, 3],
            signature: vec![9, 9],
        },
        ServerMessage::PeerCandidates {
            from: UserId(7),
            candidates: vec!["127.0.0.1:4000".parse().unwrap()],
            link_nonce: 42,
        },
    ];
    for msg in &server {
        let decoded: ServerMessage = decode(&encode(msg).expect("encode")).expect("decode");
        assert_eq!(
            &decoded, msg,
            "server message did not survive the round trip: {msg:?}"
        );
    }

    let user = UserInfo {
        id: UserId(42),
        name: "alice".into(),
        public_key_der: vec![0xde, 0xad, 0xbe, 0xef],
        key_mode: KeyMode::PqHybrid,
    };
    let decoded: UserInfo = decode(&encode(&user).expect("encode")).expect("decode");
    assert_eq!(decoded, user, "UserInfo did not survive the round trip");

    // Message content itself now travels over the direct link, not the
    // wire types above - `P2pPayload::Envelope` is where an `Envelope`
    // actually gets sent, so that's what needs the round-trip check.
    let payload = P2pPayload::Envelope {
        msg_id: None,
        channel: None,
        envelope: envelope.clone(),
    };
    let decoded: P2pPayload = decode(&encode(&payload).expect("encode")).expect("decode");
    match decoded {
        P2pPayload::Envelope {
            channel,
            msg_id: _,
            envelope: got,
        } => {
            assert_eq!(channel, None);
            assert_eq!(got, envelope, "envelope did not survive the round trip");
        }
        _ => panic!("wrong P2pPayload variant after round trip"),
    }

    w.envelope = Some(envelope);
}

#[then("every field arrives exactly as it was sent")]
async fn every_field_intact(w: &mut AlooWorld) {
    // The per-variant equality checks above already asserted this; this step
    // pins the envelope specifically, since it is the one value that carries
    // opaque ciphertext the server must never reinterpret.
    let envelope = w.envelope.as_ref().expect("no envelope round-tripped");
    let msg = P2pPayload::Envelope {
        channel: Some("general".into()),
        msg_id: None,
        envelope: envelope.clone(),
    };
    let decoded: P2pPayload = decode(&encode(&msg).unwrap()).unwrap();
    match decoded {
        P2pPayload::Envelope {
            channel,
            msg_id: _,
            envelope: got,
        } => {
            assert_eq!(
                channel.as_deref(),
                Some("general"),
                "channel routing metadata must survive"
            );
            assert_eq!(
                &got, envelope,
                "the encrypted body must survive byte for byte"
            );
            assert_eq!(got.content, Content::Text);
            assert_eq!(
                got.blocks,
                vec![vec![9, 9, 9], vec![8, 8]],
                "block boundaries must be preserved"
            );
        }
        _ => panic!("wrong variant after round trip"),
    }
}

#[then("a user announced under any key mode arrives with that same key mode")]
async fn key_mode_survives(_w: &mut AlooWorld) {
    for key_mode in [KeyMode::PqHybrid, KeyMode::PqHybrid, KeyMode::PqHybrid] {
        let user = UserInfo {
            id: UserId(1),
            name: "alice".into(),
            public_key_der: vec![1, 2, 3],
            key_mode,
        };
        let decoded: UserInfo = decode(&encode(&user).unwrap()).unwrap();
        assert_eq!(decoded, user, "round trip failed for {key_mode:?}");

        let identify = ClientMessage::Identify {
            public_key_der: vec![1, 2, 3, 4],
            key_mode,
        };
        let decoded: ClientMessage = decode(&encode(&identify).unwrap()).unwrap();
        assert_eq!(
            decoded, identify,
            "Identify round trip failed for {key_mode:?}"
        );
    }
}

#[then("a fingerprint of the key is stable and distinguishes it from any other key")]
async fn fingerprint_stable(w: &mut AlooWorld) {
    let a = w.derived.get("alice").expect("alice has no key");
    let b = w.derived.get("bob").expect("bob has no key");
    let fp_a1 = crypto::fingerprint(&a.public).unwrap();
    let fp_a2 = crypto::fingerprint(&a.public).unwrap();
    let fp_b = crypto::fingerprint(&b.public).unwrap();
    assert_eq!(fp_a1, fp_a2, "a fingerprint must be stable across calls");
    assert_ne!(fp_a1, fp_b, "different keys must fingerprint differently");
    assert_eq!(fp_a1.len(), 64, "a SHA-256 hex digest is 64 characters");
    assert_eq!(
        crypto::fingerprint_der(&public_key_to_der(&a.public).unwrap()),
        fp_a1,
        "fingerprinting raw DER must agree with fingerprinting the parsed key"
    );
}
