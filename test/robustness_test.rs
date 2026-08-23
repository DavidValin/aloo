//! Malformed input must never crash anything.
//!
//! Every decode path here is reachable by a remote peer, a server, or a
//! hand-edited local file, so all of them have to fail as errors rather
//! than panics. This is a poor relation of structured fuzzing - the real
//! thing is named as future work in `docs/SECURITY.md` - but it runs in the
//! ordinary suite on every commit, which unattended fuzzing does not.
//!
//! The generator is a seeded PRNG rather than the system one: a failure has
//! to be reproducible from the printed seed, or a red build tells you
//! nothing you can act on.

use aloo::client::idstore::IdStore;
use aloo::crypto::pq::{PqPublicBundle, SendSetup, load_identity_card, open_identity_card};
use aloo::p2p_proto::{P2pPayload, PunchDatagram};
use aloo::proto::{self, ClientMessage, ServerMessage};

/// A tiny xorshift, so the corpus is identical on every machine and the
/// seed in a failure message actually reproduces it.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() & 0xFF) as u8).collect()
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

/// Every decode this test exercises, behind one name so a new decode path
/// can be added in one place.
fn decode_everything(bytes: &[u8]) {
    let _ = proto::decode::<ClientMessage>(bytes);
    let _ = proto::decode::<ServerMessage>(bytes);
    let _ = proto::decode::<P2pPayload>(bytes);
    let _ = proto::decode::<PunchDatagram>(bytes);
    let _ = proto::decode::<PqPublicBundle>(bytes);
    let _ = proto::decode::<SendSetup>(bytes);
    let _ = proto::decode::<aloo::crypto::pq::PqRotation>(bytes);
    let _ = proto::decode::<aloo::control::ControlOffer>(bytes);
    let _ = proto::decode::<aloo::control::ControlAccept>(bytes);
    let _ = proto::parse_frame(bytes);
    let _ = aloo::crypto::pq::fingerprint_of_encoded(bytes);
    let _ = aloo::crypto::public_key_from_der(bytes);
    let _ = aloo::crypto::hex_decode(&String::from_utf8_lossy(bytes));
}

/// @requirement TB-172
#[test]
fn random_bytes_never_panic_any_decoder() {
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    for round in 0..4000 {
        let len = rng.below(300);
        let bytes = rng.bytes(len);
        // If this panics, the seed and round below reproduce it exactly.
        let guard = std::panic::catch_unwind(|| decode_everything(&bytes));
        assert!(
            guard.is_ok(),
            "decoding panicked on round {round} with bytes {bytes:?}"
        );
    }
}

/// A truncated message is the commonest real-world malformation: a short
/// read, a dropped connection, a partial file.
/// @requirement TB-172
#[test]
fn truncating_a_valid_message_never_panics() {
    let messages: Vec<Vec<u8>> = vec![
        proto::encode(&ClientMessage::Auth {
            nickname: "dave".into(),
            password: "hunter2".into(),
        })
        .unwrap(),
        proto::encode(&ServerMessage::Error {
            message: "something went wrong".into(),
        })
        .unwrap(),
        proto::encode(&P2pPayload::StreamStart {
            channel: Some("the-hall".into()),
            stream_id: 7,
            msg_id: None,
        })
        .unwrap(),
        proto::encode(&PunchDatagram::Ping { link_nonce: 42 }).unwrap(),
    ];

    for encoded in &messages {
        for cut in 0..encoded.len() {
            let guard = std::panic::catch_unwind(|| decode_everything(&encoded[..cut]));
            assert!(
                guard.is_ok(),
                "decoding panicked on a message truncated to {cut} bytes"
            );
        }
    }
}

/// Single-bit corruption of otherwise valid messages - what a flipped bit
/// on the wire, or a deliberately tampered frame, actually looks like.
/// @requirement TB-172
#[test]
fn bit_flips_in_valid_messages_never_panic() {
    let mut rng = Rng(0xfeed_face_0000_0001);
    let encoded = proto::encode(&P2pPayload::FileChunk {
        stream_id: 3,
        seq: 9,
        blocks: vec![vec![1, 2, 3], vec![4, 5]],
    })
    .unwrap();

    for round in 0..2000 {
        let mut corrupted = encoded.clone();
        let index = rng.below(corrupted.len());
        corrupted[index] ^= 1 << rng.below(8);
        let guard = std::panic::catch_unwind(|| decode_everything(&corrupted));
        assert!(guard.is_ok(), "decoding panicked on round {round}");
    }
}

/// A length prefix claiming more than `MAX_FRAME_LEN` must be refused
/// rather than believed - the whole point of the cap is not allocating
/// whatever a stranger asks for.
/// @requirement TB-172
#[test]
fn an_absurd_length_prefix_is_refused_not_allocated() {
    let mut frame = vec![0xFF, 0xFF, 0xFF, 0xFF];
    frame.extend_from_slice(b"nowhere near that long");

    assert!(
        proto::parse_frame(&frame).is_err(),
        "a length prefix past the cap must be an error"
    );
}

/// The identity store is a local file a user may hand-edit, so every kind
/// of damage has to load as "some entries, no crash".
/// @requirement TB-173
#[test]
fn a_damaged_identity_store_still_loads() {
    let cases = [
        "",
        "\n\n\n",
        "no-tab-at-all\n",
        "alice\tnot-hex\n",
        "alice\tdeadbee\n",              // odd-length hex
        "alice\tdeadbeef\tnonsense\n",   // unknown trust column
        "alice\tdeadbeef\ttofu\textra\n",
        "\t\t\n",
        "alice\tdeadbeef\nbob\tcafe\tverified\n",
    ];

    for (i, contents) in cases.iter().enumerate() {
        let path = std::env::temp_dir().join(format!(
            "aloo-robust-store-{}-{i}",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write");

        let loaded = IdStore::load(&path);
        assert!(
            loaded.is_ok(),
            "a damaged store must load with whatever survived, not fail: {contents:?}"
        );

        std::fs::remove_file(&path).ok();
    }
}

/// @requirement TB-173
#[test]
fn a_garbage_identity_card_file_is_refused_without_panicking() {
    let mut rng = Rng(0x0bad_cafe_0000_0002);
    for i in 0..200 {
        let path = std::env::temp_dir().join(format!(
            "aloo-robust-card-{}-{i}",
            std::process::id()
        ));
        let len = rng.below(200);
        std::fs::write(&path, rng.bytes(len)).expect("write");

        let guard = std::panic::catch_unwind(|| {
            let _ = load_identity_card(&path);
        });
        assert!(guard.is_ok(), "loading a garbage card panicked");

        std::fs::remove_file(&path).ok();
    }
}

/// Opening a card built from random bytes must fail closed rather than
/// yielding an identity nobody signed.
/// @requirement TB-173
#[test]
fn a_card_decoded_from_noise_never_verifies() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for _ in 0..2000 {
        let len = rng.below(400);
        let bytes = rng.bytes(len);
        if let Ok(card) = proto::decode::<aloo::crypto::pq::IdentityCard>(&bytes) {
            assert!(
                open_identity_card(&card).is_none(),
                "a card assembled from noise must never verify"
            );
        }
    }
}

/// Chunks are opened with attacker-influenced `(send_id, seq)` and
/// ciphertext; none of those may panic, whatever they contain.
/// @requirement TB-172
#[test]
fn opening_garbage_chunks_never_panics() {
    let mut rng = Rng(0xabcd_0000_1111_2222);
    let key = [7u8; 32];

    for _ in 0..2000 {
        let len = rng.below(120);
        let ciphertext = rng.bytes(len);
        let send_id = rng.next();
        let seq = (rng.next() & 0xFFFF_FFFF) as u32;
        assert!(
            aloo::crypto::pq::open_chunk(&key, send_id, seq, &ciphertext).is_none()
                || ciphertext.is_empty(),
            "noise must not open as a valid chunk"
        );
    }
}
