//! Steps for surviving hostile input (US-031).
//!
//! The exhaustive corpus lives in `test/robustness_test.rs`; these
//! scenarios state the property in the language the rest of the features
//! use, and check it end to end through the same decoders.

use aloo::p2p_proto::{P2pPayload, PunchDatagram};
use aloo::proto::{self, ClientMessage, ServerMessage};
use cucumber::{then, when};

use crate::world::AlooWorld;

/// Same seeded generator as the robustness suite, for the same reason: a
/// failure has to be reproducible.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0xFF) as u8
        })
        .collect()
}

fn try_every_decoder(bytes: &[u8]) -> bool {
    // Each of these is reachable by a remote peer. None may panic; all are
    // expected to refuse.
    let outcome = std::panic::catch_unwind(|| {
        let a = proto::decode::<ClientMessage>(bytes).is_err();
        let b = proto::decode::<ServerMessage>(bytes).is_err();
        let c = proto::decode::<P2pPayload>(bytes).is_err();
        let d = proto::decode::<PunchDatagram>(bytes).is_err();
        (a, b, c, d)
    });
    outcome.is_ok()
}

#[when(expr = "a peer sends {int} messages of pure noise")]
async fn peer_sends_noise(w: &mut AlooWorld, count: usize) {
    let mut survived = true;
    for i in 0..count {
        let bytes = noise(0xa11ce ^ i as u64, 1 + (i % 200));
        survived &= try_every_decoder(&bytes);
    }
    w.survived_malformed = survived;
}

#[when("a peer sends a message truncated at every possible length")]
async fn peer_sends_truncated(w: &mut AlooWorld) {
    let encoded = proto::encode(&P2pPayload::FileChunk {
        stream_id: 1,
        seq: 2,
        blocks: vec![vec![9; 40]],
    })
    .expect("encode");

    let mut survived = true;
    for cut in 0..encoded.len() {
        survived &= try_every_decoder(&encoded[..cut]);
    }
    w.survived_malformed = survived;
}

#[when("a peer announces a frame larger than the protocol allows")]
async fn peer_announces_huge_frame(w: &mut AlooWorld) {
    let mut frame = u32::MAX.to_be_bytes().to_vec();
    frame.extend_from_slice(b"but only these few bytes follow");
    w.oversized_frame_refused = proto::parse_frame(&frame).is_err();
}

#[then("every one is refused and the client is still running")]
async fn everything_refused(w: &mut AlooWorld) {
    assert!(
        w.survived_malformed,
        "a decoder panicked on input a stranger chose"
    );
}

#[then("the frame is refused without reserving room for it")]
async fn frame_refused(w: &mut AlooWorld) {
    assert!(
        w.oversized_frame_refused,
        "a frame past the cap must be refused before anything is allocated for it"
    );
}
