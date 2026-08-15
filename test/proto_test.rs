use aloo::proto::{
    decode, encode, frame, parse_frame, read_message, write_message, AuthKind, AuthResponse,
    ChannelInfo, ChannelKind, ClientMessage, Content, Envelope, KeyMode, ProtoError, ServerMessage,
    UserId, UserInfo, MAX_FRAME_LEN,
};

/// @requirement AC-043, TB-060
#[test]
fn encode_decode_roundtrip_client_message() {
    let msg = ClientMessage::Identify {
        display_name: "dave".into(),
        public_key_der: vec![1, 2, 3, 4],
        key_mode: KeyMode::Rsa,
    };
    let bytes = encode(&msg).expect("encode");
    let decoded: ClientMessage = decode(&bytes).expect("decode");
    assert_eq!(msg, decoded);
}

/// @requirement TB-061
#[test]
fn identify_roundtrips_with_per_message_key_mode() {
    let msg = ClientMessage::Identify {
        display_name: "dave".into(),
        public_key_der: vec![1, 2, 3, 4],
        key_mode: KeyMode::PerMessage,
    };
    let bytes = encode(&msg).expect("encode");
    let decoded: ClientMessage = decode(&bytes).expect("decode");
    assert_eq!(msg, decoded);
}

/// @requirement TB-060
#[test]
fn rotate_key_and_key_rotated_roundtrip() {
    let rotate =
        ClientMessage::RotateKey { to: UserId(3), new_public_key_der: vec![1, 2, 3], signature: vec![9, 9] };
    assert_eq!(decode::<ClientMessage>(&encode(&rotate).unwrap()).unwrap(), rotate);

    let rotated =
        ServerMessage::KeyRotated { from: UserId(3), new_public_key_der: vec![1, 2, 3], signature: vec![9, 9] };
    assert_eq!(decode::<ServerMessage>(&encode(&rotated).unwrap()).unwrap(), rotated);
}

/// @requirement AC-043, TB-060
#[test]
fn encode_decode_roundtrip_server_message() {
    let msg = ServerMessage::ChannelList(vec![
        ChannelInfo { name: "general".into(), kind: ChannelKind::Public },
        ChannelInfo { name: "secret-room".into(), kind: ChannelKind::Private },
    ]);
    let bytes = encode(&msg).expect("encode");
    let decoded: ServerMessage = decode(&bytes).expect("decode");
    assert_eq!(msg, decoded);
}

/// @requirement AC-043, TB-060
#[test]
fn envelope_roundtrips() {
    let env = Envelope { content: Content::Text, blocks: vec![vec![9, 9, 9], vec![8, 8]] };
    let msg = ClientMessage::SendDirect { to: UserId(7), envelope: env.clone() };
    let bytes = encode(&msg).unwrap();
    let decoded: ClientMessage = decode(&bytes).unwrap();
    match decoded {
        ClientMessage::SendDirect { to, envelope } => {
            assert_eq!(to, UserId(7));
            assert_eq!(envelope, env);
        }
        _ => panic!("wrong variant"),
    }
}

/// A `Content::FileOffer` envelope, carried by `ClientMessage::FileOffer`,
/// round-trips exactly like `Content::Text` (docs/PROTOCOL.md's file
/// transfer section) - no special-casing anywhere in the wire codec.
///
/// @requirement TB-123
#[test]
fn content_file_offer_envelope_roundtrips() {
    let env = Envelope { content: Content::FileOffer, blocks: vec![vec![1, 2, 3]] };
    let msg = ClientMessage::FileOffer { to: UserId(2), stream_id: 7, channel: Some("general".into()), envelope: env.clone() };
    let bytes = encode(&msg).unwrap();
    let decoded: ClientMessage = decode(&bytes).unwrap();
    match decoded {
        ClientMessage::FileOffer { to, stream_id, channel, envelope } => {
            assert_eq!(to, UserId(2));
            assert_eq!(stream_id, 7);
            assert_eq!(channel.as_deref(), Some("general"));
            assert_eq!(envelope, env);
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------
// Live-streamed voice
// ---------------------------------------------------------------------

/// @requirement TB-060
#[test]
fn stream_channel_start_chunk_end_roundtrip() {
    let start = ClientMessage::StreamChannelStart { channel: "general".into(), stream_id: 42 };
    assert_eq!(decode::<ClientMessage>(&encode(&start).unwrap()).unwrap(), start);

    let chunk = ClientMessage::StreamChannelChunk {
        channel: "general".into(),
        stream_id: 42,
        seq: 3,
        per_recipient: vec![(UserId(2), vec![vec![1, 2, 3], vec![4]])],
    };
    assert_eq!(decode::<ClientMessage>(&encode(&chunk).unwrap()).unwrap(), chunk);

    let end = ClientMessage::StreamChannelEnd { channel: "general".into(), stream_id: 42, duration_ms: 9000 };
    assert_eq!(decode::<ClientMessage>(&encode(&end).unwrap()).unwrap(), end);
}

/// @requirement TB-060
#[test]
fn stream_direct_start_chunk_end_roundtrip() {
    let start = ClientMessage::StreamDirectStart { to: UserId(9), stream_id: 7 };
    assert_eq!(decode::<ClientMessage>(&encode(&start).unwrap()).unwrap(), start);

    let chunk = ClientMessage::StreamDirectChunk { to: UserId(9), stream_id: 7, seq: 1, blocks: vec![vec![5]] };
    assert_eq!(decode::<ClientMessage>(&encode(&chunk).unwrap()).unwrap(), chunk);

    let end = ClientMessage::StreamDirectEnd { to: UserId(9), stream_id: 7, duration_ms: 500 };
    assert_eq!(decode::<ClientMessage>(&encode(&end).unwrap()).unwrap(), end);
}

/// @requirement TB-060
#[test]
fn server_stream_variants_roundtrip() {
    let msgs = vec![
        ServerMessage::ChannelStreamStart {
            channel: "general".into(),
            from: UserId(1),
            from_name: "alice".into(),
            stream_id: 42,
        },
        ServerMessage::ChannelStreamChunk {
            channel: "general".into(),
            from: UserId(1),
            stream_id: 42,
            seq: 0,
            blocks: vec![vec![1]],
        },
        ServerMessage::ChannelStreamEnd { channel: "general".into(), from: UserId(1), stream_id: 42, duration_ms: 100 },
        ServerMessage::DirectStreamStart { from: UserId(1), from_name: "alice".into(), stream_id: 7 },
        ServerMessage::DirectStreamChunk { from: UserId(1), stream_id: 7, seq: 0, blocks: vec![vec![2]] },
        ServerMessage::DirectStreamEnd { from: UserId(1), stream_id: 7, duration_ms: 50 },
    ];
    for msg in msgs {
        assert_eq!(decode::<ServerMessage>(&encode(&msg).unwrap()).unwrap(), msg, "roundtrip failed for {msg:?}");
    }
}

/// @requirement TB-062
#[test]
fn frame_roundtrip_exact_buffer() {
    let payload = b"hello world".to_vec();
    let framed = frame(&payload).unwrap();
    assert_eq!(framed.len(), 4 + payload.len());

    let (parsed, consumed) = parse_frame(&framed).unwrap().expect("complete frame");
    assert_eq!(parsed, payload.as_slice());
    assert_eq!(consumed, framed.len());
}

/// @requirement TB-063
#[test]
fn parse_frame_reports_incomplete_data() {
    let payload = b"a longer payload than the truncated buffer".to_vec();
    let framed = frame(&payload).unwrap();

    // only the length prefix, no payload yet
    assert!(parse_frame(&framed[..2]).unwrap().is_none());
    assert!(parse_frame(&framed[..4]).unwrap().is_none());
    // prefix plus a partial payload
    assert!(parse_frame(&framed[..framed.len() - 1]).unwrap().is_none());
    // full frame
    assert!(parse_frame(&framed).unwrap().is_some());
}

/// @requirement TB-064
#[test]
fn parse_frame_rejects_oversized_length_prefix() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes());
    let err = parse_frame(&buf).unwrap_err();
    assert!(matches!(err, ProtoError::FrameTooLarge(_)));
}

/// @requirement TB-065
#[test]
fn multiple_frames_can_be_parsed_sequentially_from_one_buffer() {
    let a = frame(b"first").unwrap();
    let b = frame(b"second-message").unwrap();
    let mut buf = Vec::new();
    buf.extend_from_slice(&a);
    buf.extend_from_slice(&b);

    let (p1, c1) = parse_frame(&buf).unwrap().unwrap();
    assert_eq!(p1, b"first");
    let (p2, c2) = parse_frame(&buf[c1..]).unwrap().unwrap();
    assert_eq!(p2, b"second-message");
    assert_eq!(c1 + c2, buf.len());
}

/// @requirement TB-066
#[tokio::test]
async fn async_write_then_read_message_roundtrip() {
    let (mut client, mut server) = tokio::io::duplex(4096);

    let hello = ServerMessage::Hello { auth: AuthKind::Rsa, challenge: Some(vec![1, 2, 3]) };
    write_message(&mut server, &hello).await.expect("write");

    let received: ServerMessage = read_message(&mut client)
        .await
        .expect("read")
        .expect("some message, not eof");
    assert_eq!(received, hello);
}

/// @requirement TB-067
#[tokio::test]
async fn async_read_returns_none_on_clean_close_before_next_frame() {
    let (client, server) = tokio::io::duplex(4096);
    drop(server); // close write side with nothing sent
    let mut client = client;
    let result: Option<ClientMessage> = read_message(&mut client).await.expect("read should not error");
    assert!(result.is_none());
}

/// @requirement TB-111
#[tokio::test]
async fn eof_immediately_after_a_complete_length_prefix_is_a_hard_io_error() {
    use tokio::io::AsyncWriteExt;

    let (mut client, mut server) = tokio::io::duplex(64);
    // A length prefix declaring a 10-byte payload, but no payload bytes at
    // all before the writer closes - unlike `async_read_returns_none_on_
    // clean_close_before_next_frame`, a byte of this frame (the prefix
    // itself) has already arrived, so this is not a boundary close.
    server.write_all(&10u32.to_be_bytes()).await.unwrap();
    drop(server);

    let result: aloo::proto::Result<Option<ClientMessage>> = read_message(&mut client).await;
    assert!(result.is_err(), "EOF right after the length prefix must be a hard error, not Ok(None)");
}

/// @requirement TB-111
#[tokio::test]
async fn eof_partway_through_the_payload_is_a_hard_io_error() {
    use tokio::io::AsyncWriteExt;

    let (mut client, mut server) = tokio::io::duplex(64);
    let payload = encode(&ClientMessage::LeaveChannel { name: "general".into() }).unwrap();
    let framed = frame(&payload).unwrap();
    server.write_all(&framed[..framed.len() - 1]).await.unwrap(); // one byte short of the full payload
    drop(server);

    let result: aloo::proto::Result<Option<ClientMessage>> = read_message(&mut client).await;
    assert!(result.is_err(), "EOF partway through the payload must be a hard error, not Ok(None)");
}

/// @requirement TB-065, TB-067
#[tokio::test]
async fn async_stream_carries_multiple_messages_in_order() {
    let (mut client, mut server) = tokio::io::duplex(8192);

    let msgs = vec![
        ClientMessage::JoinChannel { name: "general".into(), kind: ChannelKind::Public },
        ClientMessage::LeaveChannel { name: "general".into() },
        ClientMessage::Auth(AuthResponse::Password("hunter2".into())),
    ];
    for m in &msgs {
        write_message(&mut server, m).await.unwrap();
    }
    drop(server);

    for expected in &msgs {
        let got: ClientMessage = read_message(&mut client).await.unwrap().unwrap();
        assert_eq!(&got, expected);
    }
    let eof: Option<ClientMessage> = read_message(&mut client).await.unwrap();
    assert!(eof.is_none());
}

/// @requirement AC-043, TB-060
#[test]
fn user_info_and_channel_info_roundtrip() {
    let user = UserInfo {
        id: UserId(42),
        name: "alice".into(),
        public_key_der: vec![0xde, 0xad, 0xbe, 0xef],
        key_mode: KeyMode::Rsa,
    };
    let bytes = encode(&user).unwrap();
    let decoded: UserInfo = decode(&bytes).unwrap();
    assert_eq!(user, decoded);
}

/// @requirement TB-061
#[test]
fn user_info_roundtrips_with_per_message_key_mode() {
    let user = UserInfo {
        id: UserId(42),
        name: "alice".into(),
        public_key_der: vec![0xde, 0xad, 0xbe, 0xef],
        key_mode: KeyMode::PerMessage,
    };
    let bytes = encode(&user).unwrap();
    let decoded: UserInfo = decode(&bytes).unwrap();
    assert_eq!(user, decoded);
}

/// @requirement TB-061
#[test]
fn user_info_roundtrips_with_every_key_mode_variant() {
    for key_mode in [KeyMode::Rsa, KeyMode::Password, KeyMode::None, KeyMode::PerMessage, KeyMode::PqHybrid] {
        let user =
            UserInfo { id: UserId(1), name: "alice".into(), public_key_der: vec![1, 2, 3], key_mode };
        let bytes = encode(&user).unwrap();
        let decoded: UserInfo = decode(&bytes).unwrap();
        assert_eq!(user, decoded, "roundtrip failed for {key_mode:?}");
    }
}

/// @requirement AC-051, TB-099
#[test]
fn key_mode_label_matches_the_documented_tag_convention() {
    assert_eq!(KeyMode::PerMessage.label(), "\u{1F512} RSAPM");
    assert_eq!(KeyMode::Rsa.label(), "\u{1F512} RSA");
    assert_eq!(KeyMode::Password.label(), "\u{1F6A8} PWD");
    assert_eq!(KeyMode::None.label(), "\u{1F6A8} PLAIN");
    assert_eq!(KeyMode::PqHybrid.label(), "\u{1F6E1}\u{FE0F} PQH");
}

/// @requirement AC-051, TB-100
#[test]
fn format_with_name_puts_every_tag_after_the_name() {
    assert_eq!(KeyMode::PerMessage.format_with_name("carol"), "carol \u{1F512} RSAPM");
    assert_eq!(KeyMode::Rsa.format_with_name("bob"), "bob \u{1F512} RSA");
    assert_eq!(KeyMode::Password.format_with_name("dan"), "dan \u{1F6A8} PWD");
    assert_eq!(KeyMode::None.format_with_name("eve"), "eve \u{1F6A8} PLAIN");
    assert_eq!(KeyMode::PqHybrid.format_with_name("frank"), "frank \u{1F6E1}\u{FE0F} PQH");
}

/// The rest of the file-transfer message family (`docs/PROTOCOL.md`'s file
/// transfer section) round-trips the same way every other `ClientMessage`/
/// `ServerMessage` variant does - `FileAccept`/`FileReject`/`FileChunk`/
/// `FileEnd` are always addressed point-to-point (`to`/`from`, never a
/// channel), same shape as the existing `StreamDirect*` family.
///
/// @requirement TB-141
#[test]
fn file_transfer_message_family_roundtrips() {
    let accept = ClientMessage::FileAccept { to: UserId(2), stream_id: 7 };
    assert_eq!(decode::<ClientMessage>(&encode(&accept).unwrap()).unwrap(), accept);

    let reject = ClientMessage::FileReject { to: UserId(2), stream_id: 7 };
    assert_eq!(decode::<ClientMessage>(&encode(&reject).unwrap()).unwrap(), reject);

    let chunk = ClientMessage::FileChunk { to: UserId(2), stream_id: 7, seq: 3, blocks: vec![vec![1, 2], vec![3]] };
    assert_eq!(decode::<ClientMessage>(&encode(&chunk).unwrap()).unwrap(), chunk);

    let end = ClientMessage::FileEnd { to: UserId(2), stream_id: 7 };
    assert_eq!(decode::<ClientMessage>(&encode(&end).unwrap()).unwrap(), end);

    let accepted = ServerMessage::FileAccepted { from: UserId(2), stream_id: 7 };
    assert_eq!(decode::<ServerMessage>(&encode(&accepted).unwrap()).unwrap(), accepted);

    let rejected = ServerMessage::FileRejected { from: UserId(2), stream_id: 7 };
    assert_eq!(decode::<ServerMessage>(&encode(&rejected).unwrap()).unwrap(), rejected);

    let server_chunk = ServerMessage::FileChunk { from: UserId(2), stream_id: 7, seq: 3, blocks: vec![vec![9]] };
    assert_eq!(decode::<ServerMessage>(&encode(&server_chunk).unwrap()).unwrap(), server_chunk);

    let server_end = ServerMessage::FileEnd { from: UserId(2), stream_id: 7 };
    assert_eq!(decode::<ServerMessage>(&encode(&server_end).unwrap()).unwrap(), server_end);
}
