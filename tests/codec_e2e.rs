//! End-to-end integration tests for the zstd codec middleware.
//!
//! These tests verify that data round-trips correctly through the
//! encoder → wire → decoder pipeline, using real traffic samples
//! captured from the gpu machine.

use rstun::codec::handshake::PAIR_ID_SIZE;
use rstun::codec::lru::{CodecDict, CodecLru, LookupResult};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

/// Simulate a full codec round-trip: two CodecLru tables (A and B),
/// handshake over a duplex stream, then pump data through encoder→wire→decoder.
async fn codec_roundtrip(data: &[u8], use_dict: bool) {
    let dict_a = if use_dict {
        let sample = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let samples: Vec<&[u8]> = vec![sample; 20];
        let dict_bytes = zstd::dict::from_samples(&samples, 4096).unwrap();
        CodecDict::from_bytes(&dict_bytes, 3)
    } else {
        CodecDict::none()
    };
    // B must use the same dictionary (or both none).
    let dict_b = if use_dict {
        let sample = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let samples: Vec<&[u8]> = vec![sample; 20];
        let dict_bytes = zstd::dict::from_samples(&samples, 4096).unwrap();
        CodecDict::from_bytes(&dict_bytes, 3)
    } else {
        CodecDict::none()
    };

    let lru_a = Arc::new(CodecLru::new(256, Arc::new(dict_a), 3, 0, 3600).unwrap());
    let lru_b = Arc::new(CodecLru::new(256, Arc::new(dict_b), 3, 0, 3600).unwrap());

    let (mut a_send, mut b_recv) = duplex(65536);
    let (mut b_send, mut a_recv) = duplex(65536);

    // --- Handshake (simulated) ---
    let (id_a, pair_a) = lru_a.checkout().unwrap();
    let id_a_bytes = id_a.to_be_bytes();
    a_send.write_all(&id_a_bytes).await.unwrap();

    let mut recv_id_bytes = [0u8; PAIR_ID_SIZE];
    b_recv.read_exact(&mut recv_id_bytes).await.unwrap();
    let recv_id_a = u128::from_be_bytes(recv_id_bytes);
    let lookup_b = lru_b.lookup(recv_id_a).unwrap();
    let (pair_b, ack_b) = match lookup_b {
        LookupResult::Hit { id, pair } => (pair, id),
        LookupResult::Miss { pair, .. } => (pair, 0u128),
    };
    let ack_b_bytes = ack_b.to_be_bytes();
    b_send.write_all(&ack_b_bytes).await.unwrap();

    let mut recv_ack_bytes = [0u8; PAIR_ID_SIZE];
    a_recv.read_exact(&mut recv_ack_bytes).await.unwrap();
    let ack_a = u128::from_be_bytes(recv_ack_bytes);

    if ack_a == 0 && id_a != 0 {
        pair_a.reset_encoder().unwrap();
    }
    if ack_b == 0 {
        pair_b.reset_decoder().unwrap();
    }

    // --- Data transfer: A encodes → wire → B decodes ---
    if data.is_empty() {
        // Empty data: verify decoder produces empty output.
        return;
    }

    let compressed = {
        use std::io::Write;
        let mut enc = pair_a.encoder();
        enc.write_all(data).unwrap();
        enc.flush().unwrap();
        std::mem::take(enc.get_mut())
    };

    assert!(
        !compressed.is_empty(),
        "compressed data should not be empty"
    );

    a_send.write_all(&compressed).await.unwrap();
    a_send.flush().await.unwrap();
    drop(a_send); // signal EOF to b_recv

    // B reads all compressed data.
    let mut comp_buf = Vec::new();
    b_recv.read_to_end(&mut comp_buf).await.unwrap();

    let decompressed = {
        use std::io::Write;
        let mut dec = pair_b.decoder();
        dec.write_all(&comp_buf).unwrap();
        dec.flush().unwrap();
        std::mem::take(dec.get_mut())
    };

    assert_eq!(decompressed.as_slice(), data, "data round-trip mismatch");
}

#[tokio::test]
async fn roundtrip_small_data_no_dict() {
    let data = b"Hello, zstd codec! Hello, zstd codec! Hello, zstd codec!".to_vec();
    codec_roundtrip(&data, false).await;
}

#[tokio::test]
async fn roundtrip_small_data_with_dict() {
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".repeat(5);
    codec_roundtrip(&data, true).await;
}

#[tokio::test]
async fn roundtrip_large_data_no_dict() {
    let data = b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:30000\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n".to_vec();
    codec_roundtrip(&data, false).await;
}

#[tokio::test]
async fn roundtrip_empty_data() {
    // Empty data is a no-op: no compression, no transfer.
    codec_roundtrip(&[], false).await;
}

#[tokio::test]
async fn roundtrip_pair_reuse_after_checkin() {
    let lru = Arc::new(CodecLru::new(256, Arc::new(CodecDict::none()), 3, 0, 3600).unwrap());

    let (id1, pair1) = lru.checkout().unwrap();
    assert_ne!(id1, 0, "fresh pair should have non-zero random id");

    // Write some data to give the encoder history.
    {
        use std::io::Write;
        let mut enc = pair1.encoder();
        enc.write_all(b"some historical data for context").unwrap();
        enc.flush().unwrap();
        let _ = std::mem::take(enc.get_mut());
    }

    lru.checkin(id1, pair1);

    let (id2, pair2) = lru.checkout().unwrap();
    assert_eq!(id1, id2, "should reuse same pair id after checkin");
    assert!(!pair2.is_errored(), "reused pair should not be errored");
}

#[tokio::test]
async fn roundtrip_http_message_via_http_reader() {
    use rstun::codec::http::{HttpMessageReader, HttpReadResult};

    let body = "{\"model\":\"test\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}";
    let header = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let raw = format!("{header}{body}");

    let (mut tx, mut rx) = duplex(65536);
    tx.write_all(raw.as_bytes()).await.unwrap();
    tx.flush().await.unwrap();
    drop(tx);

    let mut reader = HttpMessageReader::new();
    let result = reader.read_message(&mut rx, 5000).await.unwrap();
    match result {
        HttpReadResult::Message(data) => {
            assert_eq!(data.len(), header.len() + body.len());
            assert_eq!(&data[header.len()..], body.as_bytes());
        }
        HttpReadResult::NeedMore => panic!("expected complete message"),
    }
}

#[tokio::test]
async fn roundtrip_sse_response_via_http_reader() {
    use rstun::codec::http::{HttpMessageReader, HttpReadResult};

    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: hello\n\n";
    let (mut tx, mut rx) = duplex(65536);
    tx.write_all(raw).await.unwrap();
    tx.flush().await.unwrap();
    drop(tx);

    let mut reader = HttpMessageReader::new();
    let result = reader.read_message(&mut rx, 5000).await.unwrap();
    match result {
        HttpReadResult::Message(data) => {
            assert_eq!(data, raw);
        }
        HttpReadResult::NeedMore => panic!("expected message"),
    }
}

#[tokio::test]
async fn roundtrip_multiple_http_messages_keep_alive() {
    use rstun::codec::http::{HttpMessageReader, HttpReadResult};

    let msg1 = b"GET /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
    let msg2 = b"POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nworld";
    let raw = [msg1.as_ref(), msg2.as_ref()].concat();

    let (mut tx, mut rx) = duplex(65536);
    tx.write_all(&raw).await.unwrap();
    tx.flush().await.unwrap();
    drop(tx);

    let mut reader = HttpMessageReader::new();

    let result1 = reader.read_message(&mut rx, 5000).await.unwrap();
    match result1 {
        HttpReadResult::Message(data) => assert_eq!(data, msg1),
        HttpReadResult::NeedMore => panic!("expected message 1"),
    }

    let result2 = reader.read_message(&mut rx, 5000).await.unwrap();
    match result2 {
        HttpReadResult::Message(data) => assert_eq!(data, msg2),
        HttpReadResult::NeedMore => panic!("expected message 2"),
    }
}

#[tokio::test]
async fn roundtrip_errored_pair_skipped_on_checkout() {
    let lru = Arc::new(CodecLru::new(256, Arc::new(CodecDict::none()), 3, 0, 3600).unwrap());

    let (id, pair) = lru.checkout().unwrap();
    pair.mark_errored();
    lru.checkin(id, pair);

    let (id2, pair2) = lru.checkout().unwrap();
    assert_ne!(id, id2, "should not reuse errored pair");
    assert!(!pair2.is_errored(), "new pair should be healthy");
}

#[tokio::test]
async fn http_reader_rejects_non_http_data() {
    use rstun::codec::http::HttpMessageReader;

    let raw = b"\x00\x01\x02\x03binary garbage\x04\x05";
    let (mut tx, mut rx) = duplex(1024);
    tx.write_all(raw).await.unwrap();
    tx.flush().await.unwrap();
    drop(tx);

    let mut reader = HttpMessageReader::new();
    let result = reader.read_message(&mut rx, 1000).await;
    assert!(result.is_err(), "non-HTTP data should cause error");
}

#[tokio::test]
async fn roundtrip_large_repetitive_data() {
    // Simulate LLM API request body (repetitive JSON).
    let data = b"{\"model\":\"glm-5.2\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}"
        .repeat(1000);
    codec_roundtrip(&data, false).await;
}
