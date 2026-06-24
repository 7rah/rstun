use crate::BUFFER_POOL;
use std::net::IpAddr;
use crate::tcp::AsyncStream;
use crate::ZstdConfig;
use anyhow::Result;
use log::debug;
use quinn::{RecvStream, SendStream};
use std::fmt::Display;
use std::io::Write as IoWrite;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::oneshot;
use tokio::time::error::Elapsed;

// ── zstd statistics ──────────────────────────────────────────────

pub struct ZstdStats {
    pub raw_bytes: AtomicU64,
    pub compressed_bytes: AtomicU64,
}

impl ZstdStats {
    pub fn new() -> Self {
        Self {
            raw_bytes: AtomicU64::new(0),
            compressed_bytes: AtomicU64::new(0),
        }
    }

    pub fn raw_bytes(&self) -> u64 {
        self.raw_bytes.load(Ordering::Relaxed)
    }

    pub fn compressed_bytes(&self) -> u64 {
        self.compressed_bytes.load(Ordering::Relaxed)
    }

    fn add_raw(&self, n: usize) {
        self.raw_bytes.fetch_add(n as u64, Ordering::Relaxed);
    }

    fn add_compressed(&self, n: usize) {
        self.compressed_bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
}

impl Default for ZstdStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── zstd helpers ──────────────────────────────────────────────────

/// Flush the zstd encoder, drain its output buffer, write compressed
/// data to `quic_send`, and update stats. Returns `false` on write error.
async fn flush_encoder_to_quic(
    encoder: &mut zstd::stream::write::Encoder<'_, Vec<u8>>,
    quic_send: &mut SendStream,
    stats: &ZstdStats,
) -> bool {
    if IoWrite::flush(encoder).is_err() {
        return false;
    }
    drain_encoder_to_quic(encoder, quic_send, stats).await
}

/// Finalize the zstd encoder (ZSTD_e_end), drain remaining output, and
/// write to `quic_send`. Returns `false` on any error.
async fn finish_encoder_to_quic(
    encoder: &mut zstd::stream::write::Encoder<'_, Vec<u8>>,
    quic_send: &mut SendStream,
    stats: &ZstdStats,
) -> bool {
    if encoder.do_finish().is_err() {
        return false;
    }
    drain_encoder_to_quic(encoder, quic_send, stats).await
}

/// Drain the encoder's inner Vec and write to QUIC. Shared by flush and finish.
async fn drain_encoder_to_quic(
    encoder: &mut zstd::stream::write::Encoder<'_, Vec<u8>>,
    quic_send: &mut SendStream,
    stats: &ZstdStats,
) -> bool {
    let comp_data = std::mem::take(encoder.get_mut());
    if comp_data.is_empty() {
        return true;
    }
    stats.add_compressed(comp_data.len());
    quic_send.write_all(&comp_data).await.is_ok()
}

/// Drain the decoder's inner Vec and write decompressed data to the TCP stream.
/// Returns `false` on write error.
async fn drain_decoder_to_stream(
    decoder: &mut zstd::stream::write::Decoder<'_, Vec<u8>>,
    stream_write: &mut WriteHalf<impl AsyncStream>,
    transfer_bytes: &mut u64,
) -> bool {
    let dec_data = std::mem::take(decoder.get_mut());
    if dec_data.is_empty() {
        return true;
    }
    *transfer_bytes += dec_data.len() as u64;
    stream_write.write_all(&dec_data).await.is_ok()
}

/// Feed compressed data to the decoder, flush, then drain to TCP.
/// Returns `false` on any zstd or write error.
async fn decode_to_stream(
    decoder: &mut zstd::stream::write::Decoder<'_, Vec<u8>>,
    compressed: &[u8],
    stream_write: &mut WriteHalf<impl AsyncStream>,
    transfer_bytes: &mut u64,
) -> bool {
    if IoWrite::write_all(decoder, compressed).is_err() {
        return false;
    }
    if IoWrite::flush(decoder).is_err() {
        return false;
    }
    drain_decoder_to_stream(decoder, stream_write, transfer_bytes).await
}

// ── error types ───────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum TransferError {
    InternalError,
    InvalidIPAddress,
    InvalidDomain,
    TimeoutError,
}

impl Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalError => write!(f, "InternalError"),
            Self::InvalidIPAddress => write!(f, "InvalidIPAddress"),
            Self::InvalidDomain => write!(f, "InvalidDomain"),
            Self::TimeoutError => write!(f, "TimeoutError"),
        }
    }
}

// ── main stream utility ──────────────────────────────────────────

pub struct StreamUtil {}

impl StreamUtil {
    pub fn start_flowing<S: AsyncStream>(
        tag: &'static str,
        stream: S,
        quic_stream: (SendStream, RecvStream),
        stream_timeout_ms: u64,
        zstd_config: ZstdConfig,
        zstd_stats: Arc<ZstdStats>,
    ) {
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                log::warn!("[{tag}] peer address unavailable, err={e}");
                return;
            }
        };

        let (mut stream_read, mut stream_write) = tokio::io::split(stream);
        let (mut quic_send, mut quic_recv) = quic_stream;
        let index = quic_send.id().index();

        debug!("[{tag}] stream open id={index}, peer={peer_addr}");

        let (quic_to_stream_tx, quic_to_stream_rx) = oneshot::channel::<()>();
        let (stream_to_quic_tx, stream_to_quic_rx) = oneshot::channel::<()>();
        const BUFFER_SIZE: usize = 8192;

        let zstd_enabled = zstd_config.enabled;
        let zstd_stats_q2s = zstd_stats.clone();

        // ── direction: QUIC → TCP (decode if zstd enabled) ──
        tokio::spawn(async move {
            let mut transfer_bytes = 0u64;
            let mut buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);

            if zstd_enabled {
                let mut decoder = match zstd::stream::write::Decoder::new(Vec::new()) {
                    Ok(d) => d,
                    Err(e) => {
                        debug!("[{tag}] zstd decoder init failed id={index}, err={e}");
                        let _ = quic_to_stream_tx.send(());
                        return;
                    }
                };

                loop {
                    let result = tokio::time::timeout(
                        Duration::from_millis(stream_timeout_ms),
                        quic_recv.read(&mut buffer),
                    )
                    .await;

                    match result {
                        Err(_) => {
                            let _ = quic_to_stream_tx.send(());
                            stream_to_quic_rx.await.ok();
                            break;
                        }
                        Ok(Err(_)) => {
                            let _ = quic_to_stream_tx.send(());
                            break;
                        }
                        Ok(Ok(None)) => {
                            let _ = IoWrite::flush(&mut decoder);
                            let _ = drain_decoder_to_stream(
                                &mut decoder,
                                &mut stream_write,
                                &mut transfer_bytes,
                            )
                            .await;
                            let _ = quic_to_stream_tx.send(());
                            break;
                        }
                        Ok(Ok(Some(len_read))) => {
                            zstd_stats_q2s.add_compressed(len_read);
                            if !decode_to_stream(
                                &mut decoder,
                                &buffer[..len_read],
                                &mut stream_write,
                                &mut transfer_bytes,
                            )
                            .await
                            {
                                let _ = quic_to_stream_tx.send(());
                                break;
                            }
                        }
                    }
                }
            } else {
                loop {
                    let result = Self::quic_to_stream(
                        &mut quic_recv,
                        &mut stream_write,
                        &mut buffer,
                        &mut transfer_bytes,
                        stream_timeout_ms,
                    )
                    .await;

                    match result {
                        Err(TransferError::TimeoutError) => {
                            let _ = quic_to_stream_tx.send(());
                            stream_to_quic_rx.await.ok();
                            break;
                        }
                        Ok(0) | Err(_) => {
                            let _ = quic_to_stream_tx.send(());
                            break;
                        }
                        _ => {}
                    }
                }
            }

            debug!(
                "[{tag}] stream close id={index}, peer={peer_addr}, dir=q2s, bytes={transfer_bytes}"
            );
        });

        // ── direction: TCP → QUIC (encode if zstd enabled) ──
        tokio::spawn(async move {
            let mut transfer_bytes = 0u64;
            let mut buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);

            if zstd_enabled {
                let mut encoder = match zstd::stream::write::Encoder::new(
                    Vec::new(),
                    zstd_config.level,
                ) {
                    Ok(e) => e,
                    Err(e) => {
                        debug!("[{tag}] zstd encoder init failed id={index}, err={e}");
                        let _ = stream_to_quic_tx.send(());
                        return;
                    }
                };
                if zstd_config.window_log > 0 {
                    let _ = encoder.window_log(zstd_config.window_log);
                }

                let flush_interval = Duration::from_millis(zstd_config.flush_interval_ms);
                let mut pending: usize = 0;

                loop {
                    let result =
                        tokio::time::timeout(flush_interval, stream_read.read(&mut buffer)).await;

                    match result {
                        Err(_) => {
                            // timeout: flush pending data if any
                            if pending > 0 {
                                if !flush_encoder_to_quic(&mut encoder, &mut quic_send, &zstd_stats)
                                    .await
                                {
                                    let _ = stream_to_quic_tx.send(());
                                    break;
                                }
                                pending = 0;
                            }
                        }
                        Ok(Err(_)) | Ok(Ok(0)) => {
                            let is_eof = matches!(result, Ok(Ok(0)));
                            let _ = finish_encoder_to_quic(&mut encoder, &mut quic_send, &zstd_stats)
                                .await;
                            if is_eof {
                                let _ = quic_send.finish();
                            }
                            let _ = stream_to_quic_tx.send(());
                            break;
                        }
                        Ok(Ok(len_read)) => {
                            zstd_stats.add_raw(len_read);
                            transfer_bytes += len_read as u64;
                            if IoWrite::write_all(&mut encoder, &buffer[..len_read]).is_err() {
                                let _ = stream_to_quic_tx.send(());
                                break;
                            }
                            pending += len_read;
                            if pending >= zstd_config.flush_size {
                                if !flush_encoder_to_quic(
                                    &mut encoder,
                                    &mut quic_send,
                                    &zstd_stats,
                                )
                                .await
                                {
                                    let _ = stream_to_quic_tx.send(());
                                    break;
                                }
                                pending = 0;
                            }
                        }
                    }
                }
            } else {
                loop {
                    let result = Self::stream_to_quic(
                        &mut stream_read,
                        &mut quic_send,
                        &mut buffer,
                        &mut transfer_bytes,
                        stream_timeout_ms,
                    )
                    .await;

                    match result {
                        Err(TransferError::TimeoutError) => {
                            let _ = stream_to_quic_tx.send(());
                            quic_to_stream_rx.await.ok();
                            break;
                        }
                        Ok(0) | Err(_) => {
                            let _ = stream_to_quic_tx.send(());
                            break;
                        }
                        _ => {}
                    }
                }
            }

            debug!(
                "[{tag}] stream close id={index}, peer={peer_addr}, dir=s2q, bytes={transfer_bytes}"
            );
            
        });
    }

    async fn stream_to_quic<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream_read: &mut ReadHalf<S>,
        quic_send: &mut SendStream,
        buffer: &mut [u8],
        transfer_bytes: &mut u64,
        stream_timeout_ms: u64,
    ) -> Result<usize, TransferError> {
        let len_read = tokio::time::timeout(
            Duration::from_millis(stream_timeout_ms),
            stream_read.read(buffer),
        )
        .await
        .map_err(|_: Elapsed| TransferError::TimeoutError)?
        .map_err(|_| TransferError::InternalError)?;
        if len_read > 0 {
            *transfer_bytes += len_read as u64;
            quic_send
                .write_all(&buffer[..len_read])
                .await
                .map_err(|_| TransferError::InternalError)?;
            Ok(len_read)
        } else {
            quic_send
                .finish()
                .map_err(|_| TransferError::InternalError)?;
            Ok(0)
        }
    }

    async fn quic_to_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        quic_recv: &mut RecvStream,
        stream_write: &mut WriteHalf<S>,
        buffer: &mut [u8],
        transfer_bytes: &mut u64,
        stream_timeout_ms: u64,
    ) -> Result<usize, TransferError> {
        let result = tokio::time::timeout(
            Duration::from_millis(stream_timeout_ms),
            quic_recv.read(buffer),
        )
        .await
        .map_err(|_: Elapsed| TransferError::TimeoutError)?
        .map_err(|_| TransferError::InternalError)?;
        if let Some(len_read) = result {
            *transfer_bytes += len_read as u64;
            stream_write
                .write_all(&buffer[..len_read])
                .await
                .map_err(|_| TransferError::InternalError)?;
            Ok(len_read)
        } else {
            stream_write
                .shutdown()
                .await
                .map_err(|_| TransferError::InternalError)?;
            Ok(0)
        }
    }

    /// Serializes a tunnel target into its wire bytes. Returns `None` when there
    /// is nothing to write (a `None` target with `mark_none == false`). Kept pure
    /// so it is unit-testable.
    ///
    /// Wire format:
    ///   family 4: [4][4-byte ipv4][2-byte port]
    ///   family 6: [6][16-byte ipv6][2-byte port]
    ///   family 3: [3][1-byte host len][host utf8][2-byte port]  (domain)
    ///   none + mark_none: [0]
    pub fn encode_tunnel_target(
        target: &Option<crate::TunnelTarget>,
        mark_none: bool,
    ) -> Result<Option<Vec<u8>>> {
        let buf = match target {
            Some(crate::TunnelTarget::Addr(SocketAddr::V4(v4))) => {
                let mut buf = Vec::with_capacity(1 + 4 + 2);
                buf.push(4);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
                buf
            }
            Some(crate::TunnelTarget::Addr(SocketAddr::V6(v6))) => {
                let mut buf = Vec::with_capacity(1 + 16 + 2);
                buf.push(6);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
                buf
            }
            Some(crate::TunnelTarget::Domain(host, port)) => {
                let host_bytes = host.as_bytes();
                if host_bytes.is_empty() || host_bytes.len() > u8::MAX as usize {
                    anyhow::bail!("invalid tunnel domain length: {}", host_bytes.len());
                }
                let mut buf = Vec::with_capacity(1 + 1 + host_bytes.len() + 2);
                buf.push(3);
                buf.push(host_bytes.len() as u8);
                buf.extend_from_slice(host_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
                buf
            }
            None => {
                if mark_none {
                    vec![0]
                } else {
                    return Ok(None);
                }
            }
        };
        Ok(Some(buf))
    }

    pub async fn write_tunnel_target(
        quic_send: &mut SendStream,
        target: &Option<crate::TunnelTarget>,
        mark_none: bool,
    ) -> Result<()> {
        if let Some(buf) = Self::encode_tunnel_target(target, mark_none)? {
            quic_send.write_all(&buf).await?;
        }
        Ok(())
    }

    pub async fn read_tunnel_target<R: AsyncRead + Unpin>(
        quic_recv: &mut R,
        stream_timeout_ms: u64,
    ) -> Result<crate::TunnelTarget, TransferError> {
        let timeout = Duration::from_millis(stream_timeout_ms);
        let family = Self::read_target_family(quic_recv, timeout).await?;
        Self::read_tunnel_target_body(quic_recv, family, timeout).await
    }

    /// Like `read_tunnel_target`, but a leading family byte of `0` (the
    /// `mark_none` sentinel produced by `encode_tunnel_target`) decodes to
    /// `None`. Used by the UDP relay, where a flow may target the server's
    /// configured default upstream instead of an explicit destination.
    pub async fn read_optional_tunnel_target<R: AsyncRead + Unpin>(
        quic_recv: &mut R,
        stream_timeout_ms: u64,
    ) -> Result<Option<crate::TunnelTarget>, TransferError> {
        let timeout = Duration::from_millis(stream_timeout_ms);
        let family = Self::read_target_family(quic_recv, timeout).await?;
        if family == 0 {
            return Ok(None);
        }
        Self::read_tunnel_target_body(quic_recv, family, timeout)
            .await
            .map(Some)
    }

    async fn read_target_family<R: AsyncRead + Unpin>(
        quic_recv: &mut R,
        timeout: Duration,
    ) -> Result<u8, TransferError> {
        let mut family = [0u8; 1];
        tokio::time::timeout(timeout, quic_recv.read_exact(&mut family))
            .await
            .map_err(|_: Elapsed| TransferError::TimeoutError)?
            .map_err(|_| TransferError::InternalError)?;
        Ok(family[0])
    }

    async fn read_tunnel_target_body<R: AsyncRead + Unpin>(
        quic_recv: &mut R,
        family: u8,
        timeout: Duration,
    ) -> Result<crate::TunnelTarget, TransferError> {
        match family {
            4 => {
                let mut buf = [0u8; 4 + 2];
                tokio::time::timeout(timeout, quic_recv.read_exact(&mut buf))
                    .await
                    .map_err(|_: Elapsed| TransferError::TimeoutError)?
                    .map_err(|_| TransferError::InternalError)?;
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Ok(crate::TunnelTarget::Addr(SocketAddr::new(
                    IpAddr::V4(ip),
                    port,
                )))
            }
            6 => {
                let mut buf = [0u8; 16 + 2];
                tokio::time::timeout(timeout, quic_recv.read_exact(&mut buf))
                    .await
                    .map_err(|_: Elapsed| TransferError::TimeoutError)?
                    .map_err(|_| TransferError::InternalError)?;
                let ip = Ipv6Addr::from([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                    buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
                ]);
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                Ok(crate::TunnelTarget::Addr(SocketAddr::new(
                    IpAddr::V6(ip),
                    port,
                )))
            }
            3 => {
                let mut len_buf = [0u8; 1];
                tokio::time::timeout(timeout, quic_recv.read_exact(&mut len_buf))
                    .await
                    .map_err(|_: Elapsed| TransferError::TimeoutError)?
                    .map_err(|_| TransferError::InternalError)?;
                let host_len = len_buf[0] as usize;
                let mut host_buf = vec![0u8; host_len];
                tokio::time::timeout(timeout, quic_recv.read_exact(&mut host_buf))
                    .await
                    .map_err(|_: Elapsed| TransferError::TimeoutError)?
                    .map_err(|_| TransferError::InternalError)?;
                let mut port_buf = [0u8; 2];
                tokio::time::timeout(timeout, quic_recv.read_exact(&mut port_buf))
                    .await
                    .map_err(|_: Elapsed| TransferError::TimeoutError)?
                    .map_err(|_| TransferError::InternalError)?;
                let host = String::from_utf8(host_buf)
                    .map_err(|_| TransferError::InvalidDomain)?;
                let port = u16::from_be_bytes(port_buf);
                Ok(crate::TunnelTarget::Domain(host, port))
            }
            _ => Err(TransferError::InvalidIPAddress),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TunnelTarget;

    async fn round_trip(target: TunnelTarget) -> TunnelTarget {
        let encoded = StreamUtil::encode_tunnel_target(&Some(target), false)
            .unwrap()
            .unwrap();
        let mut cursor = std::io::Cursor::new(encoded);
        StreamUtil::read_tunnel_target(&mut cursor, 5000)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn tunnel_target_round_trips_all_families() {
        let targets = [
            TunnelTarget::Addr("127.0.0.1:8080".parse().unwrap()),
            TunnelTarget::Addr("[::1]:443".parse().unwrap()),
            TunnelTarget::Domain("example.com".to_string(), 9999),
        ];
        for target in targets {
            let decoded = round_trip(target.clone()).await;
            assert_eq!(target, decoded);
        }
    }

    #[tokio::test]
    async fn read_optional_tunnel_target_decodes_none_and_targets() {
        // [0] → None
        let none_encoded = StreamUtil::encode_tunnel_target(&None, true)
            .unwrap()
            .unwrap();
        let mut cursor = std::io::Cursor::new(none_encoded);
        let decoded = StreamUtil::read_optional_tunnel_target(&mut cursor, 5000)
            .await
            .unwrap();
        assert!(decoded.is_none());

        // [4][127.0.0.1][8080] → Some(Addr)
        let addr = TunnelTarget::Addr("127.0.0.1:8080".parse().unwrap());
        let addr_encoded = StreamUtil::encode_tunnel_target(&Some(addr.clone()), false)
            .unwrap()
            .unwrap();
        let mut cursor = std::io::Cursor::new(addr_encoded);
        let decoded = StreamUtil::read_optional_tunnel_target(&mut cursor, 5000)
            .await
            .unwrap();
        assert_eq!(decoded, Some(addr));
    }

    #[test]
    fn encode_none_respects_mark_none() {
        // mark_none=false → None (nothing to write)
        assert!(StreamUtil::encode_tunnel_target(&None, false)
            .unwrap()
            .is_none());
        // mark_none=true → Some([0])
        let encoded = StreamUtil::encode_tunnel_target(&None, true)
            .unwrap()
            .unwrap();
        assert_eq!(encoded, vec![0]);
    }

    #[test]
    fn encode_rejects_empty_and_oversized_domain() {
        let empty = TunnelTarget::Domain(String::new(), 80);
        assert!(StreamUtil::encode_tunnel_target(&Some(empty), false).is_err());

        let oversized = TunnelTarget::Domain("a".repeat(256), 80);
        assert!(StreamUtil::encode_tunnel_target(&Some(oversized), false).is_err());
    }

    #[tokio::test]
    async fn read_rejects_unknown_family_and_zero_len_domain() {
        // unknown family byte
        let mut cursor = std::io::Cursor::new(vec![99u8]);
        let result = StreamUtil::read_tunnel_target(&mut cursor, 5000).await;
        assert!(result.is_err());

        // family=3, host_len=0
        let mut cursor = std::io::Cursor::new(vec![3u8, 0]);
        let result = StreamUtil::read_tunnel_target_body(&mut cursor, 3, Duration::from_secs(5))
            .await;
        assert!(result.is_err());
    }

    // ── zstd tests ──────────────────────────────────────────────────

    #[test]
    fn zstd_config_defaults() {
        let cfg = ZstdConfig::default();
        assert!(!cfg.enabled);

        let cfg = ZstdConfig::new(true, 0, 0, 0, 0);
        assert!(cfg.enabled);
        assert_eq!(cfg.level, 9);
        assert_eq!(cfg.window_log, 27);
        assert_eq!(cfg.flush_size, 8192);
        assert_eq!(cfg.flush_interval_ms, 100);
    }

    #[test]
    fn zstd_stats_tracking() {
        let stats = ZstdStats::new();
        assert_eq!(stats.raw_bytes(), 0);
        assert_eq!(stats.compressed_bytes(), 0);

        stats.add_raw(100);
        stats.add_raw(50);
        stats.add_compressed(30);

        assert_eq!(stats.raw_bytes(), 150);
        assert_eq!(stats.compressed_bytes(), 30);
    }

    #[test]
    fn zstd_stats_thread_safety() {
        let stats = Arc::new(ZstdStats::new());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let s = stats.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        s.add_raw(1);
                        s.add_compressed(1);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(stats.raw_bytes(), 4000);
        assert_eq!(stats.compressed_bytes(), 4000);
    }

    #[test]
    fn zstd_encode_decode_roundtrip() {
        let original = b"Hello, rstun zstd! This is a test payload.".repeat(100);

        let mut comp_buf = Vec::new();
        {
            let mut encoder = zstd::stream::write::Encoder::new(&mut comp_buf, 3).unwrap();
            IoWrite::write_all(&mut encoder, &original).unwrap();
            encoder.do_finish().unwrap();
        }

        assert!(comp_buf.len() < original.len());
        let decompressed = zstd::decode_all(comp_buf.as_slice()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn zstd_multi_flush_preserves_context() {
        let chunk_a: Vec<u8> = br#"{"id":"chunk_0","data":"AAAAAAAAAA"}"#.repeat(10);
        let chunk_b: Vec<u8> = br#"{"id":"chunk_1","data":"AAAAAAAAAA"}"#.repeat(10);
        let chunk_c: Vec<u8> = br#"{"id":"chunk_2","data":"AAAAAAAAAA"}"#.repeat(10);

        let mut comp_buf = Vec::new();
        {
            let mut encoder = zstd::stream::write::Encoder::new(&mut comp_buf, 3).unwrap();
            IoWrite::write_all(&mut encoder, &chunk_a).unwrap();
            IoWrite::flush(&mut encoder).unwrap();
            IoWrite::write_all(&mut encoder, &chunk_b).unwrap();
            IoWrite::flush(&mut encoder).unwrap();
            IoWrite::write_all(&mut encoder, &chunk_c).unwrap();
            encoder.do_finish().unwrap();
        }

        let expected = [chunk_a.as_slice(), chunk_b.as_slice(), chunk_c.as_slice()].concat();
        let decompressed = zstd::decode_all(comp_buf.as_slice()).unwrap();
        assert_eq!(decompressed, expected);

        let single_size = {
            let mut buf = Vec::new();
            let mut enc = zstd::stream::write::Encoder::new(&mut buf, 3).unwrap();
            IoWrite::write_all(&mut enc, &chunk_a).unwrap();
            enc.do_finish().unwrap();
            buf.len()
        };
        assert!(
            comp_buf.len() < single_size * 2,
            "cross-flush context not working: multi={} single={}",
            comp_buf.len(),
            single_size
        );
    }

    #[test]
    fn zstd_window_log_validation() {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
        assert!(encoder.window_log(21).is_ok());
        assert!(encoder.window_log(33).is_err());
    }
}
