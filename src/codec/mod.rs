pub mod handshake;
pub mod http;
pub mod lru;

use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::codec::lru::{CodecDict, CodecLru};
use crate::tcp::AsyncStream;
use crate::util::stream_util::StreamUtil;
use log::{debug, info, warn};
use quinn::{RecvStream, SendStream};
use std::time::Duration;

/// Per-stream compression statistics, shared between encoder and decoder tasks.
/// All fields are atomic so they can be updated from separate tokio tasks
/// without a mutex.
#[derive(Debug, Default)]
pub struct CodecStats {
    /// s2q: raw bytes read from local stream (before compression).
    pub s2q_raw: AtomicU64,
    /// s2q: compressed bytes written to QUIC (after compression).
    pub s2q_compressed: AtomicU64,
    /// q2s: compressed bytes read from QUIC (before decompression).
    pub q2s_compressed: AtomicU64,
    /// q2s: decompressed bytes written to local stream (after decompression).
    pub q2s_decompressed: AtomicU64,
}

impl CodecStats {
    /// Format a one-line summary of the current stats, with human-readable
    /// byte counts and compression ratios.
    pub fn summary(&self) -> String {
        let s2q_raw = self.s2q_raw.load(Ordering::Relaxed);
        let s2q_comp = self.s2q_compressed.load(Ordering::Relaxed);
        let q2s_comp = self.q2s_compressed.load(Ordering::Relaxed);
        let q2s_decomp = self.q2s_decompressed.load(Ordering::Relaxed);

        let s2q_ratio = if s2q_raw > 0 {
            s2q_comp as f64 / s2q_raw as f64 * 100.0
        } else {
            0.0
        };
        let q2s_ratio = if q2s_comp > 0 {
            q2s_decomp as f64 / q2s_comp as f64 * 100.0
        } else {
            0.0
        };
        format!(
            "s2q_raw={}, s2q_compressed={}, s2q_ratio={:.1}%, q2s_compressed={}, q2s_decompressed={}, q2s_ratio={:.1}%",
            crate::human_readable_bytes(s2q_raw),
            crate::human_readable_bytes(s2q_comp),
            s2q_ratio,
            crate::human_readable_bytes(q2s_comp),
            crate::human_readable_bytes(q2s_decomp),
            q2s_ratio
        )
    }
}

/// Configuration for the zstd codec middleware.
///
/// When `enabled` is false, `start_flowing_with_codec` delegates to the
/// existing `StreamUtil::start_flowing` with zero overhead.
pub struct CodecConfig {
    pub enabled: bool,
    pub http_aware: bool,
    pub level: i32,
    pub window_log: u32,
    pub pair_ttl_secs: u64,
    pub flush_interval_ms: u64,
    /// Shared LRU table, lazily initialized on first use.
    lru: Arc<tokio::sync::OnceCell<Arc<CodecLru>>>,
    dict: std::sync::Arc<CodecDict>,
}

impl Clone for CodecConfig {
    fn clone(&self) -> Self {
        CodecConfig {
            enabled: self.enabled,
            http_aware: self.http_aware,
            level: self.level,
            window_log: self.window_log,
            pair_ttl_secs: self.pair_ttl_secs,
            flush_interval_ms: self.flush_interval_ms,
            lru: self.lru.clone(),
            dict: self.dict.clone(),
        }
    }
}

impl std::fmt::Debug for CodecConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodecConfig")
            .field("enabled", &self.enabled)
            .field("http_aware", &self.http_aware)
            .field("level", &self.level)
            .field("window_log", &self.window_log)
            .field("pair_ttl_secs", &self.pair_ttl_secs)
            .field("flush_interval_ms", &self.flush_interval_ms)
            .field("has_dict", &!self.dict.is_empty())
            .finish()
    }
}

impl Default for CodecConfig {
    fn default() -> Self {
        CodecConfig {
            enabled: false,
            http_aware: false,
            level: 9,
            window_log: 24,
            pair_ttl_secs: 5 * 3600,
            flush_interval_ms: 150,
            lru: Arc::new(tokio::sync::OnceCell::new()),
            dict: std::sync::Arc::new(CodecDict::none()),
        }
    }
}

impl CodecConfig {
    /// Create a new codec configuration.
    pub fn new(
        enabled: bool,
        http_aware: bool,
        level: i32,
        window_log: u32,
        pair_ttl_secs: u64,
        flush_interval_ms: u64,
    ) -> Self {
        CodecConfig {
            enabled,
            http_aware,
            level,
            window_log,
            pair_ttl_secs,
            flush_interval_ms,
            lru: Arc::new(tokio::sync::OnceCell::new()),
            dict: std::sync::Arc::new(CodecDict::none()),
        }
    }
    /// Load a dictionary from raw bytes.  Must be called before the first
    /// stream is opened (before the LRU is lazily initialized).
    pub fn with_dictionary(mut self, dict: &[u8]) -> Self {
        if !dict.is_empty() {
            self.dict = std::sync::Arc::new(CodecDict::from_bytes(dict, self.level));
        }
        self
    }

    /// Get the shared LRU table, initializing it on first access.
    pub async fn lru(&self) -> Result<Arc<CodecLru>> {
        let lru = self
            .lru
            .get_or_try_init(|| async {
                Ok::<_, std::io::Error>(Arc::new(CodecLru::new(
                    256,
                    self.dict.clone(),
                    self.level,
                    self.window_log,
                    self.pair_ttl_secs,
                )?))
            })
            .await?;
        Ok(lru.clone())
    }
}

/// Entry point for compressed stream flowing.
///
/// When `codec.enabled` is false, delegates to `StreamUtil::start_flowing`
/// with identical behavior — the codec layer is a no-op.
///
/// When enabled:
///   1. Perform bidirectional pair_id/ack handshake on the quic stream.
///   2. Resolve encoder/decoder pair (reuse or reset based on ack).
///   3. Spawn s2q and q2s tasks with zstd compression/decompression.
pub fn start_flowing_with_codec<S: AsyncStream>(
    tag: &'static str,
    stream: S,
    quic_stream: (SendStream, RecvStream),
    stream_timeout_ms: u64,
    codec: CodecConfig,
) {
    if !codec.enabled {
        StreamUtil::start_flowing(tag, stream, quic_stream, stream_timeout_ms);
        return;
    }

    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("[{tag}] peer address unavailable, err={e}");
            return;
        }
    };

    let (stream_read, stream_write) = tokio::io::split(stream);
    let (mut quic_send, mut quic_recv) = quic_stream;
    let index = quic_send.id().index();

    debug!("[{tag}] codec stream open id={index}, peer={peer_addr}");

    tokio::spawn(async move {
        let lru = match codec.lru().await {
            Ok(lru) => lru,
            Err(e) => {
                warn!("[{tag}] failed to init codec LRU, err={e}");
                return;
            }
        };

        // Synchronous handshake before splitting into data tasks.
        let handshake_result =
            handshake::exchange_pair_id(&mut quic_send, &mut quic_recv, &lru, stream_timeout_ms)
                .await;

        let resolved = match handshake_result {
            Ok(r) => r,
            Err(e) => {
                warn!("[{tag}] codec handshake failed id={index}, err={e}");
                return;
            }
        };

        debug!(
            "[{tag}] codec handshake done id={index}, s2q_ack={}, q2s_ack={}",
            resolved.s2q_ack != 0,
            resolved.q2s_ack != 0
        );

        let (s2q_pair, q2s_pair) = (resolved.s2q_pair, resolved.q2s_pair);
        let s2q_id = resolved.s2q_id;
        let q2s_id = resolved.q2s_id;
        let flush_interval = Duration::from_millis(codec.flush_interval_ms);
        let http_aware = codec.http_aware;
        let stats = Arc::new(CodecStats::default());

        // Periodic compression stats report (every 10s).
        let stats_for_timer = stats.clone();
        let timer_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                debug!(
                    "[{tag}] codec stats id={index}, {}",
                    stats_for_timer.summary()
                );
            }
        });
        // s2q task: stream_read → encoder → quic_send
        let lru_for_s2q = lru.clone();
        let stats_for_s2q = stats.clone();
        let s2q_handle = tokio::spawn(async move {
            let mut stream_read = stream_read;
            let mut quic_send = quic_send;
            let pair = s2q_pair.clone();
            let result = run_encoder(
                tag,
                &mut stream_read,
                &mut quic_send,
                pair,
                stream_timeout_ms,
                flush_interval,
                http_aware,
                &stats_for_s2q,
            )
            .await;
            // Signal end of stream on the quic send side.
            quic_send.finish().ok();
            match result {
                Ok(false) => lru_for_s2q.checkin(s2q_id, s2q_pair.clone()),
                Ok(true) | Err(_) => s2q_pair.mark_errored(),
            }
            debug!("[{tag}] s2q task done id={index}");
        });

        // q2s task: quic_recv → decoder → stream_write
        let lru_for_q2s = lru.clone();
        let stats_for_q2s = stats.clone();
        let q2s_handle = tokio::spawn(async move {
            let mut quic_recv = quic_recv;
            let mut stream_write = stream_write;
            let pair = q2s_pair.clone();
            let result = run_decoder(
                tag,
                &mut quic_recv,
                &mut stream_write,
                pair,
                stream_timeout_ms,
                &stats_for_q2s,
            )
            .await;
            match result {
                Ok(false) => lru_for_q2s.checkin(q2s_id, q2s_pair.clone()),
                Ok(true) | Err(_) => q2s_pair.mark_errored(),
            }
            debug!("[{tag}] q2s task done id={index}");
        });

        // Wait for both directions to finish.
        let _ = s2q_handle.await;
        let _ = q2s_handle.await;
        timer_handle.abort();
        info!(
            "[{tag}] codec stream close id={index}, peer={peer_addr}, {}",
            stats.summary()
        );
    });
}

/// Run the encoder loop: read from `reader`, compress, write to `writer`.
///
/// Returns `Ok(false)` on clean EOF, `Ok(true)` on timeout.
#[allow(clippy::too_many_arguments)]
async fn run_encoder<R, W>(
    tag: &str,
    reader: &mut R,
    writer: &mut W,
    pair: std::sync::Arc<crate::codec::lru::CodecPair>,
    stream_timeout_ms: u64,
    flush_interval: Duration,
    http_aware: bool,
    stats: &CodecStats,
) -> Result<bool>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut buf = vec![0u8; crate::STREAM_IO_BUFFER_SIZE];
    let mut http_reader = if http_aware {
        Some(http::HttpMessageReader::new())
    } else {
        None
    };

    loop {
        if let Some(hr) = http_reader.as_mut() {
            // HTTP mode: read a complete message (headers + body).
            match hr.read_message(reader, stream_timeout_ms).await {
                Ok(http::HttpReadResult::Message(data)) => {
                    if data.is_empty() {
                        // clean EOF
                        flush_encoder(&pair, writer, stats).await?;
                        return Ok(false);
                    }
                    stats
                        .s2q_raw
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    write_compressed(&pair, writer, &data, stats).await?;
                }
                Ok(http::HttpReadResult::NeedMore) => continue,
                Err(e) => {
                    warn!("[{tag}] http read failed, err={e}");
                    return Err(e);
                }
            }
        } else {
            // Basic zstd mode: drain with flush timer.
            tokio::select! {
                result = tokio::time::timeout(
                    Duration::from_millis(stream_timeout_ms),
                    reader.read(&mut buf),
                ) => {
                    match result {
                        Ok(Ok(0)) => {
                            flush_encoder(&pair, writer, stats).await?;
                            return Ok(false);
                        }
                        Ok(Ok(n)) => {
                        stats.s2q_raw.fetch_add(n as u64, Ordering::Relaxed);
                        write_compressed(&pair, writer, &buf[..n], stats).await?;
                        }
                        Ok(Err(e)) => {
                            warn!("[{tag}] stream read failed, err={e}");
                            return Err(e.into());
                        }
                        Err(_) => return Ok(true), // timeout
                    }
                }
                _ = tokio::time::sleep(flush_interval) => {
                    flush_encoder(&pair, writer, stats).await?;
                }
            }
        }
    }
}

/// Write data through the encoder and drain compressed output to `writer`.
async fn write_compressed<W>(
    pair: &std::sync::Arc<crate::codec::lru::CodecPair>,
    writer: &mut W,
    data: &[u8],
    stats: &CodecStats,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use std::io::Write;
    use tokio::io::AsyncWriteExt;

    // Synchronous: encode and take produced bytes, releasing the guard.
    let produced = {
        let mut enc = pair.encoder();
        enc.write_all(data)?;
        std::mem::take(enc.get_mut())
    };
    // Async: write without holding the guard.
    if !produced.is_empty() {
        stats
            .s2q_compressed
            .fetch_add(produced.len() as u64, Ordering::Relaxed);
        writer.write_all(&produced).await?;
    }
    Ok(())
}

/// Force flush the encoder and drain remaining output.
async fn flush_encoder<W>(
    pair: &std::sync::Arc<crate::codec::lru::CodecPair>,
    writer: &mut W,
    stats: &CodecStats,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use std::io::Write;
    use tokio::io::AsyncWriteExt;

    let produced = {
        let mut enc = pair.encoder();
        enc.flush()?;
        std::mem::take(enc.get_mut())
    };
    if !produced.is_empty() {
        stats
            .s2q_compressed
            .fetch_add(produced.len() as u64, Ordering::Relaxed);
        writer.write_all(&produced).await?;
    }
    Ok(())
}

/// Run the decoder loop: read from `reader`, decompress, write to `writer`.
async fn run_decoder<R, W>(
    tag: &str,
    reader: &mut R,
    writer: &mut W,
    pair: std::sync::Arc<crate::codec::lru::CodecPair>,
    stream_timeout_ms: u64,
    stats: &CodecStats,
) -> Result<bool>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use std::io::Write;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; crate::STREAM_IO_BUFFER_SIZE];

    loop {
        let result = tokio::time::timeout(
            Duration::from_millis(stream_timeout_ms),
            reader.read(&mut buf),
        )
        .await;

        match result {
            Ok(Ok(0)) => {
                let produced = {
                    let mut dec = pair.decoder();
                    dec.flush()?;
                    std::mem::take(dec.get_mut())
                };
                if !produced.is_empty() {
                    stats
                        .q2s_decompressed
                        .fetch_add(produced.len() as u64, Ordering::Relaxed);
                    writer.write_all(&produced).await?;
                }
                writer.shutdown().await?;
                return Ok(false);
            }
            Ok(Ok(n)) => {
                stats.q2s_compressed.fetch_add(n as u64, Ordering::Relaxed);
                let produced = {
                    let mut dec = pair.decoder();
                    dec.write_all(&buf[..n])?;
                    dec.flush()?;
                    std::mem::take(dec.get_mut())
                };
                if !produced.is_empty() {
                    stats
                        .q2s_decompressed
                        .fetch_add(produced.len() as u64, Ordering::Relaxed);
                    writer.write_all(&produced).await?;
                }
            }
            Ok(Err(e)) => {
                warn!("[{tag}] quic read failed, err={e}");
                return Err(e.into());
            }
            Err(_) => return Ok(true), // timeout
        }
    }
}
