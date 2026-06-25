use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use moka::sync::Cache;
use zstd::dict::{DecoderDictionary, EncoderDictionary};
use zstd::stream::write::{Decoder, Encoder};

/// A reusable zstd encoder + decoder pair keyed by a random 128-bit id.
///
/// The encoder and decoder each write into an internal `Vec<u8>` buffer.
/// After writing input data, the caller flushes (or drains) and takes the
/// buffer contents to send over the wire.
///
/// `errored` is set when a stream using this pair ends abnormally (read
/// error / timeout).  The next handshake that encounters this pair
/// observes `errored` and returns ack=0, forcing both sides to reset.
///
/// A pair is *checked out* (removed from the LRU) when a stream starts
/// using it, and *checked in* (re-inserted) when the stream ends normally.
/// This guarantees one encoder/decoder is only used by one stream at a time.
pub struct CodecPair {
    encoder: Mutex<Encoder<'static, Vec<u8>>>,
    decoder: Mutex<Decoder<'static, Vec<u8>>>,
    errored: AtomicBool,
    /// Held so we can reset encoder/decoder to fresh instances when the
    /// remote side returns ack=0.
    dict: Arc<CodecDict>,
    level: i32,
    /// Explicit window log (0 = follow level default).  Stored so
    /// reset_encoder / reset_decoder can re-apply the same setting.
    window_log: u32,
}

impl std::fmt::Debug for CodecPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodecPair")
            .field("errored", &self.errored.load(Ordering::Relaxed))
            .finish()
    }
}

impl CodecPair {
    /// Create a fresh pair.  When `dict` contains a dictionary, both
    /// encoder and decoder are seeded with it.  `window_log == 0` means
    /// "follow the level's default window log"; a non-zero value
    /// explicitly sets both encoder `WindowLog` and decoder `WindowLogMax`.
    fn new(dict: Arc<CodecDict>, level: i32, window_log: u32) -> io::Result<Self> {
        let encoder = make_encoder(&dict, level, window_log)?;
        let decoder = make_decoder(&dict, window_log)?;
        Ok(CodecPair {
            encoder: Mutex::new(encoder),
            decoder: Mutex::new(decoder),
            errored: AtomicBool::new(false),
            dict,
            level,
            window_log,
        })
    }

    pub fn is_errored(&self) -> bool {
        self.errored.load(Ordering::Relaxed)
    }

    /// Mark this pair as broken.  The next handshake that encounters it
    /// returns ack=0, and the pair is replaced with a fresh instance.
    pub fn mark_errored(&self) {
        self.errored.store(true, Ordering::Relaxed);
    }

    pub fn encoder(&self) -> MutexGuard<'_, Encoder<'static, Vec<u8>>> {
        self.encoder.lock().expect("encoder mutex poisoned")
    }

    pub fn decoder(&self) -> MutexGuard<'_, Decoder<'static, Vec<u8>>> {
        self.decoder.lock().expect("decoder mutex poisoned")
    }

    /// Reset the encoder to a fresh instance.  Used when the remote side
    /// returns ack=0 (it doesn't have our pair's history).
    pub fn reset_encoder(&self) -> io::Result<()> {
        let new_encoder = make_encoder(&self.dict, self.level, self.window_log)?;
        *self.encoder.lock().expect("encoder mutex poisoned") = new_encoder;
        Ok(())
    }

    /// Reset the decoder to a fresh instance.
    pub fn reset_decoder(&self) -> io::Result<()> {
        let new_decoder = make_decoder(&self.dict, self.window_log)?;
        *self.decoder.lock().expect("decoder mutex poisoned") = new_decoder;
        Ok(())
    }
}

fn make_encoder(
    dict: &CodecDict,
    level: i32,
    window_log: u32,
) -> io::Result<Encoder<'static, Vec<u8>>> {
    let mut enc = match &dict.enc {
        Some(ed) => Encoder::with_prepared_dictionary(Vec::new(), ed)?,
        None => Encoder::new(Vec::new(), level)?,
    };
    // Long-distance matching is always enabled — improves compression ratio
    // for tunnel traffic with repeated patterns at low memory cost.
    enc.long_distance_matching(true)?;
    if window_log != 0 {
        enc.window_log(window_log)?;
    }
    Ok(enc)
}

fn make_decoder(dict: &CodecDict, window_log: u32) -> io::Result<Decoder<'static, Vec<u8>>> {
    let mut dec = match &dict.dec {
        Some(dd) => Decoder::with_prepared_dictionary(Vec::new(), dd)?,
        None => Decoder::new(Vec::new())?,
    };
    if window_log != 0 {
        // Decoder must accept a window at least as large as the encoder's.
        dec.window_log_max(window_log)?;
    }
    Ok(dec)
}

/// Optional zstd dictionary shared by every pair in the table.
pub struct CodecDict {
    pub enc: Option<EncoderDictionary<'static>>,
    pub dec: Option<DecoderDictionary<'static>>,
}

impl CodecDict {
    /// No dictionary — plain zstd streams.
    pub fn none() -> Self {
        CodecDict {
            enc: None,
            dec: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.enc.is_none()
    }

    /// Load a dictionary from raw bytes at the given compression level.
    pub fn from_bytes(dict: &[u8], level: i32) -> Self {
        if dict.is_empty() {
            return Self::none();
        }
        CodecDict {
            enc: Some(EncoderDictionary::copy(dict, level)),
            dec: Some(DecoderDictionary::copy(dict)),
        }
    }
}

/// Thread-safe LRU table of codec pairs, keyed by a random `u128` id.
///
/// One instance is shared across all QUIC connections on a client (via
/// `Arc`), so compression context survives reconnection.
///
/// Uses moka for automatic TTL-based eviction (pairs idle for longer than
/// `ttl` are removed) plus a hard capacity limit as a safety net.
pub struct CodecLru {
    cache: Cache<u128, Arc<CodecPair>>,
    dict: Arc<CodecDict>,
    level: i32,
    window_log: u32,
}

impl std::fmt::Debug for CodecLru {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodecLru")
            .field("pairs", &self.cache.entry_count())
            .field("level", &self.level)
            .field("has_dict", &!self.dict.is_empty())
            .finish()
    }
}

/// Outcome of looking up a pair id during handshake.
pub enum LookupResult {
    /// The pair exists and is healthy — reuse it (ack = id).
    Hit { id: u128, pair: Arc<CodecPair> },
    /// The pair does not exist, or exists but is errored.
    /// A fresh pair has been created (ack = 0).
    Miss { id: u128, pair: Arc<CodecPair> },
}

impl CodecLru {
    pub fn new(
        capacity: usize,
        dict: Arc<CodecDict>,
        level: i32,
        window_log: u32,
        ttl_secs: u64,
    ) -> io::Result<Self> {
        let cache = Cache::builder()
            .max_capacity(capacity as u64)
            .time_to_idle(Duration::from_secs(ttl_secs))
            .build();

        Ok(CodecLru {
            cache,
            dict,
            level,
            window_log,
        })
    }

    /// Check out a pair for use by a stream.  This removes the pair from
    /// the cache, guaranteeing exclusive access.
    ///
    /// Returns `(id, pair)` where `id=0` means a freshly created pair
    /// (no history) and `id!=0` means a reused pair with history.
    pub fn checkout(&self) -> io::Result<(u128, Arc<CodecPair>)> {
        // Try to find a healthy pair to reuse.
        let mut reuse_id: Option<u128> = None;
        for (id, pair) in self.cache.iter() {
            if !pair.is_errored() {
                reuse_id = Some(*id);
                break;
            }
        }

        if let Some(id) = reuse_id
            && let Some(pair) = self.cache.remove(&id)
        {
            // Double-check after removal — it may have been marked
            // errored between the scan and removal.
            if !pair.is_errored() {
                return Ok((id, pair));
            }
            // errored — fall through to create fresh
        }

        // Create a new pair with a random id.
        let id = rand_id();
        let pair = Arc::new(CodecPair::new(
            self.dict.clone(),
            self.level,
            self.window_log,
        )?);
        Ok((id, pair))
    }

    /// Look up a pair by id during handshake.  Used by the receiver side.
    ///
    /// - If the pair exists and is healthy: checkout (remove) and return Hit.
    /// - If it doesn't exist or is errored: create fresh, return Miss (ack=0).
    pub fn lookup(&self, id: u128) -> io::Result<LookupResult> {
        if id == 0 {
            let pair = Arc::new(CodecPair::new(
                self.dict.clone(),
                self.level,
                self.window_log,
            )?);
            return Ok(LookupResult::Miss { id, pair });
        }

        if let Some(pair) = self.cache.remove(&id)
            && !pair.is_errored()
        {
            return Ok(LookupResult::Hit { id, pair });
        }
        // errored — fall through to create fresh

        let pair = Arc::new(CodecPair::new(
            self.dict.clone(),
            self.level,
            self.window_log,
        )?);
        Ok(LookupResult::Miss { id, pair })
    }

    /// Check in a pair after normal stream completion.  Re-inserts it
    /// into the cache for future reuse.
    pub fn checkin(&self, id: u128, pair: Arc<CodecPair>) {
        if id == 0 || pair.is_errored() {
            // Don't re-insert fresh (id=0) or errored pairs.
            // id=0 pairs are one-shot; errored pairs are discarded.
            return;
        }
        self.cache.insert(id, pair);
    }

    /// Number of pairs currently cached.
    pub fn len(&self) -> u64 {
        self.cache.entry_count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Generate a random 128-bit id.  Uses a simple xorshift seeded from
/// thread-local state + wall time.  Returns 0 with negligible probability.
fn rand_id() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    let tid_hash = format!("{:?}", std::thread::current().id())
        .bytes()
        .fold(0u128, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u128));
    let mut x = now ^ tid_hash.rotate_left(37);
    // xorshift128-style
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    if x == 0 { 1 } else { x }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_dict() -> Arc<CodecDict> {
        Arc::new(CodecDict::none())
    }

    #[test]
    fn pair_compress_decompress_roundtrip_no_dict() {
        let pair = CodecPair::new(make_dict(), 3, 0).unwrap();
        let data = b"Hello, zstd! Hello, zstd! Hello, zstd!".repeat(10);

        {
            let mut enc = pair.encoder();
            enc.write_all(&data).unwrap();
            enc.flush().unwrap();
        }
        let compressed = {
            let mut enc = pair.encoder();
            std::mem::take(enc.get_mut())
        };

        {
            let mut dec = pair.decoder();
            dec.write_all(&compressed).unwrap();
            dec.flush().unwrap();
        }
        let decompressed = {
            let mut dec = pair.decoder();
            std::mem::take(dec.get_mut())
        };

        assert_eq!(decompressed, data);
    }

    #[test]
    fn pair_compress_decompress_roundtrip_with_dict() {
        let one = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let samples: Vec<&[u8]> = vec![one; 20];
        let dict_bytes = zstd::dict::from_samples(&samples, 4096).unwrap();
        let dict = Arc::new(CodecDict::from_bytes(&dict_bytes, 3));
        let pair = CodecPair::new(dict, 3, 0).unwrap();
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".repeat(5);

        {
            let mut enc = pair.encoder();
            enc.write_all(&data).unwrap();
            enc.flush().unwrap();
        }
        let compressed = {
            let mut enc = pair.encoder();
            std::mem::take(enc.get_mut())
        };

        {
            let mut dec = pair.decoder();
            dec.write_all(&compressed).unwrap();
            dec.flush().unwrap();
        }
        let decompressed = {
            let mut dec = pair.decoder();
            std::mem::take(dec.get_mut())
        };

        assert_eq!(decompressed.as_slice(), data.as_slice());
    }

    #[test]
    fn pair_reset_encoder_produces_valid_stream() {
        // After reset, the encoder should produce a valid standalone zstd
        // stream that a fresh decoder can decode (no back-refs to old data).
        let pair = CodecPair::new(make_dict(), 3, 0).unwrap();

        // Write some data to give the encoder history.
        {
            let mut enc = pair.encoder();
            enc.write_all(b"some old data").unwrap();
            enc.flush().unwrap();
            let _ = std::mem::take(enc.get_mut());
        }

        // Reset encoder.
        pair.reset_encoder().unwrap();

        // Write new data — should be decodable by a fresh decoder.
        let new_data = b"completely new data after reset".repeat(3);
        {
            let mut enc = pair.encoder();
            enc.write_all(&new_data).unwrap();
            enc.flush().unwrap();
        }
        let compressed = {
            let mut enc = pair.encoder();
            std::mem::take(enc.get_mut())
        };

        // Decode with a fresh decoder (reset too).
        pair.reset_decoder().unwrap();
        {
            let mut dec = pair.decoder();
            dec.write_all(&compressed).unwrap();
            dec.flush().unwrap();
        }
        let decompressed = {
            let mut dec = pair.decoder();
            std::mem::take(dec.get_mut())
        };

        assert_eq!(decompressed.as_slice(), new_data.as_slice());
    }

    #[test]
    fn lru_checkout_creates_fresh_pair() {
        let lru = CodecLru::new(4, std::sync::Arc::new(CodecDict::none()), 3, 0, 3600).unwrap();
        let (_id, _pair) = lru.checkout().unwrap();
        assert!(!lru.cache.contains_key(&_id)); // checked out (not in cache)
    }

    #[test]
    fn lru_checkin_then_checkout_reuses() {
        let lru = CodecLru::new(4, std::sync::Arc::new(CodecDict::none()), 3, 0, 3600).unwrap();

        let (id, pair) = lru.checkout().unwrap();
        lru.checkin(id, pair);
        lru.cache.run_pending_tasks();
        assert!(lru.cache.contains_key(&id));

        let (id2, _) = lru.checkout().unwrap();
        assert_eq!(id, id2); // reused
        assert!(!lru.cache.contains_key(&id)); // checked out again
    }

    #[test]
    fn lru_lookup_miss_creates_pair() {
        let lru = CodecLru::new(4, std::sync::Arc::new(CodecDict::none()), 3, 0, 3600).unwrap();
        let result = lru.lookup(42).unwrap();
        assert!(matches!(result, LookupResult::Miss { .. }));
    }

    #[test]
    fn lru_lookup_hit_returns_same_pair() {
        let lru = CodecLru::new(4, std::sync::Arc::new(CodecDict::none()), 3, 0, 3600).unwrap();

        let (id, pair) = lru.checkout().unwrap();
        lru.checkin(id, pair);

        let result = lru.lookup(id).unwrap();
        match result {
            LookupResult::Hit { id: hit_id, .. } => assert_eq!(hit_id, id),
            _ => panic!("expected hit"),
        }
    }

    #[test]
    fn lru_errored_pair_returns_miss() {
        let lru = CodecLru::new(4, std::sync::Arc::new(CodecDict::none()), 3, 0, 3600).unwrap();

        let (id, pair) = lru.checkout().unwrap();
        pair.mark_errored();
        lru.checkin(id, pair); // should NOT be re-inserted (errored)

        assert_eq!(lru.len(), 0);

        let result = lru.lookup(id).unwrap();
        assert!(matches!(result, LookupResult::Miss { .. }));
    }

    #[test]
    fn lru_lookup_id_zero_always_miss() {
        let lru = CodecLru::new(4, std::sync::Arc::new(CodecDict::none()), 3, 0, 3600).unwrap();
        let result = lru.lookup(0).unwrap();
        assert!(matches!(result, LookupResult::Miss { .. }));
    }

    #[test]
    fn rand_id_never_zero() {
        for _ in 0..1000 {
            let id = rand_id();
            assert_ne!(id, 0, "rand_id returned 0");
        }
    }

    #[tokio::test]
    async fn lru_ttl_evicts_idle_pair() {
        let lru = CodecLru::new(4, std::sync::Arc::new(CodecDict::none()), 3, 0, 1).unwrap();

        let (id, pair) = lru.checkout().unwrap();
        lru.checkin(id, pair);
        lru.cache.run_pending_tasks();
        assert!(lru.cache.contains_key(&id));

        // Wait for TTL to expire.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        // moka runs eviction asynchronously; trigger a sync.
        lru.cache.run_pending_tasks();

        // The pair should be evicted.
        assert!(
            !lru.cache.contains_key(&id),
            "pair should have been evicted by TTL"
        );
    }

    #[test]
    fn pair_with_explicit_window_log_roundtrip() {
        // window_log=20 (1MB window) should produce a valid roundtrip
        // with an encoder that explicitly sets WindowLog and a decoder
        // that sets WindowLogMax.
        let pair = CodecPair::new(make_dict(), 9, 20).unwrap();
        let data = b"window log test data, repeated for compression ".repeat(50);

        {
            let mut enc = pair.encoder();
            enc.write_all(&data).unwrap();
            enc.flush().unwrap();
        }
        let compressed = {
            let mut enc = pair.encoder();
            std::mem::take(enc.get_mut())
        };

        {
            let mut dec = pair.decoder();
            dec.write_all(&compressed).unwrap();
            dec.flush().unwrap();
        }
        let decompressed = {
            let mut dec = pair.decoder();
            std::mem::take(dec.get_mut())
        };

        assert_eq!(decompressed, data);
    }

    #[test]
    fn pair_window_log_zero_uses_level_default() {
        // window_log=0 must not call set_parameter; the encoder should
        // still work with zstd's level-derived defaults.
        let pair = CodecPair::new(make_dict(), 9, 0).unwrap();
        let data = b"zero window log should be fine ".repeat(50);

        {
            let mut enc = pair.encoder();
            enc.write_all(&data).unwrap();
            enc.flush().unwrap();
        }
        let compressed = {
            let mut enc = pair.encoder();
            std::mem::take(enc.get_mut())
        };
        assert!(!compressed.is_empty());

        {
            let mut dec = pair.decoder();
            dec.write_all(&compressed).unwrap();
            dec.flush().unwrap();
        }
        let decompressed = {
            let mut dec = pair.decoder();
            std::mem::take(dec.get_mut())
        };

        assert_eq!(decompressed, data);
    }

    #[test]
    fn pair_reset_preserves_window_log() {
        // After reset_encoder/reset_decoder, the same window_log must
        // be re-applied (reset uses self.window_log).
        let pair = CodecPair::new(make_dict(), 9, 22).unwrap();
        let old_data = b"old data to seed history ".repeat(10);
        {
            let mut enc = pair.encoder();
            enc.write_all(&old_data).unwrap();
            enc.flush().unwrap();
            let _ = std::mem::take(enc.get_mut());
        }

        pair.reset_encoder().unwrap();
        pair.reset_decoder().unwrap();

        let new_data = b"new data after reset, must decode standalone ".repeat(10);
        {
            let mut enc = pair.encoder();
            enc.write_all(&new_data).unwrap();
            enc.flush().unwrap();
        }
        let compressed = {
            let mut enc = pair.encoder();
            std::mem::take(enc.get_mut())
        };

        {
            let mut dec = pair.decoder();
            dec.write_all(&compressed).unwrap();
            dec.flush().unwrap();
        }
        let decompressed = {
            let mut dec = pair.decoder();
            std::mem::take(dec.get_mut())
        };

        assert_eq!(decompressed.as_slice(), new_data.as_slice());
    }

    #[test]
    fn lru_passes_window_log_to_pairs() {
        // CodecLru::new must propagate window_log to freshly created pairs.
        // We can't directly read the encoder's WindowLog, but we can verify
        // that a pair created with window_log=28 roundtrips (would fail if
        // decoder's WindowLogMax weren't set to match).
        let lru = CodecLru::new(4, std::sync::Arc::new(CodecDict::none()), 9, 28, 3600).unwrap();

        let (_id, pair) = lru.checkout().unwrap();

        // Large-ish data to exercise the 256MB window.
        let data = b"LDM window propagation test chunk ".repeat(1000);
        {
            let mut enc = pair.encoder();
            enc.write_all(&data).unwrap();
            enc.flush().unwrap();
        }
        let compressed = {
            let mut enc = pair.encoder();
            std::mem::take(enc.get_mut())
        };
        assert!(!compressed.is_empty());

        {
            let mut dec = pair.decoder();
            dec.write_all(&compressed).unwrap();
            dec.flush().unwrap();
        }
        let decompressed = {
            let mut dec = pair.decoder();
            std::mem::take(dec.get_mut())
        };

        assert_eq!(decompressed, data);
    }

    #[test]
    fn codec_config_default_values() {
        let cfg = crate::codec::CodecConfig::default();
        assert_eq!(cfg.level, 9);
        assert_eq!(cfg.window_log, 24);
        assert_eq!(cfg.flush_interval_ms, 150);
        assert_eq!(cfg.pair_ttl_secs, 5 * 3600);
        assert!(!cfg.enabled);
        assert!(!cfg.http_aware);
    }
}
