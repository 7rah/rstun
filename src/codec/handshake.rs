use std::sync::Arc;

use crate::codec::lru::{CodecLru, CodecPair, LookupResult};
use anyhow::{Context, Result};
use log::debug;
use quinn::{RecvStream, SendStream};
use std::time::Duration;

/// Pair id size on the wire: 16 bytes.
pub const PAIR_ID_SIZE: usize = 16;

/// Result of a completed handshake: the resolved encoder/decoder pairs
/// for both directions, plus the ids/acks for diagnostics and checkin.
pub struct HandshakeResult {
    /// Pair used for s2q direction (local encoder → remote decoder).
    pub s2q_pair: Arc<CodecPair>,
    /// Pair used for q2s direction (remote encoder → local decoder).
    pub q2s_pair: Arc<CodecPair>,
    /// The id we sent for s2q (0 = fresh, nonzero = reused).
    pub s2q_id: u128,
    /// The ack we received for s2q (0 = remote was fresh, nonzero = reused).
    pub s2q_ack: u128,
    /// The id we received for q2s (0 = remote fresh, nonzero = remote reused).
    pub q2s_id: u128,
    /// The ack we sent for q2s (0 = we were fresh, nonzero = we reused).
    pub q2s_ack: u128,
}

/// Perform the bidirectional pair_id/ack handshake.
///
/// Wire protocol per direction:
///   Sender → Receiver: [16B id]   (id=0 means fresh, nonzero means has history)
///   Receiver → Sender: [16B ack]  (ack=id means hit, ack=0 means miss)
///
/// Both directions run in parallel.  The handshake is synchronous (both
/// sides hold quic_send + quic_recv) and must complete before spawning
/// data-transfer tasks.
///
/// After the handshake, if the remote says ack=0 for our s2q pair, we
/// reset our encoder to a fresh state (no back-references to old data)
/// so the remote's fresh decoder can decode our output.
///
/// Similarly, if we returned ack=0 for the remote's q2s pair (Miss),
/// we reset our decoder to fresh state.
///
/// `stream_timeout_ms` bounds each phase of the handshake.
pub async fn exchange_pair_id(
    quic_send: &mut SendStream,
    quic_recv: &mut RecvStream,
    lru: &Arc<CodecLru>,
    stream_timeout_ms: u64,
) -> Result<HandshakeResult> {
    let timeout = Duration::from_millis(stream_timeout_ms);

    // --- Phase 1: pick our pair (for s2q direction) and send its id ---
    let (s2q_id, s2q_pair) = lru.checkout().context("failed to checkout codec pair")?;

    let s2q_id_bytes = s2q_id.to_be_bytes();
    let id_send = async {
        tokio::time::timeout(timeout, quic_send.write_all(&s2q_id_bytes))
            .await
            .context("timeout sending local pair id")?
            .context("send local pair id failed")
    };

    // --- Phase 2: read remote's id (for q2s direction) ---
    let mut remote_id_bytes = [0u8; PAIR_ID_SIZE];
    let id_recv = async {
        tokio::time::timeout(timeout, quic_recv.read_exact(&mut remote_id_bytes))
            .await
            .context("timeout reading remote pair id")?
            .context("read remote pair id failed")
    };

    let (send_res, recv_res) = tokio::join!(id_send, id_recv);
    send_res?;
    recv_res?;

    let q2s_id = u128::from_be_bytes(remote_id_bytes);

    // --- Phase 3: look up remote's id and determine ack ---
    let lookup = lru.lookup(q2s_id).context("failed to lookup remote pair")?;
    let (q2s_pair, q2s_ack) = match lookup {
        LookupResult::Hit { id, pair } => (pair, id), // ack = id (reuse)
        LookupResult::Miss { pair, .. } => (pair, 0u128), // ack = 0 (reset)
    };

    // If we got a Miss, reset our decoder so it starts fresh — matching
    // the remote's fresh encoder.
    if q2s_ack == 0 {
        q2s_pair
            .reset_decoder()
            .context("failed to reset decoder")?;
    }

    let ack_bytes = q2s_ack.to_be_bytes();
    let ack_send = async {
        tokio::time::timeout(timeout, quic_send.write_all(&ack_bytes))
            .await
            .context("timeout sending ack")?
            .context("send ack failed")
    };

    // --- Phase 4: read remote's ack for our s2q id ---
    let mut remote_ack_bytes = [0u8; PAIR_ID_SIZE];
    let ack_recv = async {
        tokio::time::timeout(timeout, quic_recv.read_exact(&mut remote_ack_bytes))
            .await
            .context("timeout reading remote ack")?
            .context("read remote ack failed")
    };

    let (ack_send_res, ack_recv_res) = tokio::join!(ack_send, ack_recv);
    ack_send_res?;
    ack_recv_res?;

    let s2q_ack = u128::from_be_bytes(remote_ack_bytes);

    // If remote says ack=0 for our s2q pair, reset our encoder so its
    // output is decodable by the remote's fresh decoder.
    if s2q_ack == 0 && s2q_id != 0 {
        s2q_pair
            .reset_encoder()
            .context("failed to reset encoder after ack=0")?;
    }

    debug!(
        "[codec] handshake done: s2q_id={} s2q_ack={} ({}), q2s_id={} q2s_ack={} ({})",
        s2q_id,
        s2q_ack,
        if s2q_ack != 0 { "reuse" } else { "fresh" },
        q2s_id,
        q2s_ack,
        if q2s_ack != 0 { "reuse" } else { "fresh" },
    );

    Ok(HandshakeResult {
        s2q_pair,
        q2s_pair,
        s2q_id,
        s2q_ack,
        q2s_id,
        q2s_ack,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_id_size_is_16_bytes() {
        assert_eq!(PAIR_ID_SIZE, 16);
        assert_eq!(PAIR_ID_SIZE, std::mem::size_of::<u128>());
    }
}
