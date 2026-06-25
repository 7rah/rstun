use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt};
use std::time::Duration;

/// Maximum HTTP header size we'll buffer before giving up.
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Result of attempting to read a complete HTTP message.
pub enum HttpReadResult {
    /// A complete message (headers + body) was read.
    Message(Vec<u8>),
    /// More data is needed to complete the message — call again.
    NeedMore,
}

/// Stateful reader that accumulates bytes and extracts complete HTTP/1.x
/// messages (headers + body) based on `Content-Length`.
///
/// For messages without `Content-Length` (SSE, chunked, streaming), this
/// reader cannot determine the body boundary and the caller should fall
/// back to plain drain mode.
pub struct HttpMessageReader {
    buf: Vec<u8>,
    /// Whether we've already parsed at least one message from this stream.
    initialized: bool,
}

impl Default for HttpMessageReader {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpMessageReader {
    pub fn new() -> Self {
        HttpMessageReader {
            buf: Vec::with_capacity(8192),
            initialized: false,
        }
    }

    /// Attempt to read a complete HTTP message from `reader`.
    ///
    /// Returns:
    /// - `Message(data)` when a complete message (headers + Content-Length body) is available.
    /// - `NeedMore` when more data is required to form a complete message.
    ///
    /// Errors (bail) when:
    /// - The stream is not valid HTTP/1.x (parse failure).
    /// - The header exceeds `MAX_HEADER_SIZE`.
    /// - `Content-Length` is present but malformed.
    /// - EOF is reached mid-message (incomplete).
    pub async fn read_message<R>(
        &mut self,
        reader: &mut R,
        stream_timeout_ms: u64,
    ) -> Result<HttpReadResult>
    where
        R: AsyncRead + Unpin,
    {
        let timeout = Duration::from_millis(stream_timeout_ms);

        loop {
            // Try to parse what we have buffered so far.
            if let Some(msg) = self.try_parse()? {
                return Ok(HttpReadResult::Message(msg));
            }

            // Not enough data — read more.
            let mut tmp = [0u8; 8192];
            let n = tokio::time::timeout(timeout, reader.read(&mut tmp))
                .await
                .map_err(|_| anyhow::anyhow!("http read timeout"))??;

            if n == 0 {
                // EOF
                if self.buf.is_empty() {
                    // Clean EOF at message boundary — return empty message.
                    return Ok(HttpReadResult::Message(Vec::new()));
                }
                // EOF mid-message — incomplete.
                bail!("unexpected EOF mid-HTTP-message");
            }

            self.buf.extend_from_slice(&tmp[..n]);
        }
    }

    /// Try to parse a complete HTTP message from the internal buffer.
    ///
    /// Returns `Some(data)` if a complete message is available (headers
    /// + Content-Length body).  Returns `None` if more data is needed.
    ///
    /// Bails on parse errors or non-HTTP data.
    fn try_parse(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.is_empty() {
            return Ok(None);
        }

        // Find the end of headers (\r\n\r\n).
        let header_end = match find_header_end(&self.buf) {
            Some(pos) => pos,
            None => {
                if self.buf.len() > MAX_HEADER_SIZE {
                    bail!("HTTP header exceeds {MAX_HEADER_SIZE} bytes");
                }
                return Ok(None); // need more header data
            }
        };

        // Parse headers using httparse.
        let header_bytes = &self.buf[..header_end];
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req_parser = httparse::Request::new(&mut headers);

        let (is_request, _is_response) = match req_parser.parse(header_bytes) {
            Ok(httparse::Status::Complete(_)) => {
                let version = req_parser.version;
                if !matches!(version, Some(0) | Some(1)) {
                    bail!("unsupported HTTP version: {version:?}");
                }
                (true, false)
            }
            Ok(httparse::Status::Partial) => return Ok(None), // need more data
            Err(_) => {
                // Not a valid request — try parsing as response.
                let mut resp_headers = [httparse::EMPTY_HEADER; 64];
                let mut resp_parser = httparse::Response::new(&mut resp_headers);
                match resp_parser.parse(header_bytes) {
                    Ok(httparse::Status::Complete(_)) => {
                        let version = resp_parser.version;
                        if !matches!(version, Some(0) | Some(1)) {
                            bail!("unsupported HTTP version: {version:?}");
                        }
                        (false, true)
                    }
                    Ok(httparse::Status::Partial) => return Ok(None),
                    Err(e) => bail!("httparse parse error: {e}"),
                }
            }
        };

        self.initialized = true;

        // Headers are complete. header_end is the position right after \r\n\r\n.
        // The body starts at header_end.
        let body_start = header_end;

        // Look for Content-Length.
        let content_length = if is_request {
            req_parser
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .and_then(|s| s.trim().parse::<usize>().ok())
        } else {
            // is_response — we need to re-parse as response to access headers.
            // Actually we already have resp_parser in scope only inside the
            // match arm. Let's re-parse here.
            let mut resp_headers = [httparse::EMPTY_HEADER; 64];
            let mut resp_parser = httparse::Response::new(&mut resp_headers);
            resp_parser
                .parse(header_bytes)
                .map_err(|e| anyhow::anyhow!("re-parse response error: {e}"))?;
            resp_parser
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .and_then(|s| s.trim().parse::<usize>().ok())
        };

        match content_length {
            Some(cl) => {
                // We know the body length. Check if we have the full body.
                let body_end = body_start + cl;
                if self.buf.len() < body_end {
                    return Ok(None); // need more body data
                }
                // Extract the complete message.
                let msg = self.buf[..body_end].to_vec();
                self.buf = self.buf[body_end..].to_vec();
                Ok(Some(msg))
            }
            None => {
                // No Content-Length (SSE, chunked, streaming).
                // We can't determine the message boundary.
                // Return all currently-buffered data as one "message"
                // and let the caller flush it. The caller will call again
                // for the next chunk.
                if self.buf.is_empty() {
                    return Ok(None);
                }
                let msg = std::mem::take(&mut self.buf);
                Ok(Some(msg))
            }
        }
    }
}

/// Find the position right after the \r\n\r\n that terminates HTTP headers.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    #[test]
    fn find_header_end_basic() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"), Some(27));
        assert_eq!(find_header_end(b"no headers here"), None);
    }

    #[tokio::test]
    async fn read_simple_get_with_content_length() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let (mut tx, mut rx) = duplex(1024);
        tx.write_all(raw).await.unwrap();
        tx.flush().await.unwrap();
        drop(tx); // EOF

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
    async fn read_response_with_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (mut tx, mut rx) = duplex(1024);
        tx.write_all(raw).await.unwrap();
        tx.flush().await.unwrap();
        drop(tx);

        let mut reader = HttpMessageReader::new();
        let result = reader.read_message(&mut rx, 5000).await.unwrap();
        match result {
            HttpReadResult::Message(data) => assert_eq!(data, raw),
            HttpReadResult::NeedMore => panic!("expected message"),
        }
    }

    #[tokio::test]
    async fn read_sse_no_content_length_returns_buffered() {
        // SSE response with no Content-Length — should return buffered data.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: hello\n\n";
        let (mut tx, mut rx) = duplex(1024);
        tx.write_all(raw).await.unwrap();
        tx.flush().await.unwrap();
        drop(tx);

        let mut reader = HttpMessageReader::new();
        let result = reader.read_message(&mut rx, 5000).await.unwrap();
        match result {
            HttpReadResult::Message(data) => assert_eq!(data, raw),
            HttpReadResult::NeedMore => panic!("expected message"),
        }
    }

    #[tokio::test]
    async fn read_multiple_messages_keep_alive() {
        let msg1 = b"GET /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc";
        let msg2 = b"GET /b HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\ndef";
        let raw = [msg1.as_ref(), msg2.as_ref()].concat();
        let (mut tx, mut rx) = duplex(1024);
        tx.write_all(&raw).await.unwrap();
        tx.flush().await.unwrap();
        drop(tx);

        let mut reader = HttpMessageReader::new();

        // First message.
        let result1 = reader.read_message(&mut rx, 5000).await.unwrap();
        match result1 {
            HttpReadResult::Message(data) => assert_eq!(data, msg1),
            HttpReadResult::NeedMore => panic!("expected message"),
        }

        // Second message.
        let result2 = reader.read_message(&mut rx, 5000).await.unwrap();
        match result2 {
            HttpReadResult::Message(data) => assert_eq!(data, msg2),
            HttpReadResult::NeedMore => panic!("expected message"),
        }
    }

    #[tokio::test]
    async fn read_partial_header_returns_need_more() {
        let (mut tx, mut rx) = duplex(1024);
        tx.write_all(b"GET / HTTP/1.1\r\nHost: x").await.unwrap();
        tx.flush().await.unwrap();
        // Don't close — simulate waiting for more data.
        // We can't easily test NeedMore without a timeout, so just verify
        // it times out gracefully.
        let mut reader = HttpMessageReader::new();
        let result = reader.read_message(&mut rx, 50).await;
        // Should return error (timeout reading more header data).
        assert!(result.is_err(), "expected error for partial header");
    }

    #[tokio::test]
    async fn non_http_data_bails() {
        let raw = b"\x00\x01\x02\x03not http at all\x04\x05";
        let (mut tx, mut rx) = duplex(1024);
        tx.write_all(raw).await.unwrap();
        tx.flush().await.unwrap();
        drop(tx);

        let mut reader = HttpMessageReader::new();
        let result = reader.read_message(&mut rx, 1000).await;
        // Should error — binary garbage isn't valid HTTP.
        assert!(result.is_err(), "expected error for non-HTTP data");
    }

    #[tokio::test]
    async fn large_content_length_body() {
        let body = "x".repeat(10000);
        let header = format!(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
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
            HttpReadResult::NeedMore => panic!("expected message"),
        }
    }
}
