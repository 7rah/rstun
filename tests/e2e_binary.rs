//! End-to-end binary integration tests.
//!
//! Spawns real `rstun` server and client binaries and verifies that TCP
//! traffic round-trips correctly through the tunnel, in plain, zstd-compressed,
//! and zstd+http-aware modes.
//!
//! Topology:
//!
//! ```text
//!   test client ──> ClientA(out) ──QUIC──> Server ──TCP──> ClientB(in) ──> echo
//!        ^                                                                    |
//!        └──────────────────────────── echo ─────────────────────────────────┘
//! ```
//!
//! Mapping semantics:
//! - ClientA (OUT): `OUT^client_a_port^server_listen_port`
//!   - ClientA listens on `client_a_port`; when a connection arrives, the
//!     server connects to `server_listen_port`.
//! - ClientB (IN): `IN^echo_port^server_listen_port`
//!   - The server listens on `server_listen_port`; when a connection arrives,
//!     ClientB forwards it to `echo_port`.
//! - Both clients share the same zstd/http settings.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

/// Path to the compiled rstun binary, resolved by Cargo at build time.
const RSTUN_BIN: &str = env!("CARGO_BIN_EXE_rstun");

const PASSWORD: &str = "testpass";
const TEST_DATA: &[u8] = b"Hello, rstun e2e! This is a longer message to ensure compression has something to work with. Repeated data helps: AAAAAAAAAAAAAAAAAAAAabcdefghijklmnopqrstuvwxyz0123456789";
const TEST_DATA_2: &[u8] = b"Second message verifying connection persistence across the tunnel.";

/// HTTP request with Content-Length (covers the encoder-flush path: small
/// messages must be flushed after each message, not buffered indefinitely).
const HTTP_REQ_WITH_CL: &[u8] = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.test\r\nContent-Type: application/json\r\nContent-Length: 60\r\n\r\n{\"model\":\"test\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}";

/// HTTP response with Transfer-Encoding: chunked and no Content-Length (covers
/// the drain-mode path: subsequent body fragments must pass through without
/// being re-parsed as HTTP headers).
const HTTP_RESP_CHUNKED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\ndata:\r\n\r\ndata: hello\n\n0\r\n\r\n";

/// A spawned child process that is killed on drop (RAII cleanup).
struct ChildGuard(Child);

impl ChildGuard {
    fn spawn(args: &[&str]) -> Self {
        let inherit = std::env::var("RSTUN_TEST_LOG").is_ok();
        let stderr = if inherit { Stdio::inherit() } else { Stdio::null() };
        let stdout = if inherit { Stdio::inherit() } else { Stdio::null() };
        let child = Command::new(RSTUN_BIN)
            .args(args)
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn `rstun {}`: {e}", args.join(" ")));
        ChildGuard(child)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A simple TCP echo server: reads data and writes it back.
struct EchoServer {
    addr: SocketAddr,
    _handle: thread::JoinHandle<()>,
}

impl EchoServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        EchoServer {
            addr,
            _handle: handle,
        }
    }
}

/// Find a free TCP port on localhost.
fn pick_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Poll until a TCP port accepts connections or panic after `timeout`.
fn wait_for_tcp_port(addr: &str, timeout: Duration) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for TCP port {addr}");
}

/// Build the common client CLI args shared by both ClientA and ClientB.
/// `extra` carries mode-specific flags (--zstd, --http) when enabled.
fn client_args<'a>(
    server_addr: &'a str,
    tcp_mapping: &'a str,
    zstd: bool,
    http: bool,
) -> Vec<&'a str> {
    let mut args: Vec<&str> = vec![
        "client",
        "--server-addr",
        server_addr,
        "--password",
        PASSWORD,
        "--tcp-mappings",
        tcp_mapping,
        "--tcp-timeout-ms",
        "30000",
        "--quic-timeout-ms",
        "30000",
        "--heartbeat-interval-ms",
        "2000",
        "--heartbeat-timeout-ms",
        "6000",
        "--wait-before-retry-ms",
        "500",
        "-l",
        "E",
    ];
    if zstd {
        args.push("--zstd");
    }
    if http {
        args.push("--http");
    }
    args
}

/// Run a full e2e tunnel test with the given zstd/http flags.
///
/// Verifies that arbitrary byte payloads round-trip through the tunnel.
/// When `http` is true, both clients run in HTTP-aware mode, exercising the
/// encoder flush path (Content-Length messages) and drain mode (chunked
/// responses without Content-Length).
fn run_e2e(zstd: bool, http: bool) {
    // --- Echo server ---
    let echo = EchoServer::start();
    let echo_port = echo.addr.port();

    // --- rstun server (auto-generated localhost cert) ---
    let server_port = pick_free_port();
    let server_addr = format!("127.0.0.1:{server_port}");

    let _server = ChildGuard::spawn(&[
        "server",
        "--addr",
        &server_addr,
        "--password",
        PASSWORD,
        "--quic-timeout-ms",
        "30000",
        "-l",
        "E",
    ]);

    // Give the server time to bind its QUIC port.
    thread::sleep(Duration::from_secs(1));

    // --- ClientB (IN mode): server listens on server_listen_port,
    //     ClientB forwards inbound streams to echo server ---
    let server_listen_port = pick_free_port();
    let tcp_mapping_b = format!("IN^{echo_port}^{server_listen_port}");

    let _client_b = ChildGuard::spawn(&client_args(
        &server_addr,
        &tcp_mapping_b,
        zstd,
        http,
    ));

    // Wait for the server's IN-port TCP listener to become ready.
    wait_for_tcp_port(
        &format!("127.0.0.1:{server_listen_port}"),
        Duration::from_secs(15),
    );

    // --- ClientA (OUT mode): listens on client_a_port, upstream is
    //     the server's IN port ---
    let client_a_port = pick_free_port();
    let tcp_mapping_a = format!("OUT^{client_a_port}^127.0.0.1:{server_listen_port}");

    let _client_a = ChildGuard::spawn(&client_args(
        &server_addr,
        &tcp_mapping_a,
        zstd,
        http,
    ));

    // Wait for ClientA's local TCP listener to become ready.
    wait_for_tcp_port(
        &format!("127.0.0.1:{client_a_port}"),
        Duration::from_secs(15),
    );

    // --- Test: connect to ClientA, send data, receive echo ---
    let mut conn = TcpStream::connect(format!("127.0.0.1:{client_a_port}"))
        .unwrap_or_else(|e| panic!("failed to connect to ClientA: {e}"));
    conn.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    conn.set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();

    // First message.
    conn.write_all(TEST_DATA).unwrap();
    let mut received = vec![0u8; TEST_DATA.len()];
    conn.read_exact(&mut received).unwrap();
    assert_eq!(
        received.as_slice(),
        TEST_DATA,
        "first echo mismatch (zstd={zstd}, http={http})"
    );

    // Second message on the same connection.
    conn.write_all(TEST_DATA_2).unwrap();
    let mut received_2 = vec![0u8; TEST_DATA_2.len()];
    conn.read_exact(&mut received_2).unwrap();
    assert_eq!(
        received_2.as_slice(),
        TEST_DATA_2,
        "second echo mismatch (zstd={zstd}, http={http})"
    );

    // ChildGuard drops kill all processes.
}

/// Run an HTTP-aware e2e tunnel test: send real HTTP messages (both
/// Content-Length and chunked/no-Content-Length forms) through a zstd+http
/// tunnel and verify they echo back byte-for-byte.
fn run_e2e_http() {
    // --- Echo server ---
    let echo = EchoServer::start();
    let echo_port = echo.addr.port();

    // --- rstun server ---
    let server_port = pick_free_port();
    let server_addr = format!("127.0.0.1:{server_port}");

    let _server = ChildGuard::spawn(&[
        "server",
        "--addr",
        &server_addr,
        "--password",
        PASSWORD,
        "--quic-timeout-ms",
        "30000",
        "-l",
        "E",
    ]);

    thread::sleep(Duration::from_secs(1));

    // --- ClientB (IN) and ClientA (OUT), both with --zstd --http ---
    let server_listen_port = pick_free_port();
    let tcp_mapping_b = format!("IN^{echo_port}^{server_listen_port}");
    let _client_b = ChildGuard::spawn(&client_args(
        &server_addr,
        &tcp_mapping_b,
        true,
        true,
    ));

    wait_for_tcp_port(
        &format!("127.0.0.1:{server_listen_port}"),
        Duration::from_secs(15),
    );

    let client_a_port = pick_free_port();
    let tcp_mapping_a = format!("OUT^{client_a_port}^127.0.0.1:{server_listen_port}");
    let _client_a = ChildGuard::spawn(&client_args(
        &server_addr,
        &tcp_mapping_a,
        true,
        true,
    ));

    wait_for_tcp_port(
        &format!("127.0.0.1:{client_a_port}"),
        Duration::from_secs(15),
    );

    // --- Test 1: HTTP request with Content-Length ---
    // Covers the encoder-flush path: the request is small enough to be
    // buffered indefinitely in the zstd encoder without an explicit flush
    // after each message.
    let mut conn = TcpStream::connect(format!("127.0.0.1:{client_a_port}"))
        .unwrap_or_else(|e| panic!("failed to connect to ClientA: {e}"));
    conn.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    conn.set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    conn.write_all(HTTP_REQ_WITH_CL).unwrap();
    let mut resp = vec![0u8; HTTP_REQ_WITH_CL.len()];
    conn.read_exact(&mut resp).unwrap();
    assert_eq!(
        resp.as_slice(),
        HTTP_REQ_WITH_CL,
        "HTTP request with Content-Length echo mismatch"
    );

    // --- Test 2: chunked HTTP response (no Content-Length), split across
    // two writes to exercise the drain-mode path ---
    // The first write carries complete headers (up to \r\n\r\n) so
    // try_parse emits the header block and enters drain mode. The second
    // write carries raw chunked-body fragments. Without drain mode,
    // httparse would re-parse these fragments as HTTP headers and bail
    // with "invalid HTTP version", killing the stream.
    let mut conn = TcpStream::connect(format!("127.0.0.1:{client_a_port}"))
        .unwrap_or_else(|e| panic!("failed to connect to ClientA: {e}"));
    conn.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    conn.set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();

    // Split at the header/body boundary so the encoder sees two separate
    // reads: headers first, then chunked body.
    let split = HTTP_RESP_CHUNKED
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .expect("chunked response must contain \\r\\n\\r\\n");
    conn.write_all(&HTTP_RESP_CHUNKED[..split]).unwrap();
    thread::sleep(Duration::from_millis(200));
    conn.write_all(&HTTP_RESP_CHUNKED[split..]).unwrap();

    let mut resp = vec![0u8; HTTP_RESP_CHUNKED.len()];
    conn.read_exact(&mut resp).unwrap();
    assert_eq!(
        resp.as_slice(),
        HTTP_RESP_CHUNKED,
        "chunked HTTP response echo mismatch"
    );

    // ChildGuard drops kill all processes.
}

#[test]
fn e2e_plain_tcp_tunnel() {
    run_e2e(false, false);
}

#[test]
fn e2e_zstd_tcp_tunnel() {
    run_e2e(true, false);
}

#[test]
fn e2e_zstd_http_tcp_tunnel() {
    run_e2e_http();
}

