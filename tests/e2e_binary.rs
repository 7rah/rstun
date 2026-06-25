//! End-to-end binary integration tests.
//!
//! Spawns real `rstun` server and client binaries and verifies that TCP
//! traffic round-trips correctly through the tunnel, in both plain and
//! zstd-compressed modes.
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
//! - Both clients share the same zstd setting.

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

/// A spawned child process that is killed on drop (RAII cleanup).
struct ChildGuard(Child);

impl ChildGuard {
    fn spawn(args: &[&str]) -> Self {
        let child = Command::new(RSTUN_BIN)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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

/// Run a full e2e tunnel test with the given zstd flag.
fn run_e2e(zstd: bool) {
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

    let _client_b = ChildGuard::spawn(&[
        "client",
        "--server-addr",
        &server_addr,
        "--password",
        PASSWORD,
        "--tcp-mappings",
        &tcp_mapping_b,
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
    ]);

    // Wait for the server's IN-port TCP listener to become ready.
    wait_for_tcp_port(
        &format!("127.0.0.1:{server_listen_port}"),
        Duration::from_secs(15),
    );

    // --- ClientA (OUT mode): listens on client_a_port, upstream is
    //     the server's IN port ---
    let client_a_port = pick_free_port();
    let tcp_mapping_a = format!("OUT^{client_a_port}^127.0.0.1:{server_listen_port}");

    let mut client_a_args: Vec<&str> = vec![
        "client",
        "--server-addr",
        &server_addr,
        "--password",
        PASSWORD,
        "--tcp-mappings",
        &tcp_mapping_a,
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
        client_a_args.push("--zstd");
    }

    let _client_a = ChildGuard::spawn(&client_a_args);

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
        "first echo mismatch (zstd={zstd})"
    );

    // Second message on the same connection.
    conn.write_all(TEST_DATA_2).unwrap();
    let mut received_2 = vec![0u8; TEST_DATA_2.len()];
    conn.read_exact(&mut received_2).unwrap();
    assert_eq!(
        received_2.as_slice(),
        TEST_DATA_2,
        "second echo mismatch (zstd={zstd})"
    );

    // ChildGuard drops kill all processes.
}

#[test]
fn e2e_plain_tcp_tunnel() {
    run_e2e(false);
}

#[test]
fn e2e_zstd_tcp_tunnel() {
    run_e2e(true);
}
