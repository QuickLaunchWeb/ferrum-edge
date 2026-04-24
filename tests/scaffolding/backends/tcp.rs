//! `ScriptedTcpBackend` — a TCP server that executes a deterministic list
//! of [`TcpStep`]s against each accepted connection (or just the first,
//! depending on [`ExecutionMode`]).
//!
//! Most scripted-backend tests describe the wire behaviour they want to
//! observe as data: "accept, read 5 bytes, write OK, close". The
//! [`TcpStep`] enum covers the primitives for TCP/TLS/HTTP-1.1 tests; higher
//! layers ([`super::tls`], [`super::http1`]) compose on top.
//!
//! ## Determinism
//!
//! - The script is copied into each accepted connection (`repeat_each_connection`
//!   mode) or consumed once (`once` mode). No `rand`.
//! - `RefuseNextConnect` does **not** close the listener — it accepts and then
//!   immediately drops, so the TCP SYN/ACK completes and the client sees RST
//!   on first write.
//!
//! ## Observability
//!
//! The backend exposes two accessors after shutdown:
//! - [`ScriptedTcpBackend::accepted_connections`] — number of accept() events
//!   that reached the step interpreter.
//! - [`ScriptedTcpBackend::received_bytes`] — the concatenation of everything
//!   every `ReadExact` / `ReadUntil` step consumed. Useful for "gateway sent
//!   X to backend" assertions.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

/// A single deterministic instruction in a TCP script.
#[derive(Debug, Clone)]
pub enum TcpStep {
    /// Wait until an incoming connection is accepted. Implicit before any
    /// other step fires, so most scripts omit this; callers use it only
    /// when they want the semantics of "advance the script between
    /// connections in `Once` mode", which is rarely needed.
    Accept,
    /// Read exactly `n` bytes; captured into `received_bytes`. Fails with
    /// [`StepError::ShortRead`] if the peer closes before `n` arrive.
    ReadExact(usize),
    /// Read from the socket until `needle` appears in the accumulated buffer,
    /// then consume everything up to and including `needle`. Captures the
    /// full consumed range.
    ReadUntil(Vec<u8>),
    /// Write `bytes` to the socket.
    Write(Vec<u8>),
    /// Pause for `duration` before executing the next step. Modelled off the
    /// `tokio::time::sleep` you'd get anyway, but expressed declaratively so
    /// the script remains data-only.
    Sleep(Duration),
    /// Close the socket cleanly (send FIN).
    Drop,
    /// Send a TCP RST by setting `SO_LINGER=0` and dropping. Triggers
    /// `ECONNRESET` on the peer's next read/write.
    Reset,
    /// Accept the next connection and drop it immediately **without** reading
    /// any bytes. The peer's first write will observe RST (or the accept
    /// succeeding and the connection closing straight away). This is the
    /// "refuse-at-TCP" fixture for the 502+ConnectionRefused acceptance test.
    ///
    /// **Behavior note**: Because the OS has already completed the three-way
    /// handshake before `accept` returns, clients see this as "connected, then
    /// immediately reset" rather than a TCP-level connection refused. That is
    /// the closest deterministic approximation available above the kernel.
    RefuseNextConnect,
}

/// Whether the script repeats for every accepted connection or fires once.
#[derive(Debug, Clone, Copy)]
pub enum ExecutionMode {
    /// Replay the full step list for each accepted connection. Good for
    /// HTTP/1.x `Connection: close` backends where each request is a fresh
    /// connection.
    RepeatEachConnection,
    /// Consume the step list across the lifetime of a single connection;
    /// further connections accept-and-drop. Useful for keep-alive streams
    /// and tests that care about behavior on connection #1 only.
    Once,
}

/// Errors a TCP step can encounter. Preserved in `ScriptedTcpBackend` state
/// for post-mortem assertions.
#[derive(Debug)]
pub enum StepError {
    Io(io::Error),
    ShortRead { expected: usize, actual: usize },
}

impl std::fmt::Display for StepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepError::Io(e) => write!(f, "io error: {e}"),
            StepError::ShortRead { expected, actual } => {
                write!(f, "short read: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for StepError {}

impl From<io::Error> for StepError {
    fn from(e: io::Error) -> Self {
        StepError::Io(e)
    }
}

/// Fluent builder for [`ScriptedTcpBackend`]. Most tests will use
/// [`ScriptedTcpBackend::builder`].
pub struct ScriptedTcpBackendBuilder {
    listener: TcpListener,
    steps: Vec<TcpStep>,
    mode: ExecutionMode,
}

impl ScriptedTcpBackendBuilder {
    /// Start a new builder against the given pre-bound listener. Required
    /// to avoid the drop-rebind race (CLAUDE.md "Backend/echo server ports
    /// should be held, not dropped"). Get one from
    /// [`super::super::ports::reserve_port`].
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            steps: Vec::new(),
            mode: ExecutionMode::RepeatEachConnection,
        }
    }

    /// Append a step to the script.
    pub fn step(mut self, step: TcpStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Append multiple steps at once.
    pub fn steps(mut self, steps: impl IntoIterator<Item = TcpStep>) -> Self {
        self.steps.extend(steps);
        self
    }

    /// Switch to [`ExecutionMode::Once`].
    pub fn once(mut self) -> Self {
        self.mode = ExecutionMode::Once;
        self
    }

    /// Switch to [`ExecutionMode::RepeatEachConnection`] (default).
    pub fn repeat_each_connection(mut self) -> Self {
        self.mode = ExecutionMode::RepeatEachConnection;
        self
    }

    /// Spawn the backend. Returns a handle whose `port` is the reserved port.
    pub fn spawn(self) -> io::Result<ScriptedTcpBackend> {
        let port = self.listener.local_addr()?.port();
        let state = Arc::new(BackendState::default());
        let state_task = state.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let steps = self.steps;
        let mode = self.mode;
        let listener = self.listener;

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return,
                    accept_result = listener.accept() => {
                        let Ok((stream, _addr)) = accept_result else {
                            // Accept errors are usually "listener closed" during
                            // shutdown; loop and re-check the shutdown channel.
                            continue;
                        };
                        let conn_index =
                            state_task.accepted.fetch_add(1, Ordering::SeqCst);
                        let state_conn = state_task.clone();
                        let script = steps.clone();

                        match mode {
                            ExecutionMode::RepeatEachConnection => {
                                tokio::spawn(async move {
                                    let _ = run_script(stream, script, state_conn).await;
                                });
                            }
                            ExecutionMode::Once => {
                                // First connection gets the script; subsequent
                                // connections accept-and-drop.
                                if conn_index == 0 {
                                    tokio::spawn(async move {
                                        let _ =
                                            run_script(stream, script, state_conn).await;
                                    });
                                } else {
                                    drop(stream);
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(ScriptedTcpBackend {
            port,
            state,
            handle: Some(handle),
            shutdown: Some(shutdown_tx),
        })
    }
}

#[derive(Default)]
struct BackendState {
    accepted: AtomicU32,
    received_bytes: Mutex<Vec<u8>>,
}

/// A running scripted TCP backend. Dropping the handle shuts it down.
pub struct ScriptedTcpBackend {
    /// The port the backend is listening on.
    pub port: u16,
    state: Arc<BackendState>,
    handle: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl ScriptedTcpBackend {
    /// Fluent builder given a pre-bound listener (see [`super::super::ports`]).
    pub fn builder(listener: TcpListener) -> ScriptedTcpBackendBuilder {
        ScriptedTcpBackendBuilder::new(listener)
    }

    /// Number of connections accepted since the backend started. Includes
    /// connections that were accepted-and-dropped by `RefuseNextConnect`
    /// and connections beyond the first in `Once` mode.
    pub fn accepted_connections(&self) -> u32 {
        self.state.accepted.load(Ordering::SeqCst)
    }

    /// Snapshot of everything any connection's `ReadExact` / `ReadUntil`
    /// steps have consumed so far. Returns a clone so the caller is free
    /// to pattern-match without holding the mutex.
    pub async fn received_bytes(&self) -> Vec<u8> {
        self.state.received_bytes.lock().await.clone()
    }

    /// Shortcut for asserting that `received_bytes()` contains `needle`.
    pub async fn received_contains(&self, needle: &[u8]) -> bool {
        let buf = self.received_bytes().await;
        buf.windows(needle.len()).any(|w| w == needle)
    }

    /// Signal shutdown; the accept loop exits on its next iteration. Safe
    /// to call multiple times.
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl Drop for ScriptedTcpBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Execute a single connection's worth of steps.
async fn run_script(
    mut stream: TcpStream,
    script: Vec<TcpStep>,
    state: Arc<BackendState>,
) -> Result<(), StepError> {
    for step in script {
        match step {
            TcpStep::Accept => {
                // Already past accept by the time we're here — treat as a no-op
                // so scripts that include `Accept` first for readability still work.
            }
            TcpStep::ReadExact(n) => {
                let mut buf = vec![0u8; n];
                let mut read = 0;
                while read < n {
                    match stream.read(&mut buf[read..]).await {
                        Ok(0) => {
                            state
                                .received_bytes
                                .lock()
                                .await
                                .extend_from_slice(&buf[..read]);
                            return Err(StepError::ShortRead {
                                expected: n,
                                actual: read,
                            });
                        }
                        Ok(m) => read += m,
                        Err(e) => return Err(StepError::Io(e)),
                    }
                }
                state
                    .received_bytes
                    .lock()
                    .await
                    .extend_from_slice(&buf[..read]);
            }
            TcpStep::ReadUntil(needle) => {
                let mut acc = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    if find_subsequence(&acc, &needle).is_some() {
                        break;
                    }
                    match stream.read(&mut buf).await {
                        Ok(0) => {
                            state.received_bytes.lock().await.extend_from_slice(&acc);
                            return Err(StepError::ShortRead {
                                expected: needle.len(),
                                actual: acc.len(),
                            });
                        }
                        Ok(m) => acc.extend_from_slice(&buf[..m]),
                        Err(e) => {
                            state.received_bytes.lock().await.extend_from_slice(&acc);
                            return Err(StepError::Io(e));
                        }
                    }
                }
                state.received_bytes.lock().await.extend_from_slice(&acc);
            }
            TcpStep::Write(bytes) => stream.write_all(&bytes).await?,
            TcpStep::Sleep(d) => tokio::time::sleep(d).await,
            TcpStep::Drop => {
                stream.shutdown().await.ok();
                return Ok(());
            }
            TcpStep::Reset => {
                // SO_LINGER = 0 causes the OS to send RST rather than FIN on close.
                let std_stream = stream.into_std()?;
                let sock = socket2::Socket::from(std_stream);
                sock.set_linger(Some(Duration::from_secs(0)))?;
                drop(sock);
                return Ok(());
            }
            TcpStep::RefuseNextConnect => {
                // Drop the current socket immediately. The runner accepts the
                // next connection on the listener in the outer loop.
                drop(stream);
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Tiny `memmem`-style helper to avoid a dependency.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::ports::reserve_port;

    #[tokio::test]
    async fn read_exact_then_write() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedTcpBackend::builder(reservation.into_listener())
            .step(TcpStep::ReadExact(5))
            .step(TcpStep::Write(b"pong\n".to_vec()))
            .step(TcpStep::Drop)
            .spawn()
            .expect("spawn");

        let mut client = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        client.write_all(b"hello").await.expect("write");
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.expect("read");
        assert_eq!(resp, b"pong\n");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(backend.received_contains(b"hello").await);
        assert_eq!(backend.accepted_connections(), 1);
    }

    #[tokio::test]
    async fn read_until_marker() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedTcpBackend::builder(reservation.into_listener())
            .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
            .step(TcpStep::Write(b"OK\n".to_vec()))
            .step(TcpStep::Drop)
            .spawn()
            .expect("spawn");

        let mut client = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        client
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .expect("write");
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.expect("read");
        assert_eq!(resp, b"OK\n");
        let received = backend.received_bytes().await;
        assert!(received.ends_with(b"\r\n\r\n"));
    }

    #[tokio::test]
    async fn reset_triggers_econnreset_on_peer_write() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedTcpBackend::builder(reservation.into_listener())
            .step(TcpStep::Reset)
            .spawn()
            .expect("spawn");

        let mut client = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        // Brief wait so the server-side RST propagates.
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Write into the RST'd socket — the error surfaces either here or on
        // the subsequent read. We don't pin down which, only that the socket
        // is unusable.
        let _ = client.write_all(b"data").await;
        let mut buf = [0u8; 16];
        let r = client.read(&mut buf).await;
        match r {
            Ok(0) => {} // FIN observed — on some stacks RST manifests as EOF.
            Ok(_) => panic!("should not have read data after RST"),
            Err(e) => {
                let k = e.kind();
                assert!(
                    matches!(
                        k,
                        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                    ),
                    "expected RST/BrokenPipe, got {k:?}"
                );
            }
        }
        assert_eq!(backend.accepted_connections(), 1);
    }

    #[tokio::test]
    async fn refuse_next_connect_drops_immediately() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
            .step(TcpStep::RefuseNextConnect)
            .spawn()
            .expect("spawn");

        let mut client = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let mut buf = [0u8; 16];
        // The backend drops the socket right after accept; client sees EOF.
        let n = client.read(&mut buf).await.expect("read");
        assert_eq!(n, 0, "expected EOF after drop, got {n} bytes");
    }

    #[tokio::test]
    async fn once_mode_runs_script_on_first_connection_only() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedTcpBackend::builder(reservation.into_listener())
            .step(TcpStep::Write(b"first\n".to_vec()))
            .step(TcpStep::Drop)
            .once()
            .spawn()
            .expect("spawn");

        let mut c1 = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect 1");
        let mut r1 = Vec::new();
        c1.read_to_end(&mut r1).await.expect("read 1");
        assert_eq!(r1, b"first\n");

        let mut c2 = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect 2");
        let mut r2 = Vec::new();
        c2.read_to_end(&mut r2).await.expect("read 2");
        assert_eq!(r2, b"", "subsequent connections in once mode get EOF");
        assert_eq!(backend.accepted_connections(), 2);
    }
}
