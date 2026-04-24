//! `NetworkSimProxy` — a TCP middleman that applies a
//! [`NetworkProfile`] (latency / bandwidth limit / truncate) to every
//! accepted connection, then relays bytes to a target backend.
//!
//! The proxy sits between the gateway under test and the scripted
//! backend. Every byte flowing in either direction passes through the
//! configured wrappers, so a test can model "slow uplink / fast
//! downlink" without patching the scripted backend.
//!
//! ## Why this instead of wrapping the backend directly?
//!
//! The Phase-1 scripted backends (`ScriptedTcpBackend`,
//! `ScriptedHttp1Backend`, `ScriptedTlsBackend`) all take a concrete
//! `tokio::net::TcpStream`. Some of their steps (e.g.,
//! `TcpStep::Reset` which calls `stream.into_std()`) are
//! `TcpStream`-only — making them generic would ripple through a lot
//! of Phase-1 code. Running the network wrappers in a separate
//! middleman proxy is free of all those constraints and drops right
//! into existing tests by just swapping the port the gateway points at.
//!
//! ## Caveats
//!
//! - Only bidirectional byte streams (no datagrams). For UDP
//!   simulation see the [`super::super::backends::udp`] helpers.
//! - The proxy reads the full request body into the bandwidth
//!   bucket; for streams that interleave multiple requests on one
//!   connection, the bandwidth wrapper limits the total traffic, not
//!   per-request.
//! - `TruncatedStream` close happens on either direction hitting the
//!   threshold — same semantics as the standalone wrapper.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinHandle};

use super::{BandwidthLimitedStream, DelayedStream, TruncatedStream};

/// Declarative description of the network transformations applied to
/// each connection through the middleman.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkProfile {
    /// Per-call read+write delay.
    pub latency: Option<Duration>,
    /// Bytes-per-second ceiling (applied to both directions).
    pub bandwidth_bps: Option<u64>,
    /// Close the stream after this many total bytes have flowed in
    /// either direction.
    pub truncate_after: Option<usize>,
    /// Delay inserted just before the truncate fires.
    pub truncate_delay: Option<Duration>,
}

impl NetworkProfile {
    pub fn is_noop(&self) -> bool {
        self.latency.is_none() && self.bandwidth_bps.is_none() && self.truncate_after.is_none()
    }
}

/// Fluent builder for [`NetworkSimProxy`].
pub struct NetworkSimProxyBuilder {
    listener: TcpListener,
    target: Option<(String, u16)>,
    profile: NetworkProfile,
}

impl NetworkSimProxyBuilder {
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            target: None,
            profile: NetworkProfile::default(),
        }
    }

    /// Point the middleman at `(host, port)`. Required.
    pub fn forward_to(mut self, target: (impl Into<String>, u16)) -> Self {
        let (h, p) = target;
        self.target = Some((h.into(), p));
        self
    }

    /// Inject a per-call read+write delay.
    pub fn with_latency(mut self, delay: Duration) -> Self {
        self.profile.latency = Some(delay);
        self
    }

    /// Limit read+write bandwidth to `bps` bytes per second.
    pub fn with_bandwidth_limit(mut self, bps: u64) -> Self {
        self.profile.bandwidth_bps = Some(bps);
        self
    }

    /// Close the stream after `bytes` total have flowed.
    pub fn with_truncate_after(mut self, bytes: usize) -> Self {
        self.profile.truncate_after = Some(bytes);
        self
    }

    /// Delay before the truncate fires.
    pub fn with_truncate_delay(mut self, delay: Duration) -> Self {
        self.profile.truncate_delay = Some(delay);
        self
    }

    pub fn spawn(self) -> io::Result<NetworkSimProxy> {
        let port = self.listener.local_addr()?.port();
        let target = self
            .target
            .ok_or_else(|| io::Error::other("NetworkSimProxy: forward_to required"))?;
        let profile = self.profile;
        let listener = self.listener;
        let state = Arc::new(ProxyState::default());
        let state_task = state.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return,
                    accept_result = listener.accept() => {
                        let Ok((client_stream, _addr)) = accept_result else {
                            continue;
                        };
                        state_task.accepted.fetch_add(1, Ordering::SeqCst);
                        let target = target.clone();
                        let state_conn = state_task.clone();
                        let track = state_conn.clone();
                        let jh = tokio::spawn(async move {
                            relay_with_profile(
                                client_stream,
                                &target.0,
                                target.1,
                                profile,
                                state_conn,
                            )
                            .await;
                        });
                        track.track_connection(jh.abort_handle());
                    }
                }
            }
        });

        Ok(NetworkSimProxy {
            port,
            state,
            handle: Some(handle),
            shutdown: Some(shutdown_tx),
        })
    }
}

/// Running middleman. Dropping it shuts down the accept loop and
/// aborts every in-flight relay task.
pub struct NetworkSimProxy {
    pub port: u16,
    state: Arc<ProxyState>,
    handle: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl NetworkSimProxy {
    pub fn builder(listener: TcpListener) -> NetworkSimProxyBuilder {
        NetworkSimProxyBuilder::new(listener)
    }

    pub fn accepted_connections(&self) -> u32 {
        self.state.accepted.load(Ordering::SeqCst)
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
        if let Ok(mut guard) = self.state.connection_aborts.lock() {
            for abort in guard.drain(..) {
                abort.abort();
            }
        }
    }
}

impl Drop for NetworkSimProxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Default)]
struct ProxyState {
    accepted: AtomicU32,
    connection_aborts: StdMutex<Vec<AbortHandle>>,
}

impl ProxyState {
    fn track_connection(&self, abort: AbortHandle) {
        if let Ok(mut guard) = self.connection_aborts.lock() {
            guard.retain(|h| !h.is_finished());
            guard.push(abort);
        }
    }
}

/// Apply the profile to a newly accepted client stream, open a
/// connection to the backend, and relay bytes bidirectionally.
///
/// The wrapping is applied in the order
/// `(latency → bandwidth → truncate)` — so the test's latency happens
/// on the "wire" before rate-limiting, and the truncate fires after
/// both.
async fn relay_with_profile(
    client: TcpStream,
    target_host: &str,
    target_port: u16,
    profile: NetworkProfile,
    _state: Arc<ProxyState>,
) {
    let backend_addr: SocketAddr = match format!("{target_host}:{target_port}").parse() {
        Ok(a) => a,
        Err(_) => return,
    };
    let Ok(backend) = TcpStream::connect(backend_addr).await else {
        return;
    };

    // Wrap BOTH sides identically. If the test only wants client→backend
    // slowdown, it should apply an asymmetric wrapper directly (not
    // exposed via `NetworkProfile` — YAGNI for Phase 5 tests).
    let client = wrap_stream(client, profile);
    let backend = wrap_stream(backend, profile);

    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut br, mut bw) = tokio::io::split(backend);

    // Bidirectional relay. Use `copy` rather than `copy_bidirectional`
    // so we don't leak memory on half-close (one direction ending
    // normally while the other blocks on the latency timer).
    let c_to_b = async move {
        let _ = tokio::io::copy(&mut cr, &mut bw).await;
    };
    let b_to_c = async move {
        let _ = tokio::io::copy(&mut br, &mut cw).await;
    };
    tokio::select! {
        _ = c_to_b => {},
        _ = b_to_c => {},
    }
}

/// Wrap `inner` in whatever `profile` wants. The order is
/// `TruncatedStream(BandwidthLimitedStream(DelayedStream(inner)))`
/// so the close fires on total bytes observed at the outermost layer
/// (after bandwidth shaping and latency injection), which matches
/// what a real slow + broken network would look like.
fn wrap_stream(
    inner: TcpStream,
    profile: NetworkProfile,
) -> Box<dyn StreamReadWrite + Send + Unpin> {
    let mut erased: Box<dyn StreamReadWrite + Send + Unpin> = Box::new(inner);
    if let Some(d) = profile.latency {
        erased = Box::new(DelayedStream::new(erased, d));
    }
    if let Some(bps) = profile.bandwidth_bps {
        erased = Box::new(BandwidthLimitedStream::new(erased, bps));
    }
    if let Some(n) = profile.truncate_after {
        let mut t = TruncatedStream::new(erased, n);
        if let Some(d) = profile.truncate_delay {
            t = t.with_pre_close_delay(d);
        }
        erased = Box::new(t);
    }
    erased
}

/// Helper: any `AsyncRead + AsyncWrite` is a `StreamReadWrite`.
pub trait StreamReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + ?Sized> StreamReadWrite for T {}

// AsyncReadExt is used in the unit tests below via `.read(...)`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::ports::reserve_port;
    use tokio::io::AsyncWriteExt;

    /// A tiny TCP echo server. Reads one chunk, echoes it, stays open.
    async fn spawn_echo(listener: TcpListener) {
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });
    }

    #[tokio::test]
    async fn relay_without_profile_is_passthrough() {
        let backend_res = reserve_port().await.expect("backend port");
        let backend_port = backend_res.port;
        spawn_echo(backend_res.into_listener()).await;

        let proxy_res = reserve_port().await.expect("proxy port");
        let proxy_port = proxy_res.port;
        let _proxy = NetworkSimProxy::builder(proxy_res.into_listener())
            .forward_to(("127.0.0.1", backend_port))
            .spawn()
            .expect("spawn proxy");

        let mut c = TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .expect("connect");
        c.write_all(b"hello").await.unwrap();

        let mut buf = [0u8; 16];
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn relay_with_latency_inserts_delay() {
        let backend_res = reserve_port().await.expect("backend port");
        let backend_port = backend_res.port;
        spawn_echo(backend_res.into_listener()).await;

        let proxy_res = reserve_port().await.expect("proxy port");
        let proxy_port = proxy_res.port;
        let _proxy = NetworkSimProxy::builder(proxy_res.into_listener())
            .forward_to(("127.0.0.1", backend_port))
            .with_latency(Duration::from_millis(150))
            .spawn()
            .expect("spawn proxy");

        let mut c = TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .expect("connect");
        let started = std::time::Instant::now();
        c.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 8];
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
        // Delay fires on every read+write. Expect at minimum two delay
        // intervals over the round trip: client write + proxy forward,
        // backend read (passthrough), backend write + proxy forward,
        // client read. Being precise about exactly how many is brittle;
        // assert on a comfortable lower bound.
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "elapsed was {:?}, expected ≥ 250ms",
            started.elapsed()
        );
    }
}
