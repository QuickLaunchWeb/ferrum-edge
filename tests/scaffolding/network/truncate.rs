//! `TruncatedStream` — stop reading / writing after N bytes, optionally
//! after a pre-close delay.
//!
//! Models "backend writes half the response then disconnects". The
//! wrapper tracks a per-direction byte counter; once the threshold is
//! reached:
//!
//! - **Writes**: further `poll_write` calls return `Ok(0)` (EOF-like
//!   semantics that higher-level hyper/reqwest paths interpret as
//!   "connection closed") — or, optionally, an `io::ErrorKind::BrokenPipe`.
//! - **Reads**: further `poll_read` calls return `Ok(())` with zero
//!   bytes (EOF).
//!
//! If `truncate_delay` is set, the wrapper delays the first
//! post-threshold poll by that duration — useful for asserting "gateway
//! observed the N-byte prefix in X ms before seeing EOF at X+delay".

use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

// Sleep is `!Unpin`; boxing it keeps the outer type `Unpin` so the
// standard tokio extension futures (`read`, `write_all`, etc.) work.
type BoxedSleep = Pin<Box<Sleep>>;

pin_project! {
    pub struct TruncatedStream<T> {
        #[pin]
        inner: T,
        after_bytes: Option<usize>,
        pre_close_delay: Duration,
        // Shared counter so read and write both contribute to the same
        // budget — the common "close after N bytes either direction"
        // case. Separate fields would fragment the budget and surprise
        // callers.
        counter: Arc<AtomicUsize>,
        close_sleep: Option<BoxedSleep>,
        closed: bool,
    }
}

impl<T> TruncatedStream<T> {
    /// Close after `after_bytes` total bytes have flowed in either
    /// direction. `None` disables the limit (the wrapper becomes a
    /// straight pass-through).
    pub fn new(inner: T, after_bytes: usize) -> Self {
        Self {
            inner,
            after_bytes: Some(after_bytes),
            pre_close_delay: Duration::ZERO,
            counter: Arc::new(AtomicUsize::new(0)),
            close_sleep: None,
            closed: false,
        }
    }

    /// Delay the close by `delay` after the threshold is reached. Useful
    /// for "served the header bytes, then disconnected" semantics.
    pub fn with_pre_close_delay(mut self, delay: Duration) -> Self {
        self.pre_close_delay = delay;
        self
    }

    /// Number of bytes that have flowed so far (read + write). Callers
    /// can snapshot this mid-test for additional assertions.
    pub fn byte_count(&self) -> usize {
        self.counter.load(Ordering::SeqCst)
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> AsyncRead for TruncatedStream<T>
where
    T: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();

        if *this.closed {
            return Poll::Ready(Ok(())); // EOF
        }

        if should_trigger_close(*this.after_bytes, this.counter.load(Ordering::SeqCst)) {
            if !this.pre_close_delay.is_zero() && this.close_sleep.is_none() {
                *this.close_sleep = Some(Box::pin(tokio::time::sleep(*this.pre_close_delay)));
            }
            if let Some(sleep) = this.close_sleep.as_mut() {
                match sleep.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(()) => {}
                }
            }
            *this.closed = true;
            return Poll::Ready(Ok(())); // EOF
        }

        // Cap the read buffer to the remaining byte budget so a single
        // `poll_read` can't deliver well past `after_bytes`. Without
        // this cap, mid-stream truncation tests can miss the exact
        // cutoff — the counter crosses the threshold mid-call and only
        // the NEXT poll triggers the close, meanwhile an additional
        // chunk of inner data has already been handed up. Mirrors the
        // write-side slicing below.
        let remaining = remaining_budget(*this.after_bytes, this.counter.load(Ordering::SeqCst));
        if this.after_bytes.is_some() && remaining < buf.remaining() {
            // Sub ReadBuf backed by a scratch buffer so we can slice
            // the read to `remaining` bytes. `ReadBuf::take` shares
            // memory with the outer but doesn't propagate `filled()`
            // back, so we use the same scratch pattern the bandwidth
            // limiter uses.
            let mut scratch = [0u8; 65535];
            let slice_len = remaining.min(scratch.len());
            let mut sub = ReadBuf::new(&mut scratch[..slice_len]);
            let res = this.inner.poll_read(cx, &mut sub);
            if let Poll::Ready(Ok(())) = &res {
                let filled = sub.filled();
                buf.put_slice(filled);
                this.counter.fetch_add(filled.len(), Ordering::SeqCst);
            }
            res
        } else {
            let pre_len = buf.filled().len();
            let res = this.inner.poll_read(cx, buf);
            if let Poll::Ready(Ok(())) = res {
                let delta = buf.filled().len() - pre_len;
                this.counter.fetch_add(delta, Ordering::SeqCst);
            }
            res
        }
    }
}

impl<T> AsyncWrite for TruncatedStream<T>
where
    T: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();

        if *this.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "truncated stream: write after close",
            )));
        }

        if should_trigger_close(*this.after_bytes, this.counter.load(Ordering::SeqCst)) {
            if !this.pre_close_delay.is_zero() && this.close_sleep.is_none() {
                *this.close_sleep = Some(Box::pin(tokio::time::sleep(*this.pre_close_delay)));
            }
            if let Some(sleep) = this.close_sleep.as_mut() {
                match sleep.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(()) => {}
                }
            }
            *this.closed = true;
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "truncated stream: close after threshold",
            )));
        }

        // Enforce that we don't write past the threshold in one call.
        let remaining_budget =
            remaining_budget(*this.after_bytes, this.counter.load(Ordering::SeqCst));
        let slice = if remaining_budget >= buf.len() {
            buf
        } else {
            &buf[..remaining_budget]
        };

        let res = this.inner.poll_write(cx, slice);
        if let Poll::Ready(Ok(n)) = res {
            this.counter.fetch_add(n, Ordering::SeqCst);
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

fn should_trigger_close(threshold: Option<usize>, count: usize) -> bool {
    match threshold {
        Some(n) => count >= n,
        None => false,
    }
}

fn remaining_budget(threshold: Option<usize>, count: usize) -> usize {
    match threshold {
        Some(n) => n.saturating_sub(count),
        None => usize::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn truncate_after_n_bytes_write_reports_broken_pipe() {
        let (a, mut b) = tokio::io::duplex(4096);
        let mut a = TruncatedStream::new(a, 4);
        // First 4 bytes go through.
        a.write_all(b"abcd").await.unwrap();
        a.flush().await.unwrap();
        // Next write hits the threshold.
        let err = a.write_all(b"e").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

        // Reader sees only the first 4 bytes; then reaches EOF after drop.
        drop(a);
        let mut buf = [0u8; 8];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcd");
    }

    #[tokio::test]
    async fn truncate_splits_oversize_write_at_threshold() {
        let (a, mut b) = tokio::io::duplex(4096);
        let mut a = TruncatedStream::new(a, 4);
        // Ask for 10 bytes; wrapper should let only 4 through.
        let n = a.write(b"abcdefghij").await.unwrap();
        assert_eq!(n, 4);
        a.flush().await.unwrap();

        let err = a.write_all(b"k").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

        drop(a);
        let mut buf = [0u8; 16];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcd");
    }

    /// Regression: `poll_read` must cap the read at the remaining
    /// budget so a single poll cannot deliver more than `after_bytes`
    /// even when the inner stream has plenty of data queued up. Pre-fix
    /// this test would return all 100 queued bytes in one call.
    #[tokio::test]
    async fn truncate_caps_read_at_remaining_budget_even_when_buf_is_bigger() {
        let (mut a, b) = tokio::io::duplex(4096);
        a.write_all(&[0u8; 100]).await.unwrap();
        drop(a); // EOF — inner has 100 bytes readable, then EOF.

        let mut t = TruncatedStream::new(b, 10);
        let mut buf = [0u8; 64]; // caller buffer is larger than the budget
        let n = t.read(&mut buf).await.unwrap();
        assert_eq!(n, 10, "single poll_read must not exceed after_bytes");
        assert_eq!(t.byte_count(), 10);

        // Next read hits the threshold and returns EOF.
        let n = t.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }
}
