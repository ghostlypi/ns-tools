//! Progress reporting and cancellation.
//!
//! The CLI used to poll an `indicatif` bar from a background thread every 100 ms. That
//! coupled the engine to a terminal UI, so it is replaced by a [`ProgressSink`] callback
//! driven directly from the copy loop.
//!
//! The 100 ms rate limit is kept, and it matters more now than it did before: the raw
//! callback fires once per 256 KiB, which on a fast LAN is thousands of calls per second
//! — and on Android each one is a JNI upcall.

use crate::error::TransferError;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How often progress is reported, at most.
const REPORT_INTERVAL: Duration = Duration::from_millis(100);

/// Receives byte-progress updates. `done` is monotonic and clamped to `total`.
pub trait ProgressSink: Send + Sync {
    fn on_progress(&self, done: u64, total: u64);
}

/// A sink that discards everything.
pub struct NoProgress;

impl ProgressSink for NoProgress {
    fn on_progress(&self, _done: u64, _total: u64) {}
}

impl<F> ProgressSink for F
where
    F: Fn(u64, u64) + Send + Sync,
{
    fn on_progress(&self, done: u64, total: u64) {
        self(done, total)
    }
}

/// Cooperative cancellation.
///
/// Checked from inside the copy loop, so it takes effect as soon as the next chunk moves.
/// A connection that has stalled completely is bounded by the socket timeouts in
/// [`crate::SendOpts`] / [`crate::RecvOpts`] instead.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Accumulates byte counts, rate-limits reporting, and polls the cancel token.
pub(crate) struct Meter<'a> {
    sink: &'a dyn ProgressSink,
    cancel: &'a CancelToken,
    total: u64,
    done: u64,
    last_report: Instant,
}

impl<'a> Meter<'a> {
    pub fn new(sink: &'a dyn ProgressSink, cancel: &'a CancelToken, total: u64) -> Self {
        Self {
            sink,
            cancel,
            total,
            done: 0,
            last_report: Instant::now(),
        }
    }

    fn add(&mut self, n: u64) -> io::Result<()> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::other("cancelled"));
        }
        self.done += n;
        if self.last_report.elapsed() >= REPORT_INTERVAL {
            self.last_report = Instant::now();
            self.report();
        }
        Ok(())
    }

    fn report(&self) {
        // Clamp: on the directory path the sender counts tar headers and padding, which
        // are not part of `total` (a sum of file sizes), so `done` can overshoot.
        self.sink.on_progress(self.done.min(self.total), self.total);
    }

    /// Emit a final 100% update. Callers that parse the progress stream — netdrop does —
    /// rely on this last line arriving.
    pub fn finish(&self) {
        self.sink.on_progress(self.total, self.total);
    }

    pub fn bytes(&self) -> u64 {
        self.done
    }
}

pub(crate) struct ProgressWriter<'m, 'a, W: Write> {
    inner: W,
    meter: &'m mut Meter<'a>,
}

impl<'m, 'a, W: Write> ProgressWriter<'m, 'a, W> {
    pub fn new(inner: W, meter: &'m mut Meter<'a>) -> Self {
        Self { inner, meter }
    }
}

impl<W: Write> Write for ProgressWriter<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.meter.add(n as u64)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) struct ProgressReader<'m, 'a, R: Read> {
    inner: R,
    meter: &'m mut Meter<'a>,
}

impl<'m, 'a, R: Read> ProgressReader<'m, 'a, R> {
    pub fn new(inner: R, meter: &'m mut Meter<'a>) -> Self {
        Self { inner, meter }
    }
}

impl<R: Read> Read for ProgressReader<'_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.meter.add(n as u64)?;
        Ok(n)
    }
}

/// Map an I/O failure to [`TransferError::Cancelled`] when cancellation is what actually
/// caused it. The flag is the source of truth; the io::Error is just how the copy loop
/// unwinds.
pub(crate) fn classify(err: TransferError, cancel: &CancelToken) -> TransferError {
    if cancel.is_cancelled() {
        TransferError::Cancelled
    } else {
        err
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(u64, u64)>>);

    impl ProgressSink for Recorder {
        fn on_progress(&self, done: u64, total: u64) {
            self.0.lock().unwrap().push((done, total));
        }
    }

    #[test]
    fn finish_always_reports_completion() {
        let rec = Recorder::default();
        let cancel = CancelToken::new();
        let meter = Meter::new(&rec, &cancel, 1000);
        meter.finish();
        assert_eq!(*rec.0.lock().unwrap(), vec![(1000, 1000)]);
    }

    /// Guards the directory-transfer overshoot: tar headers and padding are counted by
    /// the writer but are not part of the size in the header.
    #[test]
    fn reported_progress_is_clamped_to_total() {
        let rec = Recorder::default();
        let cancel = CancelToken::new();
        let mut meter = Meter::new(&rec, &cancel, 10);
        meter.last_report = Instant::now() - Duration::from_secs(1);
        meter.add(50).unwrap();
        assert_eq!(rec.0.lock().unwrap()[0], (10, 10), "done must not exceed total");
    }

    #[test]
    fn cancellation_stops_the_copy_loop() {
        let cancel = CancelToken::new();
        let mut meter = Meter::new(&NoProgress, &cancel, 100);
        assert!(meter.add(1).is_ok());
        cancel.cancel();
        assert!(meter.add(1).is_err(), "should refuse to continue once cancelled");
    }

    #[test]
    fn closures_can_be_used_as_sinks() {
        let hits = Arc::new(AtomicBool::new(false));
        let h = hits.clone();
        let sink = move |_d: u64, _t: u64| h.store(true, Ordering::Relaxed);
        sink.on_progress(1, 2);
        assert!(hits.load(Ordering::Relaxed));
    }
}
