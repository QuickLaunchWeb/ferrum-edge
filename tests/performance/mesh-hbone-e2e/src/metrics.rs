//! Latency + throughput histograms and reporting.

use hdrhistogram::Histogram;
use serde::Serialize;

pub struct BenchMetrics {
    histogram: Histogram<u64>,
    pub total_requests: u64,
    pub total_errors: u64,
    pub total_bytes: u64,
}

impl Default for BenchMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl BenchMetrics {
    pub fn new() -> Self {
        Self {
            histogram: Histogram::new_with_max(60_000_000, 3)
                .unwrap_or_else(|_| Histogram::new(3).unwrap()),
            total_requests: 0,
            total_errors: 0,
            total_bytes: 0,
        }
    }

    pub fn record(&mut self, latency_us: u64, bytes: usize) {
        let _ = self.histogram.record(latency_us);
        self.total_requests += 1;
        self.total_bytes += bytes as u64;
    }

    pub fn record_error(&mut self) {
        self.total_errors += 1;
    }

    pub fn merge(&mut self, other: &BenchMetrics) {
        let _ = self.histogram.add(&other.histogram);
        self.total_requests += other.total_requests;
        self.total_errors += other.total_errors;
        self.total_bytes += other.total_bytes;
    }

    pub fn report(
        &self,
        label: &str,
        target: &str,
        concurrency: u64,
        duration_secs: u64,
    ) -> String {
        let rps = if duration_secs > 0 {
            self.total_requests as f64 / duration_secs as f64
        } else {
            0.0
        };
        let throughput_mb = self.total_bytes as f64 / (1024.0 * 1024.0);
        let avg = self.histogram.mean() as u64;
        let p50 = self.histogram.value_at_quantile(0.50);
        let p95 = self.histogram.value_at_quantile(0.95);
        let p99 = self.histogram.value_at_quantile(0.99);
        let max = self.histogram.max();

        format!(
            "  {label}\n  Target: {target}\n  Concurrency: {concurrency}\n\n  Latency  avg {avg}us  p50 {p50}us  p95 {p95}us  p99 {p99}us  max {max}us\n  {req} requests in {dur:.2}s, {mb:.2} MB read\n  Errors: {err}\nRequests/sec: {rps:.2}\n",
            req = self.total_requests,
            dur = duration_secs as f64,
            mb = throughput_mb,
            err = self.total_errors,
        )
    }

    pub fn json(
        &self,
        label: &str,
        target: &str,
        concurrency: u64,
        duration_secs: u64,
    ) -> BenchReport {
        let rps = if duration_secs > 0 {
            self.total_requests as f64 / duration_secs as f64
        } else {
            0.0
        };
        BenchReport {
            label: label.to_string(),
            target: target.to_string(),
            concurrency,
            duration_secs,
            total_requests: self.total_requests,
            total_errors: self.total_errors,
            rps,
            latency_avg_us: self.histogram.mean() as u64,
            p50_us: self.histogram.value_at_quantile(0.50),
            p95_us: self.histogram.value_at_quantile(0.95),
            p99_us: self.histogram.value_at_quantile(0.99),
            latency_max_us: self.histogram.max(),
            total_bytes: self.total_bytes,
        }
    }
}

#[derive(Serialize)]
pub struct BenchReport {
    pub label: String,
    pub target: String,
    pub concurrency: u64,
    pub duration_secs: u64,
    pub total_requests: u64,
    pub total_errors: u64,
    pub rps: f64,
    pub latency_avg_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub latency_max_us: u64,
    pub total_bytes: u64,
}
