//! BPF metrics registry and collector implementation.

use prometheus_client::{encoding::text, registry::Registry};

use crate::{
    metric_collection::{MetricCollection, MetricFamily},
    prog_info::{ProgLabels, ProgMetric},
};

/// BPF metrics registry and collector.
pub struct BpfMetrics {
    /// Registry for where metric families are registered into.
    registry: Registry,
    /// Metrics currently being tracked.
    metrics: Vec<Box<dyn MetricFamily>>,
}

impl BpfMetrics {
    /// Initialize new BPF metrics registry.
    pub fn new() -> Self {
        Self {
            registry: Registry::with_prefix("bpf"),
            metrics: vec![],
        }
    }

    /// Collect and record currently tracking metrics into registry.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bpf_metrics::BpfMetrics;
    /// # use bpf_metrics::ProgMetric;
    ///
    /// let mut bpf_metrics = BpfMetrics::new();
    /// # bpf_metrics.register_prog_metrics([ProgMetric::Uptime].iter());
    ///
    /// bpf_metrics.collect_metrics();
    /// ```
    pub fn collect_metrics(&self) {
        for metric_col in self.metrics.iter() {
            metric_col.collect_metrics();
        }
    }

    /// Exports the metrics into the provided buffer with the OpenMetrics text format.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bpf_metrics::BpfMetrics;
    /// # use bpf_metrics::ProgMetric;
    ///
    /// let mut bpf_metrics = BpfMetrics::new();
    /// # bpf_metrics.register_prog_metrics([ProgMetric::Uptime].iter());
    /// #
    /// # bpf_metrics.collect_metrics();
    ///
    /// let mut buffer = String::new();
    /// bpf_metrics.export_metrics(&mut buffer);
    /// ```
    pub fn export_metrics(&self, buffer: &mut String) -> Result<(), std::fmt::Error> {
        text::encode(buffer, &self.registry)?;
        for metric_col in self.metrics.iter() {
            metric_col.clear_metrics();
        }
        Ok(())
    }

    /// Register [`ProgMetric`]s of interest into the registry.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bpf_metrics::{BpfMetrics, ProgMetric};
    ///
    /// let mut bpf_metrics = BpfMetrics::new();
    ///
    /// let metrics = [ProgMetric::Uptime, ProgMetric::RunTime];
    /// bpf_metrics.register_prog_metrics(metrics.iter());
    /// ```
    pub fn register_prog_metrics<'a>(
        &mut self,
        metric_options: impl Iterator<Item = &'a ProgMetric>,
    ) {
        let prog_metrics = MetricCollection::<ProgMetric, ProgLabels>::init_with_metrics(
            &mut self.registry,
            metric_options,
        );
        self.metrics.push(Box::new(prog_metrics));
    }
}
