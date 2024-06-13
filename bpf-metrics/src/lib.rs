#![deny(dead_code)]
#![deny(missing_docs)]
#![deny(unused)]

//! Collects and publishes eBPF metadata for programs, maps, and links on the host system, exposing
//! metrics using the OpenMetrics exposition format.
//!
//! ```no_run
//! use bpf_metrics::{BpfMetrics, ProgMetric};
//!
//! // Init registry
//! let mut bpf_metrics = BpfMetrics::new();
//!
//! // Define and register metrics of interest
//! let prog_metrics = [ProgMetric::Uptime, ProgMetric::MemoryLocked];
//! bpf_metrics.register_prog_metrics(prog_metrics.iter());
//!
//! // let map_metrics = [];
//! // bpf_metrics.register_map_metrics(&map_metrics);
//!
//! // let link_metrics = [];
//! // bpf_metrics.register_link_metrics(&link_metrics);
//!
//! // Collect bpf metrics from the host
//! bpf_metrics.collect_metrics();
//!
//! // Export metrics in OpenMetrics text format
//! let mut buffer = String::new();
//! bpf_metrics.export_metrics(&mut buffer);
//! ```

#[cfg(feature = "bpf-stats")]
pub mod bpf_stats;

mod bpf_metrics;
mod link_info;
mod map_info;
pub(crate) mod metric_collection;
mod prog_info;

#[cfg(feature = "metrics")]
pub use bpf_metrics::BpfMetrics;
#[cfg(feature = "metrics")]
pub use link_info::LinkMetric;
#[cfg(feature = "metrics")]
pub use map_info::MapMetric;
#[cfg(feature = "metrics")]
pub use prog_info::ProgMetric;
