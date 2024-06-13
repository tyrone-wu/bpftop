//! Metrics for `bpf_prog_info`.

use std::time::SystemTime;

use aya::{loaded_programs, programs::ProgramInfo};
use prometheus_client::{
    encoding::EncodeLabelSet,
    registry::{Registry, Unit},
};

use crate::metric_collection::{Collector, MetricCollection};

/// Metric options for the `bpf_prog_info` object.
///
/// # Example
///
/// ```no_run
/// use bpf_metrics::{BpfMetrics, ProgMetric};
///
/// // Init metrics registry
/// let mut bpf_metrics = BpfMetrics::new();
///
/// // Select and register metrics of interest
/// let metrics = [ProgMetric::RunTime, ProgMetric::RunCount];
/// bpf_metrics.register_prog_metrics(metrics.iter());
/// ```
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum ProgMetric {
    /// Size of program's JIT-compiled machine code in bytes.
    SizeJitted,
    /// Size of program's translated bytecode in bytes.
    SizeTranslated,
    /// Total duration program has been loaded on the host in nanoseconds.
    Uptime,
    // /// Maps used by the program.
    // MapIds,
    /// Accumulated time program has been actively running in nanoseconds.
    RunTime,
    /// Accumulated execution count of the program.
    RunCount,
    /// Number of verified instructions in the program.
    VerifiedInstructions,
    /// Amount of memory allocated and locked for the program in bytes.
    MemoryLocked,
}

/// Label identifier for a program metric.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct ProgLabels {
    /// Program type
    prog_type: String,
    /// Unique ID of the program
    id: u32,
    /// SHA sum of the program's instructions
    tag: u64,
    /// Program name
    name: String,
}

impl ProgLabels {
    fn new(prog_info: &ProgramInfo) -> Self {
        Self {
            prog_type: prog_info.program_type_enum().to_string(),
            id: prog_info.id(),
            tag: prog_info.tag(),
            name: prog_info.name_as_str().unwrap_or_default().to_owned(),
        }
    }
}

impl MetricCollection<ProgMetric, ProgLabels> {
    /// Init and attach sub-registry to root registry, with the selected prog metrics.
    pub(crate) fn init_with_metrics<'a>(
        registry: &mut Registry,
        metrics_iter: impl Iterator<Item = &'a ProgMetric>,
    ) -> Self {
        let prog_registry = registry.sub_registry_with_prefix("prog");
        let mut prog_metrics = MetricCollection::<ProgMetric, ProgLabels>::default();

        for metric in metrics_iter {
            match metric {
                ProgMetric::SizeJitted => prog_metrics.register_gauge(
                    prog_registry,
                    ProgMetric::SizeJitted,
                    "size_jitted",
                    "Size of program's JIT-compiled machine code",
                    Unit::Bytes,
                ),
                ProgMetric::SizeTranslated => prog_metrics.register_gauge(
                    prog_registry,
                    ProgMetric::SizeTranslated,
                    "size_translated",
                    "Size of program's translated bytecode",
                    Unit::Bytes,
                ),
                ProgMetric::Uptime => prog_metrics.register_counter(
                    prog_registry,
                    ProgMetric::Uptime,
                    "uptime",
                    "Duration program has been loaded",
                    Unit::Other("nanoseconds".to_owned()),
                ),
                // ProgMetric::MapIds => todo!(), // TODO
                ProgMetric::RunTime => prog_metrics.register_counter(
                    prog_registry,
                    ProgMetric::RunTime,
                    "run_time",
                    "Accumulated duration the program has actively ran",
                    Unit::Other("nanoseconds".to_owned()),
                ),
                ProgMetric::RunCount => prog_metrics.register_counter(
                    prog_registry,
                    ProgMetric::RunCount,
                    "execution",
                    "Accumulated execution count of the program",
                    Unit::Other("count".to_owned()),
                ),
                ProgMetric::VerifiedInstructions => prog_metrics.register_gauge(
                    prog_registry,
                    ProgMetric::VerifiedInstructions,
                    "verified_instruction",
                    "Number of verified instructions in the program",
                    Unit::Other("count".to_owned()),
                ),
                ProgMetric::MemoryLocked => prog_metrics.register_gauge(
                    prog_registry,
                    ProgMetric::MemoryLocked,
                    "memory_locked",
                    "Amount of memory allocated and locked for the program",
                    Unit::Bytes,
                ),
            }
        }

        prog_metrics
    }
}

impl Collector for MetricCollection<ProgMetric, ProgLabels> {
    fn collect_metrics(&self) {
        for prog in loaded_programs() {
            if let Ok(info) = prog {
                if info.name().is_empty() {
                    continue;
                }
                let labels = ProgLabels::new(&info);

                // Uptime
                let uptime = match SystemTime::now().duration_since(info.loaded_at()) {
                    Ok(uptime) => uptime.as_nanos() as u64,
                    Err(_) => continue,
                };
                self.update_counter(&ProgMetric::Uptime, &labels, uptime);
                // Size jitted
                self.update_gauge(&ProgMetric::SizeJitted, &labels, info.size_jitted().into());
                // Size translated
                self.update_gauge(
                    &ProgMetric::SizeTranslated,
                    &labels,
                    info.size_translated().into(),
                );
                // Run time
                self.update_counter(&ProgMetric::RunTime, &labels, info.run_time_ns());
                // Run count
                self.update_counter(&ProgMetric::RunCount, &labels, info.run_cnt());
                // Verified instructions
                self.update_gauge(
                    &ProgMetric::VerifiedInstructions,
                    &labels,
                    info.verified_instruction_count().into(),
                );
                // Memory locked
                self.update_gauge(
                    &ProgMetric::MemoryLocked,
                    &labels,
                    info.memory_locked().unwrap_or_default().into(),
                );
            }
        }
    }
}
