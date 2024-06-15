//! eBPF metrics based on OpenMetrics standard

use std::{fs, io::ErrorKind, os::fd::OwnedFd, time::SystemTime};

use anyhow::{anyhow, Context, Error};
use aya::{loaded_programs, programs::ProgramInfo, Ebpf};
use aya_obj::BpfStatsType;
use prometheus_client::{
    encoding::{text, EncodeLabelSet},
    metrics::{counter::Counter, family::Family},
    registry::{Registry, Unit},
};

/// The sysctl file for enabling/disabling statistics collection.
const PROCFS_BPF_STATS_ENABLED: &str = "/proc/sys/kernel/bpf_stats_enabled";

/// eBPF metrics registry
#[derive(Debug)]
pub struct EbpfOpenMetrics {
    /// File descriptor handler for `BPF_ENABLE_STATS`.
    fd_handler: Option<OwnedFd>,

    /// OpenMetrics registry and metrics.
    pub metrics_handler: OpenMetrics,
}

#[derive(Debug)]
pub struct OpenMetrics {
    /// OpenMetrics registry.
    registry: Registry,

    /// Metric families that are recorded.
    metrics: ProgramMetrics,
}

impl EbpfOpenMetrics {
    /// Initializes new metrics registry and metric families for `run_time_ns`, `run_cnt`, and
    /// time loaded stats.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfOpenMetrics;
    ///
    /// let mut ebpf_metrics = EbpfOpenMetrics::new();
    /// ```
    pub fn new() -> Self {
        let metrics_handler = OpenMetrics::new();
        Self {
            fd_handler: None,
            metrics_handler,
        }
    }

    /// Enable BPF stats tracking through `BPF_ENABLE_STATS` with `BPF_STATS_RUN_TIME` type set.
    ///
    /// Returns `true` if enabled successfully, `false` if not successful, or error if root privileges
    /// are missing.
    ///
    /// Note that `BPF_ENABLE_STATS` was introduced in kernel 5.8, however, some distros backport certain
    /// feature (e.g. Red Hat) so checking kernel version may not be sufficient in detecting whether this
    /// feature is available or not.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfOpenMetrics;
    ///
    /// let mut ebpf_metrics = EbpfOpenMetrics::new();
    ///
    /// let successful = match ebpf_metrics.enable_stats_fd() {
    ///     Ok(successful) => successful,
    ///     Err(_) => false,
    /// };
    /// ```
    pub fn enable_stats_fd(&mut self) -> Result<bool, Error> {
        if self.is_stats_enabled_fd() {
            return Ok(true);
        }

        match Ebpf::enable_stats_fd(BpfStatsType::RunTime) {
            Ok(fd) => {
                self.fd_handler = Some(fd);
                return Ok(true);
            }
            Err(err) => {
                if err.io_error.kind() == ErrorKind::PermissionDenied {
                    return Err(anyhow!("Root/CAP_SYS_ADMIN privileges required"));
                }
            }
        };
        Ok(false)
    }

    /// Disable BPF stats tracking by releases the file descriptor reference to `BPF_ENABLE_STATS`.
    ///
    /// Note that the fd handler works as a reference counter to the BPF object. Once there are no more
    /// references to the fd, stats tracking is disabled.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfOpenMetrics;
    ///
    /// let mut ebpf_metrics = EbpfOpenMetrics::new();
    /// # ebpf_metrics.enable_stats_fd()?;
    ///
    /// ebpf_metrics.disable_stats_fd();
    /// let is_enabled = ebpf_metrics.is_stats_enabled_fd();
    /// assert!(!is_enabled);
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn disable_stats_fd(&mut self) {
        self.fd_handler = None;
    }

    /// Returns whether BPF stats tracking is currently enabled with the BPF syscall method.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfOpenMetrics;
    ///
    /// let mut ebpf_metrics = EbpfOpenMetrics::new();
    /// ebpf_metrics.enable_stats_fd()?;
    ///
    /// let is_enabled = ebpf_metrics.is_stats_enabled_fd();
    /// assert!(is_enabled);
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn is_stats_enabled_fd(&self) -> bool {
        self.fd_handler.is_some()
    }

    /// Enables BPF stats tracking through the `procfs` file for `bpf_stats_enabled`.
    ///
    /// Returns nothing on success, otherwise returns an error on failure.
    ///
    /// Note that stats enabled through `procfs` can persist past the lifetime of this process
    /// if not disabled afterwards, as `sysctl` data is directly tied to the host system.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfOpenMetrics;
    ///
    /// EbpfOpenMetrics::enable_stats_procfs()?;
    ///
    /// let is_enabled = EbpfOpenMetrics::is_stats_enabled_procfs()?;
    /// assert!(is_enabled);
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn enable_stats_procfs() -> Result<(), Error> {
        if Self::is_stats_enabled_procfs()? {
            return Ok(());
        }

        fs::write(PROCFS_BPF_STATS_ENABLED, b"1").context(format!(
            "Failed to enable BPF stats via {}",
            PROCFS_BPF_STATS_ENABLED
        ))?;
        Ok(())
    }

    /// Disable BPF stats tracking through the `procfs` file for `bpf_stats_enabled`.
    ///
    /// Returns nothing on success, otherwise returns an error on failure.
    ///
    /// Note that stats enabled through `procfs` can persist past the lifetime of this process
    /// if not disabled, as `sysctl` data is directly tied to the host system.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfOpenMetrics;
    ///
    /// EbpfOpenMetrics::disable_stats_procfs()?;
    ///
    /// let is_enabled = EbpfOpenMetrics::is_stats_enabled_procfs()?;
    /// assert!(!is_enabled);
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn disable_stats_procfs() -> Result<(), Error> {
        if !Self::is_stats_enabled_procfs()? {
            return Ok(());
        }

        fs::write(PROCFS_BPF_STATS_ENABLED, b"0").context(format!(
            "Failed to disable BPF stats via {}",
            PROCFS_BPF_STATS_ENABLED
        ))?;
        Ok(())
    }

    /// Returns whether BPF stats tracking is currently enabled through `sysctl`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfOpenMetrics;
    ///
    /// EbpfOpenMetrics::enable_stats_procfs()?;
    ///
    /// let is_enabled = EbpfOpenMetrics::is_stats_enabled_procfs()?;
    /// assert!(is_enabled);
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn is_stats_enabled_procfs() -> Result<bool, Error> {
        fs::read_to_string(PROCFS_BPF_STATS_ENABLED)
            .context(format!("Failed to read from {}", PROCFS_BPF_STATS_ENABLED))
            .map(|value| value.trim() == "1")
    }
}

impl OpenMetrics {
    /// Initializes new metrics registry and metric families for `run_time_ns`, `run_cnt`, and
    /// time loaded stats.
    fn new() -> Self {
        let mut registry = <Registry>::with_prefix("ebpf");

        let run_time_ns = Family::<Labels, Counter>::default();
        registry.register_with_unit(
            "run_time",
            "Duration that the program has been running",
            Unit::Other("nanoseconds".to_owned()),
            run_time_ns.clone(),
        );

        let run_cnt = Family::<Labels, Counter>::default();
        registry.register_with_unit(
            "execution",
            "Execution count of the program",
            Unit::Other("count".to_owned()),
            run_cnt.clone(),
        );

        let uptime = Family::<Labels, Counter>::default();
        registry.register_with_unit(
            "uptime",
            "Duration that the program has been loaded",
            Unit::Other("nanoseconds".to_owned()),
            uptime.clone(),
        );

        let metrics = ProgramMetrics {
            run_time_ns,
            run_cnt,
            uptime,
        };
        Self { registry, metrics }
    }

    /// Record program metrics for `run_time_ns`, `run_cnt`, and time loaded.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfOpenMetrics;
    ///
    /// let mut metrics = EbpfOpenMetrics::new();
    /// metrics.enable_stats_fd()?;
    ///
    /// metrics.metrics_handler.record_metrics();
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn record_metrics(&self) {
        for prog in loaded_programs() {
            match prog {
                Ok(info) => {
                    if info.name().is_empty() {
                        continue;
                    }

                    let run_time_ns = info.run_time_ns();
                    let run_cnt = info.run_cnt();
                    let uptime = match SystemTime::now().duration_since(info.loaded_at()) {
                        Ok(time) => time.as_nanos() as u64,
                        Err(_) => continue,
                    };

                    let labels = Labels::new(&info);

                    let run_time_metric = &self.metrics.run_time_ns.get_or_create(&labels);
                    run_time_metric.inc_by(run_time_ns - run_time_metric.get());
                    let run_cnt_metric = &self.metrics.run_cnt.get_or_create(&labels);
                    run_cnt_metric.inc_by(run_cnt - run_cnt_metric.get());
                    let uptime_metric = &self.metrics.uptime.get_or_create(&labels);
                    uptime_metric.inc_by(uptime - uptime_metric.get());
                }
                Err(_) => {}
            }
        }
    }

    /// Scrape metrics from registry into a buffer in OpenMetrics text format.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfOpenMetrics;
    ///
    /// let mut metrics = EbpfOpenMetrics::new();
    /// # metrics.enable_stats_fd()?;
    /// metrics.metrics_handler.record_metrics();
    ///
    /// let mut buffer = String::new();
    /// metrics.metrics_handler.scrape_metrics(&mut buffer)?;
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn scrape_metrics(&self, buffer: &mut String) -> Result<(), std::fmt::Error> {
        text::encode(buffer, &self.registry)?;
        Ok(())
    }
}

/// Program metrics to record.
#[derive(Debug)]
struct ProgramMetrics {
    /// Duration program has been running in nanoseconds.
    run_time_ns: Family<Labels, Counter>,

    /// Execution count of the program.
    run_cnt: Family<Labels, Counter>,

    /// Duration program has been loaded in nanoseconds.
    uptime: Family<Labels, Counter>,
}

/// Information labels of the program.
#[derive(Clone, Hash, Debug, EncodeLabelSet, Eq, PartialEq)]
struct Labels {
    /// ID of program.
    id: u32,

    /// Program type.
    program_type: String,

    /// Name of program.
    name: String,
}

impl Labels {
    /// Initializes the labels of a program given the info.
    fn new(prog_info: &ProgramInfo) -> Self {
        let program_type = match prog_info.program_type_enum() {
            Ok(program_type) => program_type.to_string(),
            Err(_) => "Invalid".to_owned(),
        };
        Self {
            id: prog_info.id(),
            program_type,
            name: prog_info.name_as_str().unwrap().to_owned(),
        }
    }
}
