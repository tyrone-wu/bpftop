//! eBPF metrics based on OpenMetrics standard

use std::{fs, io::ErrorKind, os::fd::OwnedFd};

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
pub struct EbpfMetrics {
    /// File descriptor handler for `BPF_ENABLE_STATS`.
    fd_handler: Option<OwnedFd>,

    /// todo
    registry: Registry,

    /// todo
    metrics: RunTimeMetrics,
}

impl EbpfMetrics {
    /// Creates a new metrics registry and initializes metric families for `run_time_ns` and
    /// `run_cnt` stats.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfMetrics;
    ///
    /// let mut ebpf_metrics = EbpfMetrics::new();
    /// ```
    pub fn new() -> Self {
        let mut registry = <Registry>::with_prefix("ebpf_metrics");

        let run_time_ns = Family::<Labels, Counter>::default();
        registry.register_with_unit(
            "run_time_ns",
            "Duration that the eBPF program has been loaded in nanoseconds",
            Unit::Other("nanoseconds".to_owned()),
            run_time_ns.clone(),
        );

        let run_cnt = Family::<Labels, Counter>::default();
        registry.register_with_unit(
            "run_cnt",
            "Execution count of the eBPF program",
            Unit::Other("executions".to_owned()),
            run_cnt.clone(),
        );

        let metrics = RunTimeMetrics {
            run_time_ns,
            run_cnt,
        };

        Self {
            fd_handler: None,
            registry,
            metrics,
        }
    }

    /// Enable BPF stats tracking through `BPF_ENABLE_STATS` BPF syscall with `BPF_STATS_RUN_TIME`
    /// type set.
    ///
    /// Returns `true` if enabled successfully, `false` if not successful, or error if root privileges
    /// are missing.
    ///
    /// Note that `BPF_ENABLE_STATS` was introduced in kernel 5.8, however, some distros backport certain
    /// feature (e.g. Redhat) so checking kernel version may not be sufficient in detecting whether this
    /// feature is available or not.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfMetrics;
    ///
    /// let mut ebpf_metrics = EbpfMetrics::new();
    ///
    /// let is_enabled = ebpf_metrics.enable_stats_fd()?;
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
    /// use ebpf_metrics::EbpfMetrics;
    ///
    /// let mut ebpf_metrics = EbpfMetrics::new();
    /// ebpf_metrics.enable_stats_fd()?;
    ///
    /// ebpf_metrics.disable_stats_fd();
    /// ```
    pub fn disable_stats_fd(&mut self) {
        self.fd_handler = None;
    }

    /// Returns whether BPF stats tracking was enabled through the BPF syscall method.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfMetrics;
    ///
    /// let mut ebpf_metrics = EbpfMetrics::new();
    ///
    /// let is_enabled_fd = ebpf_metrics.is_stats_enabled_fd();
    /// ```
    pub fn is_stats_enabled_fd(&self) -> bool {
        self.fd_handler.is_some()
    }

    /// Enables BPF stats tracking through the `procfs` file for `bpf_stats_enabled`.
    ///
    /// Returns nothing on success, otherwise returns an error on failure.
    ///
    /// Note that stats enabled through `procfs` can persist past the lifetime of this process
    /// if not disabled, as `sysctl` data is directly tied to the host system.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfMetrics;
    ///
    /// EbpfMetrics::enable_stats_procfs()?;
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
    /// use ebpf_metrics::EbpfMetrics;
    ///
    /// EbpfMetrics::enable_stats_procfs()?;
    ///
    /// EbpfMetrics::disable_stats_procfs()?;
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

    /// Returns whether BPF stats tracking was enabled through the `procfs` file.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpf_metrics::EbpfMetrics;
    ///
    /// let is_enabled = EbpfMetrics::is_stats_enabled_procfs();
    /// ```
    pub fn is_stats_enabled_procfs() -> Result<bool, Error> {
        fs::read_to_string(PROCFS_BPF_STATS_ENABLED)
            .context(format!("Failed to read from {}", PROCFS_BPF_STATS_ENABLED))
            .map(|value| value.trim() == "1")
    }

    /// todo
    ///
    /// # Example
    ///
    /// ```no_run
    /// todo
    /// ```
    pub fn record_prog_metrics(&self) {
        for prog in loaded_programs() {
            match prog {
                Ok(info) => {
                    if info.name().is_empty() {
                        continue;
                    }

                    let run_time_ns = info.run_time_ns();
                    let run_cnt = info.run_cnt();

                    let labels = Labels::new(&info);

                    let run_time_metric = &self.metrics.run_time_ns.get_or_create(&labels);
                    run_time_metric.inc_by(run_time_ns - run_time_metric.get());
                    let run_cnt_metric = &self.metrics.run_cnt.get_or_create(&labels);
                    run_cnt_metric.inc_by(run_cnt - run_cnt_metric.get());
                }
                Err(_) => {}
            }
        }
    }

    /// todo
    ///
    /// # Example
    ///
    /// ```no_run
    /// todo
    /// ```
    pub fn print_debug(&self) -> Result<(), std::fmt::Error> {
        let mut buffer = String::new();
        text::encode(&mut buffer, &self.registry)?;
        println!("{}", buffer);
        Ok(())
    }
}

/// todo
#[derive(Debug)]
struct RunTimeMetrics {
    /// todo
    run_time_ns: Family<Labels, Counter>,

    /// todo
    run_cnt: Family<Labels, Counter>,
}

/// todo
#[derive(Clone, Hash, Debug, EncodeLabelSet, Eq, PartialEq)]
struct Labels {
    /// todo
    id: u32,

    /// todo
    program_type: String,

    /// todo
    name: String,
}

impl Labels {
    /// todo
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
