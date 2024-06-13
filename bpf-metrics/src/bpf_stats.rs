//! This modules provides functionalities for managing bpf stats.
//!
//! ```no_run
//! use bpf_metrics::bpf_stats::{
//!     disable_stats_procfs, enable_stats_fd, enable_stats_procfs, is_stats_enabled_procfs,
//! };
//!
//! // Attempt to enable bpf stats tracking via syscall
//! let mut fd = enable_stats_fd()?;
//! let enabled_fd = fd.is_some();
//!
//! // If feature is not available, attempt to enable through procfs
//! if !enabled_fd {
//!     enable_stats_procfs()?;
//! }
//! let mut enabled_procfs = is_stats_enabled_procfs()?;
//!
//! // Should result in bpf stats enabled either way
//! assert!(enabled_fd || enabled_procfs);
//!
//! // Cleanup
//! if enabled_procfs {
//!     // Disable stats through procfs if enabled via this method
//!     disable_stats_procfs()?;
//!     enabled_procfs = is_stats_enabled_procfs()?;
//! } else {
//!     // Release reference to bpf object.
//!     //
//!     // If the variable `fd` goes out of scope, then the reference to the bpf object will also
//!     // be released.
//!     fd = None;
//! }
//! assert!(!enabled_procfs);
//! # Ok::<(), anyhow::Error>(())
//! ```

use std::{fs, io::ErrorKind, os::fd::OwnedFd};

use anyhow::{anyhow, Context};
use aya::Ebpf;
use aya_obj::BpfStatsType;

/// The `procfs` file for controlling bpf stats tracking.
const PROCFS_BPF_STATS_ENABLED: &str = "/proc/sys/kernel/bpf_stats_enabled";

/// Enable BPF statistics tracking through `BPF_ENABLE_STATS` syscall with `BPF_STATS_RUN_TIME`
/// type.
///
/// Returns `Some` file descriptor if enabled successfully, `None` if feature is not available on
/// the host, or `Error` if a syscall error occurs (e.g. `CAP_SYS_ADMIN` capability missing, etc.).
///
/// **Note:** `BPF_ENABLE_STATS` was introduced in kernel 5.8, however, some distros backport
/// certain feature (e.g. Red Hat). Therefore, checking kernel version is not be sufficient in
/// detecting whether this feature is available or not.
///
/// # Example
///
/// ```no_run
/// use bpf_metrics::bpf_stats::enable_stats_fd;
///
/// let fd_opt = enable_stats_fd()?;
///
/// // Is feature available on host system
/// let feat_available = fd_opt.is_some();
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn enable_stats_fd() -> Result<Option<OwnedFd>, anyhow::Error> {
    let fd = match Ebpf::enable_stats_fd(BpfStatsType::RunTime) {
        Ok(fd) => Some(fd),
        Err(err) => match err.io_error.kind() {
            ErrorKind::InvalidInput => None, // EINVAL
            _ => return Err(anyhow!("{err}")),
        },
    };
    Ok(fd)
}

/// Enables BPF stats tracking through the `procfs` file for `bpf_stats_enabled`.
///
/// Returns nothing on success, otherwise returns `Error` on failure.
///
/// **Note:** Enabling bpf stats through `procfs` will continue to remain active (even beyond the
/// your program's lifetime) unless explicity disabled (either [disable_stats_procfs] or manually).
///
/// # Example
///
/// ```no_run
/// use bpf_metrics::bpf_stats::{enable_stats_procfs, is_stats_enabled_procfs};
///
/// enable_stats_procfs()?;
///
/// let enabled = is_stats_enabled_procfs()?;
/// assert!(enabled);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn enable_stats_procfs() -> Result<(), anyhow::Error> {
    fs::write(PROCFS_BPF_STATS_ENABLED, b"1").context(format!(
        "Failed to enable BPF stats via {}",
        PROCFS_BPF_STATS_ENABLED
    ))?;
    Ok(())
}

/// Disable BPF stats tracking through the `procfs` file for `bpf_stats_enabled`.
///
/// Returns nothing on success, otherwise returns `Error` on failure.
///
/// **Note:** Enabling bpf stats through `procfs` will continue to remain active (even beyond the
/// your program's lifetime) unless explicity disabled (either [disable_stats_procfs] or manually).
///
/// # Example
///
/// ```no_run
/// use bpf_metrics::bpf_stats::{disable_stats_procfs, is_stats_enabled_procfs};
/// # use bpf_metrics::bpf_stats::enable_stats_procfs;
///
/// # enable_stats_procfs()?;
/// # let enabled = is_stats_enabled_procfs()?;
/// # assert!(enabled);
/// #
/// disable_stats_procfs()?;
///
/// let enabled = is_stats_enabled_procfs()?;
/// assert!(!enabled);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn disable_stats_procfs() -> Result<(), anyhow::Error> {
    fs::write(PROCFS_BPF_STATS_ENABLED, b"0").context(format!(
        "Failed to disable BPF stats via {}",
        PROCFS_BPF_STATS_ENABLED
    ))?;
    Ok(())
}

/// Returns whether BPF stats tracking is currently enabled through the `procfs` file.
///
/// # Example
///
/// ```no_run
/// use bpf_metrics::bpf_stats::{enable_stats_procfs, is_stats_enabled_procfs};
///
/// enable_stats_procfs()?;
///
/// let enabled = is_stats_enabled_procfs()?;
/// assert!(enabled);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn is_stats_enabled_procfs() -> Result<bool, anyhow::Error> {
    fs::read_to_string(PROCFS_BPF_STATS_ENABLED)
        .context(format!("Failed to read from {}", PROCFS_BPF_STATS_ENABLED))
        .map(|value| value.trim() == "1")
}
