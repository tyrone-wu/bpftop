//! Prints metrics to terminal in 1 second interval.

use std::{thread::sleep, time::Duration};

use anyhow::Result;
use bpf_metrics::{bpf_stats::enable_stats_fd, BpfMetrics, ProgMetric};

fn main() -> Result<()> {
    let mut bpf_metrics = BpfMetrics::new();
    let prog_metrics = [
        ProgMetric::SizeJitted,
        ProgMetric::SizeTranslated,
        ProgMetric::Uptime,
        ProgMetric::RunTime,
        ProgMetric::RunCount,
        ProgMetric::VerifiedInstructions,
        ProgMetric::MemoryLocked,
    ];
    bpf_metrics.register_prog_metrics(prog_metrics.iter());

    let _fd = match enable_stats_fd()? {
        Some(fd) => fd,
        None => panic!("BPF_ENABLE_STATS not available"),
    };

    let mut buffer = String::new();
    loop {
        bpf_metrics.collect_metrics();
        buffer.clear();
        if let Err(err) = bpf_metrics.export_metrics(&mut buffer) {
            panic!("{err}");
        }
        println!("{buffer}\n---\n");

        sleep(Duration::from_secs(1));
    }
}
