use std::collections::BTreeMap;

use nom::{
    branch::alt,
    bytes::{
        self,
        streaming::{tag, take_until, take_until1},
    },
    character::{self, complete, streaming},
    multi::{count, fold_many0, separated_list0},
    sequence::{delimited, preceded, tuple},
    IResult,
};

use crate::bpf_program::BpfProgram;

/// Compile metrics into list from the OpenMetrics text format.
pub(crate) fn deserialize(buffer: &str) -> IResult<&str, impl Iterator<Item = BpfProgram>> {
    // OpenMetrics text format is represented as a columnstore. Since the order of emitted metrics
    // is non-deterministic, we collect and compile together based on ID.
    let (buffer, metrics) = fold_many0(
        parse_section,
        BTreeMap::new,
        |mut acc: BTreeMap<u32, BpfProgram>, metrics| {
            for (metric_name, (prog_id, prog_type, prog_name), counter) in metrics {
                let prog = acc.entry(prog_id).or_insert_with(|| BpfProgram {
                    id: prog_id,
                    bpf_type: prog_type.to_owned(),
                    name: prog_name.to_owned(),
                    prev_runtime_ns: 0,
                    run_time_ns: 0,
                    prev_run_cnt: 0,
                    run_cnt: 0,
                    uptime: 0,
                    period_ns: 0,
                    processes: vec![],
                });
                match metric_name {
                    "run_time_nanoseconds" => prog.run_time_ns = counter,
                    "execution_count" => prog.run_cnt = counter,
                    _ => prog.uptime = counter,
                }
            }
            acc
        },
    )(buffer)?;

    // Ensure there's nothing more in the buffer
    assert_eq!("# EOF\n", buffer);

    Ok((buffer, metrics.into_values()))
}

/// Parses an entire metric section, starting with the metadata portion and then the metrics
/// portion.
fn parse_section(buffer: &str) -> IResult<&str, Vec<(&str, (u32, &str, &str), u64)>> {
    let (buffer, section) = preceded(
        // Parse metadata portion
        count(
            tuple((
                complete::char('#'),
                take_until1("\n"),
                streaming::char('\n'),
            )),
            3,
        ),
        // Grab metrics portion
        take_until("#"),
    )(buffer)?;
    // Parse metrics portion
    let (_, metrics) = separated_list0(complete::char('\n'), parse_metric)(section)?;

    Ok((buffer, metrics))
}

/// Parses a metric line.
fn parse_metric(buffer: &str) -> IResult<&str, (&str, (u32, &str, &str), u64)> {
    // Parse metric name
    let (buffer, metric_name) = delimited(
        bytes::complete::tag("ebpf_"),
        alt((
            tag("run_time_nanoseconds"),
            tag("execution_count"),
            tag("time_loaded_nanoseconds"),
        )),
        tag("_total"),
    )(buffer)?;

    // Parse labels
    let (buffer, labels) = delimited(
        tag("{id=\""),
        tuple((
            character::streaming::u32,
            delimited(
                tag("\",program_type=\""),
                take_until("\""),
                tag("\",name=\""),
            ),
            take_until("\""),
        )),
        tag("\"}"),
    )(buffer)?;

    // Parse measurement
    let (buffer, counter) = preceded(streaming::char(' '), character::streaming::u64)(buffer)?;

    Ok((buffer, (metric_name, labels, counter)))
}
