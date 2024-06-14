## Example Usages

This directory contain example usages of `bpf-metrics` with various monitoring vendors.

Since this library requires root privileges, you must first build the binary so that it can be executed with `sudo`.

```bash
# Build binary
cargo build --example $name

# Execute with root privileges
sudo ./target/debug/examples/$name
```

### Prometheus

An example config file and console template have been provided, with the endpoint exposed at port `8001`.

The console template can be reach at [`localhost:9090/consoles/prog-metrics.html`](localhost:9090/consoles/prog-metrics.html).

```bash
prometheus \
    --config.file ./bpf-metrics/examples/prometheus/prometheus.yml \
    --web.console.templates ./bpf-metrics/examples/prometheus/consoles/ \
    --web.console.libraries /etc/prometheus/console_libraries/
```
