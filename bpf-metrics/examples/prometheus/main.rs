//! Minimal example of exposing a Prometheus endpoint for `ebpf-metrics` using `hyper`.
//!
//! More examples can be found using different HTTP libraries at https://github.com/prometheus/client_rust/blob/master/examples/hyper.rs.

use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
};

use anyhow::Result;
use bpf_metrics::{BpfMetrics, ProgMetric};
use http_body_util::{combinators, BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    header,
    server::conn::http1,
    service::service_fn,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use tokio::{
    net::TcpListener,
    pin,
    signal::unix::{signal, SignalKind},
};

#[tokio::main]
async fn main() -> Result<()> {
    let mut bpf_metrics = BpfMetrics::new();
    bpf_metrics.register_prog_metrics(
        [
            ProgMetric::Uptime,
            ProgMetric::RunTime,
            ProgMetric::RunCount,
        ]
        .iter(),
    );

    let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    start_server(endpoint, bpf_metrics).await;

    Ok(())
}

async fn start_server(endpoint: SocketAddr, bpf_metrics: BpfMetrics) {
    eprintln!("Starting metrics server on {endpoint}");

    let bpf_metrics = Arc::new(bpf_metrics);

    let listener = TcpListener::bind(endpoint).await.unwrap();
    while let Ok((stream, _)) = listener.accept().await {
        let conn_builder = http1::Builder::new();
        let io = TokioIo::new(stream);
        let mut shutdown_stream = signal(SignalKind::terminate()).unwrap();

        let metrics = Arc::clone(&bpf_metrics);

        tokio::task::spawn(async move {
            let conn = conn_builder.serve_connection(io, service_fn(make_handler(metrics)));
            pin!(conn);
            tokio::select! {
                _ = conn.as_mut() => {}
                _ = shutdown_stream.recv() => {
                    conn.as_mut().graceful_shutdown();
                }
            }
        });
    }
}

/// Boxed HTTP body for responses
type BoxBody = combinators::BoxBody<Bytes, hyper::Error>;

/// This function returns a HTTP handler (i.e. another function)
pub fn make_handler(
    metrics: Arc<BpfMetrics>,
) -> impl Fn(Request<Incoming>) -> Pin<Box<dyn Future<Output = io::Result<Response<BoxBody>>> + Send>>
{
    // This closure accepts a request and responds with the OpenMetrics encoding of our metrics.
    move |_req: Request<Incoming>| {
        let metrics = Arc::clone(&metrics);
        metrics.collect_metrics();

        Box::pin(async move {
            let mut buffer = String::new();
            metrics
                .export_metrics(&mut buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                .map(|_| {
                    let body = full(Bytes::from(buffer));
                    Response::builder()
                        .header(
                            header::CONTENT_TYPE,
                            "application/openmetrics-text; version=1.0.0; charset=utf-8",
                        )
                        .body(body)
                        .unwrap()
                })
        })
    }
}

/// helper function to build a full boxed body
pub fn full(body: Bytes) -> BoxBody {
    Full::new(body).map_err(|never| match never {}).boxed()
}
