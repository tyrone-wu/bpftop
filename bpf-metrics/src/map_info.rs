//! Metrics for `bpf_map_info`.

use aya::maps::{loaded_maps, MapInfo};
use prometheus_client::{
    encoding::EncodeLabelSet,
    registry::{Registry, Unit},
};

use crate::metric_collection::{Collector, MetricCollection};

/// Metric options for the `bpf_map_info` object.
///
/// # Example
///
/// ```no_run
/// use bpf_metrics::{BpfMetrics, MapMetric};
///
/// // Init metrics registry
/// let mut bpf_metrics = BpfMetrics::new();
///
/// // Select and register metrics of interest
/// let metrics = [MapMetric::ValueSize, MapMetric::MaxEntries];
/// bpf_metrics.register_map_metrics(metrics.iter());
/// ```
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum MapMetric {
    /// Size of map key in bytes.
    KeySize,
    /// Size of map value in bytes.
    ValueSize,
    /// Max entries map can hold.
    MaxEntries,
    // /// Map flags used in loading.
    // MapFlags,
}

/// Label identifier for a map metric.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct MapLabels {
    /// Map type
    map_type: String,
    /// Unique ID of the map
    id: u32,
    /// Map name
    name: String,
}

impl MapLabels {
    fn new(map_info: &MapInfo) -> Self {
        Self {
            map_type: map_info.map_type_enum().to_string(),
            id: map_info.id(),
            name: map_info.name_as_str().unwrap().to_owned(),
        }
    }
}

impl MetricCollection<MapMetric, MapLabels> {
    /// Init and attach sub-registry to root registry, with the selected map metrics.
    pub(crate) fn init_with_metrics<'a>(
        registry: &mut Registry,
        metrics: impl Iterator<Item = &'a MapMetric>,
    ) -> Self {
        let map_registry = registry.sub_registry_with_prefix("map");
        let mut map_metrics = MetricCollection::<MapMetric, MapLabels>::default();

        for metric in metrics {
            match metric {
                MapMetric::KeySize => map_metrics.register_gauge(
                    map_registry,
                    MapMetric::KeySize,
                    "key_size",
                    "Size of map key",
                    Unit::Bytes,
                ),
                MapMetric::ValueSize => map_metrics.register_gauge(
                    map_registry,
                    MapMetric::ValueSize,
                    "value_size",
                    "Size of map value",
                    Unit::Bytes,
                ),
                MapMetric::MaxEntries => map_metrics.register_gauge(
                    map_registry,
                    MapMetric::MaxEntries,
                    "max_entries",
                    "Maximum entries map can hold",
                    Unit::Other("count".to_owned()),
                ),
                // MapMetric::MapFlags => todo!(), // TODO
            }
        }

        map_metrics
    }
}

impl Collector for MetricCollection<MapMetric, MapLabels> {
    fn collect_metrics(&self) {
        for map in loaded_maps() {
            if let Ok(info) = map {
                if info.name().is_empty() {
                    continue;
                }
                let labels = MapLabels::new(&info);

                // Key size
                self.update_gauge(&MapMetric::KeySize, &labels, info.key_size().into());
                // Value size
                self.update_gauge(&MapMetric::ValueSize, &labels, info.value_size().into());
                // Max entries
                self.update_gauge(&MapMetric::MaxEntries, &labels, info.max_entries().into());
                // Map flags
                // TODO
            }
        }
    }
}
