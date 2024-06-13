//! Struct and traits for representing collection of metrics and metric families.

use std::{collections::HashMap, sync::atomic::Ordering::Relaxed};

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::{Registry, Unit},
};

/// Collection of metrics with generic `Enum` and `Labels`.
/// So far only contains counters and gauges, but may expand if needed.
pub(crate) struct MetricCollection<E, L> {
    /// Metric family counters currently being tracked.
    counters: HashMap<E, Family<L, Counter>>,
    /// Metric family gauges currently being tracked.
    gauges: HashMap<E, Family<L, Gauge>>,
}

/// Supertrait for grouping [`Collector`] and [`Reset`]
pub(crate) trait MetricFamily: Collector + Reset + Send + Sync {}
impl<E, L> MetricFamily for MetricCollection<E, L> where
    MetricCollection<E, L>: Collector + Reset + Send + Sync
{
}

pub(crate) trait Collector {
    /// Record and collect metrics into metric family collection.
    fn collect_metrics(&self);
}

pub(crate) trait Reset {
    /// Clear metrics in metric family collection.
    fn clear_metrics(&self);
}

impl<E, L> Reset for MetricCollection<E, L>
where
    L: Clone + std::hash::Hash + Eq + PartialEq,
{
    /// Clears metrics for generic [MetricCollection].
    fn clear_metrics(&self) {
        for family in self.counters.values() {
            family.clear();
        }
        for family in self.gauges.values() {
            family.clear();
        }
    }
}

impl<E, L> MetricCollection<E, L>
where
    E: std::hash::Hash + Eq + PartialEq,
    L: Clone
        + std::hash::Hash
        + Eq
        + PartialEq
        + EncodeLabelSet
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    // /// Register metric family to collection.
    // pub(crate) fn register_metric(
    //     &mut self,
    //     registry: &mut Registry,
    //     metric_type: MetricType,
    //     metric: E,
    //     name: &str,
    //     help: &str,
    //     unit: Unit,
    // ) {
    //     match metric_type {
    //         MetricType::Counter => self.register_counter(registry, metric, name, help, unit),
    //         MetricType::Gauge => self.register_gauge(registry, metric, name, help, unit),
    //         _ => {},
    //     }
    // }

    /// Register counter metric family to collection.
    pub(crate) fn register_counter(
        &mut self,
        registry: &mut Registry,
        metric: E,
        name: &str,
        help: &str,
        unit: Unit,
    ) {
        let family = Family::<L, Counter>::default();
        registry.register_with_unit(name, help, unit, family.clone());
        self.counters.insert(metric, family);
    }

    /// Register gauge metric family to collection.
    pub(crate) fn register_gauge(
        &mut self,
        registry: &mut Registry,
        metric: E,
        name: &str,
        help: &str,
        unit: Unit,
    ) {
        let family = Family::<L, Gauge>::default();
        registry.register_with_unit(name, help, unit, family.clone());
        self.gauges.insert(metric, family);
    }

    /// Update counter value for provided `metric` in a generic [MetricCollection].
    pub(crate) fn update_counter(&self, metric: &E, labels: &L, value: u64) {
        if let Some(family) = self.counters.get(metric) {
            family.get_or_create(labels).inner().store(value, Relaxed);
        }
    }

    /// Update gauge value for provided `metric` in a generic [MetricCollection].
    pub(crate) fn update_gauge(&self, metric: &E, labels: &L, value: i64) {
        if let Some(family) = self.gauges.get(metric) {
            family.get_or_create(labels).set(value);
        }
    }
}

impl<E, L> Default for MetricCollection<E, L> {
    fn default() -> Self {
        Self {
            counters: Default::default(),
            gauges: Default::default(),
        }
    }
}
