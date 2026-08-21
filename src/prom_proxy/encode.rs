//! 将指标编码为 Prometheus remote_write `WriteRequest` protobuf。

use prometheus::proto::{MetricFamily, MetricType};
use prost::Message;
use thiserror::Error;

/// 单条时序的一个采样点（也可直接构造后交给 [`encode_write_request`]）。
#[derive(Debug, Clone)]
pub struct Label {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Sample {
    pub value: f64,
    /// Unix 毫秒时间戳。
    pub timestamp_ms: i64,
}

#[derive(Debug, Clone)]
pub struct TimeSeries {
    pub labels: Vec<Label>,
    pub samples: Vec<Sample>,
}

#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("encode protobuf: {0}")]
    Prost(#[from] prost::EncodeError),
    #[error("{0}")]
    Msg(String),
}

// --- prost 手写 WriteRequest（与 Prometheus remote.proto 兼容）---

#[derive(Clone, PartialEq, Message)]
struct PbWriteRequest {
    #[prost(message, repeated, tag = "1")]
    timeseries: Vec<PbTimeSeries>,
}

#[derive(Clone, PartialEq, Message)]
struct PbTimeSeries {
    #[prost(message, repeated, tag = "1")]
    labels: Vec<PbLabel>,
    #[prost(message, repeated, tag = "2")]
    samples: Vec<PbSample>,
}

#[derive(Clone, PartialEq, Message)]
struct PbLabel {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    value: String,
}

#[derive(Clone, PartialEq, Message)]
struct PbSample {
    #[prost(double, tag = "1")]
    value: f64,
    #[prost(int64, tag = "2")]
    timestamp: i64,
}

/// 将时序列表编码为未压缩的 WriteRequest protobuf。
pub fn encode_write_request(series: &[TimeSeries]) -> Result<Vec<u8>, EncodeError> {
    let req = PbWriteRequest {
        timeseries: series
            .iter()
            .map(|ts| PbTimeSeries {
                labels: ts
                    .labels
                    .iter()
                    .map(|l| PbLabel {
                        name: l.name.clone(),
                        value: l.value.clone(),
                    })
                    .collect(),
                samples: ts
                    .samples
                    .iter()
                    .map(|s| PbSample {
                        value: s.value,
                        timestamp: s.timestamp_ms,
                    })
                    .collect(),
            })
            .collect(),
    };
    let mut buf = Vec::with_capacity(req.encoded_len());
    req.encode(&mut buf)?;
    Ok(buf)
}

/// 将 `prometheus` crate 的 [`MetricFamily`] 列表编码为 WriteRequest protobuf。
///
/// 支持 Counter / Gauge / Untyped / Histogram / Summary。
pub fn encode_metric_families(mfs: &[MetricFamily]) -> Result<Vec<u8>, EncodeError> {
    let now = chrono_now_ms();
    let mut series = Vec::new();

    for mf in mfs {
        let name = mf.get_name();
        let mtype = mf.get_field_type();
        for m in mf.get_metric() {
            let base = labels_from_metric(name, m);
            let ts = if m.get_timestamp_ms() != 0 {
                m.get_timestamp_ms()
            } else {
                now
            };

            match mtype {
                MetricType::COUNTER => {
                    series.push(ts_one(base, m.get_counter().get_value(), ts));
                }
                MetricType::GAUGE => {
                    series.push(ts_one(base, m.get_gauge().get_value(), ts));
                }
                MetricType::HISTOGRAM => {
                    let h = m.get_histogram();
                    series.push(ts_one(with_name(&base, &format!("{name}_sum")), h.get_sample_sum(), ts));
                    series.push(ts_one(
                        with_name(&base, &format!("{name}_count")),
                        h.get_sample_count() as f64,
                        ts,
                    ));
                    for b in h.get_bucket() {
                        let mut lbs = with_name(&base, &format!("{name}_bucket"));
                        lbs.push(Label {
                            name: "le".into(),
                            value: float_label(b.get_upper_bound()),
                        });
                        series.push(ts_one(lbs, b.get_cumulative_count() as f64, ts));
                    }
                    let mut inf = with_name(&base, &format!("{name}_bucket"));
                    inf.push(Label {
                        name: "le".into(),
                        value: "+Inf".into(),
                    });
                    series.push(ts_one(inf, h.get_sample_count() as f64, ts));
                }
                MetricType::SUMMARY => {
                    let s = m.get_summary();
                    series.push(ts_one(with_name(&base, &format!("{name}_sum")), s.get_sample_sum(), ts));
                    series.push(ts_one(
                        with_name(&base, &format!("{name}_count")),
                        s.get_sample_count() as f64,
                        ts,
                    ));
                    for q in s.get_quantile() {
                        let mut lbs = with_name(&base, name);
                        lbs.push(Label {
                            name: "quantile".into(),
                            value: float_label(q.get_quantile()),
                        });
                        series.push(ts_one(lbs, q.get_value(), ts));
                    }
                }
                _ => {}
            }
        }
    }

    encode_write_request(&series)
}

fn labels_from_metric(name: &str, m: &prometheus::proto::Metric) -> Vec<Label> {
    let mut labels = Vec::with_capacity(m.get_label().len() + 1);
    labels.push(Label {
        name: "__name__".into(),
        value: name.into(),
    });
    for lp in m.get_label() {
        labels.push(Label {
            name: lp.get_name().into(),
            value: lp.get_value().into(),
        });
    }
    labels
}

fn with_name(labels: &[Label], name: &str) -> Vec<Label> {
    let mut out = labels.to_vec();
    if let Some(l) = out.iter_mut().find(|l| l.name == "__name__") {
        l.value = name.into();
    } else {
        out.insert(
            0,
            Label {
                name: "__name__".into(),
                value: name.into(),
            },
        );
    }
    out
}

fn ts_one(labels: Vec<Label>, value: f64, timestamp_ms: i64) -> TimeSeries {
    TimeSeries {
        labels,
        samples: vec![Sample {
            value,
            timestamp_ms,
        }],
    }
}

fn float_label(v: f64) -> String {
    // 与 Go strconv 'f' -1 类似的紧凑表示
    let s = format!("{v}");
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

fn chrono_now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Counter, Gauge, Opts, Registry};

    #[test]
    fn encode_counter_gauge_from_registry() {
        let reg = Registry::new();
        let c = Counter::with_opts(Opts::new("demo_requests_total", "req").const_label("job", "demo"))
            .unwrap();
        let g = Gauge::with_opts(Opts::new("demo_inflight", "inf").const_label("job", "demo")).unwrap();
        reg.register(Box::new(c.clone())).unwrap();
        reg.register(Box::new(g.clone())).unwrap();
        c.inc_by(3.0);
        g.set(7.0);

        let body = encode_metric_families(&reg.gather()).unwrap();
        assert!(!body.is_empty());

        let decoded = PbWriteRequest::decode(body.as_slice()).unwrap();
        assert_eq!(decoded.timeseries.len(), 2);
    }
}
