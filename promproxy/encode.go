package promproxy

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prometheus/prompb"
)

// EncodeMetricFamilies 将 client_golang Gather 得到的 MetricFamily 编码为
// 未压缩的 prometheus.WriteRequest protobuf（可交给 RemoteWriteProtobuf）。
//
// 支持 Counter / Gauge / Untyped / Histogram / Summary。
func EncodeMetricFamilies(mfs []*dto.MetricFamily) ([]byte, error) {
	now := time.Now().UnixMilli()
	var tss []prompb.TimeSeries

	for _, mf := range mfs {
		if mf == nil {
			continue
		}
		name := mf.GetName()
		for _, m := range mf.GetMetric() {
			base := labelsFromMetric(name, m)
			ts := now
			if m.TimestampMs != nil {
				ts = m.GetTimestampMs()
			}

			switch mf.GetType() {
			case dto.MetricType_COUNTER:
				tss = append(tss, timeSeries(base, m.GetCounter().GetValue(), ts))
			case dto.MetricType_GAUGE:
				tss = append(tss, timeSeries(base, m.GetGauge().GetValue(), ts))
			case dto.MetricType_UNTYPED:
				tss = append(tss, timeSeries(base, m.GetUntyped().GetValue(), ts))
			case dto.MetricType_HISTOGRAM:
				h := m.GetHistogram()
				tss = append(tss, timeSeries(withName(base, name+"_sum"), h.GetSampleSum(), ts))
				tss = append(tss, timeSeries(withName(base, name+"_count"), float64(h.GetSampleCount()), ts))
				for _, b := range h.GetBucket() {
					bound := strconv.FormatFloat(b.GetUpperBound(), 'f', -1, 64)
					lbs := appendLabel(withName(base, name+"_bucket"), "le", bound)
					tss = append(tss, timeSeries(lbs, float64(b.GetCumulativeCount()), ts))
				}
				inf := appendLabel(withName(base, name+"_bucket"), "le", "+Inf")
				tss = append(tss, timeSeries(inf, float64(h.GetSampleCount()), ts))
			case dto.MetricType_SUMMARY:
				s := m.GetSummary()
				tss = append(tss, timeSeries(withName(base, name+"_sum"), s.GetSampleSum(), ts))
				tss = append(tss, timeSeries(withName(base, name+"_count"), float64(s.GetSampleCount()), ts))
				for _, q := range s.GetQuantile() {
					qv := strconv.FormatFloat(q.GetQuantile(), 'f', -1, 64)
					lbs := appendLabel(withName(base, name), "quantile", qv)
					tss = append(tss, timeSeries(lbs, q.GetValue(), ts))
				}
			default:
				return nil, fmt.Errorf("promproxy: unsupported metric type %v for %q", mf.GetType(), name)
			}
		}
	}

	req := &prompb.WriteRequest{Timeseries: tss}
	return req.Marshal()
}

// GatherAndEncode 调用 Gatherer.Gather 后编码为 WriteRequest protobuf。
func GatherAndEncode(g prometheus.Gatherer) ([]byte, error) {
	mfs, err := g.Gather()
	if err != nil {
		return nil, fmt.Errorf("promproxy: gather: %w", err)
	}
	return EncodeMetricFamilies(mfs)
}

// RemoteWriteGather Gather 指标并 remote_write。
func (c *Client) RemoteWriteGather(ctx context.Context, g prometheus.Gatherer) (uint16, error) {
	body, err := GatherAndEncode(g)
	if err != nil {
		return 0, err
	}
	return c.RemoteWriteProtobuf(ctx, body)
}

func labelsFromMetric(name string, m *dto.Metric) []prompb.Label {
	labels := make([]prompb.Label, 0, len(m.GetLabel())+1)
	labels = append(labels, prompb.Label{Name: "__name__", Value: name})
	for _, lp := range m.GetLabel() {
		labels = append(labels, prompb.Label{Name: lp.GetName(), Value: lp.GetValue()})
	}
	return labels
}

func withName(labels []prompb.Label, name string) []prompb.Label {
	out := make([]prompb.Label, len(labels))
	copy(out, labels)
	for i := range out {
		if out[i].Name == "__name__" {
			out[i].Value = name
			return out
		}
	}
	return append([]prompb.Label{{Name: "__name__", Value: name}}, out...)
}

func appendLabel(labels []prompb.Label, name, value string) []prompb.Label {
	out := make([]prompb.Label, len(labels), len(labels)+1)
	copy(out, labels)
	return append(out, prompb.Label{Name: name, Value: value})
}

func timeSeries(labels []prompb.Label, value float64, ts int64) prompb.TimeSeries {
	return prompb.TimeSeries{
		Labels:  labels,
		Samples: []prompb.Sample{{Value: value, Timestamp: ts}},
	}
}
