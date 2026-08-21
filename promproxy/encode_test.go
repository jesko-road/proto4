package promproxy

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prometheus/prompb"
	"google.golang.org/protobuf/proto"
)

func TestEncodeMetricFamiliesCounterGauge(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "demo_requests_total",
		Help: "requests",
		ConstLabels: prometheus.Labels{"job": "demo"},
	})
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "demo_inflight",
		Help: "inflight",
		ConstLabels: prometheus.Labels{"job": "demo"},
	})
	reg.MustRegister(c, g)
	c.Add(3)
	g.Set(7)

	body, err := GatherAndEncode(reg)
	if err != nil {
		t.Fatal(err)
	}
	var req prompb.WriteRequest
	if err := req.Unmarshal(body); err != nil {
		t.Fatal(err)
	}
	if len(req.Timeseries) != 2 {
		t.Fatalf("timeseries=%d", len(req.Timeseries))
	}

	byName := map[string]float64{}
	for _, ts := range req.Timeseries {
		var name string
		for _, l := range ts.Labels {
			if l.Name == "__name__" {
				name = l.Value
			}
		}
		byName[name] = ts.Samples[0].Value
	}
	if byName["demo_requests_total"] != 3 || byName["demo_inflight"] != 7 {
		t.Fatalf("values: %#v", byName)
	}
}

func TestEncodeHistogram(t *testing.T) {
	h := &dto.MetricFamily{
		Name: proto.String("demo_latency_seconds"),
		Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Histogram: &dto.Histogram{
				SampleCount: proto.Uint64(10),
				SampleSum:   proto.Float64(1.5),
				Bucket: []*dto.Bucket{
					{CumulativeCount: proto.Uint64(4), UpperBound: proto.Float64(0.1)},
					{CumulativeCount: proto.Uint64(10), UpperBound: proto.Float64(1)},
				},
			},
		}},
	}
	body, err := EncodeMetricFamilies([]*dto.MetricFamily{h})
	if err != nil {
		t.Fatal(err)
	}
	var req prompb.WriteRequest
	if err := req.Unmarshal(body); err != nil {
		t.Fatal(err)
	}
	// sum + count + 2 buckets + +Inf = 5
	if len(req.Timeseries) != 5 {
		t.Fatalf("timeseries=%d want 5", len(req.Timeseries))
	}
	_ = time.Now()
}
