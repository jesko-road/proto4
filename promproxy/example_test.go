package promproxy_test

import (
	"context"
	"fmt"
	"log"

	"github.com/jesko-road/proto4/promproxy"
	"github.com/prometheus/client_golang/prometheus"
)

func ExampleClient_RemoteWriteGather() {
	key, err := promproxy.ParseSecretKeyHex(
		"071c9849f90b8caf7b9083bd53817e56d7274dc35796c4206b7fc97caec44dea",
	)
	if err != nil {
		log.Fatal(err)
	}
	client, err := promproxy.New(promproxy.Config{
		Addr:      "127.0.0.1:9100",
		SecretKey: key,
	})
	if err != nil {
		log.Fatal(err)
	}

	reg := prometheus.NewRegistry()
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "demo_total", Help: "demo"})
	reg.MustRegister(c)
	c.Inc()

	status, err := client.RemoteWriteGather(context.Background(), reg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(status)
}
