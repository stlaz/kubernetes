package apiserver

import (
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

var x509MissingSANCounter = metrics.NewCounterVec(
	&metrics.CounterOpts{
		Subsystem:      "kube_aggregator",
		Name:           "x509_missing_san_count",
		Help:           "Counts the number of connection failures dues to the lack of x509 certificate SAN extension missing",
		StabilityLevel: metrics.ALPHA,
	}, []string{},
)

func init() {
	legacyregistry.MustRegister(x509MissingSANCounter)
}
