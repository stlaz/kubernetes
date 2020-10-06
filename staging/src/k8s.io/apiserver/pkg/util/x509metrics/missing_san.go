package x509metrics

import (
	"crypto/x509"
	"errors"
	"net/http"
	"strings"

	"k8s.io/component-base/metrics"
)

type x509MissingSANErrorMetricsRTWrapper struct {
	rt http.RoundTripper

	counter *metrics.CounterVec
}

// MissingSANRoundTripperWrapperFunc returns a RoundTripper wrapper that's usable
// within ClientConfig.Wrap that increases the `metricCounter` whenever:
// 1. we get a x509.HostnameError with string `x509: certificate relies on legacy Common Name field`
//    which indicates an error caused by the deprecation of Common Name field when veryfing remote
//    hostname
// 2. the server certificate in response contains no SAN. This indicates that this binary was
//    compiled with the GODEBUG=x509ignoreCN=0 in env
func MissingSANRoundTripperWrapperFunc(metricCounter *metrics.CounterVec) func(rt http.RoundTripper) http.RoundTripper {
	w := x509MissingSANErrorMetricsRTWrapper{
		counter: metricCounter,
	}
	return w.WithRoundTripper
}

func (w *x509MissingSANErrorMetricsRTWrapper) WithRoundTripper(rt http.RoundTripper) http.RoundTripper {
	w.rt = rt
	return w
}

func (w *x509MissingSANErrorMetricsRTWrapper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := w.rt.RoundTrip(req)

	if err != nil && errors.As(err, &x509.HostnameError{}) {
		// Compiled w/o GODEBUG=x509ignoreCN=0
		if errMsg := err.Error(); strings.Contains(errMsg, "x509: certificate relies on legacy Common Name field") {
			// increase the count of registered failures due to Go 1.15 x509 cert Common Name deprecation
			w.counter.WithLabelValues().Inc()
		}
	}

	var serverCert *x509.Certificate
	if resp != nil && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		if serverCert = resp.TLS.PeerCertificates[0]; !hasSAN(serverCert) {
			w.counter.WithLabelValues().Inc()
		}
	}

	return resp, err
}

func hasSAN(c *x509.Certificate) bool {
	sanOID := []int{2, 5, 29, 17}

	for _, e := range c.Extensions {
		if e.Id.Equal(sanOID) {
			return true
		}
	}
	return false
}
