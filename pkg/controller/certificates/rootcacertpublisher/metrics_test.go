/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rootcacertpublisher

import (
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/component-base/metrics/testutil"
)

func TestSyncCounter(t *testing.T) {
	testCases := []struct {
		desc    string
		err     error
		metrics []string
		want    string
	}{
		{
			desc: "nil error",
			err:  nil,
			metrics: []string{
				"root_ca_cert_publisher_sync_total",
			},
			want: `
# HELP root_ca_cert_publisher_sync_total [ALPHA] Number of namespace syncs happened in root ca cert publisher.
# TYPE root_ca_cert_publisher_sync_total counter
root_ca_cert_publisher_sync_total{code="200",namespace="test-ns"} 1
				`,
		},
		{
			desc: "kube api error",
			err:  apierrors.NewNotFound(corev1.Resource("configmap"), "test-configmap"),
			metrics: []string{
				"root_ca_cert_publisher_sync_total",
			},
			want: `
# HELP root_ca_cert_publisher_sync_total [ALPHA] Number of namespace syncs happened in root ca cert publisher.
# TYPE root_ca_cert_publisher_sync_total counter
root_ca_cert_publisher_sync_total{code="404",namespace="test-ns"} 1
				`,
		},
		{
			desc: "kube api error without code",
			err:  &apierrors.StatusError{},
			metrics: []string{
				"root_ca_cert_publisher_sync_total",
			},
			want: `
# HELP root_ca_cert_publisher_sync_total [ALPHA] Number of namespace syncs happened in root ca cert publisher.
# TYPE root_ca_cert_publisher_sync_total counter
root_ca_cert_publisher_sync_total{code="500",namespace="test-ns"} 1
				`,
		},
		{
			desc: "general error",
			err:  errors.New("test"),
			metrics: []string{
				"root_ca_cert_publisher_sync_total",
			},
			want: `
# HELP root_ca_cert_publisher_sync_total [ALPHA] Number of namespace syncs happened in root ca cert publisher.
# TYPE root_ca_cert_publisher_sync_total counter
root_ca_cert_publisher_sync_total{code="500",namespace="test-ns"} 1
				`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			recordMetrics(time.Now(), "test-ns", tc.err)
			defer syncCounter.Reset()
			if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(tc.want), tc.metrics...); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSyncCounterCleanup(t *testing.T) {
	setupMetrics := func() {
		recordMetrics(time.Now(), "test-ns", &apierrors.StatusError{})
		recordMetrics(time.Now(), "test-ns", apierrors.NewNotFound(corev1.Resource("configmap"), "test-configmap"))
		recordMetrics(time.Now(), "test-ns", nil)
		recordMetrics(time.Now(), "test-ns", nil)

		recordMetrics(time.Now(), "test-removed-ns", &apierrors.StatusError{})
		recordMetrics(time.Now(), "test-removed-ns", apierrors.NewNotFound(corev1.Resource("configmap"), "test-configmap"))
		recordMetrics(time.Now(), "test-removed-ns", nil)

	}

	testCases := []struct {
		desc      string
		removedNS string
		want      string
	}{
		{
			desc:      "deleted ns not found in metrics",
			removedNS: "very-random-ns",
			want: `
# HELP root_ca_cert_publisher_sync_total [ALPHA] Number of namespace syncs happened in root ca cert publisher.
# TYPE root_ca_cert_publisher_sync_total counter
root_ca_cert_publisher_sync_total{code="200",namespace="test-ns"} 2
root_ca_cert_publisher_sync_total{code="200",namespace="test-removed-ns"} 1
root_ca_cert_publisher_sync_total{code="404",namespace="test-ns"} 1
root_ca_cert_publisher_sync_total{code="404",namespace="test-removed-ns"} 1
root_ca_cert_publisher_sync_total{code="500",namespace="test-ns"} 1
root_ca_cert_publisher_sync_total{code="500",namespace="test-removed-ns"} 1
`,
		},
		{
			desc:      "ns with existing metrics",
			removedNS: "test-removed-ns",
			want: `
# HELP root_ca_cert_publisher_sync_total [ALPHA] Number of namespace syncs happened in root ca cert publisher.
# TYPE root_ca_cert_publisher_sync_total counter
root_ca_cert_publisher_sync_total{code="200",namespace="test-ns"} 2
root_ca_cert_publisher_sync_total{code="404",namespace="test-ns"} 1
root_ca_cert_publisher_sync_total{code="500",namespace="test-ns"} 1
				`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			setupMetrics()
			cleanupMetrics(tc.removedNS)

			defer syncCounter.Reset()
			if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(tc.want), "root_ca_cert_publisher_sync_total"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
