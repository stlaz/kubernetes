/*
Copyright 2023 The Kubernetes Authors.

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

package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"time"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/test/e2e/feature"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
	imageutils "k8s.io/kubernetes/test/utils/image"
	admissionapi "k8s.io/pod-security-admission/api"
	"k8s.io/utils/ptr"

	"github.com/onsi/ginkgo/v2"
)

var _ = SIGDescribe(feature.ClusterTrustBundle, feature.ClusterTrustBundleProjection, func() {
	f := framework.NewDefaultFramework("projected-clustertrustbundle")
	f.NamespacePodSecurityLevel = admissionapi.LevelBaseline

	var certPEMs []string
	for i := range 10 {
		certPEMs = append(certPEMs, mustMakeCAPEM(fmt.Sprintf("root%d", i)))
	}

	// We must copy the original fields. Slicing is just applied pointer arithmetics
	// and if we attempted an append to such a slice later, we'd be overriding the original
	// underlying array.
	signerOnePEMS := make([]string, 8)
	copy(signerOnePEMS[0:4], certPEMs[0:4])
	copy(signerOnePEMS[4:], certPEMs[6:])

	ginkgo.BeforeEach(func(ctx context.Context) {
		cleanup := mustInitCTBs(ctx, f, certPEMs)
		ginkgo.DeferCleanup(cleanup)
	})

	ginkgo.It("should be able to mount a single ClusterTrustBundle by name", func(ctx context.Context) {
		pod := podForCTBProjection(v1.VolumeProjection{
			ClusterTrustBundle: &v1.ClusterTrustBundleProjection{
				Name: ptr.To("test.test.signer-one.4"),
				Path: "trust-anchors.pem",
			},
		})

		fileModeRegexp := getFileModeRegex("/var/run/ctbtest/trust-anchors.pem", nil)
		expectedOutput := []string{
			regexp.QuoteMeta(certPEMs[4]),
			fileModeRegexp,
		}

		e2epodoutput.TestContainerOutputRegexp(ctx, f, "project cluster trust bundle", pod, 0, expectedOutput)
	})

	ginkgo.Describe("should be capable to mount multiple trust bundles by signer+labels", func() {
		fileModeRegexp := getFileModeRegex("/var/run/ctbtest/trust-bundle.crt", nil)

		for _, tt := range []struct {
			name                string
			signerName          string
			selector            *metav1.LabelSelector
			optionalVolume      *bool
			expectedOutputRegex []string
		}{
			{
				name:       "can combine multiple CTBs with signer name and label selector",
				signerName: "test.test/signer-one",
				selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"signer.alive": "true",
					},
				},
				expectedOutputRegex: expectedRegexFromPEMs(certPEMs[1:4]...),
			},
			{
				name:                "should start if only signer name and nil label selector + optional=true",
				signerName:          "test.test/signer-one",
				selector:            nil,
				optionalVolume:      ptr.To(true),
				expectedOutputRegex: []string{"content of file \"/var/run/ctbtest/trust-bundle.crt\": \n$"},
			},
			{
				name:                "can combine all signer CTBs with an empty label selector",
				signerName:          "test.test/signer-one",
				selector:            &metav1.LabelSelector{},
				expectedOutputRegex: expectedRegexFromPEMs(signerOnePEMS...),
			},
		} {
			ginkgo.It(tt.name, func(ctx context.Context) {
				pod := podForCTBProjection(v1.VolumeProjection{
					ClusterTrustBundle: &v1.ClusterTrustBundleProjection{
						Path:          "trust-bundle.crt",
						SignerName:    &tt.signerName,
						LabelSelector: tt.selector,
						Optional:      tt.optionalVolume,
					},
				})

				expectedOutput := append(tt.expectedOutputRegex, fileModeRegexp)

				e2epodoutput.TestContainerOutputRegexp(ctx, f, "project cluster trust bundle", pod, 0, expectedOutput)
			})
		}
	})

	ginkgo.It("should prevent a pod from starting if no trust bundle matches query and optional=false", func(ctx context.Context) {
		pod := podForCTBProjection(
			v1.VolumeProjection{
				ClusterTrustBundle: &v1.ClusterTrustBundleProjection{
					Path:       "trust-bundle.crt",
					SignerName: ptr.To("test.test/signer-one"),
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"signer.alive": "unknown",
						},
					},
				},
			},
		)

		pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Create(ctx, pod, metav1.CreateOptions{})
		if err != nil {
			framework.Failf("failed to create a testing container: %v", err)
		}

		err = wait.PollUntilContextTimeout(ctx, 1*time.Second, 10*time.Second, true, func(waitCtx context.Context) (done bool, err error) {
			waitPod, err := f.ClientSet.CoreV1().Pods(pod.Namespace).Get(waitCtx, pod.Name, metav1.GetOptions{})
			if err != nil {
				framework.Logf("failed to get pod: %v", err)
				return false, nil
			}

			if waitPod.Status.Phase == v1.PodRunning {
				return true, nil
			}

			return false, nil
		})

		if err == nil {
			framework.Fail("expected the pod not to start running, but it did")
		} else if !errors.Is(err, context.DeadlineExceeded) {
			framework.Failf("expected deadline exceeded, but got: %v", err)
		}

	})
	ginkgo.It("should be able to specify multiple CTB volumes", func(ctx context.Context) {
		pod := podForCTBProjection(
			v1.VolumeProjection{
				ClusterTrustBundle: &v1.ClusterTrustBundleProjection{
					Name: ptr.To("test.test.signer-one.4"),
					Path: "trust-anchors.pem",
				},
			},
			v1.VolumeProjection{
				ClusterTrustBundle: &v1.ClusterTrustBundleProjection{
					Path:       "trust-bundle.crt",
					SignerName: ptr.To("test.test/signer-one"),
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"signer.alive": "false",
						},
					},
				},
			},
		)
		expectedOutputs := map[int][]string{
			0: append(expectedRegexFromPEMs(certPEMs[4]), getFileModeRegex("/var/run/ctbtest/trust-anchors.pem", nil)),
			1: append(expectedRegexFromPEMs(certPEMs[6:8]...), getFileModeRegex("/var/run/ctbtest/trust-bundle.crt", nil)),
		}

		e2epodoutput.TestContainerOutputsRegexp(ctx, f, "multiple CTB volumes", pod, expectedOutputs)
	})
})

func expectedRegexFromPEMs(certPEMs ...string) []string {
	var ret []string
	for _, pem := range certPEMs {
		ret = append(ret, regexp.QuoteMeta(pem))
	}
	return ret
}

func podForCTBProjection(projectionSources ...v1.VolumeProjection) *v1.Pod {
	const volumeNameFmt = "ctb-volume-%d"

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod-projected-ctb-" + string(uuid.NewUUID()),
		},
		Spec: v1.PodSpec{
			RestartPolicy: v1.RestartPolicyNever,
		},
	}

	for i := range projectionSources {
		pod.Spec.Containers = append(pod.Spec.Containers,
			v1.Container{
				Name:  fmt.Sprintf("projected-ctb-volume-test-%d", i),
				Image: imageutils.GetE2EImage(imageutils.Agnhost),
				Args: []string{
					"mounttest",
					fmt.Sprintf("--file_content=/var/run/ctbtest/%s", projectionSources[i].ClusterTrustBundle.Path),
					fmt.Sprintf("--file_mode=/var/run/ctbtest/%s", projectionSources[i].ClusterTrustBundle.Path),
				},
				VolumeMounts: []v1.VolumeMount{
					{
						Name:      fmt.Sprintf(volumeNameFmt, i),
						MountPath: "/var/run/ctbtest",
					},
				},
			})
		pod.Spec.Volumes = append(pod.Spec.Volumes,
			v1.Volume{
				Name: fmt.Sprintf(volumeNameFmt, i),
				VolumeSource: v1.VolumeSource{
					Projected: &v1.ProjectedVolumeSource{
						Sources: []v1.VolumeProjection{projectionSources[i]},
					},
				},
			})
	}

	return pod
}

func mustInitCTBs(ctx context.Context, f *framework.Framework, certPEMs []string) func(ctx context.Context) {
	var cleanups []func(ctx context.Context)
	for i, caPEM := range certPEMs {
		var cleanup func(ctx context.Context)
		switch i {
		case 1, 2, 3:
			cleanup = mustCTBForCA(ctx, f, fmt.Sprintf("test.test:signer-one:%d", i), "test.test/signer-one", caPEM, map[string]string{"signer.alive": "true"})
		case 4:
			cleanup = mustCTBForCA(ctx, f, fmt.Sprintf("test.test.signer-one.%d", i), "", caPEM, map[string]string{"signer.alive": "true"})
		case 5:
			cleanup = mustCTBForCA(ctx, f, fmt.Sprintf("test.test:signer-two:%d", i), "test.test/signer-two", caPEM, map[string]string{"signer.alive": "true"})
		case 6, 7:
			cleanup = mustCTBForCA(ctx, f, fmt.Sprintf("test.test:signer-one:%d", i), "test.test/signer-one", caPEM, map[string]string{"signer.alive": "false"})
		default: // 0, 8 ,9
			cleanup = mustCTBForCA(ctx, f, fmt.Sprintf("test.test:signer-one:%d", i), "test.test/signer-one", caPEM, nil)
		}
		cleanups = append(cleanups, cleanup)
	}

	return func(ctx context.Context) {
		for _, c := range cleanups {
			c(ctx)
		}
	}
}

func mustCTBForCA(ctx context.Context, f *framework.Framework, ctbName, signerName, caPEM string, labels map[string]string) func(ctx context.Context) {
	if _, err := f.ClientSet.CertificatesV1beta1().ClusterTrustBundles().Create(ctx, &certificatesv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:   ctbName,
			Labels: labels,
		},
		Spec: certificatesv1beta1.ClusterTrustBundleSpec{
			SignerName:  signerName,
			TrustBundle: caPEM,
		},
	}, metav1.CreateOptions{}); err != nil {
		framework.Failf("Error while creating ClusterTrustBundle: %v", err)
	}
	return func(ctx context.Context) {
		if err := f.ClientSet.CertificatesV1beta1().ClusterTrustBundles().Delete(ctx, ctbName, metav1.DeleteOptions{}); err != nil {
			framework.Logf("failed to remove a cluster trust bundle: %v", err)
		}
	}
}

func mustMakeCAPEM(cn string) string {
	asnCert := mustMakeCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: cn,
		},
		IsCA:                  true,
		BasicConstraintsValid: true,
	})

	return mustMakePEMBlock("CERTIFICATE", nil, asnCert)
}

func mustMakeCertificate(template *x509.Certificate) []byte {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		framework.Failf("Error while generating key: %v", err)
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		framework.Failf("Error while making certificate: %v", err)
	}

	return cert
}

func mustMakePEMBlock(blockType string, headers map[string]string, data []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:    blockType,
		Headers: headers,
		Bytes:   data,
	}))
}

// getFileModeRegex returns a file mode related regex which should be matched by the mounttest pods' output.
// If the given mask is nil, then the regex will contain the default OS file modes, which are 0644 for Linux and 0775 for Windows.
func getFileModeRegex(filePath string, mask *int32) string {
	var (
		linuxMask   int32
		windowsMask int32
	)
	if mask == nil {
		linuxMask = int32(0644)
		windowsMask = int32(0775)
	} else {
		linuxMask = *mask
		windowsMask = *mask
	}

	linuxOutput := fmt.Sprintf("mode of file \"%s\": %v", filePath, os.FileMode(linuxMask))
	windowsOutput := fmt.Sprintf("mode of Windows file \"%v\": %s", filePath, os.FileMode(windowsMask))

	return fmt.Sprintf("(%s|%s)", linuxOutput, windowsOutput)
}
