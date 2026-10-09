/*
Copyright The Kubernetes Authors.

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

package cacontent

import (
	"context"
	"encoding/pem"
	"fmt"
	"math/rand/v2"

	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	certv1informers "k8s.io/client-go/informers/certificates/v1"
	"k8s.io/client-go/kubernetes"
	certv1client "k8s.io/client-go/kubernetes/typed/certificates/v1"
	certv1listers "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type clusterTrustBundleProvider struct {
	signerName string
	// TODO: add labels/ctbName support -> only store getter and liveGetter?
	signerInformer cache.SharedIndexInformer
	signerLister   certv1listers.ClusterTrustBundleLister
	certClient     certv1client.ClusterTrustBundleInterface
}

func NewClusterTrustBundleProvider(kubeClient kubernetes.Interface, signerName string) CAContentAccessor {
	return &clusterTrustBundleProvider{
		signerName: signerName,
		signerInformer: certv1informers.NewFilteredClusterTrustBundleInformer(kubeClient, 0, cache.Indexers{},
			func(options *metav1.ListOptions) {
				options.FieldSelector = fields.OneTermEqualSelector("spec.signerName", signerName).String()
			}),
	}
}

func (p *clusterTrustBundleProvider) GetPEMBundle() ([]byte, error) {
	if p.signerInformer.HasSynced() {
		signerList, err := p.signerLister.List(labels.Everything())
		if err != nil {
			return nil, err
		}
		return normalizeTrustAnchors(signerList)
	}

	signerList, err := p.certClient.List(context.TODO(), metav1.ListOptions{
		FieldSelector: "spec.signerName=" + p.signerName,
	})
	if err != nil {
		return nil, err
	}
	return normalizeTrustAnchors(sliceToPointerSlice(signerList.Items))
}

func (p *clusterTrustBundleProvider) Watch(ctx context.Context, q workqueue.TypedRateLimitingInterface[struct{}]) {
	logger := klog.LoggerWithName(klog.FromContext(ctx), "CTBCAContentProvider_"+p.signerName)
	ctx = klog.NewContext(ctx, logger)

	p.signerInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{ // TODO: ignoring error for now
		AddFunc:    func(_ any) { q.Add(struct{}{}) },
		UpdateFunc: func(_, _ any) { q.Add(struct{}{}) },
		DeleteFunc: func(_ any) { q.Add(struct{}{}) },
	})
	informerCtx, informerCancel := context.WithCancel(ctx)
	p.signerInformer.Run(informerCtx.Done())
	defer informerCancel()

	if !cache.WaitForNamedCacheSyncWithContext(ctx, p.signerInformer.HasSynced) {
		logger.Error(fmt.Errorf("failed to sync ClusterTrustBundleCache"), "cache never synced, resyncs might cause live requests")
	}

	// synthetically add item to the queue in case we only added our event handler after
	// the cached synced
	q.Add(struct{}{})

	<-ctx.Done()
}

// FIXME: borrowed from pkg/kubelet/clustertrustbundle/clustertrustbundle_manager.go
func normalizeTrustAnchors(ctbList []*certv1.ClusterTrustBundle) ([]byte, error) {
	// Deduplicate trust anchors from all ClusterTrustBundles.
	trustAnchorSet := sets.Set[string]{}
	for _, ctb := range ctbList {
		rest := []byte(ctb.Spec.TrustBundle)
		var b *pem.Block
		for {
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			trustAnchorSet = trustAnchorSet.Insert(string(b.Bytes))
		}
	}

	// Give the list a stable ordering that changes each time Kubelet restarts.
	trustAnchorList := sets.List(trustAnchorSet)
	rand.Shuffle(len(trustAnchorList), func(i, j int) {
		trustAnchorList[i], trustAnchorList[j] = trustAnchorList[j], trustAnchorList[i]
	})

	pemTrustAnchors := []byte{}
	for _, ta := range trustAnchorList {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte(ta),
		}
		pemTrustAnchors = append(pemTrustAnchors, pem.EncodeToMemory(b)...)
	}

	return pemTrustAnchors, nil
}

func sliceToPointerSlice[T any](in []T) []*T {
	out := make([]*T, len(in))
	for i := range in {
		out[i] = &in[i]
	}
	return out
}
