/*
Copyright 2019 The Kubernetes Authors.

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

package dynamiccertificates

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"sync/atomic"
	"time"

	"k8s.io/apiserver/pkg/server/dynamiccertificates/cacontent"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

// FileRefreshDuration is exposed so that integration tests can crank up the reload speed.
var FileRefreshDuration = 1 * time.Minute

// ControllerRunner is a generic interface for starting a controller
type ControllerRunner interface {
	// RunOnce runs the sync loop a single time.  This useful for synchronous priming
	RunOnce(ctx context.Context) error

	// Run should be called a go .Run
	Run(ctx context.Context, workers int)
}

// DynamicFileCAContent provides a CAContentProvider that can dynamically react to new file content
// It also fulfills the authenticator interface to provide verifyoptions
type DynamicFileCAContent struct {
	name string

	// filename is the name the file to read.
	filename string

	*embedDynamicCAContent
}

type DynamicCAContent struct {
	name string

	caBundle atomic.Value

	caPEMAccessor cacontent.CAContentAccessor

	listeners []Listener

	// queue only ever has one item, but it has nice error handling backoff/retry semantics
	queue workqueue.TypedRateLimitingInterface[struct{}]
}

// type alias for privately embedding the struct
type embedDynamicCAContent = DynamicCAContent

var _ Notifier = &DynamicFileCAContent{}
var _ CAContentProvider = &DynamicFileCAContent{}
var _ ControllerRunner = &DynamicFileCAContent{}

type caBundleAndVerifier struct {
	caBundle      []byte
	verifyOptions x509.VerifyOptions
}

// NewDynamicCAContentFromFile returns a CAContentProvider based on a filename that automatically reloads content
func NewDynamicCAContentFromFile(purpose, filename string) (*DynamicFileCAContent, error) {
	if len(filename) == 0 {
		return nil, fmt.Errorf("missing filename for ca bundle")
	}
	name := fmt.Sprintf("%s::file::%s", purpose, filename)

	fileAccessor := cacontent.NewFileCAContentAccessor(filename)

	dynamicContent, err := NewDynamicCAContent(name, fileAccessor)
	if err != nil {
		return nil, err
	}

	return &DynamicFileCAContent{
		name:                  name,
		embedDynamicCAContent: dynamicContent,
	}, nil
}

func NewDynamicCAContentFromClusterTrustBundles(kubeClient kubernetes.Interface, purpose, signerName string) (*DynamicCAContent, error) {
	if len(signerName) == 0 {
		return nil, fmt.Errorf("missing signer name for CA bundle")
	}
	name := fmt.Sprintf("%s::ctbSigner::%s", purpose, signerName)

	ctbAccessor := cacontent.NewClusterTrustBundleProvider(kubeClient, signerName)

	dynamicContent, err := NewDynamicCAContent(name, ctbAccessor)
	if err != nil {
		return nil, err
	}

	return dynamicContent, nil
}

func NewDynamicCAContent(name string, caPEMAccessor cacontent.CAContentAccessor) (*DynamicCAContent, error) {
	ret := &DynamicCAContent{
		name:          name,
		caPEMAccessor: caPEMAccessor,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[struct{}](),
			workqueue.TypedRateLimitingQueueConfig[struct{}]{Name: fmt.Sprintf("DynamicCABundle-%s", name)},
		),
	}

	if err := ret.loadCABundle(); err != nil {
		return nil, err
	}

	return ret, nil
}

// AddListener adds a listener to be notified when the CA content changes.
func (c *DynamicCAContent) AddListener(listener Listener) {
	c.listeners = append(c.listeners, listener)
}

// loadCABundle determines the next set of content for the file.
func (c *DynamicCAContent) loadCABundle() error {
	caBundle, err := c.caPEMAccessor.GetPEMBundle()

	if len(caBundle) == 0 {
		return fmt.Errorf("missing content for CA bundle %q", c.Name())
	}

	// check to see if we have a change. If the values are the same, do nothing.
	if !c.hasCAChanged(caBundle) {
		return nil
	}

	caBundleAndVerifier, err := newCABundleAndVerifier(c.Name(), caBundle)
	if err != nil {
		return err
	}
	c.caBundle.Store(caBundleAndVerifier)
	klog.V(2).InfoS("Loaded a new CA Bundle and Verifier", "name", c.Name())

	for _, listener := range c.listeners {
		listener.Enqueue()
	}

	return nil
}

// hasCAChanged returns true if the caBundle is different than the current.
func (c *DynamicCAContent) hasCAChanged(caBundle []byte) bool {
	uncastExisting := c.caBundle.Load()
	if uncastExisting == nil {
		return true
	}

	// check to see if we have a change. If the values are the same, do nothing.
	existing, ok := uncastExisting.(*caBundleAndVerifier)
	if !ok {
		return true
	}
	if !bytes.Equal(existing.caBundle, caBundle) {
		return true
	}

	return false
}

// RunOnce runs a single sync loop
func (c *DynamicCAContent) RunOnce(ctx context.Context) error {
	return c.loadCABundle()
}

// Run starts the controller and blocks until stopCh is closed.
func (c *DynamicCAContent) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrashWithContext(ctx)
	defer c.queue.ShutDown()

	klog.InfoS("Starting controller", "name", c.name)
	defer klog.InfoS("Shutting down controller", "name", c.name)

	// doesn't matter what workers say, only start one.
	go wait.Until(c.runWorker, time.Second, ctx.Done())

	go c.caPEMAccessor.Watch(ctx, c.queue)

	<-ctx.Done()
}

func (c *DynamicCAContent) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *DynamicCAContent) processNextWorkItem() bool {
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)

	err := c.loadCABundle()
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", dsKey, err))
	c.queue.AddRateLimited(dsKey)

	return true
}

// Name is just an identifier
func (c *DynamicCAContent) Name() string {
	return c.name
}

// CurrentCABundleContent provides ca bundle byte content
func (c *DynamicCAContent) CurrentCABundleContent() (cabundle []byte) {
	return c.caBundle.Load().(*caBundleAndVerifier).caBundle
}

// VerifyOptions provides verifyoptions compatible with authenticators
func (c *DynamicCAContent) VerifyOptions() (x509.VerifyOptions, bool) {
	uncastObj := c.caBundle.Load()
	if uncastObj == nil {
		return x509.VerifyOptions{}, false
	}

	return uncastObj.(*caBundleAndVerifier).verifyOptions, true
}

// newVerifyOptions creates a new verification func from a file.  It reads the content and then fails.
// It will return a nil function if you pass an empty CA file.
func newCABundleAndVerifier(name string, caBundle []byte) (*caBundleAndVerifier, error) {
	if len(caBundle) == 0 {
		return nil, fmt.Errorf("missing content for CA bundle %q", name)
	}

	// Wrap with an x509 verifier
	var err error
	verifyOptions := defaultVerifyOptions()
	verifyOptions.Roots, err = cert.NewPoolFromBytes(caBundle)
	if err != nil {
		return nil, fmt.Errorf("error loading CA bundle for %q: %v", name, err)
	}

	return &caBundleAndVerifier{
		caBundle:      caBundle,
		verifyOptions: verifyOptions,
	}, nil
}

// defaultVerifyOptions returns VerifyOptions that use the system root certificates, current time,
// and requires certificates to be valid for client auth (x509.ExtKeyUsageClientAuth)
func defaultVerifyOptions() x509.VerifyOptions {
	return x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}
