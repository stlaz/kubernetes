/*
Copyright 2024 The Kubernetes Authors.

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

package storageversionmigrator

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/goleak"

	svmv1alpha1 "k8s.io/api/storagemigration/v1alpha1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	endpointsdiscovery "k8s.io/apiserver/pkg/endpoints/discovery"
	encryptionconfigcontroller "k8s.io/apiserver/pkg/server/options/encryptionconfig/controller"
	etcd3watcher "k8s.io/apiserver/pkg/storage/etcd3"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/dynamic"
	clientgofeaturegate "k8s.io/client-go/features"
	"k8s.io/client-go/kubernetes"
	"k8s.io/component-base/featuregate"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	kubeapiservertesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/test/integration"
	"k8s.io/kubernetes/test/integration/etcd"
	"k8s.io/kubernetes/test/integration/framework"
	"k8s.io/kubernetes/test/utils/ktesting"
)

// TestStorageVersionMigration is an integration test that verifies storage version migration works.
// This test asserts following scenarios:
// 1. Start API server with encryption at rest and hot reload of encryption config enabled
// 2. Create a secret
// 3. Update encryption config file to add a new key as write key
// 4. Perform Storage Version Migration for secrets
// 5. Verify that the secret is migrated to use the new key
// 6. Verify that the secret is updated with a new resource version
// 7. Perform another Storage Version Migration for secrets
// 8. Verify that the resource version of the secret is not updated. i.e. it was a no-op update
func TestStorageVersionMigration(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.StorageVersionMigrator, true)
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, featuregate.Feature(clientgofeaturegate.InformerResourceVersion), true)

	// this makes the test super responsive. It's set to a default of 1 minute.
	encryptionconfigcontroller.EncryptionConfigFileChangePollDuration = time.Second

	ctx := ktesting.Init(t)

	svmTest := svmSetup(ctx, t)

	// ToDo: try to test with 1000 secrets
	secret, err := svmTest.createSecret(ctx, t, secretName, defaultNamespace)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	metricBeforeUpdate := svmTest.getAutomaticReloadSuccessTotal(ctx, t)
	svmTest.updateFile(t, svmTest.filePathForEncryptionConfig, encryptionConfigFileName, []byte(resources["updatedEncryptionConfig"]))
	if !svmTest.isEncryptionConfigFileUpdated(ctx, t, metricBeforeUpdate) {
		t.Fatalf("Failed to update encryption config file")
	}

	svm, err := svmTest.createSVMResource(
		ctx,
		t,
		svmName,
		svmv1alpha1.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "secrets",
		},
	)
	if err != nil {
		t.Fatalf("Failed to create SVM resource: %v", err)
	}
	if !svmTest.waitForResourceMigration(ctx, t, svm.Name, secret.Name, 1) {
		t.Fatalf("Failed to migrate resource %s/%s", secret.Namespace, secret.Name)
	}

	wantPrefix := "k8s:enc:aescbc:v1:key2"
	etcdSecret, err := svmTest.getRawSecretFromETCD(t, secret.Name, secret.Namespace)
	if err != nil {
		t.Fatalf("Failed to get secret from etcd: %v", err)
	}
	// assert that secret is prefixed with the new key
	if !bytes.HasPrefix(etcdSecret, []byte(wantPrefix)) {
		t.Fatalf("expected secret to be prefixed with %s, but got %s", wantPrefix, etcdSecret)
	}

	secretAfterMigration, err := svmTest.client.CoreV1().Secrets(secret.Namespace).Get(ctx, secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}
	// assert that RV is different
	// rv is expected to be different as the secret was re-written to etcd with the new key
	if secret.ResourceVersion == secretAfterMigration.ResourceVersion {
		t.Fatalf("Expected resource version to be different, but got the same, rv before: %s, rv after: %s", secret.ResourceVersion, secretAfterMigration.ResourceVersion)
	}

	secondSVM, err := svmTest.createSVMResource(
		ctx,
		t,
		secondSVMName,
		svmv1alpha1.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "secrets",
		},
	)
	if err != nil {
		t.Fatalf("Failed to create SVM resource: %v", err)
	}
	if !svmTest.waitForResourceMigration(ctx, t, secondSVM.Name, secretAfterMigration.Name, 2) {
		t.Fatalf("Failed to migrate resource %s/%s", secretAfterMigration.Namespace, secretAfterMigration.Name)
	}

	secretAfterSecondMigration, err := svmTest.client.CoreV1().Secrets(secretAfterMigration.Namespace).Get(ctx, secretAfterMigration.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}
	// assert that RV is same
	if secretAfterMigration.ResourceVersion != secretAfterSecondMigration.ResourceVersion {
		t.Fatalf("Expected resource version to be same, but got different, rv before: %s, rv after: %s", secretAfterMigration.ResourceVersion, secretAfterSecondMigration.ResourceVersion)
	}
}

// TestStorageVersionMigrationWithCRD is an integration test that verifies storage version migration works with CRD.
// This test asserts following scenarios:
// 1. CRD is created with version v1 (serving and storage)
// 2. Verify that CRs are written and stored as v1
// 3. Update CRD to introduce v2 (for serving only), and a conversion webhook is added
// 4. Verify that CRs are written to v2 but are stored as v1
// 5. CRD storage version is changed from v1 to v2
// 6. Verify that CR written as either v1 or v2 version are stored as v2
// 7. Perform Storage Version Migration to migrate all v1 CRs to v2
// 8. CRD is updated to no longer serve v1
// 9. Shutdown conversion webhook
// 10. Verify RV and Generations of CRs
// 11. Verify the list of CRs at v2 works
func TestStorageVersionMigrationWithCRD(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.StorageVersionMigrator, true)
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, featuregate.Feature(clientgofeaturegate.InformerResourceVersion), true)
	// decode errors are expected when using conversation webhooks
	etcd3watcher.TestOnlySetFatalOnDecodeError(false)
	t.Cleanup(func() { etcd3watcher.TestOnlySetFatalOnDecodeError(true) })
	framework.GoleakCheck(t, // block test clean up and let any lingering watches complete before making decode errors fatal again
		goleak.IgnoreTopFunction("k8s.io/kubernetes/vendor/gopkg.in/natefinch/lumberjack%2ev2.(*Logger).millRun"),
		goleak.IgnoreTopFunction("gopkg.in/natefinch/lumberjack%2ev2.(*Logger).millRun"),
		goleak.IgnoreTopFunction("github.com/moby/spdystream.(*Connection).shutdown"),
	)

	ctx := ktesting.Init(t)

	crVersions := make(map[string]versions)

	svmTest := svmSetup(ctx, t)
	certCtx := svmTest.setupServerCert(t)

	// simulate monkeys creating and deleting CRs
	svmTest.createChaos(ctx, t)

	// create CRD with v1 serving and storage
	crd := svmTest.createCRD(t, crdName, crdGroup, certCtx, v1CRDVersion)

	// create CR
	cr1 := svmTest.createCR(ctx, t, "cr1", "v1")
	if ok := svmTest.isCRStoredAtVersion(t, "v1", cr1.GetName()); !ok {
		t.Fatalf("CR not stored at version v1")
	}
	crVersions[cr1.GetName()] = versions{
		generation:  cr1.GetGeneration(),
		rv:          cr1.GetResourceVersion(),
		isRVUpdated: true,
	}

	// add conversion webhook
	shutdownServer := svmTest.createConversionWebhook(ctx, t, certCtx)

	// add v2 for serving only
	svmTest.updateCRD(ctx, t, crd.Name, v2CRDVersion, []string{"v1", "v2"}, "v1")

	// create another CR
	cr2 := svmTest.createCR(ctx, t, "cr2", "v2")
	if ok := svmTest.isCRStoredAtVersion(t, "v1", cr2.GetName()); !ok {
		t.Fatalf("CR not stored at version v1")
	}
	crVersions[cr2.GetName()] = versions{
		generation:  cr2.GetGeneration(),
		rv:          cr2.GetResourceVersion(),
		isRVUpdated: true,
	}

	// add v2 as storage version
	svmTest.updateCRD(ctx, t, crd.Name, v2StorageCRDVersion, []string{"v1", "v2"}, "v2")

	// create CR with v1
	cr3 := svmTest.createCR(ctx, t, "cr3", "v1")
	if ok := svmTest.isCRStoredAtVersion(t, "v2", cr3.GetName()); !ok {
		t.Fatalf("CR not stored at version v2")
	}
	crVersions[cr3.GetName()] = versions{
		generation:  cr3.GetGeneration(),
		rv:          cr3.GetResourceVersion(),
		isRVUpdated: false,
	}

	// create CR with v2
	cr4 := svmTest.createCR(ctx, t, "cr4", "v2")
	if ok := svmTest.isCRStoredAtVersion(t, "v2", cr4.GetName()); !ok {
		t.Fatalf("CR not stored at version v2")
	}
	crVersions[cr4.GetName()] = versions{
		generation:  cr4.GetGeneration(),
		rv:          cr4.GetResourceVersion(),
		isRVUpdated: false,
	}

	// verify cr1 ans cr2 are still stored at v1
	if ok := svmTest.isCRStoredAtVersion(t, "v1", cr1.GetName()); !ok {
		t.Fatalf("CR not stored at version v1")
	}
	if ok := svmTest.isCRStoredAtVersion(t, "v1", cr2.GetName()); !ok {
		t.Fatalf("CR not stored at version v1")
	}

	// migrate CRs from v1 to v2
	svm, err := svmTest.createSVMResource(
		ctx, t, "crdsvm",
		svmv1alpha1.GroupVersionResource{
			Group:    crd.Spec.Group,
			Version:  "v1",
			Resource: crd.Spec.Names.Plural,
		})
	if err != nil {
		t.Fatalf("Failed to create SVM resource: %v", err)
	}
	if ok := svmTest.isCRDMigrated(ctx, t, svm.Name, "triggercr"); !ok {
		t.Fatalf("CRD not migrated")
	}

	// assert all the CRs are stored in the etcd at correct version
	if ok := svmTest.isCRStoredAtVersion(t, "v2", cr1.GetName()); !ok {
		t.Fatalf("CR not stored at version v2")
	}
	if ok := svmTest.isCRStoredAtVersion(t, "v2", cr2.GetName()); !ok {
		t.Fatalf("CR not stored at version v2")
	}
	if ok := svmTest.isCRStoredAtVersion(t, "v2", cr3.GetName()); !ok {
		t.Fatalf("CR not stored at version v2")
	}
	if ok := svmTest.isCRStoredAtVersion(t, "v2", cr4.GetName()); !ok {
		t.Fatalf("CR not stored at version v2")
	}

	// update CRD to v1 not serving and storage followed by webhook shutdown
	svmTest.updateCRD(ctx, t, crd.Name, v1NotServingCRDVersion, []string{"v2"}, "v2")
	shutdownServer()

	// assert RV and Generations of CRs
	svmTest.validateRVAndGeneration(ctx, t, crVersions, "v2")

	// assert v2 CRs can be listed
	if err := svmTest.listCR(ctx, t, "v2"); err != nil {
		t.Fatalf("Failed to list CRs at version v2: %v", err)
	}
}

func TestCRDDiscoveryStorageRace(t *testing.T) {
	testCtx := ktesting.Init(t)

	etcdStorage := framework.SharedEtcd()
	testKAS := kubeapiservertesting.StartTestServerOrDie(t, nil, nil, etcdStorage)
	defer testKAS.TearDownFn()

	etcdClient, _, err := integration.GetEtcdClients(testKAS.ServerOpts.Etcd.StorageConfig.Transport)
	if err != nil {
		t.Fatalf("failed to retrieve etcd client: %v", err)
	}
	defer etcdClient.Close()

	kubeClient := kubernetes.NewForConfigOrDie(testKAS.ClientConfig)
	apiExtensionClient := apiextensionsclient.NewForConfigOrDie(testKAS.ClientConfig)
	dynamicClient := dynamic.NewForConfigOrDie(testKAS.ClientConfig)

	testCRDResourceNameFmt := "testcrd"
	testCRDGroup := "crdstorage.test.k8s.io"
	testCRDTpl := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{"api-approved.kubernetes.io": "unapproved, test-only"},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: testCRDGroup,
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name:    "v2",
					Served:  true,
					Storage: false,
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]apiextensionsv1.JSONSchemaProps{
								"host": {Type: "string"},
								"port": {Type: "string"},
							},
						},
					},
				},
				{
					Name:    "v1",
					Served:  true,
					Storage: true,
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]apiextensionsv1.JSONSchemaProps{
								"hostPort": {Type: "string"},
							},
						},
					},
				},
			},
			PreserveUnknownFields: false,
		},
	}

	turnOnV2Storage := func(crd *apiextensionsv1.CustomResourceDefinition) *apiextensionsv1.CustomResourceDefinition {
		crd.Spec.Versions = []apiextensionsv1.CustomResourceDefinitionVersion{
			{
				Name:    "v2",
				Served:  true,
				Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"host": {Type: "string"},
							"port": {Type: "string"},
						},
					},
				},
			},
			{
				Name:    "v1",
				Served:  true,
				Storage: false,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"hostPort": {Type: "string"},
						},
					},
				},
			},
		}
		return crd
	}

	getResFromEtcd := func(t *testing.T, path string) *unstructured.Unstructured {
		response, err := etcdClient.Get(context.Background(), path, clientv3.WithPrefix())
		if err != nil {
			t.Fatalf("failed to retrieve resource from etcd %v", err)
		}

		// parse data to unstructured.Unstructured
		obj := &unstructured.Unstructured{}
		err = obj.UnmarshalJSON(response.Kvs[0].Value)
		if err != nil {
			t.Fatalf("Failed to unmarshal data to unstructured: %v", err)
		}

		return obj
	}

	discoveredV2Storage := func(resourceKind string) (bool, error) {
		apiGroups, _, err := kubeClient.Discovery().ServerGroupsAndResources()
		if err != nil {
			return false, fmt.Errorf("failed to get server groups and resources: %w", err)
		}

		expectedStorageHash := endpointsdiscovery.StorageVersionHash(testCRDGroup, "v2", resourceKind)

		for _, api := range apiGroups {
			if api.Name != testCRDGroup {
				continue
			}
			var servingVersions []string
			for _, apiVersion := range api.Versions {
				servingVersions = append(servingVersions, apiVersion.Version)
			}
			sort.Strings(servingVersions)

			// Check if the serving versions are as expected
			if !reflect.DeepEqual(servingVersions, []string{"v1", "v2"}) {
				continue
			}

			resourceList, err := kubeClient.Discovery().ServerResourcesForGroupVersion(testCRDGroup + "/" + api.PreferredVersion.Version)
			if err != nil {
				return false, fmt.Errorf("failed to get server resources for group version: %w", err)
			}

			// Check if the storage version is as expected
			for _, resource := range resourceList.APIResources {
				if resource.Kind == resourceKind && resource.StorageVersionHash == expectedStorageHash {
					return true, nil
				}
			}
		}
		return false, nil
	}

	wg := sync.WaitGroup{}
	for testnum := range 100 {
		wg.Add(1)
		go t.Run(fmt.Sprintf("run %d", testnum), func(t *testing.T) {
			defer wg.Done()
			ctx := ktesting.WithCancel(testCtx)

			resName := testCRDResourceNameFmt + strconv.Itoa(testnum)
			resNamePlural := resName + "s"

			// Step 1: Create a CRD for the test
			crdRes := testCRDTpl.DeepCopy()
			crdRes.Name = resNamePlural + "." + testCRDGroup
			crdRes.Spec.Names = apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     resName,
				ListKind: resName + "List",
				Plural:   resNamePlural,
				Singular: resName,
			}

			etcd.CreateTestCRDs(t, apiExtensionClient, false, crdRes)

			// Step 2: create a CR for the CRD GV and make sure it's stored in v1 storage
			gv := schema.GroupVersionResource{
				Group:    testCRDGroup,
				Version:  "v1",
				Resource: resNamePlural,
			}
			crObject := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": gv.GroupVersion().String(),
					"kind":       resName,
					"metadata": map[string]interface{}{
						"name":      "testobj-prev2",
						"namespace": "default",
					},
				},
			}
			_, err = dynamicClient.Resource(gv).Namespace(defaultNamespace).Create(ctx, crObject, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("Failed to create CR: %v", err)
			}

			// Step 3: check we're storing the resource at the expected path
			etcdPath := fmt.Sprintf("/%s/%s/%s/%s/%s", etcdStorage.Prefix, testCRDGroup, resNamePlural, "default", "testobj-prev2")
			etcdObj := getResFromEtcd(t, etcdPath)

			if etcdObj.GetAPIVersion() != fmt.Sprintf("%s/%s", testCRDGroup, "v1") {
				t.Fatalf("a resource was not stored as v1 after CRD init")
			}

			// Step 4: switch the storage to use v2 instead of v1
			crdRes, err = apiExtensionClient.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, crdRes.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("failed to retrieve CRD: %v", err)
			}
			_, err = apiExtensionClient.ApiextensionsV1().CustomResourceDefinitions().Update(ctx, turnOnV2Storage(crdRes), metav1.UpdateOptions{})
			if err != nil {
				t.Fatalf("failed to update CRD for v2 storage: %v", err)
			}

			// Step 5: wait for discovery to broadcast v2 as the storage version
			err := wait.PollUntilContextTimeout(
				ctx,
				500*time.Millisecond,
				time.Second*60,
				true,
				func(ctx context.Context) (done bool, err error) {
					ok, err := discoveredV2Storage(resName)
					if err != nil {
						return false, fmt.Errorf("discovery failed: %w", err)
					}
					return ok, nil
				})

			if err != nil {
				t.Fatalf("failed waiting for discovery: %v", err)
			}

			// Step 6: create a new resource, expecting it to be in v2 storage
			crObject = &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": gv.GroupVersion().String(),
					"kind":       resName,
					"metadata": map[string]interface{}{
						"name":      "testobj-postv2",
						"namespace": "default",
					},
				},
			}
			_, err = dynamicClient.Resource(gv).Namespace(defaultNamespace).Create(ctx, crObject, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("Failed to create CR: %v", err)
			}

			etcdPath = fmt.Sprintf("/%s/%s/%s/%s/%s", etcdStorage.Prefix, testCRDGroup, resNamePlural, "default", "testobj-postv2")
			etcdObj = getResFromEtcd(t, etcdPath)

			if etcdObj.GetAPIVersion() != fmt.Sprintf("%s/%s", testCRDGroup, "v2") {
				t.Fatalf("a resource was not stored as v2 after CRD update")
			}
		})
	}
	wg.Wait()
}

// TestStorageVersionMigrationDuringChaos serves as a stress test for the SVM controller.
// It creates a CRD and a reasonable number of static instances for that resource.
// It also continuously creates and deletes instances of that resource.
// During all of this, it attempts to perform multiple parallel migrations of the resource.
// It asserts that all migrations are successful and that none of the static instances
// were changed after they were initially created (as the migrations must be a no-op).
func TestStorageVersionMigrationDuringChaos(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.StorageVersionMigrator, true)
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, featuregate.Feature(clientgofeaturegate.InformerResourceVersion), true)

	ctx := ktesting.Init(t)

	svmTest := svmSetup(ctx, t)

	svmTest.createChaos(ctx, t)

	crd := svmTest.createCRD(t, crdName, crdGroup, nil, v1CRDVersion)

	crVersions := make(map[string]versions)

	for i := range 50 { // a more realistic number of total resources
		cr := svmTest.createCR(ctx, t, "created-cr-"+strconv.Itoa(i), "v1")
		crVersions[cr.GetName()] = versions{
			generation:  cr.GetGeneration(),
			rv:          cr.GetResourceVersion(),
			isRVUpdated: false, // none of these CRs should change due to migrations
		}
	}

	var wg sync.WaitGroup
	const migrations = 10 // more than the total workers of SVM
	wg.Add(migrations)
	for i := range migrations {
		i := i
		go func() {
			defer wg.Done()

			svm, err := svmTest.createSVMResource(
				ctx, t, "chaos-svm-"+strconv.Itoa(i),
				svmv1alpha1.GroupVersionResource{
					Group:    crd.Spec.Group,
					Version:  "v1",
					Resource: crd.Spec.Names.Plural,
				},
			)
			if err != nil {
				t.Errorf("Failed to create SVM resource: %v", err)
				return
			}
			triggerCRName := "chaos-trigger-" + strconv.Itoa(i)
			if ok := svmTest.isCRDMigrated(ctx, t, svm.Name, triggerCRName); !ok {
				t.Errorf("CRD not migrated")
				return
			}
		}()
	}
	wg.Wait()

	svmTest.validateRVAndGeneration(ctx, t, crVersions, "v1")
}
