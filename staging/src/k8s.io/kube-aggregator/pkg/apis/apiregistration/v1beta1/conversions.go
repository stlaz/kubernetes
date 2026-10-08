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

package v1beta1

import (
	conversion "k8s.io/apimachinery/pkg/conversion"
	apiregistration "k8s.io/kube-aggregator/pkg/apis/apiregistration"
)

func Convert_apiregistration_APIServiceSpec_To_v1beta1_APIServiceSpec(from *apiregistration.APIServiceSpec, to *APIServiceSpec, s conversion.Scope) error {
	// TODO: should we error out here if ClusterTrustBundle is set?
	return autoConvert_apiregistration_APIServiceSpec_To_v1beta1_APIServiceSpec(from, to, s)
}
