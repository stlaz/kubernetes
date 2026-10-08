package v1beta1

import (
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	conversion "k8s.io/apimachinery/pkg/conversion"
	admissionregistration "k8s.io/kubernetes/pkg/apis/admissionregistration"
)

func Convert_admissionregistration_WebhookClientConfig_To_v1beta1_WebhookClientConfig(in *admissionregistration.WebhookClientConfig, out *admissionregistrationv1beta1.WebhookClientConfig, s conversion.Scope) error {
	// TODO: should we error out on ClusterTrustBundle being set?
	return autoConvert_admissionregistration_WebhookClientConfig_To_v1beta1_WebhookClientConfig(in, out, s)
}
