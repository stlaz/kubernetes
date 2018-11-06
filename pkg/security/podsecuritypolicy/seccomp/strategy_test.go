/*
Copyright 2016 The Kubernetes Authors.

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

package seccomp

import (
	"reflect"
	"strings"
	"testing"

	policy "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	api "k8s.io/kubernetes/pkg/apis/core"
)

type testStrategy struct {
	defaultProfile  *string
	allowedProfiles []string
}

var (
	// Field-specific strategies
	seccompFooProfile = "foo"
	seccompBarProfile = "bar"
	withoutSeccomp    = testStrategy{}
	allowAnyNoDefault = testStrategy{allowedProfiles: []string{SeccompAllowAny}}
	allowAnyDefault   = testStrategy{
		allowedProfiles: []string{SeccompAllowAny},
		defaultProfile:  &seccompFooProfile,
	}
	allowAnyAndSpecificDefault = testStrategy{
		allowedProfiles: []string{"bar", SeccompAllowAny},
		defaultProfile:  &seccompFooProfile,
	}
	allowSpecificNoDefault = testStrategy{allowedProfiles: []string{"foo"}}
	allowMultipleNoDefault = testStrategy{
		allowedProfiles: []string{"foo", "bar"},
	}
	allowMultipleDefault = testStrategy{
		allowedProfiles: []string{"foo", "bar"},
		defaultProfile:  &seccompFooProfile,
	}

	// Annotations-defined strategies (DEPRECATED)
	withoutSeccompAnn    = map[string]string{}
	allowAnyNoDefaultAnn = map[string]string{
		AllowedProfilesAnnotationKey: "*",
	}
	allowAnyDefaultAnn = map[string]string{
		AllowedProfilesAnnotationKey: "*",
		DefaultProfileAnnotationKey:  "foo",
	}
	allowAnyAndSpecificDefaultAnn = map[string]string{
		AllowedProfilesAnnotationKey: "*,bar",
		DefaultProfileAnnotationKey:  "foo",
	}
	allowSpecificAnn = map[string]string{
		AllowedProfilesAnnotationKey: "foo",
	}
)

func TestNewStrategy(t *testing.T) {
	// FIXME: add fields, maybe just add a testStrategy in this struct?
	tests := map[string]struct {
		annotations                   map[string]string
		pspSpec                       testStrategy
		expectedAllowedProfilesString string
		expectedAllowAny              bool
		expectedAllowedProfiles       map[string]bool
		expectedDefaultProfile        *string
	}{
		"no seccomp": {
			annotations:                   withoutSeccompAnn,
			expectedAllowAny:              false,
			expectedAllowedProfilesString: "",
			expectedAllowedProfiles:       map[string]bool{},
			expectedDefaultProfile:        nil,
		},
		"allow any, no default": {
			annotations:                   allowAnyNoDefaultAnn,
			expectedAllowAny:              true,
			expectedAllowedProfilesString: "*",
			expectedAllowedProfiles:       map[string]bool{},
			expectedDefaultProfile:        nil,
		},
		"allow any, default": {
			annotations:                   allowAnyDefaultAnn,
			expectedAllowAny:              true,
			expectedAllowedProfilesString: "*",
			expectedAllowedProfiles:       map[string]bool{},
			expectedDefaultProfile:        &seccompFooProfile,
		},
		"allow any and specific, default": {
			annotations:                   allowAnyAndSpecificDefaultAnn,
			expectedAllowAny:              true,
			expectedAllowedProfilesString: "*,bar",
			expectedAllowedProfiles: map[string]bool{
				"bar": true,
			},
			expectedDefaultProfile: &seccompFooProfile,
		},
	}
	for k, v := range tests {
		// FIXME: add fields
		policy := &policy.PodSecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: v.annotations,
			},
		}
		s := NewSeccompStrategy(policy)
		internalStrat, _ := s.(*seccompStrategy)

		if internalStrat.allowAnyProfile != v.expectedAllowAny {
			t.Errorf("%s expected allowAnyProfile to be %t but found %t", k, v.expectedAllowAny, internalStrat.allowAnyProfile)
		}
		if internalStrat.allowedProfilesString != v.expectedAllowedProfilesString {
			t.Errorf("%s expected allowedProfilesString to be %s but found %s", k, v.expectedAllowedProfilesString, internalStrat.allowedProfilesString)
		}
		if v.expectedDefaultProfile != nil {
			if internalStrat.defaultProfile == nil {
				t.Errorf("%s expected defaultProfile to be %s but found <nil>", k, *v.expectedDefaultProfile)
			} else if *internalStrat.defaultProfile != *v.expectedDefaultProfile {
				t.Errorf("%s expected defaultProfile to be %s but found %s", k, *v.expectedDefaultProfile, *internalStrat.defaultProfile)
			}
		}

		if !reflect.DeepEqual(v.expectedAllowedProfiles, internalStrat.allowedProfiles) {
			t.Errorf("%s expected expectedAllowedProfiles to be %#v but found %#v", k, v.expectedAllowedProfiles, internalStrat.allowedProfiles)
		}
	}
}

func TestGenerate(t *testing.T) {
	tests := map[string]struct {
		pspAnnotations    map[string]string
		podAnnotations    map[string]string
		podSeccompProfile *string
		expectedProfile   *string
	}{
		"no seccomp, no pod annotations": {
			pspAnnotations:  withoutSeccompAnn,
			podAnnotations:  nil,
			expectedProfile: nil,
		},
		"no seccomp, pod annotations": {
			pspAnnotations: withoutSeccompAnn,
			podAnnotations: map[string]string{
				api.SeccompPodAnnotationKey: "foo",
			},
			expectedProfile: &seccompFooProfile,
		},
		"seccomp with no default, no pod annotations": {
			pspAnnotations:  allowAnyNoDefaultAnn,
			podAnnotations:  nil,
			expectedProfile: nil,
		},
		"seccomp with no default, pod annotations": {
			pspAnnotations: allowAnyNoDefaultAnn,
			podAnnotations: map[string]string{
				api.SeccompPodAnnotationKey: "foo",
			},
			expectedProfile: &seccompFooProfile,
		},
		"seccomp with default, no pod annotations": {
			pspAnnotations:  allowAnyDefaultAnn,
			podAnnotations:  nil,
			expectedProfile: &seccompFooProfile,
		},
		"seccomp with default, pod annotations": {
			pspAnnotations: allowAnyDefaultAnn,
			podAnnotations: map[string]string{
				api.SeccompPodAnnotationKey: "bar",
			},
			expectedProfile: &seccompBarProfile,
		},
	}
	for k, v := range tests {
		// FIXME: test both fields and annotations somehow
		pod := &api.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: v.podAnnotations,
			},
			Spec: api.PodSpec{
				SecurityContext: &api.PodSecurityContext{
					SeccompProfile: v.podSeccompProfile,
				},
			},
		}
		// FIXME: add fields
		policy := &policy.PodSecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: v.pspAnnotations,
			},
		}
		s := NewSeccompStrategy(policy)
		actual, err := s.Generate(pod, nil)
		if err != nil {
			t.Errorf("%s received error during generation %#v", k, err)
			continue
		}
		// FIXME: test both fields and annotations somehow
		if v.expectedProfile != nil {
			if actual == nil {
				t.Errorf("%s expected profile to be %s but found <nil>", k, *v.expectedProfile)
			} else if *actual != *v.expectedProfile {
				t.Errorf("%s expected defaultProfile to be %s but found %s", k, *v.expectedProfile, *actual)
			}
		} else if actual != nil {
			t.Errorf("%s expected defaultProfile to be <nil> but found %s", k, *actual)
		}
	}
}

func TestValidatePod(t *testing.T) {
	tests := map[string]struct {
		pspAnnotations map[string]string
		podAnnotations map[string]string
		expectedError  string
	}{
		"no pod annotations, required profiles": {
			pspAnnotations: allowSpecificAnn,
			podAnnotations: nil,
			expectedError:  "Forbidden: <nil> is not an allowed seccomp profile. Valid values are foo",
		},
		"no pod annotations, no required profiles": {
			pspAnnotations: withoutSeccompAnn,
			podAnnotations: nil,
			expectedError:  "",
		},
		"valid pod annotations, required profiles": {
			pspAnnotations: allowSpecificAnn,
			podAnnotations: map[string]string{
				api.SeccompPodAnnotationKey: "foo",
			},
			expectedError: "",
		},
		"invalid pod annotations, required profiles": {
			pspAnnotations: allowSpecificAnn,
			podAnnotations: map[string]string{
				api.SeccompPodAnnotationKey: "bar",
			},
			expectedError: "Forbidden: bar is not an allowed seccomp profile. Valid values are foo",
		},
		"pod annotations, no required profiles": {
			pspAnnotations: withoutSeccompAnn,
			podAnnotations: map[string]string{
				api.SeccompPodAnnotationKey: "foo",
			},
			expectedError: "Forbidden: seccomp must not be set",
		},
		"pod annotations, allow any": {
			pspAnnotations: allowAnyNoDefaultAnn,
			podAnnotations: map[string]string{
				api.SeccompPodAnnotationKey: "foo",
			},
			expectedError: "",
		},
		"no pod annotations, allow any": {
			pspAnnotations: allowAnyNoDefaultAnn,
			podAnnotations: nil,
			expectedError:  "",
		},
	}
	for k, v := range tests {
		pod := &api.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: v.podAnnotations,
			},
		}
		// FIXME: add fields
		policy := &policy.PodSecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: v.pspAnnotations,
			},
		}
		s := NewSeccompStrategy(policy)
		errs := s.ValidatePod(pod, nil)
		if v.expectedError == "" && len(errs) != 0 {
			t.Errorf("%s expected no errors but received %#v", k, errs.ToAggregate().Error())
		}
		if v.expectedError != "" && len(errs) == 0 {
			t.Errorf("%s expected error %s but received none", k, v.expectedError)
		}
		if v.expectedError != "" && len(errs) > 1 {
			t.Errorf("%s received multiple errors: %s", k, errs.ToAggregate().Error())
		}
		if v.expectedError != "" && len(errs) == 1 && !strings.Contains(errs.ToAggregate().Error(), v.expectedError) {
			t.Errorf("%s expected error %s but received %s", k, v.expectedError, errs.ToAggregate().Error())
		}
	}
}

func TestValidateContainer(t *testing.T) {
	tests := map[string]struct {
		pspAnnotations map[string]string
		podAnnotations map[string]string
		pspSpec        testStrategy
		seccompProfile *string
		expectedError  string
	}{
		"no pod annotations, required profiles": {
			pspAnnotations: allowSpecificAnn,
			podAnnotations: nil,
			expectedError:  "Forbidden: <nil> is not an allowed seccomp profile. Valid values are foo",
		},
		"no pod annotations, no required profiles": {
			pspAnnotations: withoutSeccompAnn,
			podAnnotations: nil,
			expectedError:  "",
		},
		"valid pod annotations, required profiles": {
			pspAnnotations: allowSpecificAnn,
			podAnnotations: map[string]string{
				api.SeccompContainerAnnotationKeyPrefix + "container": "foo",
			},
			expectedError: "",
		},
		"invalid pod annotations, required profiles": {
			pspAnnotations: allowSpecificAnn,
			podAnnotations: map[string]string{
				api.SeccompContainerAnnotationKeyPrefix + "container": "bar",
			},
			expectedError: "Forbidden: bar is not an allowed seccomp profile. Valid values are foo",
		},
		"pod annotations, no required profiles": {
			pspAnnotations: withoutSeccompAnn,
			podAnnotations: map[string]string{
				api.SeccompContainerAnnotationKeyPrefix + "container": "foo",
			},
			expectedError: "Forbidden: seccomp must not be set",
		},
		"pod annotations, allow any": {
			pspAnnotations: allowAnyNoDefaultAnn,
			podAnnotations: map[string]string{
				api.SeccompContainerAnnotationKeyPrefix + "container": "foo",
			},
			expectedError: "",
		},
		"no pod annotations, allow any": {
			pspAnnotations: allowAnyNoDefaultAnn,
			podAnnotations: nil,
			expectedError:  "",
		},
		"container inherits valid pod annotation": {
			pspAnnotations: allowSpecificAnn,
			podAnnotations: map[string]string{
				api.SeccompPodAnnotationKey: "foo",
			},
			expectedError: "",
		},
		"container inherits invalid pod annotation": {
			pspAnnotations: allowSpecificAnn,
			podAnnotations: map[string]string{
				api.SeccompPodAnnotationKey: "bar",
			},
			expectedError: "Forbidden: bar is not an allowed seccomp profile. Valid values are foo",
		},
	}
	for k, v := range tests {
		policy := &policy.PodSecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: v.pspAnnotations,
			},
			Spec: policy.PodSecurityPolicySpec{
				DefaultSeccompProfile:  v.pspSpec.defaultProfile,
				AllowedSeccompProfiles: v.pspSpec.allowedProfiles,
			},
		}
		pod := &api.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: v.podAnnotations,
			},
			Spec: api.PodSpec{
				Containers: []api.Container{
					{
						Name: "container",
						// 			SecurityContext: &api.SecurityContext{
						// 				SeccompProfile: v.containerProfile,
						// 			},
					},
				},
			},
		}
		s := NewSeccompStrategy(policy)
		// FIXME: remove validate() from the interface, split test into validatePod and validateContainer
		// FIXME: add annotations
		errs := s.ValidateContainer(pod, &pod.Spec.Containers[0], nil)
		if v.expectedError == "" && len(errs) != 0 {
			t.Errorf("'%s' expected no errors but received '%#v'", k, errs.ToAggregate().Error())
		}
		if v.expectedError != "" && len(errs) == 0 {
			t.Errorf("'%s' expected error '%s' but received none", k, v.expectedError)
		}
		if v.expectedError != "" && len(errs) > 1 {
			t.Errorf("'%s' received multiple errors: '%s'", k, errs.ToAggregate().Error())
		}
		if v.expectedError != "" && len(errs) == 1 && !strings.Contains(errs.ToAggregate().Error(), v.expectedError) {
			t.Errorf("'%s' expected error '%s' but received '%s'", k, v.expectedError, errs.ToAggregate().Error())
		}
	}
}
