/*
Copyright 2018 Google LLC

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

package gcbsigner

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/buildpolicy"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateAndSign(t *testing.T) {
	sec1 := testutil.CreateSecret(t, "auth1_key")
	sec2 := testutil.CreateSecret(t, "auth2_key")
	sec3 := testutil.CreateSecret(t, "auth3_key")
	sMock := func(namespace string, name string) (*secrets.PGPSigningSecret, error) {
		switch name {
		case "auth1_key":
			return sec1, nil
		case "auth2_key":
			return sec2, nil
		case "auth3_key":
			return sec3, nil
		default:
			return nil, fmt.Errorf("No key for %q", name)
		}
	}
	var bps = []v1beta1.BuildPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bp_auth1",
				Namespace: "foo",
			},
			Spec: v1beta1.BuildPolicySpec{
				AttestationAuthorityName: "auth1",
				BuildRequirements: v1beta1.BuildRequirements{
					BuiltFrom: "single_attestor",
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bp_auth2",
				Namespace: "foo",
			},
			Spec: v1beta1.BuildPolicySpec{
				AttestationAuthorityName: "auth2",
				BuildRequirements: v1beta1.BuildRequirements{
					BuiltFrom: "multi_attestor",
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bp_auth3",
				Namespace: "foo",
			},
			Spec: v1beta1.BuildPolicySpec{
				AttestationAuthorityName: "auth3",
				BuildRequirements: v1beta1.BuildRequirements{
					BuiltFrom: "multi_attestor",
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bp_auth4",
				Namespace: "foo",
			},
			Spec: v1beta1.BuildPolicySpec{
				AttestationAuthorityName: "auth4",
				BuildRequirements: v1beta1.BuildRequirements{
					BuiltFrom: "no_key_attestor",
				},
			},
		},
	}
	authFetcher = func(ns string) ([]v1beta1.AttestationAuthority, error) {
		return []v1beta1.AttestationAuthority{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth1",
					Namespace: "foo",
				},
				Spec: v1beta1.AttestationAuthoritySpec{
					NoteReference:        "auth1_note",
					PrivateKeySecretName: "auth1_key",
					PublicKeyData:        sec1.PublicKey,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth2",
					Namespace: "foo",
				},
				Spec: v1beta1.AttestationAuthoritySpec{
					NoteReference:        "auth2_note",
					PrivateKeySecretName: "auth2_key",
					PublicKeyData:        sec2.PublicKey,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth3",
					Namespace: "foo",
				},
				Spec: v1beta1.AttestationAuthoritySpec{
					NoteReference:        "auth3_note",
					PrivateKeySecretName: "auth3_key",
					PublicKeyData:        sec3.PublicKey,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth4",
					Namespace: "foo",
				},
				Spec: v1beta1.AttestationAuthoritySpec{
					NoteReference:        "auth4_note",
					PrivateKeySecretName: "missing_key",
				},
			},
		}, nil
	}
	tests := []struct {
		name                 string
		buildInfo            ImageBuildInfo
		expectedAttestations map[string]string
		shdErr               bool
	}{
		{
			name: "build matches single attestor",
			buildInfo: ImageBuildInfo{
				ImageRef:  "image1",
				BuiltFrom: "single_attestor",
			},
			expectedAttestations: map[string]string{
				"image1-auth1_note": "auth1_key",
			},
		},
		{
			name: "build matches multiple attestors",
			buildInfo: ImageBuildInfo{
				ImageRef:  "image1",
				BuiltFrom: "multi_attestor",
			},
			expectedAttestations: map[string]string{
				"image1-auth2_note": "auth2_key",
				"image1-auth3_note": "auth3_key",
			},
		},
		{
			name: "build matches no attestor",
			buildInfo: ImageBuildInfo{
				ImageRef:  "image1",
				BuiltFrom: "no_attestor",
			},
		},
		{
			name: "build matches attestor without key",
			buildInfo: ImageBuildInfo{
				ImageRef:  "image1",
				BuiltFrom: "no_key_attestor",
			},
			shdErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cMock := &testutil.MockMetadataClient{}
			r := New(cMock, &Config{
				Validate: buildpolicy.ValidateBuildPolicy,
				Secret:   sMock,
			})
			if err := r.ValidateAndSign(tc.buildInfo, bps); (err != nil) != tc.shdErr {
				t.Errorf("expected ValidateAndSign to return error %t, actual error %s", tc.shdErr, err)
			}
			if !reflect.DeepEqual(tc.expectedAttestations, cMock.Occ) {
				t.Errorf("Expected: %v\n Got: %v", tc.expectedAttestations, cMock.Occ)
			}
		})
	}
}
