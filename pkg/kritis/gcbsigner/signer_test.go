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
	sec1, pub1 := testutil.CreateSecret(t, "auth1_key")
	sec2, pub2 := testutil.CreateSecret(t, "auth2_key")
	sec3, pub3 := testutil.CreateSecret(t, "auth3_key")
	sMock := func(_ string, name string) (*secrets.PGPSigningSecret, error) {
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
				PrivateKeySecretName:     "auth1_key",
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
				PrivateKeySecretName:     "auth2_key",
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
				PrivateKeySecretName:     "auth3_key",
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
				PrivateKeySecretName:     "missing_key",
				BuildRequirements: v1beta1.BuildRequirements{
					BuiltFrom: "no_key_attestor",
				},
			},
		},
	}
	authFetcher = func(ns string, name string) (*v1beta1.AttestationAuthority, error) {
		a := []v1beta1.AttestationAuthority{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth1",
					Namespace: "foo",
				},
				Spec: v1beta1.AttestationAuthoritySpec{
					NoteReference: "auth1_note",
					PublicKeys: []v1beta1.PublicKey{
						{
							KeyType:                  "PGP_KEY",
							AsciiArmoredPgpPublicKey: pub1,
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth2",
					Namespace: "foo",
				},
				Spec: v1beta1.AttestationAuthoritySpec{
					NoteReference: "auth2_note",
					PublicKeys: []v1beta1.PublicKey{
						{
							KeyType:                  "PGP_KEY",
							AsciiArmoredPgpPublicKey: pub2,
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth3",
					Namespace: "foo",
				},
				Spec: v1beta1.AttestationAuthoritySpec{
					NoteReference: "auth3_note",
					PublicKeys: []v1beta1.PublicKey{
						{
							KeyType:                  "PGP_KEY",
							AsciiArmoredPgpPublicKey: pub3,
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth4",
					Namespace: "foo",
				},
				Spec: v1beta1.AttestationAuthoritySpec{
					NoteReference: "auth4_note",
				},
			},
		}
		for _, i := range a {
			if i.Name == name {
				return &i, nil
			}
		}
		return nil, fmt.Errorf("not present")
	}

	tests := []struct {
		name                 string
		provenance           BuildProvenance
		expectedAttestations map[string]string
		shdErr               bool
	}{
		{
			name: "build matches single attestor",
			provenance: BuildProvenance{
				ImageRef:  "image1",
				BuiltFrom: "single_attestor",
			},
			expectedAttestations: map[string]string{
				"image1-auth1_note": "auth1_key",
			},
		},
		{
			name: "build matches multiple attestors",
			provenance: BuildProvenance{
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
			provenance: BuildProvenance{
				ImageRef:  "image1",
				BuiltFrom: "no_attestor",
			},
		},
		{
			name: "build matches attestor without key",
			provenance: BuildProvenance{
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
			if err := r.ValidateAndSign(tc.provenance, bps); (err != nil) != tc.shdErr {
				t.Errorf("ValidateAndSign returned error %s, want %t", err, tc.shdErr)
			}
			if !reflect.DeepEqual(cMock.Occ, tc.expectedAttestations) {
				t.Errorf("Got attestations: %v, Expected: %v\n ", cMock.Occ, tc.expectedAttestations)
			}
		})
	}
}
