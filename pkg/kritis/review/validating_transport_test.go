/*
Copyright 2019 Google LLC

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

package review

import (
	"encoding/base64"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"github.com/grafeas/kritis/pkg/kritis/util"
)

func TestValidatingTransport(t *testing.T) {
	successSec, pub := testutil.CreateSecret(t, "test-success")
	successFpr := successSec.PgpKey.Fingerprint()
	sig, err := util.CreateAttestationSignature(testutil.QualifiedImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	anotherSig, err := util.CreateAttestationSignature(testutil.IntTestImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	tcs := []struct {
		name         string
		expected     []attestation.ValidatedAttestation
		attestations []metadata.PGPAttestation
	}{
		{"at least one valid sig", []attestation.ValidatedAttestation{
			{
				AttestorName: "test-attestor",
				ArtifactName: testutil.QualifiedImage,
			},
		}, []metadata.PGPAttestation{
			{
				Signature: sig,
				KeyID:     successFpr,
			}, {
				Signature: "invalid-sig",
				KeyID:     successFpr,
			}}},
		{"no valid sig", []attestation.ValidatedAttestation{}, []metadata.PGPAttestation{
			{
				Signature: "invalid-sig",
				KeyID:     successFpr,
			}}},
		{"invalid secret", []attestation.ValidatedAttestation{}, []metadata.PGPAttestation{
			{
				Signature: "invalid-sig",
				KeyID:     "invalid-fpr",
			}}},
		{"valid sig over another host", []attestation.ValidatedAttestation{}, []metadata.PGPAttestation{
			{
				Signature: anotherSig,
				KeyID:     successFpr,
			}}},
	}

	auth := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PrivateKeySecretName: "test-success",
			PublicKeyData:        base64.StdEncoding.EncodeToString([]byte(pub)),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cMock := &testutil.MockMetadataClient{
				PGPAttestations: tc.attestations,
			}
			vat := AttestorValidatingTransport{cMock, auth}
			atts, err := vat.GetValidatedAttestations(testutil.QualifiedImage)
			if err != nil {
				t.Fatal("Error not expected ", err.Error())
			}
			if !reflect.DeepEqual(atts, tc.expected) {
				t.Fatalf("Expected %v, Got %v", tc.expected, atts)
			}
		})
	}
}
