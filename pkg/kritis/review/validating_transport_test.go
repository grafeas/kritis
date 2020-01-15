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
	"errors"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"github.com/grafeas/kritis/pkg/kritis/util"
)

func encodeB64(in string) string {
	return base64.StdEncoding.EncodeToString([]byte(in))
}

func TestValidatingTransport(t *testing.T) {
	successSec, pub := testutil.CreateSecret(t, "test-success")
	_, pub2 := testutil.CreateSecret(t, "test-success-2")
	successFpr := successSec.PgpKey.Fingerprint()
	sig, err := util.CreateAttestationSignature(testutil.QualifiedImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	anotherSig, err := util.CreateAttestationSignature(testutil.IntTestImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	validAuthWithOneGoodKey := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeyList: []string{base64.StdEncoding.EncodeToString([]byte(pub))},
		},
	}
	validAuthWithTwoGoodKeys := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeyList: []string{
				base64.StdEncoding.EncodeToString([]byte(pub)),
				base64.StdEncoding.EncodeToString([]byte(pub2)),
			},
		},
	}
	validAuthWithOneGoodOneBadKeys := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeyList: []string{"bad-key", base64.StdEncoding.EncodeToString([]byte(pub))},
		},
	}
	invalidAuthWithOneBadKey := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeyList: []string{"bad-key"},
		},
	}
	tcs := []struct {
		name          string
		auth          v1beta1.AttestationAuthority
		expected      []attestation.ValidatedAttestation
		attestations  []metadata.PGPAttestation
		errorExpected bool
		attError      error
	}{
		{name: "at least one valid sig", auth: validAuthWithOneGoodKey, expected: []attestation.ValidatedAttestation{
			{
				AttestorName: "test-attestor",
				Image:        testutil.QualifiedImage,
			},
		}, attestations: []metadata.PGPAttestation{
			{
				Signature: encodeB64(sig),
				KeyID:     successFpr,
			}, {
				Signature: encodeB64("invalid-sig"),
				KeyID:     successFpr,
			}}, errorExpected: false, attError: nil},
		{name: "auth with at least one good key", auth: validAuthWithOneGoodOneBadKeys, expected: []attestation.ValidatedAttestation{
			{
				AttestorName: "test-attestor",
				Image:        testutil.QualifiedImage,
			},
		}, attestations: []metadata.PGPAttestation{
			{
				Signature: encodeB64(sig),
				KeyID:     successFpr,
			}, {
				Signature: encodeB64("invalid-sig"),
				KeyID:     successFpr,
			}}, errorExpected: false, attError: nil},
		{name: "auth with at two good keys", auth: validAuthWithTwoGoodKeys, expected: []attestation.ValidatedAttestation{
			{
				AttestorName: "test-attestor",
				Image:        testutil.QualifiedImage,
			},
		}, attestations: []metadata.PGPAttestation{
			{
				Signature: encodeB64(sig),
				KeyID:     successFpr,
			}, {
				Signature: encodeB64("invalid-sig"),
				KeyID:     successFpr,
			}}, errorExpected: false, attError: nil},
		{name: "no valid sig", auth: validAuthWithOneGoodKey, expected: []attestation.ValidatedAttestation{}, attestations: []metadata.PGPAttestation{
			{
				Signature: encodeB64("invalid-sig"),
				KeyID:     successFpr,
			}}, errorExpected: false, attError: nil},
		{name: "sig not base64 encoded", auth: validAuthWithOneGoodKey, expected: []attestation.ValidatedAttestation{}, attestations: []metadata.PGPAttestation{
			{
				Signature: sig,
				KeyID:     successFpr,
			}}, errorExpected: false, attError: nil},
		{name: "invalid secret", auth: validAuthWithOneGoodKey, expected: []attestation.ValidatedAttestation{}, attestations: []metadata.PGPAttestation{
			{
				Signature: encodeB64("invalid-sig"),
				KeyID:     "invalid-fpr",
			}}, errorExpected: false, attError: nil},
		{name: "valid sig over another host", auth: validAuthWithOneGoodKey, expected: []attestation.ValidatedAttestation{}, attestations: []metadata.PGPAttestation{
			{
				Signature: encodeB64(anotherSig),
				KeyID:     successFpr,
			}}, errorExpected: false, attError: nil},
		{name: "attestation fetch error", auth: validAuthWithOneGoodKey, expected: nil, attestations: nil, errorExpected: true, attError: errors.New("can't fetch attestations")},
		{name: "invalid attestation authority error", auth: invalidAuthWithOneBadKey, expected: nil, attestations: []metadata.PGPAttestation{
			{
				Signature: encodeB64(sig),
				KeyID:     successFpr,
			}}, errorExpected: true, attError: nil},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cMock := &testutil.MockMetadataClient{
				PGPAttestations: tc.attestations,
			}
			if tc.attError != nil {
				cMock.SetError(tc.attError)
			}
			vat := AttestorValidatingTransport{cMock, tc.auth}

			atts, err := vat.GetValidatedAttestations(testutil.QualifiedImage)
			if err != nil && !tc.errorExpected {
				t.Fatal("Error not expected ", err.Error())
			} else if err == nil && tc.errorExpected {
				t.Fatal("Expected error but got success")
			}
			if !reflect.DeepEqual(atts, tc.expected) {
				t.Fatalf("Expected %v, Got %v", tc.expected, atts)
			}
		})
	}
}
