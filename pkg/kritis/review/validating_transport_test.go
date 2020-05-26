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
	"testing"

	"github.com/google/go-cmp/cmp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"github.com/grafeas/kritis/pkg/kritis/util"
)

func TestValidatingTransport(t *testing.T) {
	successSec, pub := testutil.CreateSecret(t, "test-success")
	// second public key for the second attestor
	successSec2, pub2 := testutil.CreateSecret(t, "test-success-2")
	successFpr, successFpr2 := successSec.PgpKey.Fingerprint(), successSec2.PgpKey.Fingerprint()
	sig, err := util.CreateAttestationSignature(testutil.QualifiedImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	anotherSig, err := util.CreateAttestationSignature(testutil.IntTestImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	validAuthWithOneGoodPgpKey := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeys: []v1beta1.PublicKey{
				{
					KeyType:                  "PGP",
					KeyId:                    successFpr,
					AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
				},
			},
		},
	}
	validAuthWithTwoGoodPgpKeys := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeys: []v1beta1.PublicKey{
				{
					KeyType:                  "PGP",
					KeyId:                    successFpr,
					AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
				},
				{
					KeyType:                  "PGP",
					KeyId:                    successFpr2,
					AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub2)),
				},
			},
		},
	}
	validAuthWithOneGoodOneBadPgpKeys := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeys: []v1beta1.PublicKey{
				{
					KeyType:                  "PGP",
					AsciiArmoredPgpPublicKey: "bad-key",
				},
				{
					KeyType:                  "PGP",
					KeyId:                    successFpr,
					AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
				},
			},
		},
	}
	invalidAuthWithOneBadPgpKey := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeys: []v1beta1.PublicKey{
				{
					KeyType:                  "PGP",
					AsciiArmoredPgpPublicKey: "bad-key",
				},
			},
		},
	}
	invalidAuthWithOneInvalidPgpKeyId := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeys: []v1beta1.PublicKey{
				{
					KeyType:                  "PGP",
					KeyId:                    "bad-key-id",
					AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
				},
			},
		},
	}
	validAuthWithOneGoodPkixKey := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeys: []v1beta1.PublicKey{
				{
					KeyType: "PKIX",
					KeyId:   "good-key-id",
					// TODO(acamadeo): After implementing PKIX key verification
					// replace this with a valid PKIX public key.
					PkixPublicKey: v1beta1.PkixPublicKey{
						PublicKeyPem: "good-key",
					},
				},
			},
		},
	}
	invalidAuthWithOneInvalidPkixKeyId := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeys: []v1beta1.PublicKey{
				{
					KeyType: "PKIX",
					KeyId:   "bad_key_id:foo",
					// TODO(acamadeo): After implementing PKIX key verification
					// replace this with a valid PKIX public key.
					PkixPublicKey: v1beta1.PkixPublicKey{
						PublicKeyPem: "good-key",
					},
				},
			},
		},
	}
	invalidAuthWithPgpTypeAndPkixKey := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeys: []v1beta1.PublicKey{
				{
					KeyType:                  "PGP",
					KeyId:                    successFpr,
					AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
					// TODO(acamadeo): After implementing PKIX key verification
					// replace this with a valid PKIX public key.
					PkixPublicKey: v1beta1.PkixPublicKey{
						PublicKeyPem: "good-key",
					},
				},
			},
		},
	}
	invalidAuthWithPkixTypeAndPgpKey := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeys: []v1beta1.PublicKey{
				{
					KeyType:                  "PKIX",
					KeyId:                    successFpr,
					AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
					PkixPublicKey: v1beta1.PkixPublicKey{
						PublicKeyPem: "good-key",
					},
				},
			},
		},
	}
	invalidAuthWithUnknownKeyType := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeys: []v1beta1.PublicKey{
				{
					KeyType:                  "INVALID_KEY",
					KeyId:                    "good-key-id",
					AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
				},
			},
		},
	}
	tcs := []struct {
		name          string
		auth          v1beta1.AttestationAuthority
		wantAtts      []attestation.ValidatedAttestation
		attestations  []metadata.RawAttestation
		errorExpected bool
		attError      error
	}{
		{name: "at least one valid sig", auth: validAuthWithOneGoodPgpKey, wantAtts: []attestation.ValidatedAttestation{
			{
				AttestorName: "test-attestor",
				Image:        testutil.QualifiedImage,
			},
		}, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.PgpSignatureType, sig, successFpr, ""),
			metadata.MakeRawAttestation(metadata.PgpSignatureType, "invalid-sig", successFpr, ""),
		}, errorExpected: false, attError: nil},
		{name: "auth with at least one good PGP key", auth: validAuthWithOneGoodOneBadPgpKeys, wantAtts: []attestation.ValidatedAttestation{
			{
				AttestorName: "test-attestor",
				Image:        testutil.QualifiedImage,
			},
		}, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.PgpSignatureType, sig, successFpr, ""),
			metadata.MakeRawAttestation(metadata.PgpSignatureType, "invalid-sig", successFpr, ""),
		}, errorExpected: false, attError: nil},
		{name: "auth with at two good PGP keys", auth: validAuthWithTwoGoodPgpKeys, wantAtts: []attestation.ValidatedAttestation{
			{
				AttestorName: "test-attestor",
				Image:        testutil.QualifiedImage,
			},
		}, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.PgpSignatureType, sig, successFpr, ""),
			metadata.MakeRawAttestation(metadata.PgpSignatureType, "invalid-sig", successFpr, ""),
		}, errorExpected: false, attError: nil},
		{name: "no valid sig", auth: validAuthWithOneGoodPgpKey, wantAtts: []attestation.ValidatedAttestation{}, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.PgpSignatureType, "invalid-sig", successFpr, ""),
		}, errorExpected: false, attError: nil},
		{name: "regression: sig is base64 encoded", auth: validAuthWithOneGoodPgpKey, wantAtts: []attestation.ValidatedAttestation{}, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.PgpSignatureType, base64.StdEncoding.EncodeToString([]byte(sig)), successFpr, ""),
		}, errorExpected: false, attError: nil},
		{name: "invalid secret", auth: validAuthWithOneGoodPgpKey, wantAtts: []attestation.ValidatedAttestation{}, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.PgpSignatureType, "invalid-sig", "invalid-fpr", ""),
		}, errorExpected: false, attError: nil},
		{name: "valid sig over another host", auth: validAuthWithOneGoodPgpKey, wantAtts: []attestation.ValidatedAttestation{}, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.PgpSignatureType, anotherSig, successFpr, ""),
		}, errorExpected: false, attError: nil},
		{name: "attestation fetch error", auth: validAuthWithOneGoodPgpKey, wantAtts: nil, attestations: nil, errorExpected: true, attError: errors.New("can't fetch attestations")},
		{name: "auth with invalid PGP key", auth: invalidAuthWithOneBadPgpKey, wantAtts: nil, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.PgpSignatureType, sig, successFpr, ""),
		}, errorExpected: true, attError: nil},
		{name: "auth with generic signature type", auth: validAuthWithOneGoodPgpKey, wantAtts: nil, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.GenericSignatureType, "test-sig", "test-id", "generic-address"),
		}, errorExpected: true, attError: nil},
		{name: "auth with unknown signature type", auth: validAuthWithOneGoodPgpKey, wantAtts: nil, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.UnknownSignatureType, sig, successFpr, ""),
		}, errorExpected: true, attError: nil},
		{name: "valid auth with invalid PGP key id", auth: invalidAuthWithOneInvalidPgpKeyId, wantAtts: []attestation.ValidatedAttestation{}, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.PgpSignatureType, sig, successFpr, ""),
		}, errorExpected: false, attError: nil},
		// TODO(acamadeo): After PKIX key verification implementation, the
		// `wantAtts` field for this test case should be a list of
		// ValidatedAttestations. `errorExpected` should also be false, but
		// currently attestations with GenericSignatureType throw an error.
		{name: "auth with valid PKIX key", auth: validAuthWithOneGoodPkixKey, wantAtts: nil, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.GenericSignatureType, "", "", ""),
		}, errorExpected: true, attError: nil},
		{name: "auth with invalid PKIX key id", auth: invalidAuthWithOneInvalidPkixKeyId, wantAtts: nil, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.GenericSignatureType, "", "", ""),
		}, errorExpected: true, attError: nil},
		{name: "invalid auth with PGP key type but PKIX key", auth: invalidAuthWithPgpTypeAndPkixKey, wantAtts: nil, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.PgpSignatureType, sig, successFpr, ""),
		}, errorExpected: true, attError: nil},
		{name: "invalid auth with PKIX key type but PGP key", auth: invalidAuthWithPkixTypeAndPgpKey, wantAtts: nil, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.GenericSignatureType, "", "", ""),
		}, errorExpected: true, attError: nil},
		{name: "invalid key with unknown key type", auth: invalidAuthWithUnknownKeyType, wantAtts: nil, attestations: []metadata.RawAttestation{
			metadata.MakeRawAttestation(metadata.PgpSignatureType, sig, successFpr, ""),
		}, errorExpected: true, attError: nil},
		// TODO(acamadeo): Add a test case for a PKIX key with a bad key once
		// the PKIX key verification is implemented.
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cMock := &testutil.MockMetadataClient{
				RawAttestations: tc.attestations,
			}
			if tc.attError != nil {
				cMock.SetError(tc.attError)
			}
			vat := AttestorValidatingTransport{cMock, tc.auth}

			gotAtts, err := vat.GetValidatedAttestations(testutil.QualifiedImage)
			if err != nil && !tc.errorExpected {
				t.Fatal("Error not expected ", err.Error())
			} else if err == nil && tc.errorExpected {
				t.Fatal("Expected error but got success")
			}
			if !cmp.Equal(gotAtts, tc.wantAtts) {
				t.Fatalf("Expected %#v, Got %#v", tc.wantAtts, gotAtts)
			}
		})
	}
}
