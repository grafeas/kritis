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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
)

func encodeB64(in string) string {
	return base64.StdEncoding.EncodeToString([]byte(in))
}

func TestValidatePublicKey(t *testing.T) {
	sec, pub := testutil.CreateSecret(t, "sec")
	secFpr := sec.PgpKey.Fingerprint()
	validPgpKeyWithFingerprintId := v1beta1.PublicKey{
		KeyId:                    secFpr,
		KeyType:                  "PGP_KEY",
		AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
	}
	validPgpKeyWithEmptyId := v1beta1.PublicKey{
		KeyId:                    "",
		KeyType:                  "PGP_KEY",
		AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
	}
	// This specification is allowed but discouraged
	validPgpKeyWithNonFingerprintId := v1beta1.PublicKey{
		KeyId:                    "foobar",
		KeyType:                  "PGP_KEY",
		AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
	}
	invalidPgpKeyWithPkixPayload := v1beta1.PublicKey{
		KeyId:                    secFpr,
		KeyType:                  "PGP_KEY",
		AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
		// TODO(acamadeo): After implementing PKIX key verification replace
		// this with a valid PKIX public key.
		PkixPublicKey: v1beta1.PkixPublicKey{
			PublicKey: "good-key",
		},
	}
	invalidPgpKeyWithoutPgpPayload := v1beta1.PublicKey{
		KeyId:   secFpr,
		KeyType: "PGP_KEY",
	}
	validPkixKeyWithValidId := v1beta1.PublicKey{
		// Notice the ID is RFC3986 conformant
		KeyId:   "good-key-id",
		KeyType: "PKIX_KEY",
		// TODO(acamadeo): After implementing PKIX key verification replace
		// this with a valid PKIX public key.
		PkixPublicKey: v1beta1.PkixPublicKey{
			PublicKey: "good-key",
		},
	}
	invalidPkixKeyWithInvalidId := v1beta1.PublicKey{
		// Notice the ID is not RFC3986 conformant
		KeyId:   "bad_key_id:foo",
		KeyType: "PKIX_KEY",
		// TODO(acamadeo): After implementing PKIX key verification replace
		// this with a valid PKIX public key.
		PkixPublicKey: v1beta1.PkixPublicKey{
			PublicKey: "good-key",
		},
	}
	invalidPkixKeyWithPgpPayload := v1beta1.PublicKey{
		KeyId:   "good-key-id",
		KeyType: "PKIX_KEY",
		// TODO(acamadeo): After implementing PKIX key verification replace
		// this with a valid PKIX public key.
		PkixPublicKey: v1beta1.PkixPublicKey{
			PublicKey: "good-key",
		},
		AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
	}
	invalidPkixKeyWithoutPkixPayload := v1beta1.PublicKey{
		KeyId:   "good-key-id",
		KeyType: "PKIX_KEY",
	}
	invalidPublicKeyWithUnsupportedType := v1beta1.PublicKey{
		KeyId:                    secFpr,
		KeyType:                  "UNKNOWN",
		AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pub)),
	}
	tcs := []struct {
		name          string
		pubKey        v1beta1.PublicKey
		errorExpected bool
	}{
		{"valid PGP key with fingerprint id", validPgpKeyWithFingerprintId, false},
		{"valid PGP key with empty id", validPgpKeyWithEmptyId, false},
		{"valid PGP key with non-fingerprint id", validPgpKeyWithNonFingerprintId, false},
		{"invalid PGP key with PkixPublicKey set", invalidPgpKeyWithPkixPayload, true},
		{"invalid PGP key with AsciiARmoredPgpPublicKey empty", invalidPgpKeyWithoutPgpPayload, true},
		{"valid PKIX key with valid id", validPkixKeyWithValidId, false},
		{"invalid PKIX key with invalid id", invalidPkixKeyWithInvalidId, true},
		{"invalid PKIX key with AsciiARmoredPgpPublicKey set", invalidPkixKeyWithPgpPayload, true},
		{"invalid PKIX key with PkixPublicKey empty", invalidPkixKeyWithoutPkixPayload, true},
		{"invalid public key with unsupported key type", invalidPublicKeyWithUnsupportedType, true},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePublicKey(tc.pubKey)
			if err != nil && !tc.errorExpected {
				t.Fatalf("Error not expected: %v", err)
			}
		})
	}
}

func TestGetValidatedAttestation(t *testing.T) {
	type (
		testAttestation struct {
			rawAtt     metadata.RawAttestation
			unverified bool
		}
		testPublicKey struct {
			pubKey  v1beta1.PublicKey
			invalid bool
		}
	)

	// Mock clients
	cMock := &testutil.MockMetadataClient{}
	cMockWithError := &testutil.MockMetadataClient{}
	cMockWithError.SetError(errors.New("can't fetch attestations"))

	// Attestations
	pgpAttEncoded := metadata.MakeRawAttestation(metadata.PgpSignatureType, encodeB64("---sig---"), "pgp-key-id-1", "")
	pgpAttUnencoded := metadata.MakeRawAttestation(metadata.PgpSignatureType, "---sig---", "pgp-key-id-1", "")
	pgpAttEncodedOther := metadata.MakeRawAttestation(metadata.PgpSignatureType, encodeB64("---sig---"), "pgp-key-id-other", "")
	genericAtt := metadata.MakeRawAttestation(metadata.GenericSignatureType, encodeB64("---sig---"), "pkix-key-id", "")
	unknownAtt := metadata.MakeRawAttestation(metadata.UnknownSignatureType, "", "", "")

	// Public keys
	pgpPublicKey := v1beta1.PublicKey{KeyType: "PGP", KeyId: "pgp-key-id"}
	pgpPublicKeyOther := v1beta1.PublicKey{KeyType: "PGP", KeyId: "pgp-key-id-other"}
	pkixPublicKey := v1beta1.PublicKey{KeyType: "PKIX", KeyId: "pkix-key-id"}

	tcs := []struct {
		name             string
		testKeys         []testPublicKey
		testAtts         []testAttestation
		mockClient       *testutil.MockMetadataClient
		wantNumValidAtts int
		wantError        bool
	}{
		{"error if no public keys", []testPublicKey{}, []testAttestation{{rawAtt: pgpAttEncoded}}, cMock, 0, true},
		{"filters out invalid public keys", []testPublicKey{{pubKey: pgpPublicKey, invalid: true}}, []testAttestation{{rawAtt: pgpAttEncoded}}, cMock, 0, true},
		{"no error if duplicate key", []testPublicKey{{pubKey: pgpPublicKey}, {pubKey: pgpPublicKey}}, []testAttestation{{rawAtt: pgpAttEncoded}}, cMock, 1, false},
		{"error if error retrieving attestations", []testPublicKey{{pubKey: pgpPublicKey}}, nil, cMockWithError, 0, true},
		// TODO(acamadeo): After PKIX key verification, `wantNumValidAtts` should not be 0, and `wantError` should be false.
		{"error if PKIX signature", []testPublicKey{{pubKey: pkixPublicKey}}, []testAttestation{{rawAtt: genericAtt}}, cMock, 0, true},
		{"error if unsupported signature", []testPublicKey{{pubKey: pgpPublicKey}}, []testAttestation{{rawAtt: unknownAtt}}, cMock, 0, true},
		{"skip signature if not base64 encoded", []testPublicKey{{pubKey: pgpPublicKey}, {pubKey: pgpPublicKeyOther}}, []testAttestation{
			{rawAtt: pgpAttUnencoded},
			{rawAtt: pgpAttEncodedOther},
		}, cMock, 1, false},
		{"filters out non-verified signatures", []testPublicKey{{pubKey: pgpPublicKey}, {pubKey: pgpPublicKeyOther}}, []testAttestation{
			{rawAtt: pgpAttEncoded, unverified: true},
			{rawAtt: pgpAttEncodedOther},
		}, cMock, 1, false},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rawAtts, invalidKeys, unverifiedSigs := []metadata.RawAttestation{}, []bool{}, []bool{}
			for _, tk := range tc.testKeys {
				invalidKeys = append(invalidKeys, tk.invalid)
			}
			for _, ta := range tc.testAtts {
				rawAtts = append(rawAtts, ta.rawAtt)
				unverifiedSigs = append(unverifiedSigs, ta.unverified)
			}

			// Mock ValidatePublicKey
			mockKeyValidator := mockPublicKeyValidator{invalidKeys: invalidKeys}
			validatePublicKey = mockKeyValidator.validatePublicKey

			// Mock container host
			acsMock := &mockAtomicContainerSig{UnverifiedSigs: unverifiedSigs, Err: errors.New("cannot verify signature")}

			// Attestations
			tc.mockClient.RawAttestations = rawAtts

			// Attestation authority
			pubKeys := []v1beta1.PublicKey{}
			for _, tk := range tc.testKeys {
				pubKeys = append(pubKeys, tk.pubKey)
			}
			attAuth := makeAttestationAuthority(pubKeys)

			transport := AttestorValidatingTransport{Client: tc.mockClient, Attestor: attAuth, ContainerHost: acsMock}
			gotAtts, err := transport.GetValidatedAttestations(testutil.QualifiedImage)
			if err != nil && !tc.wantError {
				t.Fatal("Error not expected ", err.Error())
			} else if err == nil && tc.wantError {
				t.Fatal("Expected error but got success")
			}
			if len(gotAtts) != tc.wantNumValidAtts {
				t.Fatalf("Expected %d validated attestations, Got %d", tc.wantNumValidAtts, len(gotAtts))
			}
		})
	}
}

type mockPublicKeyValidator struct {
	invalidKeys []bool
}

func (m mockPublicKeyValidator) validatePublicKey(pubKey v1beta1.PublicKey) error {
	if len(m.invalidKeys) == 0 {
		return nil
	}
	invalid := m.invalidKeys[0]
	m.invalidKeys = m.invalidKeys[1:]
	if invalid {
		return errors.New("invalid key")
	}
	return nil
}

type mockAtomicContainerSig struct {
	container.AtomicContainerSigInterface

	Err            error
	UnverifiedSigs []bool
}

func (m *mockAtomicContainerSig) VerifySignature(v1beta1.PublicKey, string) error {
	if len(m.UnverifiedSigs) == 0 {
		return nil
	}
	unverified := m.UnverifiedSigs[0]
	m.UnverifiedSigs = m.UnverifiedSigs[1:]
	if unverified {
		return m.Err
	}
	return nil
}

func makeAttestationAuthority(pubKeys []v1beta1.PublicKey) v1beta1.AttestationAuthority {
	return v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "test-attestor"},
		Spec: v1beta1.AttestationAuthoritySpec{
			PublicKeys: pubKeys,
		},
	}
}
