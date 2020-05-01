/*
Copyright 2020 Google LLC

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

package cryptolib

import (
	"testing"
)

func TestVerifyAttestation(t *testing.T) {
	att := &Attestation{
		PublicKeyID:       "key-id",
		Signature:         []byte("signature"),
		SerializedPayload: []byte("payload"),
	}
	matchingKey := NewPublicKey(Pkix, []byte("key-data"), "key-id")
	otherMatchingKey := NewPublicKey(Pkix, []byte("key-data-other"), "key-id")
	nonmatchingKey := NewPublicKey(Pkix, []byte("key-data-other"), "key-id-other")

	pkixVerify = func([]byte, []byte, []byte) error { return nil }
	authenticatedAttestationChecker = func(authenticatedAttestation, string) error { return nil }

	tcs := []struct {
		name        string
		att         *Attestation
		publicKeys  []PublicKey
		expectedErr bool
	}{
		{
			name:        "happy case",
			att:         att,
			publicKeys:  []PublicKey{matchingKey},
			expectedErr: false,
		},
		{
			// This is a possibility with user-provided IDs
			name:        "different keys with same ID",
			att:         att,
			publicKeys:  []PublicKey{matchingKey, otherMatchingKey},
			expectedErr: false,
		},
		{
			name:        "key not found",
			att:         att,
			publicKeys:  []PublicKey{nonmatchingKey},
			expectedErr: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			verifier, err := NewVerifier("test-image-digest", tc.publicKeys)
			if err != nil {
				t.Fatalf("Error creating Verifier: %v", err)
			}

			err = verifier.VerifyAttestation(tc.att)
			if tc.expectedErr != (err != nil) {
				t.Errorf("VerifyAttestation(_) got %v, wanted error? = %v", err, tc.expectedErr)
			}
		})
	}
}
