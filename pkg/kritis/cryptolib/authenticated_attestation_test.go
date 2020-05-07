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

import "testing"

const validPayload = `{
    "critical": {
        "identity": {
            "docker-reference": "gcr.io/google-samples/hello-app"
        },
        "image": {
            "docker-manifest-digest": "sha256:bedb3feb23e81d162e33976fd7b245adff00379f4755c0213e84405e5b1e0988"
        },
    "type": "Google cloud binauthz container signature"
    }
}`

const invalidPayload = `{ invalid-json }`

func TestFormAuthenticatedAttestation(t *testing.T) {
	tcs := []struct {
		name        string
		payload     []byte
		expectedErr bool
		expected    authenticatedAttestation
	}{
		{
			name:        "correct authenticated attestation",
			payload:     []byte(validPayload),
			expectedErr: false,
			expected: authenticatedAttestation{
				ImageName:   "gcr.io/google-samples/hello-app",
				ImageDigest: "sha256:bedb3feb23e81d162e33976fd7b245adff00379f4755c0213e84405e5b1e0988",
			},
		},
		{
			name:        "cannot unmarshal payload",
			payload:     []byte(invalidPayload),
			expectedErr: true,
		},
	}
	f := authenticatedAttFormerImpl{}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := f.formAuthenticatedAttestation(tc.payload)
			if tc.expectedErr {
				if err == nil {
					t.Fatalf("formAuthenticatedAttestation(%v) should have failed, but didn't", tc.payload)
				}
			} else {
				if err != nil {
					t.Fatalf("formAuthenticatedAttestation(%v) failed with error %v", tc.payload, err)
				}
				if actual == nil || *actual != tc.expected {
					t.Errorf("formAuthenticatedAttestation(%v) = %v, want %v", tc.payload, actual, &tc.expected)
				}
			}
		})
	}
}

// NOTE: This deserves its own test because the rules for checking an
// authenticatedAttestation will become more complex (esp. with JWT).
func TestCheckAuthenticatedAttestation(t *testing.T) {
	tcs := []struct {
		name        string
		authAtt     authenticatedAttestation
		imageName   string
		imageDigest string
		expectedErr bool
	}{
		{
			name:        "authenticated attestation satisfies requirements",
			authAtt:     authenticatedAttestation{ImageName: "test-image", ImageDigest: "test-digest"},
			imageName:   "test-image",
			imageDigest: "test-digest",
			expectedErr: false,
		},
		{
			name:        "incorrect image name in authenticated attestation",
			authAtt:     authenticatedAttestation{ImageName: "invalid", ImageDigest: "test-digest"},
			imageName:   "test-image",
			imageDigest: "test-digest",
			expectedErr: true,
		},
		{
			name:        "incorrect image digest in authenticated attestation",
			authAtt:     authenticatedAttestation{ImageName: "test-image", ImageDigest: "invalid"},
			imageName:   "test-image",
			imageDigest: "test-digest",
			expectedErr: true,
		},
	}
	c := authenticatedAuthCheckerImpl{}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := c.checkAuthenticatedAttestation(&tc.authAtt, tc.imageName, tc.imageDigest)
			if tc.expectedErr != (err != nil) {
				t.Errorf("checkAuthenticatedAttestation(_) got %v, wanted error? = %v", err, tc.expectedErr)
			}
		})
	}
}
