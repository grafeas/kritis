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

package attestlib

import (
	"testing"
)

func TestParsePkixPrivateKeyPem(t *testing.T) {
	tcs := []struct {
		name          string
		privateKey    []byte
		expectedError bool
	}{
		{
			name:          " parse rsa key successful",
			privateKey:    []byte(rsa2048PrivateKey),
			expectedError: false,
		}, {
			name:          "parse ecdsa key successful",
			privateKey:    []byte(ec256PrivateKey),
			expectedError: false,
		},
		{
			name:          "invalid key",
			privateKey:    []byte("not a pem"),
			expectedError: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePkixPrivateKeyPem(tc.privateKey)
			if tc.expectedError {
				if err == nil {
					t.Errorf("parsePkixPrivateKeyPem(...) = nil, expected non nil")

				}
			} else {
				if err != nil {
					t.Errorf("parsePkixPrivateKeyPem(..) = %v, expected nil", err)
				}
			}

		})
	}
}

func TestGeneratePKIXPublicKeyId(t *testing.T) {
	tcs := []struct {
		name          string
		privateKey    []byte
		expectedError bool
	}{
		{
			name:          " genrate rsa key id successful",
			privateKey:    []byte(rsa2048PrivateKey),
			expectedError: false,
		}, {
			name:          "generate ecdsa key id successful",
			privateKey:    []byte(ec256PrivateKey),
			expectedError: false,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			key, err := parsePkixPrivateKeyPem(tc.privateKey)
			if err != nil {
				t.Fatalf("error parsing key %v", err)
			}
			_, err = generatePkixPublicKeyId(key)
			if tc.expectedError {
				if err == nil {
					t.Errorf("generatePkixPublicKeyId(...) = nil, expected non nil")

				}
			} else {
				if err != nil {
					t.Errorf("generatePkixPublicKeyId(..) = %v, expected nil", err)
				}
			}

		})
	}
}
