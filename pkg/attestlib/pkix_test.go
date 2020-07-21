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

func TestNewPkixSigner(t *testing.T) {
	tcs := []struct {
		name               string
		privateKey         []byte
		publicKeyId        string
		signatureAlgorithm SignatureAlgorithm
		expectedError      bool
	}{
		{
			name:               "valid RSA 2048 key",
			privateKey:         []byte(rsa2048PrivateKey),
			publicKeyId:        "kid",
			signatureAlgorithm: RsaSignPkcs12048Sha256,
			expectedError:      false,
		},
		{
			name:               "valid EC key",
			privateKey:         []byte(ec256PrivateKey),
			publicKeyId:        "kid",
			signatureAlgorithm: EcdsaP256Sha256,
			expectedError:      false,
		}, {
			name:               "valid RSA key with no id successful",
			privateKey:         []byte(rsa2048PrivateKey),
			publicKeyId:        "",
			signatureAlgorithm: RsaSignPkcs12048Sha256,
			expectedError:      false,
		}, {
			name:               "invalid private key",
			privateKey:         []byte("invalid key"),
			publicKeyId:        "invalid-kid",
			signatureAlgorithm: RsaSignPkcs12048Sha256,
			expectedError:      true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPkixSigner(tc.privateKey, tc.signatureAlgorithm, tc.publicKeyId)
			if tc.expectedError {
				if err == nil {
					t.Errorf("NewPkixSigner(...) = nil, expected non nil")

				}
			} else {
				if err != nil {
					t.Errorf("NewPkixSigner(..) = %v, expected nil", err)
				}
			}
		})
	}
}

func TestCreatePkixAttestation(t *testing.T) {
	tcs := []struct {
		name               string
		privateKey         []byte
		publicKeyId        string
		signatureAlgorithm SignatureAlgorithm
		expectedError      bool
	}{
		{
			name:               "create RSA 2048 signature successful",
			privateKey:         []byte(rsa2048PrivateKey),
			publicKeyId:        "kid",
			signatureAlgorithm: RsaSignPkcs12048Sha256,
			expectedError:      false,
		},
		{
			name:               "create EC P256 signature successful",
			privateKey:         []byte(ec256PrivateKey),
			publicKeyId:        "kid",
			signatureAlgorithm: EcdsaP256Sha256,
			expectedError:      false,
		},
		{
			name:               "invalid signature algorithm",
			privateKey:         []byte(rsa2048PrivateKey),
			publicKeyId:        "kid",
			signatureAlgorithm: 0,
			expectedError:      true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := NewPkixSigner(tc.privateKey, tc.signatureAlgorithm, tc.publicKeyId)
			if err != nil {
				t.Fatalf("failed to create signer")
			}
			attestation, err := signer.CreateAttestation([]byte(payload))
			if tc.expectedError {
				if err == nil {
					t.Errorf("CreateAttestation(...) = nil, expected non nil")

				}
			} else {
				if err != nil {
					t.Errorf("CreateAttestation(..) = %v, expected nil", err)
				} else if attestation.PublicKeyID != tc.publicKeyId {
					t.Errorf("attestation.PublicKeyID = %v, expected %v", attestation.PublicKeyID, tc.publicKeyId)
				}
			}
		})
	}
}

func TestVerifyPkixAttestation(t *testing.T){
	pkixVerifier := pkixVerifierImpl{}
	signer, err := NewPkixSigner([]byte(rsa2048PrivateKey), RsaSignPkcs12048Sha256, "")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	attestation, err := signer.CreateAttestation([]byte(payload))
	if err != nil {
		t.Fatalf("failed to create attestation: %v", err)
	}
	publicKey, err := NewPublicKey(Pkix,[]byte(rsa2048PubKey), "" )

	err = pkixVerifier.verifyPkix(attestation.Signature, attestation.SerializedPayload, *publicKey)

	if err != nil {
		t.Errorf("error verifying attestation: %v", err)
	}
}
