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
	"crypto/ecdsa"
	"crypto/rsa"
	"github.com/pkg/errors"
)

type pkixSigner struct {
	PrivateKey         interface{}
	PublicKeyID        string
	SignatureAlgorithm SignatureAlgorithm
}

// NewPkixSigner creates a Signer interface for PKIX Attestations. `privateKey`
// contains the PEM-encoded private key. `publicKeyID` is the ID of the public
// key that can verify the Attestation signature.
func NewPkixSigner(privateKey []byte, publicKeyID string, alg SignatureAlgorithm) (Signer, error) {

	key, err := parsePkixPrivateKeyPem(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing private key")
	}

	// If no ID id provided one is computed based on the default digest-based URI extracted from the public key material
	if len(publicKeyID) == 0 {
		publicKeyID, err = generatePkixPublicKeyId(key)
		if err != nil {
			return nil, errors.Wrap(err, "error generating public key id")
		}
	}
	return &pkixSigner{
		PrivateKey:         key,
		PublicKeyID:        publicKeyID,
		SignatureAlgorithm: alg,
	}, nil
}

// CreateAttestation creates a signed PKIX Attestation. See Signer for more details.
func (s *pkixSigner) CreateAttestation(payload []byte) (*Attestation, error) {
	switch s.SignatureAlgorithm {
	case RsaSignPkcs12048Sha256, RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256, RsaSignPkcs14096Sha512, RsaPss2048Sha256, RsaPss3072Sha256, RsaPss4096Sha256, RsaPss4096Sha512:
		signature, err := rsaSign(s.PrivateKey.(*rsa.PrivateKey), payload, s.SignatureAlgorithm)
		if err != nil {
			return nil, errors.Wrap(err, "error creating signature")
		}
		return &Attestation{
			PublicKeyID:       s.PublicKeyID,
			Signature:         signature,
			SerializedPayload: payload,
		}, nil
	case EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512:
		signature, err := ecSign(s.PrivateKey.(*ecdsa.PrivateKey), payload, s.SignatureAlgorithm)
		if err != nil {
			return nil, errors.Wrap(err, "error creating signature")
		}
		return &Attestation{
			PublicKeyID:       s.PublicKeyID,
			Signature:         signature,
			SerializedPayload: payload,
		}, nil
	default:
		return nil, errors.New("unknown signature algorithm")

	}
}
