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

import "errors"

// Verifier contains methods to validate an Attestation.
type Verifier interface {
	// VerifyAttestation verifies whether an Attestation satisfies at least one
	// of the public keys under an image. This function finds the public key
	// whose ID matches the attestation's PublicKeyID, and uses this key to
	// verify the signature.
	VerifyAttestation(att *Attestation, publicKeySet []PublicKey, image string) error
}

// PublicKey stores public key material for all key types.
type PublicKey struct {
	// KeyData holds the raw key material which can verify a signature.
	KeyData []byte
	// ID uniquely identifies this public key. For PGP, this should be the
	// OpenPGP RFC4880 V4 fingerprint of the key.
	ID string
}

type verifier struct{}

// NewVerifier creates a Verifier interface.
func NewVerifier() Verifier {
	return &verifier{}
}

// VerifyAttestation verifies an Attestation. See Verifier for more details.
func (v *verifier) VerifyAttestation(att *Attestation, publicKeySet []PublicKey, image string) error {
	var (
		err     error
		payload []byte
	)

	// Extract the public key from `publicKeySet` whose ID matches the one in
	// `att`.
	// TODO: Replace no-op with correct implementation.
	publicKey := publicKeySet[0]

	switch extractKeyMode(att.Signature) {
	case Pkix:
		err = verifyPkix(att.Signature, att.SerializedPayload, publicKey.KeyData)
		payload = att.SerializedPayload
	case Pgp:
		payload, err = verifyPgp(att.Signature, publicKey.KeyData)
	case Jwt:
		payload, err = verifyJwt(att.Signature, publicKey.KeyData)
	default:
		return errors.New("signature uses an unsupported key mode")
	}
	if err != nil {
		return err
	}

	expected := Metadata{image}
	actual := extractMetadata(payload)
	return checkMetadata(actual, expected)
}

func verifyPkix(signature []byte, payload []byte, publicKey []byte) error {
	return errors.New("verify not implemented")
}

func verifyPgp(signature []byte, publicKey []byte) ([]byte, error) {
	return []byte{}, errors.New("verify not implemented")
}

func verifyJwt(signature []byte, publicKey []byte) ([]byte, error) {
	return []byte{}, errors.New("verify not implemented")
}

// Metadata stores the most important information from the payload of an
// attestation. After an attestation is verified, this information is extracted
// and compared against the expected metadata for that image.
type Metadata struct {
	Image string
}

func extractMetadata(payload []byte) Metadata {
	return Metadata{}
}

func checkMetadata(actual Metadata, expected Metadata) error {
	return errors.New("check metadata not implemented")
}
