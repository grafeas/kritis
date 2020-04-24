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

// NewVerifier creates a Verifier interface for verifying Attestations.
func NewVerifier() Verifier {
	return &verifier{}
}

// VerifyAttestation verifies an Attestation. See Verifier for more details.
func (v *verifier) VerifyAttestation(att *Attestation, publicKeySet []PublicKey, imageDigest string) error {
	var (
		err     error
		payload []byte
	)

	// Extract the public key from `publicKeySet` whose ID matches the one in
	// `att`.
	// TODO: Replace no-op with correct implementation.
	publicKey := publicKeySet[0]

	switch att.extractKeyMode() {
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

	// Extract the payload into an AuthenticatedAttestation, whose contents we
	// can trust.
	actual := formAuthenticatedAttestation(payload)
	return checkAuthenticatedAttestation(actual, imageDigest)
}

func verifyPkix(signature []byte, payload []byte, publicKey []byte) error {
	return errors.New("verify pkix not implemented")
}

func verifyJwt(signature []byte, publicKey []byte) ([]byte, error) {
	return []byte{}, errors.New("verify jwt not implemented")
}

// AuthenticatedAttestation contains data that is extracted from an Attestation
// only after its signature has been verified. The contents of an Attestation
// payload should never be analyzed directly, as it may or may not be verified.
// Instead, these should be extracted into an AuthenticatedAttestation and
// analyzed from there.
// NOTE: The concept and usefulness of an AuthenticatedAttestation are still
// under discussion and is subject to change.
type AuthenticatedAttestation struct {
	ImageDigest string
}

func formAuthenticatedAttestation(payload []byte) AuthenticatedAttestation {
	return AuthenticatedAttestation{}
}

// Check that the data within the Attestation payload matches what we expect.
// NOTE: This is a simple comparison for plain attestations, but it would be
// more complex for rich attestations.
func checkAuthenticatedAttestation(actual AuthenticatedAttestation, imageDigest string) error {
	if actual.ImageDigest != imageDigest {
		return errors.New("invalid payload for authenticated attestation")
	}
	return nil
}
