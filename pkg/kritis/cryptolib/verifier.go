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
	"errors"
	"fmt"
)

// TODO: Remove function stubs once implemented
// For testing
var (
	pkixVerify                      = verifyPkix
	jwtVerify                       = verifyJwt
	authenticatedAttestationChecker = checkAuthenticatedAttestation
)

// Verifier contains methods to validate an Attestation.
type Verifier interface {
	// VerifyAttestation verifies whether an Attestation satisfies at least one
	// of the public keys under an image. This function finds the public key
	// whose ID matches the attestation's PublicKeyID, and uses this key to
	// verify the signature.
	VerifyAttestation(att *Attestation) error
}

// PublicKey stores public key material for all key types.
type PublicKey struct {
	// KeyType stores the type of the public key, one of Pgp, Pkix, or Jwt.
	KeyType KeyType
	// KeyData holds the raw key material which can verify a signature.
	KeyData []byte
	// ID uniquely identifies this public key. For PGP, this should be the
	// OpenPGP RFC4880 V4 fingerprint of the key.
	ID string
}

// NewPublicKey creates a new PublicKey. `keyType` contains the type of the
// public key, one of Pgp, Pkix or Jwt. `keyData` contains the raw key
// material. `keyID` contains a unique identifier for the public key. For PGP,
// this should be the OpenPGP RFC4880 V4 fingerprint of the key.
func NewPublicKey(keyType KeyType, keyData []byte, keyID string) PublicKey {
	return PublicKey{
		KeyType: keyType,
		KeyData: keyData,
		ID:      keyID,
	}
}

type verifier struct {
	ImageDigest  string
	PublicKeySet []PublicKey
}

// NewVerifier creates a Verifier interface for verifying Attestations.
// `imageDigest` contains the digest of the image that was signed over. This
// should be provided directly by the policy evaluator, NOT by the Attestation.
// `publicKeySet` contains a list of PublicKeys that the Verifier will use to
// try to verify an Attestation.
func NewVerifier(imageDigest string, publicKeySet []PublicKey) (Verifier, error) {
	return &verifier{
		ImageDigest:  imageDigest,
		PublicKeySet: publicKeySet,
	}, nil
}

// VerifyAttestation verifies an Attestation. See Verifier for more details.
func (v *verifier) VerifyAttestation(att *Attestation) error {
	var (
		err       error
		payload   []byte
		publicKey PublicKey
	)

	// Extract the public key from `publicKeySet` whose ID matches the one in
	// `att`.
	foundKey := false
	for _, key := range v.PublicKeySet {
		if key.ID == att.PublicKeyID {
			publicKey, foundKey = key, true
			break
		}
	}
	if !foundKey {
		return fmt.Errorf("Verifier doesn't contain matching public key with ID %s", att.PublicKeyID)
	}

	switch publicKey.KeyType {
	case Pkix:
		err = pkixVerify(att.Signature, att.SerializedPayload, publicKey.KeyData)
		payload = att.SerializedPayload
	case Pgp:
		payload, err = verifyPgp(att.Signature, publicKey.KeyData)
	case Jwt:
		payload, err = jwtVerify(att.Signature, publicKey.KeyData)
	default:
		return errors.New("signature uses an unsupported key mode")
	}
	if err != nil {
		return err
	}

	// Extract the payload into an AuthenticatedAttestation, whose contents we
	// can trust.
	actual := formAuthenticatedAttestation(payload)
	return authenticatedAttestationChecker(actual, v.ImageDigest)
}

func verifyPkix(signature []byte, payload []byte, publicKey []byte) error {
	return errors.New("verify pkix not implemented")
}

func verifyJwt(signature []byte, publicKey []byte) ([]byte, error) {
	return []byte{}, errors.New("verify jwt not implemented")
}

// authenticatedAttestation contains data that is extracted from an Attestation
// only after its signature has been verified. The contents of an Attestation
// payload should never be analyzed directly, as it may or may not be verified.
// Instead, these should be extracted into an AuthenticatedAttestation and
// analyzed from there.
// NOTE: The concept and usefulness of an AuthenticatedAttestation are still
// under discussion and is subject to change.
type authenticatedAttestation struct {
	ImageDigest string
}

func formAuthenticatedAttestation(payload []byte) authenticatedAttestation {
	return authenticatedAttestation{}
}

// Check that the data within the Attestation payload matches what we expect.
// NOTE: This is a simple comparison for plain attestations, but it would be
// more complex for rich attestations.
func checkAuthenticatedAttestation(actual authenticatedAttestation, imageDigest string) error {
	if actual.ImageDigest != imageDigest {
		return errors.New("invalid payload for authenticated attestation")
	}
	return nil
}
