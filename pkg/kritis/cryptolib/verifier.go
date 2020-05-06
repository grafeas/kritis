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
	"fmt"

	"github.com/golang/glog"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
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

type pkixVerifier interface {
	verifyPkix(signature []byte, payload []byte, publicKey []byte) error
}

type pgpVerifier interface {
	verifyPgp(signature, publicKey []byte) ([]byte, error)
}

type jwtVerifier interface {
	verifyJwt(signature []byte, publicKey []byte) ([]byte, error)
}

type authenticatedAttFormer interface {
	formAuthenticatedAttestation(payload []byte) (*authenticatedAttestation, error)
}

type authenticatedAuthChecker interface {
	checkAuthenticatedAttestation(authAtt *authenticatedAttestation, imageName string, imageDigest string) error
}

type verifier struct {
	ImageName   string
	ImageDigest string
	// PublicKeys is an index of public keys by their ID.
	PublicKeys map[string]PublicKey

	// Interfaces for testing
	pkixVerifier
	pgpVerifier
	jwtVerifier
	authenticatedAttFormer
	authenticatedAuthChecker
}

// NewVerifier creates a Verifier interface for verifying Attestations.
// `image` contains the untruncated image name <image_name@digest> of the image
// that was signed. This should be provided directly by the policy evaluator,
// NOT by the Attestation.
// `publicKeySet` contains a list of PublicKeys that the Verifier will use to
// try to verify an Attestation.
func NewVerifier(image string, publicKeySet []PublicKey) (Verifier, error) {
	digest, err := name.NewDigest(image, name.StrictValidation)
	if err != nil {
		return nil, errors.Wrap(err, "invalid image name")
	}

	keyMap := map[string]PublicKey{}
	for _, publicKey := range publicKeySet {
		if _, found := keyMap[publicKey.ID]; found {
			glog.Warningf("Key with ID %s already exists in publicKeySet. Overwriting previous key.", publicKey.ID)
		}
		keyMap[publicKey.ID] = publicKey
	}

	return &verifier{
		ImageName:                digest.Repository.Name(),
		ImageDigest:              digest.DigestStr(),
		PublicKeys:               keyMap,
		pkixVerifier:             actualPkixVerifier{},
		pgpVerifier:              actualPgpVerifier{},
		jwtVerifier:              actualJwtVerifier{},
		authenticatedAttFormer:   attAuthFormer{},
		authenticatedAuthChecker: attAuthChecker{},
	}, nil
}

// VerifyAttestation verifies an Attestation. See Verifier for more details.
func (v *verifier) VerifyAttestation(att *Attestation) error {
	// Extract the public key from `publicKeySet` whose ID matches the one in
	// `att`.
	publicKey, found := v.PublicKeys[att.PublicKeyID]
	if !found {
		return fmt.Errorf("no public key with ID %s found", att.PublicKeyID)
	}

	var err error
	payload := []byte{}
	switch publicKey.KeyType {
	case Pkix:
		err = v.verifyPkix(att.Signature, att.SerializedPayload, publicKey.KeyData)
		payload = att.SerializedPayload
	case Pgp:
		payload, err = v.verifyPgp(att.Signature, publicKey.KeyData)
	case Jwt:
		payload, err = v.verifyJwt(att.Signature, publicKey.KeyData)
	default:
		return errors.New("signature uses an unsupported key mode")
	}
	if err != nil {
		return err
	}

	// Extract the payload into an AuthenticatedAttestation, whose contents we
	// can trust.
	authenticatedAtt, err := v.formAuthenticatedAttestation(payload)
	if err != nil {
		return err
	}
	return v.checkAuthenticatedAttestation(authenticatedAtt, v.ImageName, v.ImageDigest)
}

type actualPkixVerifier struct{}

func (v actualPkixVerifier) verifyPkix(signature []byte, payload []byte, publicKey []byte) error {
	return errors.New("verify pkix not implemented")
}

type actualJwtVerifier struct{}

func (v actualJwtVerifier) verifyJwt(signature []byte, publicKey []byte) ([]byte, error) {
	return []byte{}, errors.New("verify jwt not implemented")
}
