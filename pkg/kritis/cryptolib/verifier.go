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
	"bytes"
	"fmt"
	"regexp"

	"github.com/golang/glog"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
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
	// Signature Algorithm holds the signing and padding algorithm for the signature.
	SignatureAlgorithm SignatureAlgorithm
	// KeyData holds the raw key material which can verify a signature.
	KeyData []byte
	// ID uniquely identifies this public key. For PGP, this should be the
	// OpenPGP RFC4880 V4 fingerprint of the key.
	ID string
}

// NewPublicKey creates a new PublicKey. `keyType` contains the type of the
// public key, one of Pgp, Pkix or Jwt. `keyData` contains the raw key
// material. `keyID` contains a unique identifier for the public key. For PGP,
// this should be the OpenPGP RFC4880 V4 fingerprint of the key. For PKIX and
// JWT, the ID should contain valid URI characters.
func NewPublicKey(keyType KeyType, keyData []byte, keyID string) (*PublicKey, error) {
	switch keyType {
	case Pgp:
		err := validatePgpKeyID(keyData, keyID)
		if err != nil {
			return nil, err
		}
	case Pkix, Jwt:
		// Valid URI characters (see http://tools.ietf.org/html/rfc3986#section-2)
		reURI := regexp.MustCompile(`^[a-zA-Z0-9-._~:\/?#\[\]@!$&'\(\)*+,;=%]+$`)
		if !reURI.MatchString(keyID) {
			return nil, fmt.Errorf("key ID contains invalid characters")
		}
	case UnknownKeyType:
		return nil, fmt.Errorf("invalid key type")
	default:
		return nil, fmt.Errorf("invalid key type")
	}

	return &PublicKey{
		KeyType: keyType,
		KeyData: keyData,
		ID:      keyID,
	}, nil
}

func validatePgpKeyID(keyData []byte, keyID string) error {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(keyData))
	if err != nil {
		return fmt.Errorf("error reading armored public key: %v", err)
	}
	if len(keyring) != 1 {
		return fmt.Errorf("expected 1 public key, got %d", len(keyring))
	}
	key := keyring[0]
	if keyID != fmt.Sprintf("%X", key.PrimaryKey.Fingerprint) {
		return fmt.Errorf("keyID does not match key fingerprint")
	}
	return nil
}

type pkixVerifier interface {
	verifyPkix(signature []byte, payload []byte, publicKey []byte) error
}

type pgpVerifier interface {
	verifyPgp(signature, publicKey []byte) ([]byte, error)
}

type jwtVerifier interface {
	verifyJwt(signature []byte, publicKey PublicKey) ([]byte, error)
}

type convertFunc func(payload []byte) (*authenticatedAttestation, error)

type authenticatedAttChecker interface {
	checkAuthenticatedAttestation(payload []byte, imageName string, imageDigest string, convert convertFunc) error
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
	authenticatedAttChecker
}

// NewVerifier creates a Verifier interface for verifying Attestations.
// `image` contains the untruncated image name <image_name@digest> of the image
// that was signed. This should be provided directly by the policy evaluator,
// NOT by the Attestation.
// `publicKeySet` contains a list of PublicKeys that the Verifier will use to
// try to verify an Attestation.
func NewVerifier(image string, publicKeySet []PublicKey) (Verifier, error) {
	// TODO(https://github.com/grafeas/kritis/issues/503): Move this check to
	// the call where the user supplies the image name.
	digest, err := name.NewDigest(image, name.StrictValidation)
	if err != nil {
		return nil, errors.Wrap(err, "invalid image name")
	}

	keyMap := indexPublicKeysByID(publicKeySet)
	return &verifier{
		ImageName:               digest.Repository.Name(),
		ImageDigest:             digest.DigestStr(),
		PublicKeys:              keyMap,
		pkixVerifier:            pkixVerifierImpl{},
		pgpVerifier:             pgpVerifierImpl{},
		jwtVerifier:             jwtVerifierImpl{},
		authenticatedAttChecker: authenticatedAttCheckerImpl{},
	}, nil
}

func indexPublicKeysByID(publicKeyset []PublicKey) map[string]PublicKey {
	keyMap := map[string]PublicKey{}
	for _, publicKey := range publicKeyset {
		if _, ok := keyMap[publicKey.ID]; ok {
			glog.Warningf("Key with ID %q already exists in publicKeySet. Overwriting previous key.", publicKey.ID)
		}
		keyMap[publicKey.ID] = publicKey
	}
	return keyMap
}

// VerifyAttestation verifies an Attestation. See Verifier for more details.
func (v *verifier) VerifyAttestation(att *Attestation) error {
	// Extract the public key from `publicKeySet` whose ID matches the one in
	// `att`.
	publicKey, ok := v.PublicKeys[att.PublicKeyID]
	if !ok {
		return fmt.Errorf("no public key with ID %q found", att.PublicKeyID)
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
		payload, err = v.verifyJwt(att.Signature, publicKey)
	default:
		return errors.New("signature uses an unsupported key mode")
	}
	if err != nil {
		return err
	}

	// TODO(https://github.com/grafeas/kritis/issues/503): Determine whose
	// responsibility it is to check the payload. If cryptolib is responsible
	// determine an API for checking the payload.
	// Extract the payload into an AuthenticatedAttestation, whose contents we
	// can trust.
	return v.checkAuthenticatedAttestation(payload, v.ImageName, v.ImageDigest, convertAuthenticatedAttestation)
}

type pkixVerifierImpl struct{}

func (v pkixVerifierImpl) verifyPkix(signature []byte, payload []byte, publicKey []byte) error {
	return errors.New("verify pkix not implemented")
}
