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
	switch publicKey.AuthenticatorType {
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
