/*
Copyright 2019 Google LLC

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

package review

import (
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/golang/glog"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/cryptolib"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/pkg/errors"
)

// ValidatingTransport allows the caller to obtain validated attestations for a given container image.
// Implementations should return trusted and verified attestations.
type ValidatingTransport interface {
	GetValidatedAttestations(image string) ([]attestation.ValidatedAttestation, error)
}

// Implements ValidatingTransport.
type AttestorValidatingTransport struct {
	Client   metadata.ReadOnlyClient
	Attestor v1beta1.AttestationAuthority
}

// validatePublicKey makes sure that a PublicKey is specified correctly.
func (avt *AttestorValidatingTransport) validatePublicKey(pubKey v1beta1.PublicKey) error {
	if err := validatePublicKeyType(pubKey); err != nil {
		return err
	}
	if err := avt.validatePublicKeyId(pubKey); err != nil {
		return err
	}
	return nil
}

// validatePublicKeyType ensures that the appropriate fields of a PublicKey
// are set given its KeyType.
func validatePublicKeyType(pubKey v1beta1.PublicKey) error {
	switch pubKey.KeyType {
	case v1beta1.PgpKeyType:
		if pubKey.PkixPublicKey != (v1beta1.PkixPublicKey{}) {
			return fmt.Errorf("Invalid PGP key: %v. PkixPublicKey field should not be set", pubKey)
		}
		if pubKey.AsciiArmoredPgpPublicKey == "" {
			return fmt.Errorf("Invalid PGP key: %v. AsciiArmoredPgpPublicKey field should be set", pubKey)
		}
	case v1beta1.PkixKeyType:
		if pubKey.AsciiArmoredPgpPublicKey != "" {
			return fmt.Errorf("Invalid PKIX key: %v. AsciiArmoredPgpPublicKey field should not be set", pubKey)
		}
		if pubKey.PkixPublicKey == (v1beta1.PkixPublicKey{}) {
			return fmt.Errorf("Invalid PKIX key: %v. PkixPublicKey field should be set", pubKey)
		}
	default:
		return fmt.Errorf("Unsupported key type %s for key %v", pubKey.KeyType, pubKey)
	}
	return nil
}

// validatePublicKeyId ensures that a PublicKey's KeyId field is valid given
// its KeyType.
func (avt *AttestorValidatingTransport) validatePublicKeyId(pubKey v1beta1.PublicKey) error {
	switch pubKey.KeyType {
	case v1beta1.PgpKeyType:
		_, keyId, err := secrets.KeyAndFingerprint(pubKey.AsciiArmoredPgpPublicKey)
		if err != nil {
			return fmt.Errorf("Error parsing PGP key for %q: %v", avt.Attestor.Name, err)
		}
		if pubKey.KeyId == "" {
			glog.Warningf("No PGP key id was provided. Will use the following keyId: %s", keyId)
		} else if pubKey.KeyId != keyId {
			glog.Warningf("The provided PGP keyId does not match the RFC4880 V4 fingerprint of the public key. Will use fingerprint as keyId.\nProvided keyId: %s\nFingerprint: %s\n", pubKey.KeyId, keyId)
		}
		return nil
	case v1beta1.PkixKeyType:
		if _, err := url.Parse(pubKey.KeyId); err != nil {
			return fmt.Errorf("PKIX key with id %s was skipped. KeyId should be a valid RFC3986 URI", pubKey.KeyId)
		}
	default:
		return fmt.Errorf("Unsupported key type %s for key %v", pubKey.KeyType, pubKey)
	}
	return nil
}

// NOTE: I am considering changing this function signature to:
// func (avt *AttestorValidatingTransport) CheckValidatedAttestation(image string) error
// The function would propagate the error (or success) of the
// verifier.VerifyAttestation call. It currently returns ValdiatedAttestations,
// which contain unused and not particularly meaningful information.
// This is not a trivial change, and would be done in a follow-up PR.
func (avt *AttestorValidatingTransport) GetValidatedAttestations(image string) ([]attestation.ValidatedAttestation, error) {
	publicKeys := []cryptolib.PublicKey{}
	numKeys := len(avt.Attestor.Spec.PublicKeys)
	validatedAtts := []attestation.ValidatedAttestation{}

	for i, attestorKey := range avt.Attestor.Spec.PublicKeys {
		if err := avt.validatePublicKey(attestorKey); err != nil {
			// warning level because single key failure is something tolerable
			glog.Warningf("Error parsing key %d (%d keys total) for %q: %v", i, numKeys, avt.Attestor.Name, err)
			continue
		}
		// Base64 decode the attestor's key
		decodedKey, err := base64.StdEncoding.DecodeString(attestorKey.AsciiArmoredPgpPublicKey)
		if err != nil {
			glog.Infof("Cannot base64 decode public key: %v", err)
			continue
		}
		publicKey := cryptolib.NewPublicKey(cryptolib.Pgp, decodedKey, attestorKey.KeyId)
		publicKeys = append(publicKeys, publicKey)
	}
	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("unable to find any valid key for %q", avt.Attestor.Name)
	}

	// Check for properly formatted image digest
	digest, err := name.NewDigest(image, name.StrictValidation)
	if err != nil {
		return nil, errors.Wrap(err, "error extracting image digest")
	}

	verifier, err := cryptolib.NewVerifier(digest.DigestStr(), publicKeys)
	if err != nil {
		return nil, errors.Wrap(err, "error creating verifier")
	}

	rawAtts, err := avt.Client.Attestations(image, &avt.Attestor)
	if err != nil {
		return nil, fmt.Errorf("error fetching attestations for image %s: %v", image, err)
	}
	for _, rawAtt := range rawAtts {
		if rawAtt.SignatureType != metadata.PgpSignatureType && rawAtt.SignatureType != metadata.GenericSignatureType {
			glog.Warningf("Skipping attestation with unsupported signature type %s", rawAtt.SignatureType.String())
			continue
		}
		decodedSig, err := base64.StdEncoding.DecodeString(rawAtt.Signature.Signature)
		if err != nil {
			glog.Warningf("Cannot base64 decode signature for attestation %v. Error: %v", rawAtt, err)
			continue
		}
		// TODO: Remove this after cryptolib.Attestation is used throughout
		// Kritis.
		att := &cryptolib.Attestation{
			PublicKeyID:       rawAtt.Signature.PublicKeyId,
			Signature:         decodedSig,
			SerializedPayload: rawAtt.SerializedPayload,
		}

		if err := verifier.VerifyAttestation(att); err != nil {
			glog.Warningf("error verifying attestation: %v", err)
			continue
		}
		validatedAtts = append(validatedAtts, attestation.ValidatedAttestation{AttestorName: avt.Attestor.Name, Image: image})
	}
	return validatedAtts, nil
}
