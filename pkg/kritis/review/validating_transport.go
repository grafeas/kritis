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
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
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

func (avt *AttestorValidatingTransport) validatePublicKey(pubKey v1beta1.PublicKey) error {
	if err := validatePublicKeyType(pubKey); err != nil {
		return err
	}
	if err := avt.validatePublicKeyId(pubKey); err != nil {
		return err
	}
	return nil
}

func validatePublicKeyType(pubKey v1beta1.PublicKey) error {
	switch pubKey.KeyType {
	case v1beta1.PgpKeyType:
		if pubKey.PkixPublicKey != (v1beta1.PkixPublicKey{}) {
			return fmt.Errorf("Invalid PGP key: %v. PkixPublicKey field should not be set", pubKey)
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

func (avt *AttestorValidatingTransport) GetValidatedAttestations(image string) ([]attestation.ValidatedAttestation, error) {
	keys := map[string]v1beta1.PublicKey{}
	numKeys := len(avt.Attestor.Spec.PublicKeys)
	for i, pubKey := range avt.Attestor.Spec.PublicKeys {
		if err := avt.validatePublicKey(pubKey); err != nil {
			// warning level because single key failure is something tolerable
			glog.Warningf("Error parsing key %d (%d keys total) for %q: %v", i, numKeys, avt.Attestor.Name, err)
			continue
		}
		if _, ok := keys[pubKey.KeyId]; ok {
			glog.Warningf("Overwriting key with same fingerprint %s for %q.", pubKey.KeyId, avt.Attestor.Name)
		}
		keys[pubKey.KeyId] = pubKey
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("unable to find any valid key for %q", avt.Attestor.Name)
	}

	out := []attestation.ValidatedAttestation{}
	host, err := container.NewAtomicContainerSig(image, map[string]string{})
	if err != nil {
		glog.Error(err)
		return nil, err
	}
	rawAtts, err := avt.Client.Attestations(image, &avt.Attestor)
	if err != nil {
		glog.Error(err)
		return nil, err
	}

	for _, rawAtt := range rawAtts {
		if rawAtt.SignatureType != metadata.PgpSignatureType {
			return nil, fmt.Errorf("Signature type %s is not supported for Attestation %v", rawAtt.SignatureType.String(), rawAtt)
		}
		decodedSig, err := base64.StdEncoding.DecodeString(rawAtt.Signature.Signature)
		if err != nil {
			glog.Warningf("Cannot base64 decode signature for attestation %v. Error: %v", rawAtt, err)
			continue
		}
		keyId := rawAtt.Signature.PublicKeyId
		if err = host.VerifySignature(keys[keyId], string(decodedSig)); err != nil {
			glog.Warningf("Could not find or verify attestation for attestor %s: %s", keyId, err.Error())
			continue
		}
		out = append(out, attestation.ValidatedAttestation{AttestorName: avt.Attestor.Name, Image: image})
	}
	return out, nil
}
