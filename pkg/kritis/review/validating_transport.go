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

func (avt *AttestorValidatingTransport) GetValidatedAttestations(image string) ([]attestation.ValidatedAttestation, error) {
	keys := map[string]string{}
	for _, keyData := range avt.Attestor.Spec.PublicKeyList {
		key, fingerprint, err := secrets.KeyAndFingerprint(keyData)
		if err != nil {
			glog.Warningf("Error parsing key for %q: %v", avt.Attestor.Name, err)
		} else {
			if _, ok := keys[fingerprint]; ok {
				glog.Warningf("Duplicate keys with fingerprint %s for %q.", fingerprint, avt.Attestor.Name)
			}
			keys[fingerprint] = key
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("Unable to find any valid key for %q", avt.Attestor.Name)
	}

	out := []attestation.ValidatedAttestation{}
	host, err := container.NewAtomicContainerSig(image, map[string]string{})
	if err != nil {
		glog.Error(err)
		return nil, err
	}
	attestations, err := avt.Client.Attestations(image, &avt.Attestor)
	if err != nil {
		glog.Error(err)
		return nil, err
	}
	for _, a := range attestations {
		// TODO(acamadeo): Temporarily hardcoding this to work only for PGP Attestations.
		signature := a.PGPAttestation.Signature.Signature
		decodedSig := make([]byte, base64.StdEncoding.DecodedLen(len(signature)))
		_, err := base64.StdEncoding.Decode(decodedSig, signature)
		if err != nil {
			glog.Infof("Cannot base64 decode signature: %v", err)
			continue
		}
		keyId := a.PGPAttestation.Signature.PublicKeyId
		if err = host.VerifyAttestationSignature(keys[keyId], string(decodedSig)); err != nil {
			glog.Infof("Could not find or verify attestation for attestor %s: %s", keyId, err.Error())
			continue
		}
		out = append(out, attestation.ValidatedAttestation{AttestorName: avt.Attestor.Name, Image: image})
	}
	return out, nil
}
