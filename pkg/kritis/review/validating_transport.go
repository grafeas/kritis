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
	Client   metadata.Fetcher
	Attestor v1beta1.AttestationAuthority
}

func (avt *AttestorValidatingTransport) GetValidatedAttestations(image string) ([]attestation.ValidatedAttestation, error) {
	keys := map[string]string{}
	key, fingerprint, err := secrets.KeyAndFingerprint(avt.Attestor.Spec.PublicKeyData)
	if err != nil {
		glog.Errorf("Error parsing key for %q: %v", avt.Attestor.Name, err)
		return nil, err
	}
	keys[fingerprint] = key

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
		if err = host.VerifyAttestationSignature(keys[a.KeyID], a.Signature); err != nil {
			glog.Errorf("Could not find or verify attestation for attestor %s: %s", a.KeyID, err.Error())
		} else {
			out = append(out, attestation.ValidatedAttestation{AttestorName: avt.Attestor.Name, Image: image})
		}
	}
	return out, nil
}
