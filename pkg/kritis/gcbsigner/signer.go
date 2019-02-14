/*
Copyright 2018 Google LLC

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

package gcbsigner

import (
	"encoding/base64"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/crd/authority"
	"github.com/grafeas/kritis/pkg/kritis/crd/buildpolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
)

type Signer struct {
	config *Config
	client metadata.Fetcher
}

type Config struct {
	Secret   secrets.Fetcher
	Validate buildpolicy.ValidateFunc
}

func New(client metadata.Fetcher, c *Config) Signer {
	return Signer{
		client: client,
		config: c,
	}
}

type BuildProvenance struct {
	BuildID   string
	ImageRef  string
	BuiltFrom string
}

// For testing
var (
	authFetcher = authority.Authority
)

// ValidateAndSign validates builtFrom against the build policies and creates
// attestations for all authorities for the matching policies.
// Returns an error if creating an attestation for any authority fails.
func (s Signer) ValidateAndSign(prov BuildProvenance, bps []v1beta1.BuildPolicy) error {
	for _, bp := range bps {
		// If Image already is attested using the AttestationAuthority the Policy, return true.
		if s.verifyAttestations(prov.ImageRef, bp.Namespace, bp.Spec.AttestationAuthorityName) {
			glog.Infof("Image %q has valid attestation for BuildPolicy %q", prov.ImageRef, bp.ObjectMeta.Name)
			return nil
		}

		glog.Infof("Validating %q against BuildPolicy %q", prov.ImageRef, bp.Name)
		if result := s.config.Validate(bp, prov.BuiltFrom); result != nil {
			glog.Errorf("Image %q does not match BuildPolicy %q: %s", prov.ImageRef, bp.ObjectMeta.Name, result)
			continue
		}
		glog.Infof("Image %q matches BuildPolicy %s, creating attestations", prov.ImageRef, bp.Name)
		if err := s.addAttestation(prov.ImageRef, bp.Namespace, bp.Spec.AttestationAuthorityName); err != nil {
			return err
		}
	}
	return nil
}

func (s Signer) verifyAttestations(image string, ns string, authority string) bool {
	// Get AttestaionAuthority specified in the buildpolicy.
	auth, err := authFetcher(ns, authority)
	if err != nil {
		glog.Errorf("Error while fetching authorities %s", err)
		return false
	}
	atts, err := s.client.Attestations(image)
	if err != nil {
		glog.Errorf("Error while fetching attestations %s", err)
		return false
	}
	return s.hasValidImageAttestations(image, atts, auth)
}

// re-use reviewe.Review
func (s Signer) hasValidImageAttestations(image string, attestations []metadata.PGPAttestation, auth *v1beta1.AttestationAuthority) bool {
	host, err := container.NewAtomicContainerSig(image, map[string]string{})
	if err != nil {
		glog.Error(err)
		return false
	}
	key, fp, err := fingerprint(auth.Spec.PublicKeyData)
	if err != nil {
		glog.Errorf("Error parsing key for %q: %v", auth.Name, err)
		return false
	}
	for _, a := range attestations {
		if a.KeyID == fp {
			if err = host.VerifyAttestationSignature(key, a.Signature); err != nil {
				glog.Errorf("Could not find verify attestation for attestation authority %s", a.KeyID)
			} else {
				return true
			}
		}
	}
	return false
}

func (s Signer) addAttestation(image string, ns string, authority string) error {
	// Get AttestaionAuthority specified in the buildpolicy.
	a, err := authFetcher(ns, authority)
	if err != nil {
		return err
	}
	n, err := util.GetOrCreateAttestationNote(s.client, a)
	if err != nil {
		return err
	}
	// Get secret for this Authority
	sec, err := s.config.Secret(ns, a.Spec.PrivateKeySecretName)
	if err != nil {
		return err
	}
	// Create Attestation Signature
	_, err = s.client.CreateAttestationOccurence(n, image, sec)
	return err
}

// fingerprint returns the fingerprint and key from the base64 encoded public key data
// re-use from review.Review
func fingerprint(publicKeyData string) (key, fingerprint string, err error) {
	publicData, err := base64.StdEncoding.DecodeString(publicKeyData)
	if err != nil {
		return key, fingerprint, err
	}
	s, err := secrets.NewPgpKey("", "", string(publicData))
	if err != nil {
		return key, fingerprint, err
	}
	return string(publicData), s.Fingerprint(), nil
}
