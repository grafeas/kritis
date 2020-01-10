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
	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/authority"
	"github.com/grafeas/kritis/pkg/kritis/crd/buildpolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/metadata/grafeas"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
)

type Signer struct {
	config *Config
	client metadata.ReadWriteClient
}

type Config struct {
	Secret   secrets.Fetcher
	Validate buildpolicy.ValidateFunc
}

func New(client metadata.ReadWriteClient, c *Config) Signer {
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
		glog.Infof("Validating %q against BuildPolicy %q", prov.ImageRef, bp.Name)
		if result := s.config.Validate(bp, prov.BuiltFrom); result != nil {
			glog.Errorf("Image %q does not match BuildPolicy %q: %s", prov.ImageRef, bp.ObjectMeta.Name, result)
			continue
		}
		glog.Infof("Image %q matches BuildPolicy %s, creating attestations", prov.ImageRef, bp.Name)
		if err := s.addAttestation(prov.ImageRef, bp.Namespace, bp.Spec.AttestationAuthorityName, bp.Spec.PrivateKeySecretName); err != nil {
			return err
		}
	}
	return nil
}

func (s Signer) addAttestation(image string, ns string, authority string, keySecretName string) error {
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
	sec, err := s.config.Secret(ns, keySecretName)
	if err != nil {
		return err
	}
	// Create Attestation Signature
	_, err = s.client.CreateAttestationOccurrence(n, image, sec, grafeas.DefaultProject)
	return err
}
