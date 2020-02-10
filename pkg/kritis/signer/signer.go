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

package signer

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/authority"
	"github.com/grafeas/kritis/pkg/kritis/crd/vulnzsigningpolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
)

type Signer struct {
	config *Config
	client metadata.ReadWriteClient
}

type Config struct {
	Secret    secrets.Fetcher
	Validate  vulnzsigningpolicy.ValidateFunc
	PgpKey    *secrets.PgpKey
	Authority v1beta1.AttestationAuthority
	Project   string
}

func New(client metadata.ReadWriteClient, c *Config) Signer {
	return Signer{
		client: client,
		config: c,
	}
}

type ImageVulnerabilities struct {
	ImageRef        string
	Vulnerabilities []metadata.Vulnerability
}

// For testing
var (
	authFetcher = authority.Authority
)

// ValidateAndSign validates image from vulnz signing policy and then creates
// attestation for the passing image.
// Returns an error if image does not pass or creating an attestation fails.
func (s Signer) ValidateAndSign(imageVulnz ImageVulnerabilities, vps v1beta1.VulnzSigningPolicy) error {
	glog.Infof("Validating %q against VulnzSigningPolicy %q", imageVulnz.ImageRef, vps.Name)
	if violations, err := s.config.Validate(vps, imageVulnz.ImageRef, imageVulnz.Vulnerabilities); err != nil {
		return fmt.Errorf("image %q does not pass VulnzSigningPolicy %q: %v", imageVulnz.ImageRef, vps.Name, violations)
	} else {
		glog.Infof("Image %q passes VulnzSigningPolicy %s, creating attestations", imageVulnz.ImageRef, vps.Name)

		if err := s.addAttestation(imageVulnz.ImageRef); err != nil {
			return err
		}
		return nil
	}
}

func (s Signer) addAttestation(image string) error {
	n, err := util.GetOrCreateAttestationNote(s.client, &s.config.Authority)
	if err != nil {
		return err
	}
	// Create secret for this authority
	sec := &secrets.PGPSigningSecret{
		PgpKey:     s.config.PgpKey,
		SecretName: "signing-secret",
	}

	// Create Attestation Signature
	_, err = s.client.CreateAttestationOccurrence(n, image, sec, s.config.Project)
	return err
}
