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

// A signer is used for creating attestations for an image.
type Signer struct {
	config *Config
	client metadata.ReadWriteClient
}

// A signer config that includes necessary data and handler for signing.
type Config struct {
	Validate  vulnzsigningpolicy.ValidateFunc
	PgpKey    *secrets.PgpKey
	Authority v1beta1.AttestationAuthority
	Project   string
}

// Creating a new signer object.
func New(client metadata.ReadWriteClient, c *Config) Signer {
	return Signer{
		client: client,
		config: c,
	}
}

// ImageVulnerabilities is an input for running vulnerability policy validation.
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
	violations, err := s.config.Validate(vps, imageVulnz.ImageRef, imageVulnz.Vulnerabilities)
	if err != nil {
		return fmt.Errorf("error when evaluating image %q against policy %q", imageVulnz.ImageRef, vps.Name)
	}
	if violations != nil && len(violations) != 0 {
		return fmt.Errorf("image %q does not pass VulnzSigningPolicy %q: %v", imageVulnz.ImageRef, vps.Name, violations)
	}

	glog.Infof("Image %q passes VulnzSigningPolicy %s.", imageVulnz.ImageRef, vps.Name)
	return s.SignImage(imageVulnz.ImageRef)
}

// ValidateAndSign signs an image without doing any policy check.
// Returns an error if image does not pass or creating an attestation fails.
func (s Signer) SignImage(image string) error {
	existed, _ := s.isAttestationAlreadyExist(image)
	if existed {
		glog.Warningf("Attestation for image %q has already been created.", image)
		return nil
	}
	glog.Infof("Creating attestations for image %q.", image)
	if err := s.addAttestation(image); err != nil {
		return err
	}
	return nil
}

// Creating an attestation if not already exist under the same note.
// The method will create a note if it does not already exist.
// Returns error if creation failed, e.g., if an attestation already exists.
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
	_, err = s.client.CreateAttestationOccurrence(n.GetName(), image, sec, s.config.Project)
	return err
}

func (s Signer) isAttestationAlreadyExist(image string) (bool, error) {
	atts, err := s.client.Attestations(image, &s.config.Authority)
	if err == nil && len(atts) > 0 {
		return true, nil
	}

	return false, err
}
