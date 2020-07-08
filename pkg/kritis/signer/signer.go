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
	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/crd/authority"
	"github.com/grafeas/kritis/pkg/kritis/cryptolib"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/util"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A signer is used for creating attestations for an image.
type Signer struct {
	config *config
	client metadata.ReadWriteClient
}

// A signer config that includes necessary data and handler for signing.
type config struct {
	cSigner cryptolib.Signer
	// an AttestaionAuthority that is used in metadata client APIs.
	// We should consider refactor it out because:
	// 1. the only useful field here is noteName
	// 2. other fields, e.g., public key, are unset
	// TODO: refactor out the authority code
	authority v1beta1.AttestationAuthority
	project   string
}

// Creating a new signer object.
func New(client metadata.ReadWriteClient, cSigner cryptolib.Signer, noteName string, project string) Signer {
	return Signer{
		client: client,
		config: &config{
			cSigner,
			v1beta1.AttestationAuthority{
				ObjectMeta: metav1.ObjectMeta{Name: "signing-aa"},
				Spec: v1beta1.AttestationAuthoritySpec{
					NoteReference: noteName,
					PublicKeys:    []v1beta1.PublicKey{},
				},
			},
			project,
		},
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

// SignImage signs an image without doing any policy check.
// Returns an error if creating an attestation fails.
func (s Signer) SignImage(image string) error {
	existed, _ := s.isAttestationAlreadyExist(image)
	if existed {
		glog.Warningf("Attestation for image %q has already been created.", image)
		return nil
	}

	glog.Infof("Creating attestation for image %q.", image)
	// Create attestation
	att, err := s.createAttestation(image)
	if err != nil {
		return err
	}
	glog.Infof("Attestation for image %q is successfully created locally.", image)

	glog.Infof("Uploading attestation for image %q.", image)
	if err := s.uploadAttestation(image, att); err != nil {
		return err
	}
	glog.Infof("Attestation for image %q is successfully uploaded.", image)

	return nil
}

// Creating an atestation.
func (s Signer) createAttestation(image string) (*cryptolib.Attestation, error) {
	payload, err := attestation.AtomicContainerPayload(image)
	if err != nil {
		return nil, err
	}

	att, err := s.config.cSigner.CreateAttestation(payload)
	if err != nil {
		return nil, err
	}
	return att, nil
}

// Uploading an attestation if not already exist under the same note.
// The method will create a note if it does not already exist.
// Returns error if upload failed, e.g., if an attestation already exists.
func (s Signer) uploadAttestation(image string, att *cryptolib.Attestation) error {
	note, err := util.GetOrCreateAttestationNote(s.client, &s.config.authority)
	if err != nil {
		return err
	}

	// Upload attestation
	_, err = s.client.UploadAttestationOccurrence(note.GetName(), image, att, s.config.project, metadata.PgpSignatureType)
	return err
}

func (s Signer) isAttestationAlreadyExist(image string) (bool, error) {
	atts, err := s.client.Attestations(image, &s.config.authority)
	if err == nil && len(atts) > 0 {
		return true, nil
	}

	return false, err
}
