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

package metadata

import (
	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
)

type MetadataFetcher interface {
	// GetVulnerabilities returns package vulnerabilities for a container
	GetVulnerabilities(containerImage string) ([]Vulnerability, error)
	// Create Attesatation Occurrence for an image.
	CreateAttestationOccurence(note *containeranalysispb.Note,
		containerImage string,
		pgpSigningKey *secrets.PGPSigningSecret) (*containeranalysispb.Occurrence, error)
	// Get Attestation Note for an Attestation Authority.
	GetAttestationNote(aa kritisv1beta1.AttestationAuthority) (*containeranalysispb.Note, error)
	// Get Attestation Occurrences for given image.
	GetAttestations(containerImage string) ([]PGPAttestation, error)
}

type Vulnerability struct {
	Severity        string
	HasFixAvailable bool
	CVE             string
}

// PGPAttestation represents the Signature and the Singer Key Id from the
// containeranalysis Occurrence_Attestation instance.
type PGPAttestation struct {
	Signature string
	KeyId     string
}
