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
	grafeasv1beta1 "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
)

type Fetcher interface {
	// Vulnerabilities returns package vulnerabilities for a given image.
	Vulnerabilities(containerImage string) ([]Vulnerability, error)
	// Create Attesatation Occurrence for an image.
	CreateAttestationOccurence(note *grafeasv1beta1.Note,
		containerImage string,
		pgpSigningKey *secrets.PGPSigningSecret) (*grafeasv1beta1.Occurrence, error)
	//AttestationNote getches a Attestation note for an Attestation Authority.
	AttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeasv1beta1.Note, error)
	// Create Attestation Note for an Attestation Authority.
	CreateAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeasv1beta1.Note, error)
	//Attestations get Attestation Occurrences for given image.
	Attestations(containerImage string) ([]PGPAttestation, error)

	// Builds get Build Occurrences for given image.
	Builds(containerImage string) ([]Build, error)
}

type Vulnerability struct {
	Severity        string
	HasFixAvailable bool
	CVE             string
}

// PGPAttestation represents the Signature and the Signer Key Id from the
// containeranalysis Occurrence_Attestation instance.
type PGPAttestation struct {
	Signature string
	KeyID     string
	// OccID is the occurrence ID for containeranalysis Occurrence_Attestation instance
	OccID string
}

type Build struct {
	Provenance *BuildProvenance
}

type BuildProvenance struct {
	ProjectID string
	Creator   string
}
