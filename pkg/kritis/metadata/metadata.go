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
	"fmt"
	"strings"

	"github.com/grafeas/kritis/pkg/kritis/cryptolib"

	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	attestationpb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/attestation"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	grafeasv1beta1 "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	gcspkg "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/package"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/vulnerability"
)

type SignatureType int

const (
	UnknownSignatureType SignatureType = iota
	PgpSignatureType
	GenericSignatureType
)

func (st SignatureType) String() string {
	return [...]string{"UnknownSignatureType", "PgpSignatureType", "GenericSignatureType"}[st]
}

// Read/write interface to access Occurrences and Notes using Grafeas API.
type ReadWriteClient interface {
	// Vulnerabilities returns package vulnerabilities for a given image.
	Vulnerabilities(containerImage string) ([]Vulnerability, error)
	// CreateAttestationOccurrence creates an Attestation occurrence for a given image, secret, and project.
	CreateAttestationOccurrence(noteName string,
		containerImage string, pgpSigningKey *secrets.PGPSigningSecret, proj string) (*grafeasv1beta1.Occurrence, error)
	//AttestationNote fetches an Attestation note for an Attestation Authority.
	AttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeasv1beta1.Note, error)
	// Create Attestation Note for an Attestation Authority.
	CreateAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeasv1beta1.Note, error)
	// Attestations get Attestation Occurrences for given image.
	Attestations(containerImage string, aa *kritisv1beta1.AttestationAuthority) ([]cryptolib.Attestation, error)
	// Close closes client connections
	Close()
}

// Read-only interface to access Occurrences and Notes using Grafeas API.
type ReadOnlyClient interface {
	// Vulnerabilities returns package vulnerabilities for a given image.
	Vulnerabilities(containerImage string) ([]Vulnerability, error)
	//Attestations get Attestation Occurrences for given image.
	Attestations(containerImage string, aa *kritisv1beta1.AttestationAuthority) ([]cryptolib.Attestation, error)
	// Close closes client connections
	Close()
}

type Vulnerability struct {
	Severity        string
	HasFixAvailable bool
	CVE             string
}

// ParseNoteReference extracts the project ID and the note ID from the NoteReference.
func ParseNoteReference(ref string) (string, string, error) {
	parts := strings.Split(ref, "/")
	if len(parts) != 4 || parts[0] != "projects" || parts[2] != "notes" {
		return "", "", fmt.Errorf("invalid Note Reference, should be in format projects/<project_id>/notes/<note_id>, actual: %s", ref)
	}
	return parts[1], parts[3], nil
}

func IsFixAvailable(pis []*vulnerability.PackageIssue) bool {
	for _, pi := range pis {
		if pi.GetFixedLocation() == nil || pi.GetFixedLocation().GetVersion().Kind == gcspkg.Version_MAXIMUM {
			// If FixedLocation.Version.Kind = MAXIMUM then no fix is available. Return false
			return false
		}
	}
	return true
}

func GetVulnerabilityFromOccurrence(occ *grafeas.Occurrence) *Vulnerability {
	vulnDetails := occ.GetVulnerability()
	if vulnDetails == nil {
		return nil
	}
	hasFixAvailable := IsFixAvailable(vulnDetails.GetPackageIssue())
	vulnerability := Vulnerability{
		Severity:        vulnerability.Severity_name[int32(vulnDetails.Severity)],
		HasFixAvailable: hasFixAvailable,
		CVE:             occ.GetNoteName(),
	}
	return &vulnerability
}

// GetAttestationsFromOccurrence parses Attestations from PgpSignedAttestation
// and GenericSignedAttestation Occurrences. A PgpSignedAttestation has one
// signature and is parsed into one Attestation. A GenericSignedAttestation may
// have multiple signatures, which are parsed into multiple Attestations.
func GetAttestationsFromOccurrence(occ *grafeas.Occurrence) ([]cryptolib.Attestation, error) {
	atts := []cryptolib.Attestation{}
	occAtt := occ.GetAttestation().GetAttestation()
	switch occAtt.Signature.(type) {
	case *attestationpb.Attestation_PgpSignedAttestation:
		psa := occAtt.GetPgpSignedAttestation()
		att := cryptolib.Attestation{
			PublicKeyID: psa.GetPgpKeyId(),
			Signature:   []byte(psa.GetSignature()),
		}
		atts = append(atts, att)
	case *attestationpb.Attestation_GenericSignedAttestation:
		gsa := occAtt.GetGenericSignedAttestation()
		for _, sig := range gsa.GetSignatures() {
			att := cryptolib.Attestation{
				PublicKeyID:       string(sig.PublicKeyId),
				Signature:         sig.Signature,
				SerializedPayload: gsa.GetSerializedPayload(),
			}
			atts = append(atts, att)
		}
	default:
		return nil, fmt.Errorf("Unknown signature type for attestation %v", occAtt)
	}
	return atts, nil
}

// MakeAttestation is testing purposes. Should not be used as part of metadata
// external API.
func MakeAttestation(publicKeyID string, signature string, serializedPayload []byte) cryptolib.Attestation {
	return cryptolib.Attestation{
		PublicKeyID:       publicKeyID,
		Signature:         []byte(signature),
		SerializedPayload: serializedPayload,
	}
}
