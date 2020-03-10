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
	CreateAttestationOccurrence(note *grafeasv1beta1.Note,
		containerImage string, pgpSigningKey *secrets.PGPSigningSecret,
		proj string) (*grafeasv1beta1.Occurrence, error)
	//AttestationNote fetches an Attestation note for an Attestation Authority.
	AttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeasv1beta1.Note, error)
	// Create Attestation Note for an Attestation Authority.
	CreateAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeasv1beta1.Note, error)
	//Attestations get Attestation Occurrences for given image.
	Attestations(containerImage string, aa *kritisv1beta1.AttestationAuthority) ([]RawAttestation, error)
	// Close closes client connections
	Close()
}

// Read-only interface to access Occurrences and Notes using Grafeas API.
type ReadOnlyClient interface {
	// Vulnerabilities returns package vulnerabilities for a given image.
	Vulnerabilities(containerImage string) ([]Vulnerability, error)
	//Attestations get Attestation Occurrences for given image.
	Attestations(containerImage string, aa *kritisv1beta1.AttestationAuthority) ([]RawAttestation, error)
	// Close closes client connections
	Close()
}

type Vulnerability struct {
	Severity        string
	HasFixAvailable bool
	CVE             string
}

// RawAttestation represents an unauthenticated attestation, stripped of any
// information specific to the wire format. RawAttestation may only be
// trusted after successfully verifying its Signature. Each RawAttestation
// contains one signature.
//
// RawAttestations are parsed from either PgpSignedAttestation or
// GenericSignedAttestation Occurrences. PgpSignedAttestation has one
// signature, and is parsed into one RawAttestation. GenericSignedAttestation
// has multiple signatures, and is parsed into multiple RawAttestations.
type RawAttestation struct {
	SignatureType     SignatureType
	Signature         RawSignature
	SerializedPayload []byte
}

// RawSignature contains the signature content and an ID for the public key
// that can verify the signature. The ID does not by itself verify the
// signature. It is merely a key lookup hint.
type RawSignature struct {
	PublicKeyId string
	Signature   string
}

// ParseNoteReference extracts the project ID and the note ID from the NoteReference.
func ParseNoteReference(ref string) (string, string, error) {
	parts := strings.Split(ref, "/")
	if len(parts) != 4 || parts[0] != "projects" || parts[2] != "notes" {
		return "", "", fmt.Errorf("invalid Note Reference, should be in format projects/<project_id>/notes/<note_id>")
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

func GetRawAttestationsFromOccurrence(occ *grafeas.Occurrence) ([]RawAttestation, error) {
	ras := []RawAttestation{}
	att := occ.GetAttestation().GetAttestation()
	switch att.Signature.(type) {
	case *attestationpb.Attestation_PgpSignedAttestation:
		psa := att.GetPgpSignedAttestation()
		ra := RawAttestation{
			SignatureType: PgpSignatureType,
			Signature: RawSignature{
				PublicKeyId: psa.GetPgpKeyId(),
				Signature:   psa.GetSignature(),
			},
			SerializedPayload: []byte{},
		}
		ras = append(ras, ra)
	case *attestationpb.Attestation_GenericSignedAttestation:
		gsa := att.GetGenericSignedAttestation()
		for _, sig := range gsa.GetSignatures() {
			newSig := RawSignature{
				PublicKeyId: sig.PublicKeyId,
				Signature:   string(sig.Signature),
			}
			ra := RawAttestation{
				SignatureType:     GenericSignatureType,
				Signature:         newSig,
				SerializedPayload: gsa.GetSerializedPayload(),
			}
			ras = append(ras, ra)
		}
	default:
		return nil, fmt.Errorf("Unknown signature type for attestation %v", att)
	}
	return ras, nil
}

// For testing purposes. Should not be used as part of metadata external API.
func MakeRawAttestation(sigType SignatureType, sig, id, payload string) RawAttestation {
	return RawAttestation{
		SignatureType: sigType,
		Signature: RawSignature{
			Signature:   sig,
			PublicKeyId: id,
		},
		SerializedPayload: []byte(payload),
	}
}
