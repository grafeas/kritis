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

package util

import (
	"fmt"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	attestationpb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/attestation"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	pkg "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/package"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/vulnerability"
)

func GetVulnerabilityFromOccurrence(occ *grafeas.Occurrence) *metadata.Vulnerability {
	vulnDetails := occ.GetVulnerability()
	if vulnDetails == nil {
		return nil
	}
	hasFixAvailable := IsFixAvailable(vulnDetails.GetPackageIssue())
	vulnerability := metadata.Vulnerability{
		Severity:        vulnerability.Severity_name[int32(vulnDetails.Severity)],
		HasFixAvailable: hasFixAvailable,
		CVE:             occ.GetNoteName(),
	}
	return &vulnerability
}

func IsFixAvailable(pis []*vulnerability.PackageIssue) bool {
	for _, pi := range pis {
		if pi.GetFixedLocation() == nil || pi.GetFixedLocation().GetVersion().Kind == pkg.Version_MAXIMUM {
			// If FixedLocation.Version.Kind = MAXIMUM then no fix is available. Return false
			return false
		}
	}
	return true
}

func GetResourceURL(containerImage string) string {
	return fmt.Sprintf("%s%s", constants.ResourceURLPrefix, containerImage)
}

func GetResource(image string) *grafeas.Resource {
	return &grafeas.Resource{Uri: GetResourceURL(image)}
}

func GetRawAttestationsFromOccurrence(occ *grafeas.Occurrence) ([]metadata.RawAttestation, error) {
	ras := []metadata.RawAttestation{}
	att := occ.GetAttestation().GetAttestation()
	switch att.Signature.(type) {
	case *attestationpb.Attestation_PgpSignedAttestation:
		psa := att.GetPgpSignedAttestation()
		ra := metadata.RawAttestation{
			SignatureType: metadata.PgpSignatureType,
			Signature: metadata.RawSignature{
				PublicKeyId: psa.GetPgpKeyId(),
				Signature:   psa.GetSignature(),
			},
			SerializedPayload: []byte{},
		}
		ras = append(ras, ra)
	case *attestationpb.Attestation_GenericSignedAttestation:
		gsa := att.GetGenericSignedAttestation()
		for _, sig := range gsa.GetSignatures() {
			newSig := metadata.RawSignature{
				PublicKeyId: sig.PublicKeyId,
				Signature:   string(sig.Signature),
			}
			ra := metadata.RawAttestation{
				SignatureType:     metadata.GenericSignatureType,
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

func CreateAttestationSignature(image string, pgpSigningKey *secrets.PGPSigningSecret) (string, error) {
	hostSig, err := container.NewAtomicContainerSig(image, map[string]string{})
	if err != nil {
		return "", err
	}
	hostStr, err := hostSig.JSON()
	if err != nil {
		return "", err
	}
	return attestation.CreateMessageAttestation(pgpSigningKey.PgpKey, hostStr)
}

func GetAttestationKeyFingerprint(pgpSigningKey *secrets.PGPSigningSecret) string {
	return pgpSigningKey.PgpKey.Fingerprint()
}

// GetOrCreateAttestationNote returns a note if exists and creates one if it does not exist.
func GetOrCreateAttestationNote(c metadata.ReadWriteClient, a *v1beta1.AttestationAuthority) (*grafeas.Note, error) {
	n, err := c.AttestationNote(a)
	if err == nil {
		return n, nil
	}
	return c.CreateAttestationNote(a)
}
