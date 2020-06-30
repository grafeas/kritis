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

package metadata

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/grafeas/kritis/pkg/kritis/cryptolib"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/attestation"
	attestationpb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/attestation"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/common"
	commonpb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/common"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	pkg "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/package"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/vulnerability"
)

var (
	attestationNoteName = "projects/test-project/notes/test-note"
)

func TestGetVulnerabilityFromOccurence(t *testing.T) {
	tests := []struct {
		name        string
		severity    vulnerability.Severity
		fixKind     pkg.Version_VersionKind
		noteName    string
		expectedVul Vulnerability
	}{
		{"fix available", vulnerability.Severity_LOW,
			pkg.Version_MAXIMUM,
			"CVE-1",
			Vulnerability{
				CVE:             "CVE-1",
				Severity:        "LOW",
				HasFixAvailable: false,
			},
		},
		{"fix not available", vulnerability.Severity_MEDIUM,
			pkg.Version_NORMAL,
			"CVE-2",
			Vulnerability{
				CVE:             "CVE-2",
				Severity:        "MEDIUM",
				HasFixAvailable: true,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vulnDetails := &grafeas.Occurrence_Vulnerability{
				Vulnerability: &vulnerability.Details{
					EffectiveSeverity: tc.severity,
					PackageIssue: []*vulnerability.PackageIssue{
						{
							AffectedLocation: &vulnerability.VulnerabilityLocation{},
							FixedLocation: &vulnerability.VulnerabilityLocation{
								Version: &pkg.Version{
									Kind: tc.fixKind,
								},
							},
						},
					},
				}}
			occ := &grafeas.Occurrence{
				NoteName: tc.noteName,
				Details:  vulnDetails,
			}

			actualVuln := GetVulnerabilityFromOccurrence(occ)
			if !reflect.DeepEqual(*actualVuln, tc.expectedVul) {
				t.Fatalf("Expected \n%v\nGot \n%v", tc.expectedVul, actualVuln)
			}
		})
	}
}

func TestGetAttestationsFromOccurrence(t *testing.T) {
	tests := []struct {
		name         string
		att          attestation.Attestation
		expectedAtts []cryptolib.Attestation
	}{
		{
			"pgp attestation",
			makeOccAttestationPgp("sig-1", "id-1"),
			[]cryptolib.Attestation{
				{
					PublicKeyID: "id-1",
					Signature:   []byte("sig-1"),
				},
			},
		},
		{
			"generic attestation",
			makeOccAttestationGeneric([]string{"sig-1"}, []string{"id-1"}, "generic-address"),
			[]cryptolib.Attestation{
				{
					PublicKeyID:       "id-1",
					Signature:         []byte("sig-1"),
					SerializedPayload: []byte("generic-address"),
				},
			},
		},
		{
			"generic attestation multiple signatures",
			makeOccAttestationGeneric([]string{"sig-1", "sig-2"}, []string{"id-1", "id-2"}, "generic-address"),
			[]cryptolib.Attestation{
				{
					PublicKeyID:       "id-1",
					Signature:         []byte("sig-1"),
					SerializedPayload: []byte("generic-address"),
				},
				{
					PublicKeyID:       "id-2",
					Signature:         []byte("sig-2"),
					SerializedPayload: []byte("generic-address"),
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			occ := &grafeas.Occurrence{
				NoteName: attestationNoteName,
				Details: &grafeas.Occurrence_Attestation{
					Attestation: &attestation.Details{Attestation: &tc.att},
				},
			}
			actualAtts, err := GetAttestationsFromOccurrence(occ)
			if err != nil {
				t.Fatalf("Error while parsing Attestation from Occurrence: %v", err)
			}
			if !cmp.Equal(actualAtts, tc.expectedAtts, cmpopts.SortSlices(func(att1, att2 cryptolib.Attestation) bool {
				return att1.PublicKeyID > att2.PublicKeyID
			})) {
				t.Fatalf("Expected: \n%v\nGot: \n%v", tc.expectedAtts, actualAtts)
			}
		})
	}
}

func TestCreateOccurrenceFromAttestation(t *testing.T) {
	tests := []struct {
		name        string
		image       string
		noteName    string
		sType       SignatureType
		cryptoAtt   *cryptolib.Attestation
		expectedOcc *grafeas.Occurrence
	}{
		{
			"pgp attestation",
			"image-1",
			"note-1",
			PgpSignatureType,
			&cryptolib.Attestation{
				PublicKeyID:       "id-1",
				Signature:         []byte("sig-1"),
				SerializedPayload: []byte("payload-1"),
			},
			&grafeas.Occurrence{
				Resource: &grafeas.Resource{Uri: "https://image-1"},
				NoteName: "note-1",
				Details: &grafeas.Occurrence_Attestation{
					Attestation: &attestation.Details{
						Attestation: &attestation.Attestation{
							Signature: &attestation.Attestation_PgpSignedAttestation{
								PgpSignedAttestation: &attestation.PgpSignedAttestation{
									Signature: "sig-1",
									KeyId: &attestation.PgpSignedAttestation_PgpKeyId{
										PgpKeyId: "id-1",
									},
									ContentType: attestationpb.PgpSignedAttestation_SIMPLE_SIGNING_JSON,
								},
							},
						},
					},
				},
			},
		},
		{
			"generic attestation",
			"image-1",
			"note-1",
			GenericSignatureType,
			&cryptolib.Attestation{
				PublicKeyID:       "id-1",
				Signature:         []byte("sig-1"),
				SerializedPayload: []byte("payload-1"),
			},
			&grafeas.Occurrence{
				Resource: &grafeas.Resource{Uri: "https://image-1"},
				NoteName: "note-1",
				Details: &grafeas.Occurrence_Attestation{
					Attestation: &attestation.Details{
						Attestation: &attestationpb.Attestation{
							Signature: &attestationpb.Attestation_GenericSignedAttestation{
								GenericSignedAttestation: &attestationpb.GenericSignedAttestation{
									Signatures: []*commonpb.Signature{
										{
											Signature:   []byte("sig-1"),
											PublicKeyId: "id-1",
										},
									},
									SerializedPayload: []byte("payload-1"),
									ContentType:       attestationpb.GenericSignedAttestation_SIMPLE_SIGNING_JSON,
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualOcc, err := CreateOccurrenceFromAttestation(tc.cryptoAtt, tc.image, tc.noteName, tc.sType)
			if err != nil {
				t.Fatalf("Error while creating occurrence from attestation: %v", err)
			}
			if !reflect.DeepEqual(actualOcc, tc.expectedOcc) {
				t.Fatalf("Expected: \n%v\nGot: \n%v", tc.expectedOcc, actualOcc)
			}
		})
	}
}

func TestIsFixable(t *testing.T) {
	tests := []struct {
		name            string
		pis             []*vulnerability.PackageIssue
		expectedFixable bool
	}{
		{"fix version normal is fixable",
			[]*vulnerability.PackageIssue{
				{
					AffectedLocation: &vulnerability.VulnerabilityLocation{},
					FixedLocation: &vulnerability.VulnerabilityLocation{
						Version: &pkg.Version{
							Kind: pkg.Version_NORMAL,
						},
					},
				},
			},
			true,
		},
		{"fix version maximum is not fixable",
			[]*vulnerability.PackageIssue{
				{
					AffectedLocation: &vulnerability.VulnerabilityLocation{},
					FixedLocation: &vulnerability.VulnerabilityLocation{
						Version: &pkg.Version{
							Kind: pkg.Version_MAXIMUM,
						},
					},
				},
			},
			false,
		},
		{"fix location nil is not fixable",
			[]*vulnerability.PackageIssue{
				{
					AffectedLocation: &vulnerability.VulnerabilityLocation{},
					FixedLocation:    nil,
				},
			},
			false,
		},
		{"one issue fixable one issue not fixable is not fixable",
			[]*vulnerability.PackageIssue{
				{
					AffectedLocation: &vulnerability.VulnerabilityLocation{},
					FixedLocation: &vulnerability.VulnerabilityLocation{
						Version: &pkg.Version{
							Kind: pkg.Version_NORMAL,
						},
					},
				},
				{
					AffectedLocation: &vulnerability.VulnerabilityLocation{},
					FixedLocation:    nil,
				},
			},
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualFixable := IsFixAvailable(tc.pis)
			if actualFixable != tc.expectedFixable {
				t.Fatalf("Expected \n%v\nGot \n%v", tc.expectedFixable, actualFixable)
			}
		})
	}
}

func makeOccAttestationPgp(signature, id string) attestation.Attestation {
	return attestation.Attestation{
		Signature: &attestation.Attestation_PgpSignedAttestation{
			PgpSignedAttestation: &attestation.PgpSignedAttestation{
				Signature: signature,
				KeyId: &attestation.PgpSignedAttestation_PgpKeyId{
					PgpKeyId: id,
				},
			},
		},
	}
}

func makeOccAttestationGeneric(sigs, ids []string, payload string) attestation.Attestation {
	signatures := []*common.Signature{}
	for i, sig := range sigs {
		newSig := &common.Signature{
			PublicKeyId: ids[i],
			Signature:   []byte(sig),
		}
		signatures = append(signatures, newSig)
	}
	return attestation.Attestation{
		Signature: &attestation.Attestation_GenericSignedAttestation{
			GenericSignedAttestation: &attestation.GenericSignedAttestation{
				SerializedPayload: []byte(payload),
				Signatures:        signatures,
			},
		},
	}
}
