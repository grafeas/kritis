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
	"reflect"
	"testing"

	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/common"

	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/attestation"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	pkg "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/package"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/vulnerability"
)

func TestGetVulnerabilityFromOccurence(t *testing.T) {
	tests := []struct {
		name        string
		severity    vulnerability.Severity
		fixKind     pkg.Version_VersionKind
		noteName    string
		expectedVul metadata.Vulnerability
	}{
		{"fix available", vulnerability.Severity_LOW,
			pkg.Version_MAXIMUM,
			"CVE-1",
			metadata.Vulnerability{
				CVE:             "CVE-1",
				Severity:        "LOW",
				HasFixAvailable: false,
			},
		},
		{"fix not available", vulnerability.Severity_MEDIUM,
			pkg.Version_NORMAL,
			"CVE-2",
			metadata.Vulnerability{
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
					Severity: tc.severity,
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

func TestGetRawAttestationFromOccurrence(t *testing.T) {
	tests := []struct {
		name           string
		noteName       string
		att            attestation.Attestation
		expectedRawAtt metadata.RawAttestation
	}{
		{
			"pgp attestation",
			"CVE-1",
			makeOccAttestationPgp("sig-1", "id-1"),
			makeRawAttestationPgp("sig-1", "id-1"),
		},
		{
			"generic attestation",
			"CVE-2",
			makeOccAttestationGeneric([]string{"sig-1"}, []string{"id-1"}, "generic-address"),
			makeRawAttestationGeneric([]string{"sig-1"}, []string{"id-1"}, "generic-address"),
		},
		{
			"generic attestation multiple signatures",
			"CVE-3",
			makeOccAttestationGeneric([]string{"sig-1", "sig-2"}, []string{"id-1", "id-2"}, "generic-address"),
			makeRawAttestationGeneric([]string{"sig-1", "sig-2"}, []string{"id-1", "id-2"}, "generic-address"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			occ := &grafeas.Occurrence{
				NoteName: tc.noteName,
				Details: &grafeas.Occurrence_Attestation{
					Attestation: &attestation.Details{Attestation: &tc.att},
				},
			}
			actualRawAtt, err := GetRawAttestationFromOccurrence(occ)
			if err != nil {
				t.Fatalf("Error while parsing RawAttestation from Occurrence: %v", err)
			}
			if !reflect.DeepEqual(*actualRawAtt, tc.expectedRawAtt) {
				t.Fatalf("Expected \n%v\nGot \n%v", tc.expectedRawAtt, *actualRawAtt)
			}
		})
	}
}

func TestGetResource(t *testing.T) {
	r := GetResource("gcr.io/test/image:sha")
	e := &grafeas.Resource{Uri: "https://gcr.io/test/image:sha"}
	testutil.DeepEqual(t, e, r)
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

func makeRawAttestationPgp(signature, id string) metadata.RawAttestation {
	return metadata.RawAttestation{
		SignatureType: metadata.PgpSignatureType,
		Signatures: []metadata.RawSignature{
			{
				Signature:   signature,
				PublicKeyId: id,
			},
		},
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

func makeRawAttestationGeneric(sigs, ids []string, payload string) metadata.RawAttestation {
	signatures := []metadata.RawSignature{}
	for i, sig := range sigs {
		newSig := metadata.RawSignature{
			PublicKeyId: ids[i],
			Signature:   sig,
		}
		signatures = append(signatures, newSig)
	}
	return metadata.RawAttestation{
		SignatureType:     metadata.GenericSignatureType,
		SerializedPayload: []byte(payload),
		Signatures:        signatures,
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
