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

	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	pkg "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/package"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/vulnerability"
)

func TestGetVulnerabilityFromOccurrence(t *testing.T) {
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

func TestGetResource(t *testing.T) {
	r := GetResource("gcr.io/test/image:sha")
	e := &grafeas.Resource{Uri: "https://gcr.io/test/image:sha"}
	testutil.DeepEqual(t, e, r)
}
