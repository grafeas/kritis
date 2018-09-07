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

package containeranalysis

import (
	"reflect"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
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

			actualVuln := getVulnerabilityFromOccurence(occ)
			if !reflect.DeepEqual(*actualVuln, tc.expectedVul) {
				t.Fatalf("Expected \n%v\nGot \n%v", tc.expectedVul, actualVuln)
			}
		})
	}
}

func Test_isRegistryGCR(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		expected bool
	}{
		{
			name:     "gcr image",
			registry: "gcr.io",
			expected: true,
		},
		{
			name:     "eu gcr image",
			registry: "eu.gcr.io",
			expected: true,
		},
		{
			name:     "invalid gcr image",
			registry: "foogcr.io",
			expected: false,
		},
		{
			name:     "non gcr image",
			registry: "index.docker.io",
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := isRegistryGCR(test.registry)
			testutil.CheckErrorAndDeepEqual(t, false, nil, test.expected, actual)
		})
	}
}

func TestGetProjectFromNoteRef(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		shdErr bool
		output string
	}{
		{"good", "v1aplha1/projects/name", false, "name"},
		{"bad1", "some", true, ""},
		{"bad2", "some/t", true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := getProjectFromNoteReference(tc.input)
			testutil.CheckErrorAndDeepEqual(t, tc.shdErr, err, tc.output, actual)
		})
	}
}
