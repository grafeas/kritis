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

package imagesecuritypolicy

import (
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"testing"
)

var (
	vulnz1 = metadata.Vulnerability{
		CVE:             "cve1",
		Severity:        "LOW",
		HasFixAvailable: true,
	}

	vulnz2 = metadata.Vulnerability{
		CVE:             "cve2",
		Severity:        "MEDIUM",
		HasFixAvailable: false,
	}
)

type mockMetadataClient struct {
}

func (m mockMetadataClient) GetVulnerabilities(project string, containerImage string) []metadata.Vulnerability {
	return []metadata.Vulnerability{
		vulnz1,
		vulnz2,
	}
}

func Test_ValidISP(t *testing.T) {
	isp := ImageSecurityPolicy{
		v1beta1.ImageSecurityPolicy{
			Spec: v1beta1.ImageSecurityPolicySpec{
				v1beta1.PackageVulernerabilityRequirements{
					MaximumSeverity: "MEDIUM",
				},
			},
		},
	}
	violations, err := isp.ValidateImageSecurityPolicy("", "", mockMetadataClient{})
	if err != nil {
		t.Errorf("error validating isp: %v", err)
	}
	if violations != nil {
		t.Errorf("got unexpected violations: %v", violations)
	}
}

func Test_BlockallPass(t *testing.T) {
	isp := ImageSecurityPolicy{
		v1beta1.ImageSecurityPolicy{
			Spec: v1beta1.ImageSecurityPolicySpec{
				v1beta1.PackageVulernerabilityRequirements{
					MaximumSeverity: "BLOCKALL",
					WhitelistCVEs: []string{
						"cve1",
						"cve2",
					},
				},
			},
		},
	}
	violations, err := isp.ValidateImageSecurityPolicy("", "", mockMetadataClient{})
	if err != nil {
		t.Errorf("error validating isp: %v", err)
	}
	if violations != nil {
		t.Errorf("got unexpected violations: %v", violations)
	}
}

func Test_BlockallFail(t *testing.T) {
	isp := ImageSecurityPolicy{
		v1beta1.ImageSecurityPolicy{
			Spec: v1beta1.ImageSecurityPolicySpec{
				v1beta1.PackageVulernerabilityRequirements{
					MaximumSeverity: "BLOCKALL",
					WhitelistCVEs: []string{
						"cve1",
					},
				},
			},
		},
	}
	violations, err := isp.ValidateImageSecurityPolicy("", "", mockMetadataClient{})
	testutil.CheckErrorAndDeepEqual(t, false, err, violations, []metadata.Vulnerability{vulnz2})
}

func Test_MaxSeverityFail(t *testing.T) {
	isp := ImageSecurityPolicy{
		v1beta1.ImageSecurityPolicy{
			Spec: v1beta1.ImageSecurityPolicySpec{
				v1beta1.PackageVulernerabilityRequirements{
					MaximumSeverity: "LOW",
				},
			},
		},
	}
	violations, err := isp.ValidateImageSecurityPolicy("", "", mockMetadataClient{})
	testutil.CheckErrorAndDeepEqual(t, false, err, violations, []metadata.Vulnerability{vulnz2})
}

func Test_WhitelistedImage(t *testing.T) {
	isp := ImageSecurityPolicy{
		v1beta1.ImageSecurityPolicy{
			ImageWhitelist: []string{"image"},
			Spec: v1beta1.ImageSecurityPolicySpec{
				v1beta1.PackageVulernerabilityRequirements{
					MaximumSeverity: "LOW",
				},
			},
		},
	}
	violations, err := isp.ValidateImageSecurityPolicy("", "image", mockMetadataClient{})
	if err != nil {
		t.Errorf("error validating isp: %v", err)
	}
	if violations != nil {
		t.Errorf("got unexpected violations: %v", violations)
	}
}

func Test_WhitelistedCVEAboveSeverityThreshold(t *testing.T) {
	isp := ImageSecurityPolicy{
		v1beta1.ImageSecurityPolicy{
			ImageWhitelist: []string{"image"},
			Spec: v1beta1.ImageSecurityPolicySpec{
				v1beta1.PackageVulernerabilityRequirements{
					MaximumSeverity: "LOW",
					WhitelistCVEs: []string{
						"cve2",
					},
				},
			},
		},
	}
	violations, err := isp.ValidateImageSecurityPolicy("", "image", mockMetadataClient{})
	if err != nil {
		t.Errorf("error validating isp: %v", err)
	}
	if violations != nil {
		t.Errorf("got unexpected violations: %v", violations)
	}
}

func Test_OnlyFixesNotAvailableFail(t *testing.T) {
	isp := ImageSecurityPolicy{
		v1beta1.ImageSecurityPolicy{
			Spec: v1beta1.ImageSecurityPolicySpec{
				v1beta1.PackageVulernerabilityRequirements{
					MaximumSeverity:       "LOW",
					OnlyFixesNotAvailable: true,
				},
			},
		},
	}
	violations, err := isp.ValidateImageSecurityPolicy("", "", mockMetadataClient{})
	testutil.CheckErrorAndDeepEqual(t, false, err, violations, []metadata.Vulnerability{vulnz2})
}
func Test_OnlyFixesNotAvailablePassWithWhitelist(t *testing.T) {
	isp := ImageSecurityPolicy{
		v1beta1.ImageSecurityPolicy{
			Spec: v1beta1.ImageSecurityPolicySpec{
				v1beta1.PackageVulernerabilityRequirements{
					MaximumSeverity:       "CRITICAL",
					OnlyFixesNotAvailable: true,
					WhitelistCVEs:         []string{"cve2"},
				},
			},
		},
	}
	violations, err := isp.ValidateImageSecurityPolicy("", "", mockMetadataClient{})
	if err != nil {
		t.Errorf("error validating isp: %v", err)
	}
	if violations != nil {
		t.Errorf("got unexpected violations: %v", violations)
	}
}

func Test_severityWithinThreshold(t *testing.T) {
	var tests = []struct {
		name        string
		maxSeverity string
		severity    string
		expected    bool
	}{
		{
			name:        "test severity below max",
			maxSeverity: "CRITICAL",
			severity:    "LOW",
			expected:    true,
		},
		{
			name:        "test severity equal to max",
			maxSeverity: "LOW",
			severity:    "LOW",
			expected:    true,
		},
		{
			name:        "test bloackall max severity",
			maxSeverity: "BLOCKALL",
			severity:    "LOW",
			expected:    false,
		},
		{
			name:        "test severity above max",
			maxSeverity: "LOW",
			severity:    "MEDIUM",
			expected:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isp := ImageSecurityPolicy{
				v1beta1.ImageSecurityPolicy{
					Spec: v1beta1.ImageSecurityPolicySpec{
						v1beta1.PackageVulernerabilityRequirements{
							MaximumSeverity:       test.maxSeverity,
							OnlyFixesNotAvailable: true,
						},
					},
				},
			}
			if isp.severityWithinThreshold(test.severity) != test.expected {
				t.Error("got incorrect severity threshold")
			}
		})
	}

}
