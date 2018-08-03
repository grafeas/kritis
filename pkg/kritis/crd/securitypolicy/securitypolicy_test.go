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

package securitypolicy

import (
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
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

func (m mockMetadataClient) GetVulnerabilities(containerImage string) ([]metadata.Vulnerability, error) {
	return []metadata.Vulnerability{
		vulnz1,
		vulnz2,
	}, nil
}

func Test_ValidISP(t *testing.T) {
	isp := v1beta1.ImageSecurityPolicy{
		Spec: v1beta1.ImageSecurityPolicySpec{
			PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
				MaximumSeverity: "MEDIUM",
			},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mockMetadataClient{})
	if err != nil {
		t.Errorf("error validating isp: %v", err)
	}
	if violations != nil {
		t.Errorf("got unexpected violations: %v", violations)
	}
}

func Test_UnqualifiedImage(t *testing.T) {
	isp := v1beta1.ImageSecurityPolicy{
		Spec: v1beta1.ImageSecurityPolicySpec{
			PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
				MaximumSeverity: "MEDIUM",
			},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, "", mockMetadataClient{})
	expected := []SecurityPolicyViolation{
		{
			Vulnerability: metadata.Vulnerability{},
			Violation:     UnqualifiedImageViolation,
			Reason:        UnqualifiedImageViolationReason(""),
		},
	}
	testutil.CheckErrorAndDeepEqual(t, false, err, violations, expected)
}

func Test_BlockallPass(t *testing.T) {
	isp := v1beta1.ImageSecurityPolicy{
		Spec: v1beta1.ImageSecurityPolicySpec{
			PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
				MaximumSeverity: "BLOCKALL",
				WhitelistCVEs: []string{
					"cve1",
					"cve2",
				},
			},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mockMetadataClient{})
	if err != nil {
		t.Errorf("error validating isp: %v", err)
	}
	if violations != nil {
		t.Errorf("got unexpected violations: %v", violations)
	}
}

func Test_BlockallFail(t *testing.T) {
	isp := v1beta1.ImageSecurityPolicy{
		Spec: v1beta1.ImageSecurityPolicySpec{
			PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
				MaximumSeverity: "BLOCKALL",
				WhitelistCVEs: []string{
					"cve1",
				},
			},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mockMetadataClient{})
	expected := []SecurityPolicyViolation{
		{
			Vulnerability: vulnz2,
			Violation:     ExceedsMaxSeverityViolation,
			Reason:        ExceedsMaxSeverityViolationReason(testutil.QualifiedImage, vulnz2, isp),
		},
	}
	testutil.CheckErrorAndDeepEqual(t, false, err, violations, expected)
}

func Test_MaxSeverityFail(t *testing.T) {
	isp := v1beta1.ImageSecurityPolicy{
		Spec: v1beta1.ImageSecurityPolicySpec{
			PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
				MaximumSeverity: "LOW",
			},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mockMetadataClient{})
	expected := []SecurityPolicyViolation{
		{
			Vulnerability: vulnz2,
			Violation:     ExceedsMaxSeverityViolation,
			Reason:        ExceedsMaxSeverityViolationReason(testutil.QualifiedImage, vulnz2, isp),
		},
	}
	testutil.CheckErrorAndDeepEqual(t, false, err, violations, expected)
}

func Test_WhitelistedImage(t *testing.T) {
	isp := v1beta1.ImageSecurityPolicy{
		Spec: v1beta1.ImageSecurityPolicySpec{
			ImageWhitelist: []string{"image"},
			PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
				MaximumSeverity: "LOW",
			},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, "image", mockMetadataClient{})
	if err != nil {
		t.Errorf("error validating isp: %v", err)
	}
	if violations != nil {
		t.Errorf("got unexpected violations: %v", violations)
	}
}

func Test_WhitelistedCVEAboveSeverityThreshold(t *testing.T) {
	isp := v1beta1.ImageSecurityPolicy{
		Spec: v1beta1.ImageSecurityPolicySpec{
			ImageWhitelist: []string{"image"},
			PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
				MaximumSeverity: "LOW",
				WhitelistCVEs: []string{
					"cve2",
				},
			},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mockMetadataClient{})
	if err != nil {
		t.Errorf("error validating isp: %v", err)
	}
	if violations != nil {
		t.Errorf("got unexpected violations: %v", violations)
	}
}

func Test_OnlyFixesNotAvailableFail(t *testing.T) {
	isp := v1beta1.ImageSecurityPolicy{
		Spec: v1beta1.ImageSecurityPolicySpec{
			PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
				MaximumSeverity:       "LOW",
				OnlyFixesNotAvailable: true,
			},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mockMetadataClient{})
	expected := []SecurityPolicyViolation{
		{
			Vulnerability: vulnz2,
			Violation:     FixesNotAvailableViolation,
			Reason:        FixesNotAvailableViolationReason(testutil.QualifiedImage, vulnz2),
		},
	}
	testutil.CheckErrorAndDeepEqual(t, false, err, violations, expected)
}
func Test_OnlyFixesNotAvailablePassWithWhitelist(t *testing.T) {
	isp := v1beta1.ImageSecurityPolicy{
		Spec: v1beta1.ImageSecurityPolicySpec{
			PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
				MaximumSeverity:       "CRITICAL",
				OnlyFixesNotAvailable: true,
				WhitelistCVEs:         []string{"cve2"},
			},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mockMetadataClient{})
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
			isp := v1beta1.ImageSecurityPolicy{
				Spec: v1beta1.ImageSecurityPolicySpec{
					PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
						MaximumSeverity:       test.maxSeverity,
						OnlyFixesNotAvailable: true,
					},
				},
			}
			if severityWithinThreshold(isp, test.severity) != test.expected {
				t.Error("got incorrect severity threshold")
			}
		})
	}
}
