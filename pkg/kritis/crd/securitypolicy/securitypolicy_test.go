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

func Test_ValidISP(t *testing.T) {
	var tests = []struct {
		name        string
		maxSeverity string
		cveSeverity string
		expectErr   bool
	}{
		{"ok", "MEDIUM", "MEDIUM", false},
		{"bad maxSeverity", "!", "MEDIUM", true},
		{"bad severity", "MEDIUM", "?", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isp := v1beta1.ImageSecurityPolicy{
				Spec: v1beta1.ImageSecurityPolicySpec{
					PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
						MaximumSeverity: test.maxSeverity,
					},
				},
			}
			mc := &testutil.MockMetadataClient{
				Vulnz: []metadata.Vulnerability{{CVE: "m", Severity: test.cveSeverity}},
			}
			violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mc)
			if test.expectErr {
				if err == nil {
					t.Errorf("%s: expected error, but got nil. violations: %+v", test.name, violations)
				}
				return
			}
			if err != nil {
				t.Errorf("%s: error validating isp: %v", test.name, err)
			}
			if violations != nil {
				t.Errorf("%s: got unexpected violations: %v", test.name, violations)
			}
		})
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
	violations, err := ValidateImageSecurityPolicy(isp, "", &testutil.MockMetadataClient{})
	expected := []Violation{
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
				WhitelistCVEs:   []string{"l", "m", "c"},
			},
		},
	}
	mc := &testutil.MockMetadataClient{
		Vulnz: []metadata.Vulnerability{
			{CVE: "l", Severity: "LOW"},
			{CVE: "m", Severity: "MEDIUM"},
			{CVE: "c", Severity: "CRITICAL"},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mc)
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
				WhitelistCVEs:   []string{"m"},
			},
		},
	}
	mc := &testutil.MockMetadataClient{
		Vulnz: []metadata.Vulnerability{{CVE: "l", Severity: "LOW"}},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mc)
	expected := []Violation{
		{
			Vulnerability: mc.Vulnz[0],
			Violation:     ExceedsMaxSeverityViolation,
			Reason:        ExceedsMaxSeverityViolationReason(testutil.QualifiedImage, mc.Vulnz[0], isp),
		},
	}
	testutil.CheckErrorAndDeepEqual(t, false, err, violations, expected)
}

func Test_MaxSeverityFail(t *testing.T) {
	isp := v1beta1.ImageSecurityPolicy{
		Spec: v1beta1.ImageSecurityPolicySpec{
			PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
				MaximumSeverity: "MEDIUM",
			},
		},
	}
	mc := &testutil.MockMetadataClient{
		Vulnz: []metadata.Vulnerability{
			{CVE: "l", Severity: "LOW"},
			{CVE: "m", Severity: "MEDIUM"},
			{CVE: "c", Severity: "CRITICAL"},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mc)
	expected := []Violation{
		{
			Vulnerability: mc.Vulnz[2],
			Violation:     ExceedsMaxSeverityViolation,
			Reason:        ExceedsMaxSeverityViolationReason(testutil.QualifiedImage, mc.Vulnz[2], isp),
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
	mc := &testutil.MockMetadataClient{
		Vulnz: []metadata.Vulnerability{{CVE: "l", Severity: "LOW"}},
	}
	violations, err := ValidateImageSecurityPolicy(isp, "image", mc)
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
				WhitelistCVEs:   []string{"c"},
			},
		},
	}
	mc := &testutil.MockMetadataClient{
		Vulnz: []metadata.Vulnerability{
			{CVE: "c", Severity: "CRITICAL"},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mc)
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
				MaximumSeverity:       "MEDIUM",
				OnlyFixesNotAvailable: true,
			},
		},
	}
	mc := &testutil.MockMetadataClient{
		Vulnz: []metadata.Vulnerability{
			{CVE: "l", Severity: "LOW", HasFixAvailable: true},
			{CVE: "lnofix", Severity: "LOW", HasFixAvailable: false},
			{CVE: "m", Severity: "MEDIUM", HasFixAvailable: true},
			{CVE: "mnofix", Severity: "MEDIUM", HasFixAvailable: false},
		},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mc)
	expected := []Violation{
		{
			Vulnerability: mc.Vulnz[1],
			Violation:     FixesNotAvailableViolation,
			Reason:        FixesNotAvailableViolationReason(testutil.QualifiedImage, mc.Vulnz[1]),
		},
		{
			Vulnerability: mc.Vulnz[3],
			Violation:     FixesNotAvailableViolation,
			Reason:        FixesNotAvailableViolationReason(testutil.QualifiedImage, mc.Vulnz[3]),
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
				WhitelistCVEs:         []string{"c"},
			},
		},
	}
	mc := &testutil.MockMetadataClient{
		Vulnz: []metadata.Vulnerability{{CVE: "c", Severity: "CRITICAL", HasFixAvailable: true}},
	}
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mc)
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
			name:        "test blockall max severity",
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
			got, err := severityWithinThreshold(test.maxSeverity, test.severity)
			if err != nil {
				t.Errorf("%s: severityWithinThreshold(%s, %s) encountered error: %v", test.maxSeverity, test.severity, test.name, err)
			}
			if got != test.expected {
				t.Errorf("%s: severityWithinThreshold(%s, %s) = %v, wanted %v", test.name, test.maxSeverity, test.severity, got, test.expected)
			}
		})
	}
}
