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
	"reflect"
	"sort"
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
				Vulnz: []metadata.Vulnerability{{CVE: "m", Severity: test.cveSeverity, HasFixAvailable: true}},
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
			Reason:        UnqualifiedImageReason(""),
		},
	}
	testutil.CheckErrorAndDeepEqual(t, false, err, violations, expected)
}

func Test_SeverityThresholds(t *testing.T) {
	mc := &testutil.MockMetadataClient{
		Vulnz: []metadata.Vulnerability{
			{CVE: "l", Severity: "LOW", HasFixAvailable: true},
			{CVE: "l_nofix", Severity: "LOW", HasFixAvailable: false},
			{CVE: "m", Severity: "MEDIUM", HasFixAvailable: true},
			{CVE: "m_nofix", Severity: "MEDIUM", HasFixAvailable: false},
			{CVE: "h", Severity: "HIGH", HasFixAvailable: true},
			{CVE: "h_nofix", Severity: "HIGH", HasFixAvailable: false},
			{CVE: "c", Severity: "CRITICAL", HasFixAvailable: true},
			{CVE: "c_nofix", Severity: "CRITICAL", HasFixAvailable: false},
		},
	}
	var tests = []struct {
		name                      string
		maxSeverity               string
		maxFixUnavailableSeverity string
		want                      []string
	}{
		{"default to allow all", "", "", []string{}},
		{"critical", "CRITICAL", "", []string{}}, // same as allow all.
		{"high", "HIGH", "", []string{"c"}},
		{"medium", "MEDIUM", "", []string{"h", "c"}},
		{"low", "LOW", "", []string{"m", "h", "c"}},
		{"block all", "BLOCK_ALL", "", []string{"l", "m", "h", "c"}},
		{"block all fixable, but allow all unfixable", "BLOCK_ALL", "ALLOW_ALL", []string{"l", "m", "h", "c"}},
		{"explicit allow all", "ALLOW_ALL", "", []string{}},
		{"allow all but unfixable", "ALLOW_ALL", "BLOCK_ALL", []string{"l_nofix", "m_nofix", "h_nofix", "c_nofix"}},
		{"medium fixable + high unfixable", "MEDIUM", "HIGH", []string{"h", "c", "c_nofix"}},
		{"high fixable + medium unfixable", "HIGH", "MEDIUM", []string{"c", "c_nofix", "h_nofix"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isp := v1beta1.ImageSecurityPolicy{
				Spec: v1beta1.ImageSecurityPolicySpec{
					PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
						MaximumSeverity:               test.maxSeverity,
						MaximumFixUnavailableSeverity: test.maxFixUnavailableSeverity,
					},
				},
			}
			vs, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mc)
			if err != nil {
				t.Errorf("%s: error validating isp: %v", test.name, err)
			}
			got := []string{}
			for _, v := range vs {
				got = append(got, v.Vulnerability.CVE)
			}
			sort.Strings(got)
			sort.Strings(test.want)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("%s: got %s, want %s", test.name, got, test.want)
			}
		})
	}
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
func Test_OnlyFixesNotAvailablePassWithWhitelist(t *testing.T) {
	isp := v1beta1.ImageSecurityPolicy{
		Spec: v1beta1.ImageSecurityPolicySpec{
			PackageVulnerabilityRequirements: v1beta1.PackageVulnerabilityRequirements{
				MaximumSeverity:               "CRITICAL",
				MaximumFixUnavailableSeverity: "BLOCK_ALL",
				WhitelistCVEs:                 []string{"c"},
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
