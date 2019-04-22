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
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/policy"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
)

type returnNilAttestorFetcher struct{}

func (a returnNilAttestorFetcher) GetAttestor(name string) (*Attestor, error) {
	return nil, nil
}

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
			violations, err := ValidateImageSecurityPolicy(
				isp, testutil.QualifiedImage, mc, returnNilAttestorFetcher{})
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
	violations, err := ValidateImageSecurityPolicy(isp, "", &testutil.MockMetadataClient{}, returnNilAttestorFetcher{})
	expected := []policy.Violation{}
	expected = append(expected, Violation{
		vType:  policy.UnqualifiedImageViolation,
		reason: UnqualifiedImageReason(""),
	})
	testutil.CheckErrorAndDeepEqual(t, false, err, expected, violations)
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
			vs, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mc, returnNilAttestorFetcher{})
			if err != nil {
				t.Errorf("%s: error validating isp: %v", test.name, err)
			}
			got := []string{}
			for _, v := range vs {
				vuln := v.Details().(metadata.Vulnerability)
				got = append(got, vuln.CVE)
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
	violations, err := ValidateImageSecurityPolicy(isp, "image", mc, returnNilAttestorFetcher{})
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
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mc, returnNilAttestorFetcher{})
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
	violations, err := ValidateImageSecurityPolicy(isp, testutil.QualifiedImage, mc, returnNilAttestorFetcher{})
	if err != nil {
		t.Errorf("error validating isp: %v", err)
	}
	if violations != nil {
		t.Errorf("got unexpected violations: %v", violations)
	}
}

func Test_BuiltProjectIDs(t *testing.T) {
	type subCase struct {
		name            string
		buildProvenance *metadata.BuildProvenance
		hasViolation    bool
	}

	var cases = []struct {
		name            string
		builtProjectIDs []string
		subCases        []subCase
	}{
		{
			"ISP has 1 buildProjectIDs",
			[]string{"kritis-p-1"},
			[]subCase{
				{
					"should have a build projectID violation",
					nil,
					true,
				},
				{
					"allowed with correct build projectID",
					&metadata.BuildProvenance{
						ProjectID: "kritis-p-1",
						Creator:   "kritis-p-1@example.com",
					},
					false,
				},
			},
		},
		{
			"ISP has 2 buildProjectIDs",
			[]string{"kritis-p-1", "kritis-p-2"},
			[]subCase{
				{
					"should have a build projectID violation",
					nil,
					true,
				},
				{
					"allowed with correct build projectID (1)",
					&metadata.BuildProvenance{
						ProjectID: "kritis-p-1",
						Creator:   "kritis-p-1@example.com",
					},
					false,
				},
				{
					"allowed with correct build projectID (2)",
					&metadata.BuildProvenance{
						ProjectID: "kritis-p-2",
						Creator:   "kritis-p-2@example.com",
					},
					false,
				},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			isp := v1beta1.ImageSecurityPolicy{
				Spec: v1beta1.ImageSecurityPolicySpec{
					BuiltProjectIDs: c.builtProjectIDs,
				},
			}
			for _, sc := range c.subCases {
				t.Run(sc.name, func(t *testing.T) {
					builds := []metadata.Build{}
					if sc.buildProvenance != nil {
						builds = append(builds, metadata.Build{
							Provenance: sc.buildProvenance,
						})
					}
					mc := &testutil.MockMetadataClient{
						Build: builds,
					}
					violations, err := ValidateImageSecurityPolicy(
						isp, testutil.QualifiedImage, mc, returnNilAttestorFetcher{})
					if err != nil {
						t.Errorf("error validating isp: %v", err)
					}
					if sc.hasViolation {
						if len(violations) != 1 {
							t.Errorf("should have a violation")
						}
					} else {
						if violations != nil {
							t.Errorf("got unexpected violations: %v", violations)
						}
					}
				})
			}
		})
	}
}

type testAttestorFetcher struct {
	getAttestor func(name string) (*Attestor, error)
}

func (f *testAttestorFetcher) GetAttestor(name string) (*Attestor, error) {
	return f.getAttestor(name)
}

func newTestAttestorFetcher(getAttestor func(name string) (*Attestor, error)) AttestorFetcher {
	return &testAttestorFetcher{
		getAttestor: getAttestor,
	}
}

func Test_RequireAttestationsBy(t *testing.T) {
	// TODO: implement
	t.Log("TODO: implement")

	cases := []struct {
		name            string
		hasError        bool
		hasViolation    bool
		getAttestorFunc func(name string) (*Attestor, error)
	}{
		{
			"attestorFetcher returns error",
			true,
			false,
			func(name string) (*Attestor, error) {
				return nil, errors.New("failed to get attestor")
			},
		},
		{
			"attestor not found",
			true,
			false,
			func(name string) (*Attestor, error) {
				return nil, nil
			},
		},
		{
			"attestor exists",
			false,
			false,
			func(name string) (*Attestor, error) {
				if name != "projects/kritis-attestor-p-1/attestors/kritis-required-attestor-1" {
					return nil, nil
				}

				return &Attestor{
					Name: "attestor-1",
					PublicKeys: []*AttestorPublicKey{
						{
							ID:         testutil.PgpKeyFingerprint,
							AsciiArmor: testutil.Base64PublicTestKey(t),
						},
					},
				}, nil
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			isp := v1beta1.ImageSecurityPolicy{
				Spec: v1beta1.ImageSecurityPolicySpec{
					BuiltProjectIDs:       []string{"kritis-p-1"},
					RequireAttestationsBy: []string{"projects/kritis-attestor-p-1/attestors/kritis-required-attestor-1"},
				},
			}
			mc := &testutil.MockMetadataClient{
				Build: []metadata.Build{
					{
						Provenance: &metadata.BuildProvenance{
							ProjectID: "kritis-p-1",
							Creator:   "kritis-p-1@example.com",
						},
					},
				},
				PGPAttestations: []metadata.PGPAttestation{
					{
						KeyID:     testutil.PgpKeyFingerprint,
						Signature: goodImageSignature,
					},
				},
			}

			violations, err := ValidateImageSecurityPolicy(
				isp,
				goodImage,
				mc,
				newTestAttestorFetcher(c.getAttestorFunc),
			)

			if c.hasError {
				if err == nil {
					t.Error("error expected, but no error")
				}
			} else {
				if err != nil {
					t.Errorf("error validating isp: %v", err)
				}
				if c.hasViolation {
					if len(violations) != 1 {
						t.Errorf("should have a violation")
					}
				} else {
					if violations != nil {
						t.Errorf("got unexpected violations: %v", violations)
					}
				}
			}
		})
	}
}

// from pkg/kritis/container/container_test.go
var (
	goodImage          = "gcr.io/kritis-project/kritis-server@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8"
	goodImageSignature = `-----BEGIN PGP MESSAGE-----

owGbwMvMwMW4rjtzimCy6GLG0we0kxiik31OVislF2WWZCYn5ihZVStlpqTmlWSW
VILYKfnJ2alFukWpaalFqXnJqUpWSunJRXqZ+frZIB3FugVF+VmpySUwbnFqUVlq
kVKtjlJmbmJ6KpIRuYl5mWmpxSW6KZnpQApoUHFGopGpmVWScZpxanJyWoqRebKl
hZmJsaFRYpqxuaWZgZl5qnlKkpGFgYF5oqGpmVmqYaqBiVGyqYWZUWpqinFammGS
UbIFyLKSygKQ0xJL8nMzkxWS8/NKEjPzUosUijPT8xJLSotSlWprOxmPsDAwcjHo
iSmyXGpe+vXr1zer5n1sPQoLDlYmUFAIyJQAXecA8Y5eflE6AxenAEzJi+fc/wMy
C8UP8S9ZvsB5Wvg35SX6S+XSWvP1jq/aJ/zOYkedhuGRoAuep/nkcvZkBPXstFZi
c3rspd9w6KC7kG9v7574Y+1XsvmP/LkcXSX9sqFw7dnfEydU+y4xfv/lS92pS38W
v2O6fVA13XXB6qedMXKrF2jouu+el32nYLHlu/AKqfS+vwcmCPexrj+Rd3P9VoG4
KcmrVJuelizOnzXVaZWOUsBpjuRXz3xW+4lNXrFtYcSTjhVR8pMM43WE+eeU3X+X
6RG4ue3MfZmblifbT3RXiF6c+mJy5g/zNAkdth0fQoI9FpV/sVk8/UTGBeYJf+2Y
I7Nkpp34OunBiqi3dXady5wM1eralue8OcFaVhIRVLKt2Kpvc2HG+50/eVNZCgJe
7VLoW5Ypm/1X7e6JMCODVQ/WqMyIYllm5z/zY6iUX5UW76ygqtdT5lndbBKt3CN5
n2HdhN2nqz4+uhG7Um+VVGT1yQKzn8uu+HBfvat3LVHv09ETQu1C15qmZvayuV1i
1lLxOcT0b/3XN22f7k4X81b7rgYA
=eOFW
-----END PGP MESSAGE-----`
)
