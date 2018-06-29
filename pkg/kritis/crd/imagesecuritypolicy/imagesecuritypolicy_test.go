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
	testutil.CheckErrorAndDeepEqual(t, false, err, nil, violations)
}

func Test_BlockallPass(t *testing.T) {

}

func Test_BlockallFail(t *testing.T) {

}

func Test_MaxSeverityPass(t *testing.T) {

}

func Test_MaxSeverityFail(t *testing.T) {

}

func Test_WhitelistedImage(t *testing.T) {

}
