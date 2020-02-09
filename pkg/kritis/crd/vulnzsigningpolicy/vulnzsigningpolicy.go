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

package vulnzsigningpolicy

import (
	"fmt"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/kubectl/plugins/resolve"
	metadata "github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/policy"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/vulnerability"
)

// ValidateFunc defines the type for Validating Image Security Policies
type ValidateFunc func(vsp v1beta1.VulnzSigningPolicy, image string, vulnz []metadata.Vulnerability) ([]policy.Violation, error)

// ValidateImageSecurityPolicy checks if an image satisfies ISP requirements
// It returns a list of vulnerabilities that don't pass
func ValidateVulnzSigningPolicy (vsp v1beta1.VulnzSigningPolicy, image string, vulnz []metadata.Vulnerability) ([]policy.Violation, error) {
	var violations []policy.Violation
	// Next, check if image is qualified
	if !resolve.FullyQualifiedImage(image) {
		violations = append(violations, Violation{
			vType:  policy.UnqualifiedImageViolation,
			reason: UnqualifiedImageReason(image),
		})
		return violations, nil
	}

	maxSev := vsp.Spec.PackageVulnerabilityRequirements.MaximumSeverity
	if maxSev == "" {
		maxSev = "CRITICAL"
	}

	maxNoFixSev := vsp.Spec.PackageVulnerabilityRequirements.MaximumFixUnavailableSeverity
	if maxNoFixSev == "" {
		maxNoFixSev = "ALLOW_ALL"
	}

	for _, v := range vulnz {
		// First, check if the vulnerability is in allowlist
		if cveInAllowlist(vsp, v.CVE) {
			continue
		}

		// Allow operators to set a higher threshold for CVE's that have no fix available.
		if !v.HasFixAvailable {
			ok, err := severityWithinThreshold(maxNoFixSev, v.Severity)
			if err != nil {
				return violations, err
			}
			if ok {
				continue
			}
			violations = append(violations, Violation{
				vulnerability: v,
				vType:         policy.FixUnavailableViolation,
				reason:        FixUnavailableReason(image, v, vsp),
			})
			continue
		}
		ok, err := severityWithinThreshold(maxSev, v.Severity)
		if err != nil {
			return violations, err
		}
		if ok {
			continue
		}
		violations = append(violations, Violation{
			vulnerability: v,
			vType:         policy.SeverityViolation,
			reason:        SeverityReason(image, v, vsp),
		})
	}
	return violations, nil
}

func cveInAllowlist(isp v1beta1.VulnzSigningPolicy, cve string) bool {
	for _, w := range isp.Spec.PackageVulnerabilityRequirements.AllowlistCVEs {
		if w == cve {
			return true
		}
	}
	return false
}

func severityWithinThreshold(maxSeverity string, severity string) (bool, error) {
	if maxSeverity == constants.BlockAll {
		return false, nil
	}
	if maxSeverity == constants.AllowAll {
		return true, nil
	}
	if _, ok := vulnerability.Severity_value[maxSeverity]; !ok {
		return false, fmt.Errorf("invalid max severity level: %s", maxSeverity)
	}
	if _, ok := vulnerability.Severity_value[severity]; !ok {
		return false, fmt.Errorf("invalid severity level: %s", severity)
	}
	return vulnerability.Severity_value[severity] <= vulnerability.Severity_value[maxSeverity], nil
}
