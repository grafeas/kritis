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
	"fmt"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	clientset "github.com/grafeas/kritis/pkg/kritis/client/clientset/versioned"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/kubectl/plugins/resolve"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/policy"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/vulnerability"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// ValidateFunc defines the type for Validating Image Security Policies
type ValidateFunc func(isp v1beta1.ImageSecurityPolicy, image string, client metadata.Fetcher) ([]policy.Violation, error)

// ImageSecurityPolicies returns all ISPs in the specified namespaces
// Pass in an empty string to get all ISPs in all namespaces
func ImageSecurityPolicies(namespace string) ([]v1beta1.ImageSecurityPolicy, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error building config: %v", err)
	}

	client, err := clientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error building clientset: %v", err)
	}
	list, err := client.KritisV1beta1().ImageSecurityPolicies(namespace).List(metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing all image policy requirements: %v", err)
	}
	return list.Items, nil
}

// ValidateImageSecurityPolicy checks if an image satisfies ISP requirements
// It returns a list of vulnerabilities that don't pass
func ValidateImageSecurityPolicy(isp v1beta1.ImageSecurityPolicy, image string, client metadata.Fetcher) ([]policy.Violation, error) {
	// First, check if image is whitelisted
	if imageInWhitelist(isp, image) {
		return nil, nil
	}
	var violations []policy.Violation
	// Next, check if image is qualified
	if !resolve.FullyQualifiedImage(image) {
		violations = append(violations, Violation{
			vType:  policy.UnqualifiedImageViolation,
			reason: UnqualifiedImageReason(image),
		})
		return violations, nil
	}
	// Now, check vulnz in the image
	vulnz, err := client.Vulnerabilities(image)
	if err != nil {
		return nil, err
	}
	maxSev := isp.Spec.PackageVulnerabilityRequirements.MaximumSeverity
	if maxSev == "" {
		maxSev = "CRITICAL"
	}

	maxNoFixSev := isp.Spec.PackageVulnerabilityRequirements.MaximumFixUnavailableSeverity
	if maxNoFixSev == "" {
		maxNoFixSev = "ALLOW_ALL"
	}

	for _, v := range vulnz {
		// First, check if the vulnerability is whitelisted
		if cveInWhitelist(isp, v.CVE) {
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
				reason:        FixUnavailableReason(image, v, isp),
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
			reason:        SeverityReason(image, v, isp),
		})
	}
	return violations, nil
}

func imageInWhitelist(isp v1beta1.ImageSecurityPolicy, image string) bool {
	for _, i := range isp.Spec.ImageWhitelist {
		if i == image {
			return true
		}
	}
	return false
}

func cveInWhitelist(isp v1beta1.ImageSecurityPolicy, cve string) bool {
	for _, w := range isp.Spec.PackageVulnerabilityRequirements.WhitelistCVEs {
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
