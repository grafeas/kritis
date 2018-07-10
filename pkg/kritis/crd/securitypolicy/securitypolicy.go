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
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	ca "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// ImageSecurityPolicies returns all ISP's in the specified namespaces
// Pass in an empty string to get all ISPs in all namespaces
func ImageSecurityPolicies(namespace string) ([]v1beta1.ImageSecurityPolicy, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		return nil, fmt.Errorf("error building config: %v", err)
	}

	client, err := clientset.NewForConfig(cfg)
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
// It returns a list of vulnerabilites that don't pass
func ValidateImageSecurityPolicy(isp v1beta1.ImageSecurityPolicy, project, image string, client metadata.MetadataFetcher) ([]metadata.Vulnerability, error) {
	// First, check if image is whitelisted
	if imageInWhitelist(isp, image) {
		return nil, nil
	}
	// Now, check vulnz in the image
	vulnz, err := client.GetVulnerabilities(project, image)
	if err != nil {
		return nil, err
	}
	var violations []metadata.Vulnerability

	for _, v := range vulnz {
		// First, check if the vulnerability is whitelisted
		if cveInWhitelist(isp, v.CVE) {
			continue
		}
		// Check ifFixesNotAvailable
		if isp.Spec.PackageVulernerabilityRequirements.OnlyFixesNotAvailable && !v.HasFixAvailable {
			violations = append(violations, v)
			continue
		}
		// Next, see if the severity is below or at threshold
		if severityWithinThreshold(isp, v.Severity) {
			continue
		}
		// Else, add to list of CVEs in violation
		violations = append(violations, v)
	}
	return violations, nil
}

func imageInWhitelist(isp v1beta1.ImageSecurityPolicy, image string) bool {
	for _, i := range isp.ImageWhitelist {
		if i == image {
			return true
		}
	}
	return false
}

func cveInWhitelist(isp v1beta1.ImageSecurityPolicy, cve string) bool {
	for _, w := range isp.Spec.PackageVulernerabilityRequirements.WhitelistCVEs {
		if w == cve {
			return true
		}
	}
	return false
}

func severityWithinThreshold(isp v1beta1.ImageSecurityPolicy, severity string) bool {
	maxSeverity := isp.Spec.PackageVulernerabilityRequirements.MaximumSeverity
	if maxSeverity == constants.BLOCKALL {
		return false
	}
	return ca.VulnerabilityType_Severity_value[severity] <= ca.VulnerabilityType_Severity_value[maxSeverity]
}
