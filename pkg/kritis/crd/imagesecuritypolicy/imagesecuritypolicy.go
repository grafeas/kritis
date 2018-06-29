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
	"fmt"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	clientset "github.com/grafeas/kritis/pkg/kritis/client/clientset/versioned"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	ca "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

type ImageSecurityPolicy struct {
	v1beta1.ImageSecurityPolicy
}

// ImageSecurityPolicies returns all ISP's in all namespaces
func ImageSecurityPolicies() ([]ImageSecurityPolicy, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		return nil, fmt.Errorf("error building config: %v", err)
	}

	client, err := clientset.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("error building clientset: %v", err)
	}
	list, err := client.KritisV1beta1().ImageSecurityPolicies("").List(metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing all image policy requirements: %v", err)
	}
	ispList := []ImageSecurityPolicy{}
	for _, i := range list.Items {
		ispList = append(ispList, ImageSecurityPolicy{i})
	}
	return ispList, nil
}

// ValidateImageSecurityPolicy checks if an image satisfies ISP requirements
// It returns a list of vulnerabilites that don't pass
func (isp ImageSecurityPolicy) ValidateImageSecurityPolicy(project, image string, client metadata.MetadataFetcher) ([]metadata.Vulnerability, error) {
	// First, check if image is whitelisted
	if isp.imageInWhitelist(image) {
		return nil, nil
	}
	// Now, check vulnz in the image
	vulnz := client.GetVulnerabilities(project, image)
	var violations []metadata.Vulnerability

VulnzLoop:
	for _, v := range vulnz {
		// First, check if the vulnerability is whitelisted
		for _, w := range isp.Spec.PackageVulernerabilityRequirements.WhitelistCVEs {
			if w == v.CVE {
				continue VulnzLoop
			}
		}
		// Check ifFixesNotAvailable
		if isp.Spec.PackageVulernerabilityRequirements.OnlyFixesNotAvailable && !v.HasFixAvailable {
			violations = append(violations, v)
			continue VulnzLoop
		}
		// Next, see if the severity is below or at threshold
		if isp.severityWithinThreshold(v.Severity) {
			continue VulnzLoop
		}
		// Else, add to list of CVEs in violation
		violations = append(violations, v)
	}
	return violations, nil
}

func (isp ImageSecurityPolicy) imageInWhitelist(image string) bool {
	for _, i := range isp.ImageWhitelist {
		if i == image {
			return true
		}
	}
	return false
}

func (isp ImageSecurityPolicy) severityWithinThreshold(severity string) bool {
	maxSeverity := isp.Spec.PackageVulernerabilityRequirements.MaximumSeverity
	if maxSeverity == constants.BLOCKALL {
		return false
	}
	return ca.VulnerabilityType_Severity_value[severity] <= ca.VulnerabilityType_Severity_value[maxSeverity]
}
