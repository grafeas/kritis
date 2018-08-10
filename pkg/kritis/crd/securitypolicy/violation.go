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
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
)

type Reason string

// A list of security policy violations
// TODO: Add Attestation checking violations
const (
	UnqualifiedImageViolation int = iota
	FixesNotAvailableViolation
	ExceedsMaxSeverityViolation
)

// Violation represents a vulnerability that violates an ISP
type Violation struct {
	Vulnerability metadata.Vulnerability
	Violation     int
	Reason        Reason
}

// UnqualifiedImageViolationReason returns a detailed reason if the image is unqualified
func UnqualifiedImageViolationReason(image string) Reason {
	return Reason(fmt.Sprintf("%s is not a fully qualified image", image))
}

// FixesAvailableViolationReason returns a detailed reason if a CVE doesn't have a fix available
func FixesNotAvailableViolationReason(image string, vulnz metadata.Vulnerability) Reason {
	return Reason(fmt.Sprintf("found CVE %s in %s which has fixes available", vulnz.CVE, image))
}

// ExceedsMaxSeverityViolationReason returns a detailed reason if a CVE exceeds max severity
func ExceedsMaxSeverityViolationReason(image string, vulnz metadata.Vulnerability, isp v1beta1.ImageSecurityPolicy) Reason {
	maxSeverity := isp.Spec.PackageVulnerabilityRequirements.MaximumSeverity
	if maxSeverity == constants.BLOCKALL {
		return Reason(fmt.Sprintf("found CVE %s in %s which isn't whitelisted, violating max severity %s",
			vulnz.CVE, image, maxSeverity))
	}
	return Reason(fmt.Sprintf("found CVE %s in %s, which has severity %s exceeding max severity %s", vulnz.CVE, image,
		vulnz.Severity, maxSeverity))
}
