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

const (
	UnqualifiedImageViolation = iota
	FixesAvailableViolation
	ExceedsMaxSeverityViolation
)

type SecurityPolicyViolation struct {
	Vulnerability metadata.Vulnerability
	Violation     int
	Reason        string
}

func UnqualifiedImageViolationReason(image string) string {
	return fmt.Sprintf("%s is not a fully qualified image", image)
}

func FixesAvailableViolationReason(image string, vulnz metadata.Vulnerability) string {
	return fmt.Sprintf("found CVE %s in %s which has fixes available", vulnz.CVE, image)
}

func ExceedsMaxSeverityViolationReason(image string, vulnz metadata.Vulnerability, isp v1beta1.ImageSecurityPolicy) string {
	maxSeverity := isp.Spec.PackageVulernerabilityRequirements.MaximumSeverity
	if maxSeverity == constants.BLOCKALL {
		return fmt.Sprintf("found CVE %s in %s which isn't whitelisted, violating max severity %s",
			vulnz.CVE, image, maxSeverity)
	}
	return fmt.Sprintf("found CVE %s in %s, which has severity %s exceeding max severity %s", vulnz.CVE, image,
		vulnz.Severity, maxSeverity)
}
