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
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/policy"
)

// Violation represents a vulnerability that violates an ISP
type Violation struct {
	vulnerability metadata.Vulnerability
	vType         policy.ViolationType
	reason        policy.Reason
}

func NewViolation(vulnz *metadata.Vulnerability, t policy.ViolationType, r policy.Reason) Violation {
	v := Violation{
		vType:  t,
		reason: r,
	}
	if vulnz != nil {
		v.vulnerability = *vulnz
	}
	return v
}

// Reason returns the reason
func (v Violation) Reason() policy.Reason {
	return v.reason
}

// Type returns the violation type
func (v Violation) Type() policy.ViolationType {
	return v.vType
}

// Details returns the detailed violation
func (v Violation) Details() interface{} {
	return v.vulnerability
}

// UnqualifiedImageReason returns a detailed reason if the image is unqualified
func UnqualifiedImageReason(image string) policy.Reason {
	return policy.Reason(fmt.Sprintf("%s is not a fully qualified image. You can run 'kubectl plugin resolve-tags' to qualify all images with a digest.", image))
}

// UnfixableSeverityViolationReason returns a detailed reason if an unfixable CVE exceeds max severity
func UnfixableSeverityViolationReason(image string, v metadata.Vulnerability, vsp v1beta1.VulnzSigningPolicy) policy.Reason {
	ms := vsp.Spec.ImageVulnerabilityRequirements.MaximumUnfixableSeverity
	if ms == constants.BlockAll {
		return policy.Reason(fmt.Sprintf("found unfixable CVE %s in %s which isn't in allowlist, violating max unfixable severity %s",
			v.CVE, image, ms))
	}
	return policy.Reason(fmt.Sprintf("found unfixable CVE %s in %s, which has severity %s exceeding max unfixable severity %s",
		v.CVE, image, v.Severity, ms))
}

// FixableSeverityViolationReason returns a detailed reason if a CVE exceeds max severity
func FixableSeverityViolationReason(image string, v metadata.Vulnerability, vsp v1beta1.VulnzSigningPolicy) policy.Reason {
	ms := vsp.Spec.ImageVulnerabilityRequirements.MaximumFixableSeverity
	if ms == constants.BlockAll {
		return policy.Reason(fmt.Sprintf("found fixable CVE %s in %s which isn't in allowlist, violating max fixable severity %s",
			v.CVE, image, ms))
	}
	return policy.Reason(fmt.Sprintf("found fixable CVE %s in %s, which has severity %s exceeding max fixable severity %s",
		v.CVE, image, v.Severity, ms))
}
