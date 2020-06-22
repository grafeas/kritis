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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type VulnzSigningPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec VulnzSigningPolicySpec `json:"spec"`
}

// v is the spec for a BuildPolicy resource
type VulnzSigningPolicySpec struct {
	Project                        string                         `json:"project"`
	NoteReference                  string                         `json:"noteReference"`
	ImageVulnerabilityRequirements ImageVulnerabilityRequirements `json:"imageVulnerabilityRequirements"`
}

// ImageVulnerabilityRequirements is the vulnerability requirements of an image for an VulnzSigningPolicy
type ImageVulnerabilityRequirements struct {
	// CVE's with fixes.
	MaximumFixableSeverity string `json:"maximumFixableSeverity"`
	// CVE's without fixes.
	MaximumUnfixableSeverity string   `json:"maximumUnfixableSeverity"`
	AllowlistCVEs            []string `json:"allowlistCVEs"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VulnzSigningPolicyList is a list of VulnzSigningPolicy resources
type VulnzSigningPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []VulnzSigningPolicy `json:"items"`
}
