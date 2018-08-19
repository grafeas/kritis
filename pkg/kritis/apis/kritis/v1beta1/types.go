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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ImageSecurityPolicy is a specification for a ImageSecurityPolicy resource
type ImageSecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ImageSecurityPolicySpec `json:"spec"`
}

// PackageVulnerabilityRequirements is the requirements for package vulnz for an ImageSecurityPolicy
type PackageVulnerabilityRequirements struct {
	// CVE's with fixes.
	MaximumSeverity string `json:"maximumSeverity"`
	// CVE's without fixes.
	MaximumFixUnavailableSeverity string   `json:"maximumFixNotAvailableSeverity"`
	WhitelistCVEs                 []string `json:"whitelistCVEs"`
}

// ImageSecurityPolicy is the spec for a ImageSecurityPolicy resource
type ImageSecurityPolicySpec struct {
	ImageWhitelist                   []string                         `json:"imageWhitelist"`
	PackageVulnerabilityRequirements PackageVulnerabilityRequirements `json:"packageVulnerabilityRequirements"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ImageSecurityPolicyList is a list of ImageSecurityPolicy resources
type ImageSecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ImageSecurityPolicy `json:"items"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BuildPolicy is a specification for a BuildPolicy resource
type BuildPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec BuildPolicySpec `json:"spec"`
}

// BuildPolicySpec is the spec for a BuildPolicy resource
type BuildPolicySpec struct {
	AttestationAuthorityName string `yaml:"attestationAuthorityName"`
	BuildRequirements        struct {
		BuiltFrom string `yaml:"builtFrom"`
	} `yaml:"buildRequirements"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BuildPolicyList is a list of BuildPolicy resources
type BuildPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []BuildPolicy `json:"items"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AttestationAuthority struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AttestationAuthoritySpec `json:"spec"`
}

// AttestationAuthoritySpec is the spec for a AttestationAuthority resource
type AttestationAuthoritySpec struct {
	NoteReference        string `json:"noteReference"`
	PrivateKeySecretName string `json:"privateKeySecretName"`
	PublicKeyData        string `json:"publicKeyData"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AttestationAuthorityList is a list of AttestationAuthority resources
type AttestationAuthorityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []AttestationAuthority `json:"items"`
}
