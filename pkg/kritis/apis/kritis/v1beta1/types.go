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

	Spec                 ImageSecurityPolicySpec `json:"spec"`
	RequiredAttestations []string                `json:"requiredAttestations"`
	ImageWhitelist       []string                `json:"imageWhitelist"`
}

// PackageVulernerabilityRequirements is the requirements for package vulnz for an ImageSecurityPolicy
type PackageVulernerabilityRequirements struct {
	MaximumSeverity       string   `json:"maximumSeverity"`
	OnlyFixesNotAvailable bool     `json:"onlyFixesNotAvailable"`
	WhitelistCVEs         []string `json:"whitelistCVEs"`
}

// ImageSecurityPolicy is the spec for a ImageSecurityPolicy resource
type ImageSecurityPolicySpec struct {
	PackageVulernerabilityRequirements PackageVulernerabilityRequirements `json:"packageVulnerabilityRequirements"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ImageSecurityPolicy is a list of ImageSecurityPolicy resources
type ImageSecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ImageSecurityPolicy `json:"items"`
}
