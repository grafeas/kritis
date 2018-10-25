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

package constants

const (
	// AllowAll is the value used to allow all images with CVEs, except for whitelisted CVEs
	AllowAll = "ALLOW_ALL"
	// BlockAll is the value used to block all images with CVEs, except for whitelisted CVEs
	BlockAll = "BLOCK_ALL"

	// InvalidImageSecPolicy is the key for labels and annotations
	InvalidImageSecPolicy = "kritis.grafeas.io/invalidImageSecPolicy"
	// InvalidImageSecPolicyLabelValue is the label used when an image has violated the Kritis security policy.
	InvalidImageSecPolicyLabelValue = "invalidImageSecPolicy"

	// ImageAttestation is the key for labels for indication attestaions.
	ImageAttestation = "kritis.grafeas.io/attestation"
	// NoAttestationsLabelValue is the annotation used when a pod has not been attested.
	NoAttestationsLabelValue = "notAttested"
	// PreviouslyAttestedLabelValue is the AttestationsAnnotation used when a pod has previously been attested.
	PreviouslyAttestedLabelValue = "attested"

	// Breakglass is the key for the breakglass annotation
	Breakglass = "kritis.grafeas.io/breakglass"

	// A list of annotation values

	// PreviouslyAttestedAnnotation is the annotation used when a pod has previously been attested.
	PreviouslyAttestedAnnotation = "Previously attested."

	// NoAttestationsAnnotation is the annotation used when a pod has not been attested.
	NoAttestationsAnnotation = "No valid attestations present. This pod will not be able to restart in future"

	// AtomicContainerSigType is the Atomic Container Signature type
	AtomicContainerSigType = "atomic container signature"

	// PrivateKey is the key name used for looking up the private key used for Attestation Secrets.
	PrivateKey = "private"
	// PublicKey is the key name used for looking up the public key used for Attestation Secrets.
	PublicKey = "public"

	// Constants for Metadata Library

	// PageSize is how many values to request per call to an external API service
	PageSize = int32(100)
	// ResourceURLPrefix is the root prefix which all container image URL's are based on.
	ResourceURLPrefix = "https://"

	// Constants relevant for the GCB event parser

	// CloudSourceRepoPattern is used to generate a build provenance source URL for a GCB image.
	CloudSourceRepoPattern = "https://source.developers.google.com/p/%s/r/%s%s"
)

var (
	// GlobalImageWhitelist is a list of images that are globally whitelisted
	// They should always pass the webhook check
	GlobalImageWhitelist = []string{"gcr.io/kritis-project/kritis-server",
		"gcr.io/kritis-project/preinstall",
		"gcr.io/kritis-project/postinstall",
		"gcr.io/kritis-project/predelete"}
)
