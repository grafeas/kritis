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

const (
	// Key Types
	PgpKeyType  = "PGP"
	PkixKeyType = "PKIX"
)

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
	NoteReference string      `json:"noteReference"`
	PublicKeys    []PublicKey `json:"publicKeys"`
}

// PublicKey stores key data used to verify Attestations.
type PublicKey struct {
	// KeyId is the ID of this public key (required for PKIX keys). For PKIX
	// keys, please use a RFC3986 conformant URI. For PGP keys, this field
	// should be the OpenPGP RFC4880 V4 fingerprint of the key or be left
	// blank. If left blank, KeyId will be computed as the key's OpenPGP
	// fingerprint.
	KeyId string `json:"keyId"`
	// KeyType is the type of this public key. It should be one of "PGP" or
	// "PKIX".
	KeyType string `json:"keyType"`
	// AsciiArmoredPgpPublicKey is the base64-encoded payload for a PGP public key. Provide
	// this directly as a string.
	AsciiArmoredPgpPublicKey string `json:"asciiArmoredPgpPublicKey,omitemtpy"`
	// DO NOT USE THIS FIELD: it is currently unsupported.
	// PkixPublicKey stores data for a PKIX public key.
	PkixPublicKey PkixPublicKey `json:"pkixPublicKey,omitempty"`
}

type PkixPublicKey struct {
	// PublicKeyPem is the payload for a PKIX public key. Provide this as a string.
	PublicKeyPem string `json:"publicKeyPem"`
	// TODO(acamadeo): After implementing PKIX key verification, provide the
	// supported algorithm options here.
	// SignatureAlgorithm is the type of algorithm that was used to generate
	// the signature.
	SignatureAlgorithm string `json:"signatureAlgorithm"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AttestationAuthorityList is a list of AttestationAuthority resources
type AttestationAuthorityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []AttestationAuthority `json:"items"`
}
