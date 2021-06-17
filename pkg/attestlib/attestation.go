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

package attestlib

// Attestation represents an unauthenticated attestation, stripped of information
// specific to the wire format. An Attestation can only be trusted after
// successfully verifying its Signature.
//
// Each Attestation contains one signature. It can store signatures generated
// by PGP or PKIX keys, or it can store an attestation represented as a JWT.
type Attestation struct {
	// PublicKeyID is the ID of the public key that can verify the Attestation.
	PublicKeyID string
	// Signature stores the signature content for the Attestation. For PKIX,
	// this is only the raw signature. For PGP, this is an attached signature,
	// containing both the signature and message payload. For JWT, this is a
	// signed and serialized JWT.
	Signature []byte
	// SerializedPayload stores the payload over which the signature was
	// signed. This field is only used for PKIX Attestations.
	SerializedPayload []byte
}
