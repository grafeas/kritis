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

package cryptolib

import "errors"

// Verifier contains methods to validate an Attestation.
type Verifier interface {
	VerifyAttestation(att *Attestation, publicKey []byte, image string) error
}

type verifier struct{}

// NewVerifier creates a Verifier interface.
func NewVerifier() Verifier {
	return &verifier{}
}

// VerifyAttestation verifies whether an Attestation satisfies an
// AttestationAuthority's public key under an image.
func (v *verifier) VerifyAttestation(att *Attestation, publicKey []byte, image string) error {
	switch att.KeyMode {
	case Pkix:
		return verifyPkixAndCheckPayload(att, image)
	case Pgp:
		return verifyPgpAndCheckPayload(att, image)
	case Jwt:
		return verifyJwtAndCheckPayload(att, image)
	default:
		return errors.New("invalid key mode")
	}
}

// Unimplemented functions
func verifyPkixAndCheckPayload(att *Attestation, image string) error {
	return errors.New("verify not implemented")
}

func verifyPgpAndCheckPayload(att *Attestation, image string) error {
	return errors.New("verify not implemented")
}

func verifyJwtAndCheckPayload(att *Attestation, image string) error {
	return errors.New("verify not implemented")
}
