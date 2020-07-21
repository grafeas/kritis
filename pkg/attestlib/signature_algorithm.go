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

// SignatureAlgorithm specifies the algorithm and hashing functions used to
// sign PKIX and JWT Attestations.
type SignatureAlgorithm int

// Enumeration of SignatureAlgorithm
const (
	UnknownSigningAlgorithm SignatureAlgorithm = iota
	// RSASSA-PSS 2048 bit key with a SHA256 digest.
	RsaPss2048Sha256
	// RSASSA-PSS 3072 bit key with a SHA256 digest.
	RsaPss3072Sha256
	// RSASSA-PSS 4096 bit key with a SHA256 digest.
	RsaPss4096Sha256
	// RSASSA-PSS 4096 bit key with a SHA512 digest.
	RsaPss4096Sha512

	// RSASSA-PKCS1-v1_5 with a 2048 bit key and a SHA256 digest.
	RsaSignPkcs12048Sha256
	// RSASSA-PKCS1-v1_5 with a 3072 bit key and a SHA256 digest.
	RsaSignPkcs13072Sha256
	// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA256 digest.
	RsaSignPkcs14096Sha256
	// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA512 digest.
	RsaSignPkcs14096Sha512

	// ECDSA on the NIST P-256 curve with a SHA256 digest.
	EcdsaP256Sha256
	// ECDSA on the NIST P-384 curve with a SHA384 digest.
	EcdsaP384Sha384
	// ECDSA on the NIST P-521 curve with a SHA512 digest.
	EcdsaP521Sha512
	// Valid for PGP case
	PGPUnused
)

// AuthenticatorType specifies the transport format of the Attestation. It
// indicates to the Verifier how to extract the appropriate information out of
// an Attestation.
type AuthenticatorType int

// Enumeration of AuthenticatorType
const (
	UnknownAuthenticatorType AuthenticatorType = iota
	Pgp
	Pkix
	Jwt
)
