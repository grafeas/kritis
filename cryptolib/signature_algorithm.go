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

type (
	SignatureAlgorithm int
	keyMode            int
)

// Enumeration of SignatureAlgorithm
const (
	// PKIX Signing Algorithms
	//
	// RSASSA-PSS 2048 bit key with a SHA256 digest.
	PkixRsaPss2048Sha256 SignatureAlgorithm = iota
	// RSASSA-PSS 3072 bit key with a SHA256 digest.
	PkixRsaPss3072Sha256
	// RSASSA-PSS 4096 bit key with a SHA256 digest.
	PkixRsaPss4096Sha256
	// RSASSA-PSS 4096 bit key with a SHA512 digest.
	PkixRsaPss4096Sha512

	// RSASSA-PKCS1-v1_5 with a 2048 bit key and a SHA256 digest.
	PkixRsaSignPkcs12048Sha256
	// RSASSA-PKCS1-v1_5 with a 3072 bit key and a SHA256 digest.
	PkixRsaSignPkcs13072Sha256
	// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA256 digest.
	PkixRsaSignPkcs14096Sha256
	// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA512 digest.
	PkixRsaSignPkcs14096Sha512

	// ECDSA on the NIST P-256 curve with a SHA256 digest.
	PkixEcdsaP256Sha256
	// ECDSA on the NIST P-384 curve with a SHA384 digest.
	PkixEcdsaP384Sha384
	// ECDSA on the NIST P-521 curve with a SHA512 digest.
	PkixEcdsaP521Sha512

	// PGP Signing Algorithms
	//
	// RSASSA-PKCS1-v1_5 with a 2048 bit key and a SHA256 digest.
	PgpRsaSignPkcs12048Sha256
	// RSASSA-PKCS1-v1_5 with a 3072 bit key and a SHA256 digest.
	PgpRsaSignPkcs13072Sha256
	// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA256 digest.
	PgpRsaSignPkcs14096Sha256
	// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA512 digest.
	PgpRsaSignPkcs14096Sha512

	// JWT Signing Algorithms
	//
	// RSASSA-PSS 2048 bit key with a SHA256 digest.
	JwtRsaPss2048Sha256
	// RSASSA-PSS 3072 bit key with a SHA256 digest.
	JwtRsaPss3072Sha256
	// RSASSA-PSS 4096 bit key with a SHA256 digest.
	JwtRsaPss4096Sha256
	// RSASSA-PSS 4096 bit key with a SHA512 digest.
	JwtRsaPss4096Sha512

	// RSASSA-PKCS1-v1_5 with a 2048 bit key and a SHA256 digest.
	JwtRsaSignPkcs12048Sha256
	// RSASSA-PKCS1-v1_5 with a 3072 bit key and a SHA256 digest.
	JwtRsaSignPkcs13072Sha256
	// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA256 digest.
	JwtRsaSignPkcs14096Sha256
	// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA512 digest.
	JwtRsaSignPkcs14096Sha512

	// ECDSA on the NIST P-256 curve with a SHA256 digest.
	JwtEcdsaP256Sha256
	// ECDSA on the NIST P-384 curve with a SHA384 digest.
	JwtEcdsaP384Sha384
	// ECDSA on the NIST P-521 curve with a SHA512 digest.
	JwtEcdsaP521Sha512

	UnknownSigningAlgorithm
)

const (
	UnknownKeyMode keyMode = iota
	Pgp
	Pkix
	Jwt
)

func (sa SignatureAlgorithm) keyMode() keyMode {
	switch {
	case sa >= PkixRsaPss2048Sha256 && sa < PgpRsaSignPkcs14096Sha512:
		return Pkix
	case sa >= PgpRsaSignPkcs14096Sha512 && sa < JwtRsaPss2048Sha256:
		return Pgp
	case sa >= JwtRsaPss2048Sha256 && sa < UnknownSigningAlgorithm:
		return Jwt
	}
	return UnknownKeyMode
}
