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

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// PublicKey stores public key material for all key types.
type PublicKey struct {
	// AuthenticatorType indicates the transport format of the Attestation this
	// key verifies, one of Pgp, Pkix, or Jwt.
	AuthenticatorType AuthenticatorType
	// Signature Algorithm holds the signing and padding algorithm for the signature.
	SignatureAlgorithm SignatureAlgorithm
	// KeyData holds the raw key material which can verify a signature.
	KeyData []byte
	// ID uniquely identifies this public key. For PGP, this should be the
	// OpenPGP RFC4880 V4 fingerprint of the key. For PKIX and JWT, this should
	// be a StringOrURI: it must either not contain ":" or be a valid URI.
	ID string
}

// NewPublicKey creates a new PublicKey.
// `authenticatorType` indicates the transport format of the Attestation this
// PublicKey verifies, one of Pgp, Pkix or Jwt.
// `keyData` contains the raw key material.
// `keyID` contains a unique identifier for the public key. For PGP, this field
// should be left blank. The ID will be the OpenPGP RFC4880 V4 fingerprint of
// the key. For PKIX and JWT, this may be left blank, and the ID  will be
// generated based on the DER encoding of the key. If not blank, the ID should
// be a StringOrURI: it must either not contain ":" or be a valid URI.
func NewPublicKey(authenticatorType AuthenticatorType, keyData []byte, keyID string) (*PublicKey, error) {
	newKeyID := ""
	switch authenticatorType {
	case Pgp:
		id, err := extractPgpKeyID(keyData)
		if err != nil {
			return nil, err
		}
		newKeyID = id
	case Pkix, Jwt:
		id, err := extractPkixKeyID(keyData, keyID)
		if err != nil {
			return nil, err
		}
		newKeyID = id
	default:
		return nil, fmt.Errorf("invalid AuthenticatorType")
	}

	return &PublicKey{
		AuthenticatorType: authenticatorType,
		KeyData:           keyData,
		ID:                newKeyID,
	}, nil
}

func extractPgpKeyID(keyData []byte) (string, error) {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(keyData))
	if err != nil {
		return "", fmt.Errorf("error reading armored public key: %v", err)
	}
	if len(keyring) != 1 {
		return "", fmt.Errorf("expected 1 public key, got %d", len(keyring))
	}
	return fmt.Sprintf("%X", keyring[0].PrimaryKey.Fingerprint), nil
}

func extractPkixKeyID(keyData []byte, keyID string) (string, error) {
	if (len(keyID) == 0){
		return generatePkixPublicKeyId(keyData)
	}
	if strings.Contains(keyID, ":") {
		_, err := url.ParseRequestURI(keyID)
		if err != nil {
			return "", fmt.Errorf("keyID %q not formatted as StringOrURI: must either not contain \":\" or be valid URI", keyID)
		}
	}
	return keyID, nil
}
