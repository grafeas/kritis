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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"math/big"
)

type pkixSigner struct {
	PrivateKey         interface{}
	PublicKeyID        string
	SignatureAlgorithm SignatureAlgorithm
}

// NewPkixSigner creates a Signer interface for PKIX Attestations. `privateKey`
// contains the PEM-encoded private key. `publicKeyID` is the ID of the public
// key that can verify the Attestation signature.
func NewPkixSigner(privateKey []byte, publicKeyID string, alg SignatureAlgorithm) (Signer, error) {
	der, rest := pem.Decode(privateKey)

	if len(rest) != 0 {
		return nil, errors.New("expected one public key")
	}

	key, err := x509.ParsePKCS8PrivateKey(der.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "some err")
	}

	// If no ID id provided one is computed based on the default digest-based URI extracted from the public key material
	if len(publicKeyID) == 0 {
		var publicKeyMaterial []byte
		switch key.(type) {
		case *rsa.PrivateKey:
			privKey := key.(*rsa.PrivateKey)
			publicKeyMaterial, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			if err != nil {
				return nil, errors.Wrap(err, "some err")
			}
		case *ecdsa.PrivateKey:
			privKey := key.(*ecdsa.PrivateKey)
			publicKeyMaterial, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			if err != nil {
				return nil, errors.Wrap(err, "some err")
			}
		default:
			return nil, errors.New("unexpected key type")
		}
		dgst := sha256.Sum256(publicKeyMaterial)
		base64Dgst := base64.RawURLEncoding.EncodeToString(dgst[:])
		publicKeyID = fmt.Sprintf("ni:///sha-256;%s", base64Dgst)
	}
	return &pkixSigner{
		PrivateKey:         key,
		PublicKeyID:        publicKeyID,
		SignatureAlgorithm: alg,
	}, nil
}

// CreateAttestation creates a signed PKIX Attestation. See Signer for more details.
func (s *pkixSigner) CreateAttestation(payload []byte) (*Attestation, error) {
	switch s.SignatureAlgorithm {
	case RsaSignPkcs12048Sha256, RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256, RsaSignPkcs14096Sha512:
		hash, hashedPayload, err := hashPayload(payload, s.SignatureAlgorithm)
		if err != nil {
			return nil, errors.Wrap(err, "some err")
		}
		signature, err := rsa.SignPKCS1v15(rand.Reader, s.PrivateKey.(*rsa.PrivateKey), hash, hashedPayload[:])
		if err != nil {
			return nil, errors.Wrap(err, "some err")
		}
		return &Attestation{
			PublicKeyID:       s.PublicKeyID,
			Signature:         signature,
			SerializedPayload: hashedPayload,
		}, nil
	case RsaPss2048Sha256, RsaPss3072Sha256, RsaPss4096Sha256, RsaPss4096Sha512:
		hash, hashedPayload, err := hashPayload(payload, s.SignatureAlgorithm)
		if err != nil {
			return nil, errors.Wrap(err, "some err")
		}
		signature, err := rsa.SignPSS(rand.Reader, s.PrivateKey.(*rsa.PrivateKey), hash, hashedPayload[:], nil)
		if err != nil {
			return nil, errors.Wrap(err, "some err")
		}
		return &Attestation{
			PublicKeyID:       s.PublicKeyID,
			Signature:         signature,
			SerializedPayload: payload,
		}, nil
	case EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512:
		var sigStruct struct {
			R, S *big.Int
		}
		_, hashedPayload, err := hashPayload(payload, s.SignatureAlgorithm)
		if err != nil {
			return nil, errors.Wrap(err, "some err")
		}
		sigStruct.R, sigStruct.S, err = ecdsa.Sign(rand.Reader, s.PrivateKey.(*ecdsa.PrivateKey), hashedPayload[:])
		if err != nil {
			return nil, errors.Wrap(err, "some err")
		}
		signature, err := asn1.Marshal(sigStruct)
		if err != nil {
			return nil, errors.Wrap(err, "some err")
		}
		return &Attestation{
			PublicKeyID:       s.PublicKeyID,
			Signature:         signature,
			SerializedPayload: payload,
		}, nil
	default:
		return nil, errors.New("unknown signature algorithm")

	}
}
