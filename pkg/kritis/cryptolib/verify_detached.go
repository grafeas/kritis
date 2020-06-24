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

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"github.com/pkg/errors"
	"math/big"
)

func hashPayload(payload []byte, signingAlg SignatureAlgorithm) (crypto.Hash, []byte, error) {
	switch signingAlg {
	case RsaSignPkcs12048Sha256, RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256, RsaPss2048Sha256, RsaPss3072Sha256, RsaPss4096Sha256, EcdsaP256Sha256:
		hashedPayload := sha256.Sum256(payload)
		return crypto.SHA256, hashedPayload[:], nil
	case EcdsaP384Sha384:
		hashedPayload := sha512.Sum384(payload)
		return crypto.SHA384, hashedPayload[:], nil
	case RsaSignPkcs14096Sha512, RsaPss4096Sha512, EcdsaP521Sha512:
		hashedPayload := sha512.Sum512(payload)
		return crypto.SHA512, hashedPayload[:], nil
	default:
		return 0, nil, errors.New("invalid signature algorithm")
	}
}

// This function will be used to verify PKIX and JWT signatures. PGP detached signatures are not supported by this function.
// Signature is the raw byte signature.
// PublicKey is the PEM encoded public key that will be used to verify the signature.
// Payload is the plaintext that was hashed and then signed.
func verifyDetached(signature []byte, publicKey []byte, signingAlg SignatureAlgorithm, payload []byte) error {
	// Decode public key to der and parse for key type.
	// This is needed to create PublicKey type needed for the verify functions.
	der, rest := pem.Decode(publicKey)
	if der == nil {
		return errors.New("failed to decode PEM")
	}
	if !bytes.Equal(rest, []byte("")) {
		return errors.New("more than one public key given")
	}
	pub, err := x509.ParsePKIXPublicKey(der.Bytes)
	if err != nil {
		return errors.Wrap(err, "error parsing public key")
	}

	switch signingAlg {
	case RsaSignPkcs12048Sha256, RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256, RsaSignPkcs14096Sha512:
		var rsa_key *rsa.PublicKey
		var ok bool
		if rsa_key, ok = pub.(*rsa.PublicKey); !ok {
			return errors.New("expected rsa key")
		}
		hash, hashedPayload, payloadErr := hashPayload(payload, signingAlg)
		if payloadErr != nil {
			return errors.Wrap(payloadErr, "error hashing payload")
		}
		err := rsa.VerifyPKCS1v15(rsa_key, hash, hashedPayload, signature)
		if err != nil {
			return errors.Wrap(err, "signature verification failed")
		}
		return nil
	case RsaPss2048Sha256, RsaPss3072Sha256, RsaPss4096Sha256, RsaPss4096Sha512:
		var rsa_key *rsa.PublicKey
		var ok bool
		if rsa_key, ok = pub.(*rsa.PublicKey); !ok {
			return errors.New("expected rsa key")
		}
		hash, hashedPayload, payloadErr := hashPayload(payload, signingAlg)
		if payloadErr != nil {
			return errors.Wrap(payloadErr, "error hashing payload")
		}
		err := rsa.VerifyPSS(rsa_key, hash, hashedPayload, signature, nil)
		if err != nil {
			return errors.Wrap(err, "signature verification failed")
		}
		return nil
	case EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512:
		var ec_key *ecdsa.PublicKey
		var ok bool
		if ec_key, ok = pub.(*ecdsa.PublicKey); !ok {
			return errors.New("expected ecdsa key")
		}
		var sigStruct struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(signature, &sigStruct); err != nil {
			return errors.Wrap(err, "error unmarshaling ecdsa signature")
		}
		// hashPayload returns the hash function, the hashed payload and an error. The hash function is not needed for ecdsa.Verify.
		_, hashedPayload, payloadErr := hashPayload(payload, signingAlg)
		if payloadErr != nil {
			return errors.Wrap(payloadErr, "error hashing payload")
		}
		if !ecdsa.Verify(ec_key, hashedPayload, sigStruct.R, sigStruct.S) {
			return errors.New("failed to verify ecdsa signature")
		}
		return nil
	default:
		return errors.New("signature algorithm not supported")
	}
}
