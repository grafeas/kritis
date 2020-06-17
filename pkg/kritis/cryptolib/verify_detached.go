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

func hashPlaintext(plaintext []byte, signingAlg SignatureAlgorithm) []byte {
	switch signingAlg {
	case RsaSignPkcs12048Sha256, RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256, RsaPss2048Sha256, RsaPss3072Sha256, RsaPss4096Sha256, EcdsaP256Sha256:
		hashed_plaintext := sha256.Sum256(plaintext)
		return hashed_plaintext[:]
	case EcdsaP384Sha384:
		hashed_plaintext := sha512.Sum384(plaintext)
		return hashed_plaintext[:]
	case RsaSignPkcs14096Sha512, RsaPss4096Sha512, EcdsaP521Sha512:
		hashed_plaintext := sha512.Sum512(plaintext)
		return hashed_plaintext[:]
	default:
		return nil
	}
}

func verifyDetached(signature []byte, publicKey []byte, signingAlg SignatureAlgorithm, plaintext []byte) error {
	// Decode public key to der and parse for key type.
	// This is needed to create PublicKey type needed for the verify functions.
	der, _ := pem.Decode(publicKey)
	if der == nil {
		return errors.New("failed to decode PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(der.Bytes)
	if err != nil {
		return errors.Wrap(err, "error parsing public key")
	}
	var hashed_plaintext []byte
	var hash crypto.Hash
	switch signingAlg {
	case RsaSignPkcs12048Sha256, RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256, RsaSignPkcs14096Sha512:
		var rsa_key *rsa.PublicKey
		var ok bool
		if rsa_key, ok = pub.(*rsa.PublicKey); !ok {
			return errors.New("expected rsa key")
		}
		if signingAlg == RsaSignPkcs14096Sha512 {
			hash = crypto.SHA512
		} else {
			hash = crypto.SHA256
		}
		hashed_plaintext = hashPlaintext(plaintext, signingAlg)
		err := rsa.VerifyPKCS1v15(rsa_key, hash, hashed_plaintext, signature)
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
		if signingAlg == RsaPss4096Sha512 {
			hash = crypto.SHA512
		} else {
			hash = crypto.SHA256
		}
		hashed_plaintext = hashPlaintext(plaintext, signingAlg)
		return rsa.VerifyPSS(rsa_key, hash, hashed_plaintext, signature, nil)
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
		if signingAlg == EcdsaP256Sha256 {
			hash = crypto.SHA256
		} else if signingAlg == EcdsaP384Sha384 {
			hash = crypto.SHA384
		} else {
			hash = crypto.SHA512
		}
		hashed_plaintext = hashPlaintext(plaintext, signingAlg)
		if !ecdsa.Verify(ec_key, hashed_plaintext, sigStruct.R, sigStruct.S) {
			return errors.New("failed to verify ecdsa signature")
		}
		return nil
	default:
		return errors.New("public key type not supported")
	}
}
