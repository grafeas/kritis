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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/pkg/errors"
)

func rsaSign(privateKey *rsa.PrivateKey, payload []byte, signatureAlgorithm SignatureAlgorithm) ([]byte, error) {
	switch signatureAlgorithm {
	case RsaSignPkcs12048Sha256, RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256, RsaSignPkcs14096Sha512:
		hash, hashedPayload, err := hashPayload(payload, signatureAlgorithm)
		if err != nil {
			return nil, errors.Wrap(err, "hash payload error")
		}
		return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashedPayload[:])
	case RsaPss2048Sha256, RsaPss3072Sha256, RsaPss4096Sha256, RsaPss4096Sha512:
		hash, hashedPayload, err := hashPayload(payload, signatureAlgorithm)
		if err != nil {
			return nil, errors.Wrap(err, "hash payload error")
		}
		return rsa.SignPSS(rand.Reader, privateKey, hash, hashedPayload[:], nil)

	default:
		return nil, fmt.Errorf("expected rsa signature algorithm, got %v", signatureAlgorithm)
	}
}
