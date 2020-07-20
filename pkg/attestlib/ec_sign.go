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
	"encoding/asn1"
	"fmt"
	"github.com/pkg/errors"
	"math/big"
)

// ecSign returns the asn1 encoded representation of the integer signature returned from ecdsa.Sign.
func ecSign(privateKey *ecdsa.PrivateKey, payload []byte, signatureAlgorithm SignatureAlgorithm) ([]byte, error) {
	switch signatureAlgorithm {
	case EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512:
		var sigStruct struct {
			R, S *big.Int
		}
		_, hashedPayload, err := hashPayload(payload, signatureAlgorithm)
		if err != nil {
			return nil, errors.Wrap(err, "hash payload error")
		}
		sigStruct.R, sigStruct.S, err = ecdsa.Sign(rand.Reader, privateKey, hashedPayload[:])
		if err != nil {
			return nil, errors.Wrap(err, "error creating ecdsa signature")
		}
		return asn1.Marshal(sigStruct)
	default:
		return nil, fmt.Errorf("expected ecdsa signature algorithm, got %v", signatureAlgorithm)
	}
}
