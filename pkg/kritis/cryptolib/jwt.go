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
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
)

func decodeBase64(in []byte) ([]byte, error) {
	toDecode := make([]byte, len(in))
	switch len(in) % 4 {
	case 0: // no padding
		toDecode = in
	case 2:
		toDecode = make([]byte, len(in)+2)
		copy(toDecode[:len(in)], in)
		copy(toDecode[len(in):len(in)+2], []byte("==")) //two pad chars
	case 3:
		toDecode = make([]byte, len(in)+1)
		copy(toDecode[:len(in)], in)
		copy(toDecode[len(in):len(in)+1], []byte("=")) // one pad char
	default:
		return []byte(""), errors.New("Invalid base64 encoding")
	}
	decodedBytes := make([]byte, len(toDecode)/4*3)
	if len(in)%4 == 0 {
		decodedBytes = make([]byte, len(toDecode)*6/8)
	}
	n, err := base64.URLEncoding.Decode(decodedBytes, toDecode)
	return decodedBytes[:n], err

}

func convertKeyTypetoKeyAlg(alg SignatureAlgorithm) string {
	switch alg {
	case RsaPss2048Sha256, RsaPss3072Sha256, RsaPss4096Sha256:
		return "PS256"
	case RsaPss4096Sha512:
		return "PS512"
	case RsaSignPkcs12048Sha256, RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256:
		return "RS256"
	case RsaSignPkcs14096Sha512:
		return "RS512"
	case EcdsaP256Sha256:
		return "ES256"
	case EcdsaP384Sha384:
		return "ES384"
	case EcdsaP521Sha512:
		return "ES512"
	default:
		return "Key Type Not Supported"

	}
}

func checkHeader(headerIn []byte, publicKey PublicKey) error {
	type headerTemplate struct {
		Typ, Alg, Kid string
	}
	var jsonHeader headerTemplate
	err := json.Unmarshal(headerIn, &jsonHeader)
	if err != nil {
		return err
	}
	if jsonHeader.Typ != "JWT" {
		return errors.New("type field invalid")
	}
	if jsonHeader.Alg != convertKeyTypetoKeyAlg(publicKey.SignatureAlgorithm) {
		return errors.New("Alg field does not match the algorithm of the public key")
	}
	if jsonHeader.Kid != publicKey.ID {
		return errors.New("KID field does not match the public key ID")
	}

	return nil

}

type jwtVerifierImpl struct{}

func (v jwtVerifierImpl) verifyJwt(signature []byte, publicKey PublicKey) ([]byte, error) {
	parts := bytes.Split(signature, []byte("."))
	if len(parts) != 3 {
		return []byte(""), errors.New("Invalid JWT: more than 3 parts")
	}
	header, err := decodeBase64(parts[0])
	if err != nil {
		return []byte(""), errors.Wrap(err, "Cannot decode header")
	}
	err = checkHeader(header, publicKey)
	if err != nil {
		return []byte(""), errors.Wrap(err, "Invalid header")
	}
	payload, err := decodeBase64(parts[1])
	if err != nil {
		return []byte(""), errors.Wrap(err, "Cannot decode payload")
	}
	verifyDetached(parts[2], publicKey.KeyData, publicKey.SignatureAlgorithm, append(parts[0], parts[1]...))

	return payload, nil
}

func verifyDetached(signature []byte, publicKey []byte, signingAlg SignatureAlgorithm, plaintext []byte) error {
	return errors.New("VerifyDetached is not implemented yet")
}
