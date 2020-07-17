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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
)

func parsePkixPrivateKeyPem(privateKey []byte) (interface{}, error) {
	der, rest := pem.Decode(privateKey)

	if len(rest) != 0 {
		return nil, errors.New("expected one public key")
	}

	key, err := x509.ParsePKCS8PrivateKey(der.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func generatePkixPublicKeyId(privateKey interface{}) (string, error) {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		rsaKey := privateKey.(*rsa.PrivateKey)
		publicKeyMaterial, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			return "", errors.Wrap(err, "some err")
		}
		dgst := sha256.Sum256(publicKeyMaterial)
		base64Dgst := base64.RawURLEncoding.EncodeToString(dgst[:])
		return fmt.Sprintf("ni:///sha-256;%s", base64Dgst), nil
	case *ecdsa.PrivateKey:
		ecKey := privateKey.(*ecdsa.PrivateKey)
		publicKeyMaterial, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		if err != nil {
			return "", errors.Wrap(err, "some err")
		}
		dgst := sha256.Sum256(publicKeyMaterial)
		base64Dgst := base64.RawURLEncoding.EncodeToString(dgst[:])
		return fmt.Sprintf("ni:///sha-256;%s", base64Dgst), nil
	default:
		return "", errors.New("unexpected key type")
	}

}
