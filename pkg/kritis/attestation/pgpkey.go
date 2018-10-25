/*
Copyright 2018 Google LLC

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

package attestation

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// PGPKey struct converts the base64 encoded PEM keys into openpgp private and
// public keys. Kubernetes Secrets are stored as base64 encoded PEM keys.
type PGPKey struct {
	privateKey *packet.PrivateKey
	publicKey  *packet.PublicKey
}

// NewPGPKey returns a PGPKey structure given base64 encoded public and private keys.
func NewPGPKey(privateKeyStr string, publicKeyStr string) (*PGPKey, error) {
	var publicKey *packet.PublicKey
	var privateKey *packet.PrivateKey
	var err error

	if privateKeyStr != "" {
		privateKey, err = parsePrivateKey(privateKeyStr)
		if err != nil {
			return nil, errors.Wrap(err, "parsing private key")
		}
	}
	if publicKeyStr != "" {
		publicKey, err = parsePublicKey(publicKeyStr)
		if err != nil {
			return nil, errors.Wrap(err, "parsing public key")
		}
	}
	return &PGPKey{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// PublicKey returns the PGP public key.
func (key *PGPKey) PublicKey() *packet.PublicKey {
	return key.publicKey
}

// PrivateKey returns the PGP private key.
func (key *PGPKey) PrivateKey() *packet.PrivateKey {
	return key.privateKey
}

// Fingerprint returns the PGP fingerprint.
func (key *PGPKey) Fingerprint() string {
	return fmt.Sprintf("%X", key.publicKey.Fingerprint)
}

func parsePublicKey(publicKey string) (*packet.PublicKey, error) {
	pkt, err := parseKey(publicKey, openpgp.PublicKeyType)
	if err != nil {
		return nil, err
	}
	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Not a public key")
	}
	return key, nil
}

func parsePrivateKey(privateKey string) (*packet.PrivateKey, error) {
	pkt, err := parseKey(privateKey, openpgp.PrivateKeyType)
	if err != nil {
		return nil, err
	}
	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Not a private Key")
	}
	return key, nil
}

func parseKey(key string, keytype string) (packet.Packet, error) {
	r := strings.NewReader(key)
	block, err := armor.Decode(r)
	if err != nil {
		return nil, err
	}
	if block.Type != keytype {
		return nil, err
	}
	reader := packet.NewReader(block.Body)
	return reader.Next()
}
