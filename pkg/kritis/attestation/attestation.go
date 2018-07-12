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

// Package attestation defines methods to attest a message using Pgp Private and
// Public Key pair.
package attestation

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/grafeas/kritis/pkg/kritis/admission/constants"

	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
)

var pgpConfig = packet.Config{
	// Use Sha256
	DefaultHash:            crypto.SHA256,
	DefaultCipher:          packet.CipherAES256,
	DefaultCompressionAlgo: packet.CompressionZLIB,
	CompressionConfig: &packet.CompressionConfig{
		Level: packet.DefaultCompression,
	},
	RSABits: constants.RSABits,
}

// VerifyImageAttestation verifies if the image is attested using the Base64
// encoded public key.
func VerifyImageAttestation(pubKeyEnc string, attestationHash string) error {
	attestation, err := base64.StdEncoding.DecodeString(attestationHash)
	if err != nil {
		return err
	}
	// Create a PgpKey from Encoded Public Key
	pgpKey, err := NewPgpKey("", pubKeyEnc)
	if err != nil {
		return err
	}

	// Decode Attestation.
	b, _ := clearsign.Decode(attestation)
	if b == nil {
		return fmt.Errorf("Not a valid signature!")
	}

	reader := packet.NewReader(b.ArmoredSignature.Body)
	pkt, err := reader.Next()
	if err != nil {
		return err
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		return fmt.Errorf("Not a valid signature")
	}

	hash := sig.Hash.New()
	_, err = io.Copy(hash, bytes.NewReader(b.Bytes))
	if err != nil {
		return err
	}

	// Verify Signature using the Public Key
	return pgpKey.PublicKey().VerifySignature(hash, sig)
}

// AttestMessage attests the message using the given public and private key.
// pubKeyEnc: Base64 Encoded Public Key
// privKeyEnc: Base64 Decoded Private Key
// message: Message to attest
func AttestMessage(pubKeyEnc string, privKeyEnc string, message string) (string, error) {

	// Create a PgpKey from Encoded Public Key
	pgpKey, err := NewPgpKey(privKeyEnc, pubKeyEnc)
	if err != nil {
		return "", err
	}
	// Create a Detached Signature using clearsign
	clearSignedMsg := bytes.NewBuffer(nil)
	dec, err := clearsign.Encode(clearSignedMsg, pgpKey.PrivateKey(), &pgpConfig)
	if err != nil {
		return "", err
	}
	dec.Write([]byte(message))
	dec.Close()
	return base64.StdEncoding.EncodeToString(clearSignedMsg.Bytes()), err
}
