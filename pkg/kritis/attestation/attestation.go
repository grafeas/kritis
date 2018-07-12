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
	"strings"

	"github.com/grafeas/kritis/pkg/kritis/admission/constants"
	"github.com/pkg/errors"

	"golang.org/x/crypto/openpgp"
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
func VerifyImageAttestation(pubKeyEnc string, attestationHash string, message string) error {
	pemPublicKey, err := base64.StdEncoding.DecodeString(pubKeyEnc)
	if err != nil {
		return err
	}
	attestation, err := base64.StdEncoding.DecodeString(attestationHash)
	if err != nil {
		return err
	}
	// // Create a PgpKey from Encoded Public Key
	// pgpKey, err := NewPgpKey("", pubKeyEnc)
	// if err != nil {
	// 	return err
	// }

	// buf := bytes.NewBuffer([]byte(attestation))
	// pkt, err := packet.Read(buf)
	// if err != nil {
	// 	fmt.Println("error 1")
	// 	return err
	// }

	// sig, ok := pkt.(*packet.Signature)
	// if !ok {
	// 	return fmt.Errorf("Not a valid signature")
	// }

	// hash := sig.Hash.New()
	// _, err = io.Copy(hash, bytes.NewReader([]byte(message)))
	// if err != nil {
	// 	return err
	// }
	fmt.Println(string(pemPublicKey))
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(string(pemPublicKey)))
	if err != nil {
		fmt.Println("errroorr", err)
		return err
	}
	// Verify Signature using the Public Key
	verificationString := strings.NewReader(message)
	_, err = openpgp.CheckArmoredDetachedSignature(
		keyring,
		verificationString,
		bytes.NewReader(attestation),
	)
	return err
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
	// Sign the Message.
	signer := createEntityFromKeys(pgpKey.PublicKey(), pgpKey.PrivateKey())
	var b bytes.Buffer
	err = openpgp.ArmoredDetachSignText(&b, signer, strings.NewReader(message), nil)
	if err != nil {
		return "", errors.Wrap(err, "Error while signing:")
	}
	fmt.Println(string(b.Bytes()))
	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	currentTime := pgpConfig.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         pgpConfig.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      pgpConfig.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}
