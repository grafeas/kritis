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
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/openpgp"

	"github.com/grafeas/kritis/pkg/kritis/admission/constants"
	"golang.org/x/crypto/openpgp/armor"
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

func VerifyImageAttestation(pubKeyEnc string, attestationHash string) error {
	attestation, err := base64.StdEncoding.DecodeString(attestationHash)
	if err != nil {
		return err
	}

	pemPublicKey, err := base64.StdEncoding.DecodeString(pubKeyEnc)
	if err != nil {
		return err
	}
	key, err := parsePublicKey(string(pemPublicKey))
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
	io.Copy(hash, bytes.NewReader(b.Bytes))

	err = key.VerifySignature(hash, sig)
	if err != nil {
		return err
	}
	return nil
}

// AttestMessage attests the message using the given public and private key.
// pubKeyEnc: Base64 Encoded Public Key
// privKeyEnc: Base64 Decoded Private Key
// message: Message to attest
func AttestMessage(pubKeyEnc string, privKeyEnc string, message string) (string, error) {
	pemPublicKey, err := base64.StdEncoding.DecodeString(pubKeyEnc)
	if err != nil {
		return "", err
	}
	pemPrivateKey, err := base64.StdEncoding.DecodeString(privKeyEnc)
	if err != nil {
		return "", err
	}
	pubKey, encErr := parsePublicKey(string(pemPublicKey))
	if encErr != nil {
		return "", encErr
	}
	privKey, encErr := parsePrivateKey(string(pemPrivateKey))
	if encErr != nil {
		return "", encErr
	}

	// Create a Detached Signature.
	signer := createEntityFromKeys(pubKey, privKey)
	// Sign the Message
	clearSignedMsg := bytes.NewBuffer(nil)
	dec, err := clearsign.Encode(clearSignedMsg, signer.PrivateKey, &pgpConfig)
	if err != nil {
		return "", err
	}
	dec.Write([]byte(message))
	dec.Close()
	return base64.StdEncoding.EncodeToString(clearSignedMsg.Bytes()), err
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
