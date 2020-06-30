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

package util

import (
	"bytes"
	"crypto"
	"fmt"
	"strings"

	"golang.org/x/crypto/openpgp"

	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/cryptolib"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
)

const (
	RSABits = 4096
)

var pgpConfig = packet.Config{
	// Use Sha256
	DefaultHash:            crypto.SHA256,
	DefaultCipher:          packet.CipherAES256,
	DefaultCompressionAlgo: packet.CompressionZLIB,
	CompressionConfig: &packet.CompressionConfig{
		Level: packet.DefaultCompression,
	},
	RSABits: RSABits,
}

// Check that note name is in the form of projects/[PROVIDER_ID]/notes/[NOTE_ID]
// Throws error if not
func CheckNoteName(note string) error {
	tok := strings.Split(note, "/")
	if len(tok) != 4 || tok[0] != "projects" || tok[2] != "notes" {
		return fmt.Errorf("note name %s is not in the form of projects/[PROVIDER_ID]/notes/[NOTE_ID]", note)
	}
	return nil
}

func GetProjectFromContainerImage(image string) string {
	tok := strings.Split(image, "/")
	if len(tok) < 2 {
		return ""
	}
	return tok[1]
}

func GetResourceURL(containerImage string) string {
	return fmt.Sprintf("%s%s", constants.ResourceURLPrefix, containerImage)
}

func GetResource(image string) *grafeas.Resource {
	return &grafeas.Resource{Uri: GetResourceURL(image)}
}

func CreateAttestation(image string, pgpSigningKey *secrets.PGPSigningSecret) (*cryptolib.Attestation, error) {
	privateKey, err := extractPrivateKeyBytes(pgpSigningKey)
	if err != nil {
		return nil, err
	}
	signer, err := cryptolib.NewPgpSigner(privateKey)
	if err != nil {
		return nil, err
	}

	payload, err := attestation.AtomicContainerPayload(image)
	if err != nil {
		return nil, err
	}

	att, err := signer.CreateAttestation(payload)
	if err != nil {
		return nil, err
	}
	return att, nil
}

func extractPrivateKeyBytes(secret *secrets.PGPSigningSecret) ([]byte, error) {
	keyBuffer := bytes.NewBuffer(nil)
	armorWriter, err := armor.Encode(keyBuffer, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, err
	}
	entity, err := createEntityFromKeys(secret.PgpKey.PublicKey(), secret.PgpKey.PrivateKey())
	if err != nil {
		return nil, err
	}
	err = entity.SerializePrivate(armorWriter, nil)
	if err != nil {
		return nil, err
	}
	armorWriter.Close()
	return keyBuffer.Bytes(), nil
}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) (*openpgp.Entity, error) {
	currentTime := pgpConfig.Now()
	uid := packet.NewUserId("", "", "")
	if uid == nil {
		return nil, fmt.Errorf("got nil UserId")
	}

	e := &openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryID := true
	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Id,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         pgpConfig.Hash(),
			IsPrimaryId:  &isPrimaryID,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}
	err := e.Identities[uid.Id].SelfSignature.SignUserId(uid.Id, e.PrimaryKey, e.PrivateKey, &pgpConfig)
	if err != nil {
		return nil, err
	}

	// Set Config Hash from Config
	hashID, ok := s2k.HashToHashId(pgpConfig.DefaultHash)
	if !ok {
		return nil, fmt.Errorf("tried to convert unknown hash %d", pgpConfig.DefaultHash)
	}
	e.Identities[uid.Id].SelfSignature.PreferredHash = []uint8{hashID}

	// Set Config Cipher from Config
	e.Identities[uid.Id].SelfSignature.PreferredSymmetric = []uint8{uint8(pgpConfig.DefaultCipher)}

	return e, nil
}

func GetAttestationKeyFingerprint(pgpSigningKey *secrets.PGPSigningSecret) string {
	return pgpSigningKey.PgpKey.Fingerprint()
}

// GetOrCreateAttestationNote returns a note if exists and creates one if it does not exist.
func GetOrCreateAttestationNote(c metadata.ReadWriteClient, a *v1beta1.AttestationAuthority) (*grafeas.Note, error) {
	n, err := c.AttestationNote(a)
	if err == nil {
		return n, nil
	}
	return c.CreateAttestationNote(a)
}
