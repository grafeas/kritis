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

package container

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/pkg/errors"
)

// for testing
var (
	hType = constants.AtomicContainerSigType
)

// AtomicContainerSig represents Red Hat’s Atomic Host attestation signature format
// defined here https://github.com/aweiteka/image/blob/e5a20d98fe698732df2b142846d007b45873627f/docs/signature.md
type AtomicContainerSig struct {
	Critical *critical         `json:"critical"`
	Optional map[string]string `json:"optional,omitempty"`
}

// NewAtomicContainerSig creates a AtomicContainerSig from given image and optional map.
func NewAtomicContainerSig(image string, optional map[string]string) (*AtomicContainerSig, error) {
	critical, err := newCritical(image)
	if err != nil {
		return nil, err
	}
	return &AtomicContainerSig{
		Critical: critical,
		Optional: optional,
	}, nil
}

// Equals returns if the Identity and Image fields for the host are same.
func (acs *AtomicContainerSig) Equals(acsOther *AtomicContainerSig) bool {
	return acs.Critical.Equals(acsOther.Critical)
}

type critical struct {
	Identity *identity `json:"identity"`
	Image    *image    `json:"image"`
	Type     string    `json:"type"`
}

func newCritical(image string) (*critical, error) {
	digest, err := name.NewDigest(image, name.StrictValidation)
	if err != nil {
		return nil, err
	}
	return &critical{
		Identity: newIdentity(digest.Repository.Name()),
		Image:    newImage(digest.DigestStr()),
		Type:     hType,
	}, nil
}

// Equals returns if the Identity and Image fields for the host are same.
func (c1 *critical) Equals(c2 *critical) bool {
	return *c1.Identity == *c2.Identity && *c1.Image == *c2.Image
}

type identity struct {
	DockerRef string `json:"docker-reference"`
}

func newIdentity(image string) *identity {
	return &identity{
		DockerRef: image,
	}
}

type image struct {
	Digest string `json:"docker-manifest-digest"`
}

func newImage(digest string) *image {
	return &image{
		Digest: digest,
	}
}

func (acs *AtomicContainerSig) JSON() (string, error) {
	bytes, err := json.Marshal(acs)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (acs *AtomicContainerSig) CreateAttestationSignature(pgpSigningKey *secrets.PGPSigningSecret) (string, error) {
	hostStr, err := acs.JSON()
	if err != nil {
		return "", err
	}
	return attestation.CreateMessageAttestation(pgpSigningKey.PgpKey, hostStr)
}

func (acs *AtomicContainerSig) VerifySignature(publicKey v1beta1.PublicKey, sig string) error {
	switch publicKey.KeyType {
	case v1beta1.PgpKeyType:
		decodedKey, err := base64.StdEncoding.DecodeString(publicKey.AsciiArmoredPgpPublicKey)
		if err != nil {
			return err
		}
		return acs.VerifyPgpSignature(string(decodedKey), sig)
	case v1beta1.PkixKeyType:
	default:
		return fmt.Errorf("Unsupported key type: %s", publicKey.KeyType)
	}
	return nil
}

func (acs *AtomicContainerSig) VerifyPgpSignature(publicKey string, sig string) error {
	hostSig, err := attestation.GetPlainMessage(publicKey, sig)
	if err != nil {
		return errors.Wrap(err, "error verifying signature")
	}
	// Unmarshall the json host string to get AtomicContainerSig struct
	var host AtomicContainerSig
	if err := json.Unmarshal(hostSig, &host); err != nil {
		return errors.Wrap(err, "error unmarshaling json")
	}

	if !host.Equals(acs) {
		h1, _ := host.JSON()
		h2, _ := acs.JSON()
		return fmt.Errorf("sig not verified. Expected %s, Got %s", h1, h2)
	}
	return nil
}
