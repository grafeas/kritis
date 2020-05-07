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
	"encoding/json"

	"github.com/pkg/errors"
)

// AtomicContainerSig represents a JSON-encoded Attestation payload. It
// conforms to Red Hat's Atomic Host attestation signature format defined here:
// https://github.com/aweiteka/image/blob/e5a20d98fe698732df2b142846d007b45873627f/docs/signature.md
type atomicContainerSig struct {
	Critical critical          `json:"critical"`
	Optional map[string]string `json:"optional,omitempty"`
}

type critical struct {
	Identity identity `json:"identity"`
	Image    image    `json:"image"`
	Type     string   `json:"type"`
}

type identity struct {
	DockerRef string `json:"docker-reference"`
}

type image struct {
	Digest string `json:"docker-manifest-digest"`
}

// TODO(https://github.com/grafeas/kritis/issues/503): Decide whether
// AuthenticatedAttestation is a useful abstraction.
// AuthenticatedAttestation contains data that is extracted from an Attestation
// only after its signature has been verified. The contents of an Attestation
// payload should never be analyzed directly, as it may or may not be verified.
// Instead, these should be extracted into an AuthenticatedAttestation and
// analyzed from there.
type authenticatedAttestation struct {
	ImageName   string
	ImageDigest string
}

type authenticatedAttCheckerImpl struct{}

// Check that the data within the Attestation payload matches what we expect.
// NOTE: This is a simple comparison for plain attestations, but it is more
// complex for rich attestations.
func (c authenticatedAttCheckerImpl) checkAuthenticatedAttestation(payload []byte, imageName string, imageDigest string, convert convertFunc) error {
	authAtt, err := convert(payload)
	if err != nil {
		return err
	}
	if authAtt.ImageName != imageName {
		return errors.New("incorrect image name in Attestation payload")
	}
	if authAtt.ImageDigest != imageDigest {
		return errors.New("incorrect image digest in Attestation payload")
	}
	return nil
}
func convertAuthenticatedAttestation(payload []byte) (*authenticatedAttestation, error) {
	atomicSig := &atomicContainerSig{}
	if err := json.Unmarshal(payload, atomicSig); err != nil {
		return nil, errors.Wrap(err, "error parsing attestation payload")
	}

	return &authenticatedAttestation{
		ImageName:   atomicSig.Critical.Identity.DockerRef,
		ImageDigest: atomicSig.Critical.Image.Digest,
	}, nil
}
