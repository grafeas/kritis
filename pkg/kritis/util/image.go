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
	"encoding/json"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/grafeas/kritis/pkg/kritis/constants"
)

// AtomicContainerSig represents Red Hat’s Atomic Host attestation signature format
// defined here https://github.com/aweiteka/image/blob/e5a20d98fe698732df2b142846d007b45873627f/docs/signature.md
type AtomicContainerSig struct {
	Critical *Critical         `json:"critical"`
	Optional map[string]string `json:"optional,omitempty"`
}

func NewAtomicContainerSig(image string, optional map[string]string) (*AtomicContainerSig, error) {
	critical, err := NewCritical(image)
	if err != nil {
		return nil, err
	}
	return &AtomicContainerSig{
		Critical: critical,
		Optional: optional,
	}, nil
}

type Critical struct {
	Identity *ContainerIdentity `json:"identity"`
	Image    *ContainerImage    `json:"image"`
	Type     string             `json:"type"`
}

func NewCritical(image string) (*Critical, error) {
	digest, err := name.NewDigest(image, name.StrictValidation)
	if err != nil {
		return nil, err
	}
	return &Critical{
		Identity: NewContainerIdentity(digest.Repository.Name()),
		Image:    NewContainerImage(digest.DigestStr()),
		Type:     constants.AtomicContainerSigType,
	}, nil
}

type ContainerIdentity struct {
	DockerRef string `json:"docker-reference"`
}

func NewContainerIdentity(image string) *ContainerIdentity {
	return &ContainerIdentity{
		DockerRef: image,
	}
}

type ContainerImage struct {
	DockerDigest string `json:"docker-manifest-digest"`
}

func NewContainerImage(digest string) *ContainerImage {
	return &ContainerImage{
		DockerDigest: digest,
	}
}

func (acs *AtomicContainerSig) Json() (string, error) {
	bytes, err := json.Marshal(acs)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
