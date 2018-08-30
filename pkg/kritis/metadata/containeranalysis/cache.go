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

package containeranalysis

import (
	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
)

// Cache struct defines Cache for container analysis client.
type Cache struct {
	client metadata.Fetcher
	vCache map[string][]metadata.Vulnerability
	aCache map[string][]metadata.PGPAttestation
	nCache map[*kritisv1beta1.AttestationAuthority]*containeranalysispb.Note
}

// NewCache Create a new Cache for container analysis client.
func NewCache() (*Cache, error) {
	c, err := New()
	if err != nil {
		return nil, err
	}
	return &Cache{
		client: c,
		vCache: map[string][]metadata.Vulnerability{},
		aCache: map[string][]metadata.PGPAttestation{},
		nCache: map[*kritisv1beta1.AttestationAuthority]*containeranalysispb.Note{},
	}, nil
}

// GetVulnerabilities gets Package Vulnerabilities Occurrences for a specified image.
func (c Cache) GetVulnerabilities(image string) ([]metadata.Vulnerability, error) {
	if v, ok := c.vCache[image]; ok {
		return v, nil
	}
	v, err := c.client.GetVulnerabilities(image)
	if err != nil {
		c.vCache[image] = v
	}
	return v, err
}

// GetAttestations gets AttesationAuthority Occurrences for a specified image from cache or from client.
func (c Cache) GetAttestations(image string) ([]metadata.PGPAttestation, error) {
	if a, ok := c.aCache[image]; ok {
		return a, nil
	}
	a, err := c.client.GetAttestations(image)
	if err != nil {
		c.aCache[image] = a
	}
	return a, err
}

// CreateAttestationNote creates an attestation note from AttestationAuthority
func (c Cache) CreateAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*containeranalysispb.Note, error) {
	return c.client.CreateAttestationNote(aa)
}

// GetAttestationNote returns a note if it exists for given AttestationAuthority
func (c Cache) GetAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*containeranalysispb.Note, error) {
	if n, ok := c.nCache[aa]; ok {
		return n, nil
	}
	n, err := c.client.GetAttestationNote(aa)
	if err != nil {
		c.nCache[aa] = n
	}
	return n, err
}

// CreateAttestationOccurence creates an Attestation occurrence for a given image and secret.
func (c Cache) CreateAttestationOccurence(n *containeranalysispb.Note,
	image string,
	pKey *secrets.PGPSigningSecret) (*containeranalysispb.Occurrence, error) {
	return c.client.CreateAttestationOccurence(n, image, pKey)
}
