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
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
)

// Cache struct defines Cache for container analysis client.
type Cache struct {
	client metadata.Fetcher
	vuln   map[string][]metadata.Vulnerability
	att    map[string][]metadata.PGPAttestation
	build  map[string][]metadata.Build
	notes  map[*kritisv1beta1.AttestationAuthority]*grafeas.Note
}

// NewCache Create a new Cache for container analysis client.
func NewCache() (*Cache, error) {
	c, err := New()
	if err != nil {
		return nil, err
	}
	return &Cache{
		client: c,
		vuln:   map[string][]metadata.Vulnerability{},
		att:    map[string][]metadata.PGPAttestation{},
		notes:  map[*kritisv1beta1.AttestationAuthority]*grafeas.Note{},
	}, nil
}

// Vulnerabilities gets Package Vulnerabilities Occurrences for a specified image.
func (c Cache) Vulnerabilities(image string) ([]metadata.Vulnerability, error) {
	if v, ok := c.vuln[image]; ok {
		return v, nil
	}
	v, err := c.client.Vulnerabilities(image)
	if err != nil {
		c.vuln[image] = v
	}
	return v, err
}

// Attestations gets AttesationAuthority Occurrences for a specified image from cache or from client.
func (c Cache) Attestations(image string) ([]metadata.PGPAttestation, error) {
	if a, ok := c.att[image]; ok {
		return a, nil
	}
	a, err := c.client.Attestations(image)
	if err != nil {
		c.att[image] = a
	}
	return a, err
}

// CreateAttestationNote creates an attestation note from AttestationAuthority
func (c Cache) CreateAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeas.Note, error) {
	return c.client.CreateAttestationNote(aa)
}

// AttestationNote returns a note if it exists for given AttestationAuthority
func (c Cache) AttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeas.Note, error) {
	if n, ok := c.notes[aa]; ok {
		return n, nil
	}
	n, err := c.client.AttestationNote(aa)
	if err != nil {
		c.notes[aa] = n
	}
	return n, err
}

// CreateAttestationOccurence creates an Attestation occurrence for a given image and secret.
func (c Cache) CreateAttestationOccurence(n *grafeas.Note, image string, p *secrets.PGPSigningSecret) (*grafeas.Occurrence, error) {
	return c.client.CreateAttestationOccurence(n, image, p)
}

// Builds gets Build Occurrences for a specified image.
func (c Cache) Builds(image string) ([]metadata.Build, error) {
	if v, ok := c.build[image]; ok {
		return v, nil
	}
	v, err := c.client.Builds(image)
	if err != nil {
		c.build[image] = v
	}
	return v, err
}
