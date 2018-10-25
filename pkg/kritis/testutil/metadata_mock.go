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

package testutil

import (
	"fmt"

	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
)

// MockMetadataClient is a mock Grafeas client.
type MockMetadataClient struct {
	Vulnz           []metadata.Vulnerability
	PGPAttestations []metadata.PGPAttestation
	Occ             map[string]string
}

// Vulnerabilities gets Package Vulnerabilities Occurrences for a specified image.
func (m *MockMetadataClient) Vulnerabilities(containerImage string) ([]metadata.Vulnerability, error) {
	return m.Vulnz, nil
}

// CreateAttestationOccurrence creates an Attestation occurrence for a given image and secret.
func (m *MockMetadataClient) CreateAttestationOccurrence(n *grafeas.Note, image string,
	s *secrets.PGPSigningSecret) (*grafeas.Occurrence, error) {
	if m.Occ == nil {
		m.Occ = map[string]string{}
	}
	m.Occ[fmt.Sprintf("%s-%s", image, n.Name)] = s.SecretName
	return nil, nil
}

// AttestationNote returns a note if it exists for given AttestationAuthority
func (m *MockMetadataClient) AttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeas.Note, error) {
	if aa == nil {
		return nil, fmt.Errorf("could not get note")
	}
	return &grafeas.Note{
		Name: aa.Spec.NoteReference,
	}, nil
}

// CreateAttestationNote creates an attestation note from AttestationAuthority
func (m *MockMetadataClient) CreateAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeas.Note, error) {
	return &grafeas.Note{
		Name: aa.Spec.NoteReference,
	}, nil
}

// Attestations gets AttesationAuthority Occurrences for a specified image.
func (m *MockMetadataClient) Attestations(containerImage string) ([]metadata.PGPAttestation, error) {
	return m.PGPAttestations, nil
}

// NilFetcher returns a mock metadata.Fetcher wired to a MockMetadataClient
func NilFetcher() func() (metadata.Fetcher, error) {
	return func() (metadata.Fetcher, error) {
		return &MockMetadataClient{
			Vulnz:           []metadata.Vulnerability{},
			PGPAttestations: []metadata.PGPAttestation{},
		}, nil
	}
}
