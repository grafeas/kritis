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
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
)

type MockMetadataClient struct {
	Vulnz           []metadata.Vulnerability
	PGPAttestations []metadata.PGPAttestation
	Occ             map[string]string
}

func (m *MockMetadataClient) GetVulnerabilities(containerImage string) ([]metadata.Vulnerability, error) {
	return m.Vulnz, nil
}

func (m *MockMetadataClient) CreateAttestationOccurence(n *containeranalysispb.Note, image string,
	s *secrets.PGPSigningSecret) (*containeranalysispb.Occurrence, error) {
	if m.Occ == nil {
		m.Occ = map[string]string{}
	}
	m.Occ = map[string]string{
		image: s.SecretName,
	}
	return nil, nil
}

func (m *MockMetadataClient) GetAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*containeranalysispb.Note, error) {
	if aa == nil {
		return nil, fmt.Errorf("could not get note")
	}
	return &containeranalysispb.Note{
		Name: aa.Name,
	}, nil
}

func (m *MockMetadataClient) CreateAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*containeranalysispb.Note, error) {
	return &containeranalysispb.Note{
		Name: aa.Name,
	}, nil
}

func (m *MockMetadataClient) GetAttestations(containerImage string) ([]metadata.PGPAttestation, error) {
	return m.PGPAttestations, nil
}

func NilFetcher() func() (metadata.MetadataFetcher, error) {
	return func() (metadata.MetadataFetcher, error) {
		return &MockMetadataClient{
			Vulnz:           []metadata.Vulnerability{},
			PGPAttestations: []metadata.PGPAttestation{},
		}, nil
	}
}
