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
package integration

import (
	"testing"

	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
)

func getAttestations(t *testing.T, images []string, attestationAuthority *kritisv1beta1.AttestationAuthority) map[string]bool {
	t.Helper()
	m := make(map[string]bool, len(images))
	if len(images) == 0 {
		return m
	}
	client, err := containeranalysis.NewCache()
	if err != nil {
		t.Fatalf("Unexpected error while fetching client %v", err)
	}
	remote, err := containeranalysis.New()
	if err != nil {
		t.Fatalf("Unexpected error while fetching remote client %v", err)
	}
	for _, i := range images {
		ras, err := client.Attestations(i, attestationAuthority)
		if err != nil {
			t.Fatalf("Unexpected error while listing attestations for image %s, %v", i, err)
		}
		if ras != nil {
			m[i] = true
		}
		for _, ra := range ras {
			// TODO(acamadeo): This is hard-coded to work for PGPAttestation. Undo this
			if err := remote.DeleteOccurrence(ra.PGPAttestation.OccID); err != nil {
				t.Logf("could not delete attestations occurrence %s due to %v", ra.PGPAttestation.OccID, err)
			}
		}
	}
	return m
}
