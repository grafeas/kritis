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
	"reflect"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	cpb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestVCache(t *testing.T) {
	vCache := []metadata.Vulnerability{{CVE: "CVE-1"}}
	vClient := []metadata.Vulnerability{{CVE: "CVE-misss"}}
	c := Cache{
		client: &testutil.MockMetadataClient{Vulnz: vClient},
		vuln:   map[string][]metadata.Vulnerability{"image-hit": vCache},
		att:    nil,
		notes:  nil,
	}
	tcs := []struct {
		name     string
		image    string
		expected []metadata.Vulnerability
	}{
		{"hit", "image-hit", vCache},
		{"miss", "image-miss", vClient},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := c.Vulnerabilities(tc.image)
			if err != nil {
				t.Errorf("unexpected error %v", err)
			}
			if !reflect.DeepEqual(tc.expected, actual) {
				t.Errorf("Expected %v, Got %v", tc.expected, actual)
			}
		})
	}
}

func TestACache(t *testing.T) {
	aCache := []metadata.PGPAttestation{{OccID: "occc-1"}}
	aClient := []metadata.PGPAttestation{{OccID: "occc-miss"}}
	c := Cache{
		client: &testutil.MockMetadataClient{PGPAttestations: aClient},
		vuln:   nil,
		att:    map[string][]metadata.PGPAttestation{"image-hit": aCache},
		notes:  nil,
	}
	tcs := []struct {
		name     string
		image    string
		expected []metadata.PGPAttestation
	}{
		{"hit", "image-hit", aCache},
		{"miss", "image-miss", aClient},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := c.Attestations(tc.image)
			if err != nil {
				t.Errorf("unexpected error %v", err)
			}
			if !reflect.DeepEqual(tc.expected, actual) {
				t.Errorf("Expected %v, Got %v", tc.expected, actual)
			}
		})
	}

}

func TestNCache(t *testing.T) {
	aaHit := &v1beta1.AttestationAuthority{ObjectMeta: metav1.ObjectMeta{
		Name: "test-aa",
	}}
	aaMiss := &v1beta1.AttestationAuthority{Spec: v1beta1.AttestationAuthoritySpec{
		NoteReference: "from-client"},
	}
	nCache := &cpb.Note{Name: "from-cache"}
	c := Cache{
		client: &testutil.MockMetadataClient{},
		vuln:   nil,
		att:    nil,
		notes:  map[*v1beta1.AttestationAuthority]*cpb.Note{aaHit: nCache},
	}
	tcs := []struct {
		name     string
		aa       *v1beta1.AttestationAuthority
		expected *cpb.Note
	}{
		{"hit", aaHit, nCache},
		{"miss", aaMiss, &cpb.Note{Name: "from-client"}},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := c.AttestationNote(tc.aa)
			if err != nil {
				t.Errorf("unexpected error %v", err)
			}
			if !reflect.DeepEqual(tc.expected, actual) {
				t.Errorf("Expected %v, Got %v", tc.expected, actual)
			}
		})
	}
}
