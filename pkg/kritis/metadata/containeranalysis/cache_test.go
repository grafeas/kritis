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
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var vuln = []metadata.Vulnerability{{
	CVE:             "CVE-1",
	Severity:        "LOW",
	HasFixAvailable: false,
}}

var pgpAtt = []metadata.PGPAttestation{{
	Signature: "test-sig",
	KeyID:     "test",
	OccID:     "occc-1",
}}

var note = &containeranalysispb.Note{
	Name: "test-note",
}
var mock = &testutil.MockMetadataClient{}

func TestVCache(t *testing.T) {
	c := Cache{
		client: mock,
		vCache: map[string][]metadata.Vulnerability{"image-hit": vuln},
		aCache: nil,
		nCache: nil,
	}
	tcs := []struct {
		name     string
		image    string
		expected []metadata.Vulnerability
	}{
		{"hit", "image-hit", vuln},
		{"miss", "image-miss", nil},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := c.GetVulnerabilities(tc.image)
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
	c := Cache{
		client: mock,
		vCache: nil,
		aCache: map[string][]metadata.PGPAttestation{"image-hit": pgpAtt},
		nCache: nil,
	}
	tcs := []struct {
		name     string
		image    string
		expected []metadata.PGPAttestation
	}{
		{"hit", "image-hit", pgpAtt},
		{"miss", "image-miss", nil},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := c.GetAttestations(tc.image)
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
	c := Cache{
		client: mock,
		vCache: nil,
		aCache: nil,
		nCache: map[*v1beta1.AttestationAuthority]*containeranalysispb.Note{
			aaHit: note,
		},
	}
	tcs := []struct {
		name     string
		aa       *v1beta1.AttestationAuthority
		expected *containeranalysispb.Note
	}{
		{"hit", aaHit, note},
		{"miss", &v1beta1.AttestationAuthority{}, &containeranalysispb.Note{}},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := c.GetAttestationNote(tc.aa)
			if err != nil {
				t.Errorf("unexpected error %v", err)
			}
			if !reflect.DeepEqual(tc.expected, actual) {
				t.Errorf("Expected %v, Got %v", tc.expected, actual)
			}
		})
	}
}
