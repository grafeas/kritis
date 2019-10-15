// +build integration

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
	"fmt"
	"testing"

	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	IntTestNoteName = "test-aa-note"
	IntAPI          = "testv1"
	IntProject      = "kritis-int-test"
)

func GetAA() []kritisv1beta1.AttestationAuthority {
	aa := &kritisv1beta1.AttestationAuthority{
		Spec: kritisv1beta1.AttestationAuthoritySpec{
			NoteReference: fmt.Sprintf("%s/projects/%s", IntAPI, IntProject),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: IntTestNoteName,
		},
	}
	return aa
}

func TestGetVulnerabilities(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("Could not initialize the client %s", err)
	}
	vuln, err := d.Vulnerabilities("gcr.io/kritis-int-test/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a")
	if err != nil {
		t.Fatalf("Found err %s", err)
	}
	if vuln == nil {
		t.Fatalf("Expected some vulnerabilities. Nil found")
	}
}

func TestCreateAttestationNoteAndOccurrence(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("Could not initialize the client %s", err)
	}
	aa := GetAA()
	_, err = d.CreateAttestationNote(aa)
	if err != nil {
		t.Fatalf("Unexpected error while creating Note %v", err)
	}
	defer d.DeleteAttestationNote(aa)

	note, err := d.AttestationNote(aa)
	if err != nil {
		t.Fatalf("Unexpected no error while getting attestation note %v", err)
	}
	expectedNoteName := fmt.Sprintf("projects/%s/notes/%s", IntProject, IntTestNoteName)
	if note.Name != expectedNoteName {
		t.Fatalf("Expected %s.\n Got %s", expectedNoteName, note.Name)
	}

	actualHint := note.GetAttestationAuthority().Hint.GetHumanReadableName()
	if actualHint != IntTestNoteName {
		t.Fatalf("Expected %s.\n Got %s", expectedNoteName, actualHint)
	}
	// Test Create Attestation Occurence
	pub, priv := testutil.CreateKeyPair(t, "test")
	pgpKey, err := secrets.NewPgpKey(priv, "", pub)
	if err != nil {
		t.Fatalf("Unexpected error while creating PGP key %v", err)
	}
	secret := &secrets.PGPSigningSecret{
		PgpKey:     pgpKey,
		SecretName: "test",
	}

	occ, err := d.CreateAttestationOccurence(note, testutil.IntTestImage, secret, IntProject)
	if err != nil {
		t.Fatalf("Unexpected error while creating Occurence %v", err)
	}
	expectedPgpKeyID := pgpKey.Fingerprint()
	if err != nil {
		t.Fatalf("Unexpected error while extracting PGP key id %v", err)
	}
	pgpKeyID := occ.GetAttestation().GetAttestation().GetPgpSignedAttestation().GetPgpKeyId()
	if pgpKeyID != expectedPgpKeyID {
		t.Errorf("Expected PGP key id: %q, got %q", expectedPgpKeyID, pgpKeyID)
	}
	defer d.DeleteOccurrence(occ.GetName())

	occurrences, err := d.Attestations(testutil.IntTestImage, aa)
	if err != nil {
		t.Fatalf("Unexpected error while listing Occ %v", err)
	}
	if occurrences == nil {
		t.Fatal("Should have created at least 1 occurrence")
	}

}
