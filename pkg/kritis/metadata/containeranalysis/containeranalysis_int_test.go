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
	"time"

	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	IntTestNoteName = "test-aa-note"
	IntProject      = "kritis-int-test"
)

func GetAA() *kritisv1beta1.AttestationAuthority {
	aa := &kritisv1beta1.AttestationAuthority{
		Spec: kritisv1beta1.AttestationAuthoritySpec{
			NoteReference: fmt.Sprintf("projects/%s/notes/%s", IntProject, IntTestNoteName),
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

	proj, _, err := metadata.ParseNoteReference(aa.Spec.NoteReference)
	if err != nil {
		t.Fatalf("Failed to extract project ID %v", err)
	}
	occ, err := d.CreateAttestationOccurrence(note, testutil.IntTestImage, secret, proj)
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

	// Keep trying to list attestation occurrences until we time out.
	// Because the staleness bound is on the order of seconds, no need to try faster than once a second.
	timeout := time.After(20 * time.Second)
	tick := time.Tick(1 * time.Second)
	for {
		select {
		// Got a timeout! fail with a timeout error
		case <-timeout:
			t.Fatal("Should have created at least 1 occurrence")

			// Got a tick, we should check note occurrences
		case <-tick:
			if occurrences, err := d.Attestations(testutil.IntTestImage, aa); err != nil {
				t.Fatalf("Failed to retrieve attestations: %v", err)
			} else if len(occurrences) > 0 {
				// Successfully retrieved attestations, exit the loop and the test.
				return
			}
		}
	}
}

func TestGetMultiplePages_Vulnerabilities(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("Could not initialize the client %s", err)
	}

	// Set PageSize to 300
	createListOccurrencesRequest = createListOccurrencesRequestTest

	vuln, err := d.Vulnerabilities("gcr.io/kritis-int-test/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a")
	if err != nil {
		t.Fatalf("Found err %s", err)
	}

	if len(vuln) <= 900 {
		t.Errorf("Pagination error: did not receive results from the final page.")
	}
}

func createListOccurrencesRequestTest(containerImage, kind string) *grafeas.ListOccurrencesRequest {
	return &grafeas.ListOccurrencesRequest{
		Filter:   fmt.Sprintf("resourceUrl=%q AND kind=%q", util.GetResourceURL(containerImage), kind),
		Parent:   fmt.Sprintf("projects/%s", getProjectFromContainerImage(containerImage)),
		PageSize: int32(100),
	}
}
