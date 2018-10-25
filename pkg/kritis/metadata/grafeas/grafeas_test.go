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
package grafeas

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/golang/protobuf/ptypes/empty"
	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCreateAttestationNoteAndOccurrence(t *testing.T) {
	socketPath = ".grafeas.sock"
	server := grpc.NewServer()
	grafeasMock := newGrafeasServerMock()
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to listen on socket %v", err)
	}
	_, err = os.Stat(socketPath)
	t.Logf("File %v", err)
	grafeas.RegisterGrafeasV1Beta1Server(server, grafeasMock)
	go func() {
		if serr := server.Serve(lis); serr != nil {
			t.Fatalf("Failed to server %v", serr)
		}
	}()
	defer func() {
		server.GracefulStop()
		os.Remove(socketPath)
	}()
	client, err := New()
	if err != nil {
		t.Fatalf("Could not initialize the client %v", err)
	}
	aa := &kritisv1beta1.AttestationAuthority{
		Spec: kritisv1beta1.AttestationAuthoritySpec{
			NoteReference: fmt.Sprintf("%s/projects/%s", "api", DefaultProject),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "note1",
		},
	}
	if _, err = client.CreateAttestationNote(aa); err != nil {
		t.Fatalf("Unexpected error while creating Note %v", err)
	}
	note, err := client.AttestationNote(aa)
	if err != nil {
		t.Fatalf("Unexpected no error while getting attestation note %v", err)
	}
	expectedNoteName := fmt.Sprintf("projects/%s/notes/note1", DefaultProject)
	if note.Name != expectedNoteName {
		t.Fatalf("Expected %s.\n Got %s", expectedNoteName, note.Name)
	}
	actualHint := note.GetAttestationAuthority().Hint.GetHumanReadableName()
	if actualHint != "note1" {
		t.Fatalf("Expected %s.\n Got %s", expectedNoteName, actualHint)
	}
	// Test Create Attestation Occurrence
	pub, priv := testutil.CreateKeyPair(t, "test")
	secret := &secrets.PGPSigningSecret{
		PrivateKey: priv,
		PublicKey:  pub,
		SecretName: "test",
	}
	occ, err := client.CreateAttestationOccurrence(note, testutil.IntTestImage, secret)
	if err != nil {
		t.Fatalf("Unexpected error while creating Occurrence %v", err)
	}
	expectedPGPKeyID, err := attestation.GetKeyFingerprint(pub)
	if err != nil {
		t.Fatalf("Unexpected error while extracting PGP key id %v", err)
	}

	pgpKeyID := occ.GetAttestation().GetAttestation().GetPgpSignedAttestation().GetPgpKeyId()
	if pgpKeyID != expectedPGPKeyID {
		t.Errorf("Expected PGP key id: %q, got %q", expectedPGPKeyID, pgpKeyID)
	}
	occurrences, err := client.Attestations(testutil.IntTestImage)
	if err != nil {
		t.Fatalf("Unexpected error while listing Occ %v", err)
	}
	if occurrences == nil {
		t.Fatal("Shd have created atleast 1 occurrence")
	}
}

// grafeasServerMock is a mock for grafeas grpc API
type grafeasServerMock struct {
	notes       map[string]*grafeas.Note
	occurrences map[string]*grafeas.Occurrence
}

func newGrafeasServerMock() *grafeasServerMock {
	return &grafeasServerMock{notes: make(map[string]*grafeas.Note), occurrences: make(map[string]*grafeas.Occurrence)}
}

func (g *grafeasServerMock) GetOccurrence(ctx context.Context, req *grafeas.GetOccurrenceRequest) (*grafeas.Occurrence, error) {
	return g.occurrences[req.Name], nil
}

func (g *grafeasServerMock) ListOccurrences(context.Context, *grafeas.ListOccurrencesRequest) (*grafeas.ListOccurrencesResponse, error) {
	var resp grafeas.ListOccurrencesResponse
	for _, occ := range g.occurrences {
		resp.Occurrences = append(resp.Occurrences, occ)
	}
	return &resp, nil
}

func (g *grafeasServerMock) DeleteOccurrence(context.Context, *grafeas.DeleteOccurrenceRequest) (*empty.Empty, error) {
	return nil, nil
}

func (g *grafeasServerMock) CreateOccurrence(ctx context.Context, req *grafeas.CreateOccurrenceRequest) (*grafeas.Occurrence, error) {
	occ := req.Occurrence
	g.occurrences[occ.Name] = occ
	return occ, nil
}

func (g *grafeasServerMock) BatchCreateOccurrences(context.Context, *grafeas.BatchCreateOccurrencesRequest) (*grafeas.BatchCreateOccurrencesResponse, error) {
	return nil, nil
}

func (g *grafeasServerMock) UpdateOccurrence(context.Context, *grafeas.UpdateOccurrenceRequest) (*grafeas.Occurrence, error) {
	return nil, nil
}

func (g *grafeasServerMock) GetOccurrenceNote(context.Context, *grafeas.GetOccurrenceNoteRequest) (*grafeas.Note, error) {
	return nil, nil
}

func (g *grafeasServerMock) GetNote(ctx context.Context, req *grafeas.GetNoteRequest) (*grafeas.Note, error) {
	return g.notes[req.Name], nil
}

func (g *grafeasServerMock) ListNotes(context.Context, *grafeas.ListNotesRequest) (*grafeas.ListNotesResponse, error) {
	return nil, nil
}

func (g *grafeasServerMock) DeleteNote(context.Context, *grafeas.DeleteNoteRequest) (*empty.Empty, error) {
	return nil, nil
}

func (g *grafeasServerMock) CreateNote(ctx context.Context, req *grafeas.CreateNoteRequest) (*grafeas.Note, error) {
	note := req.Note
	g.notes[note.Name] = note
	return note, nil
}

func (g *grafeasServerMock) BatchCreateNotes(context.Context, *grafeas.BatchCreateNotesRequest) (*grafeas.BatchCreateNotesResponse, error) {
	return nil, nil
}

func (g *grafeasServerMock) UpdateNote(context.Context, *grafeas.UpdateNoteRequest) (*grafeas.Note, error) {
	return nil, nil
}

func (g *grafeasServerMock) ListNoteOccurrences(context.Context, *grafeas.ListNoteOccurrencesRequest) (*grafeas.ListNoteOccurrencesResponse, error) {
	return nil, nil
}

func (g *grafeasServerMock) GetVulnerabilityOccurrencesSummary(context.Context, *grafeas.GetVulnerabilityOccurrencesSummaryRequest) (*grafeas.VulnerabilityOccurrencesSummary, error) {
	return nil, nil
}
