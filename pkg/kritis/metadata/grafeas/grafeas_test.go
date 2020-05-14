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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/credentials"

	"github.com/golang/protobuf/ptypes/empty"
	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	// Certificates valid for 10 years
	// Generated using cfssl
	clientCert = filepath.Join("testdata", "client.pem")
	clientKey  = filepath.Join("testdata", "client-key.pem")
	serverCert = filepath.Join("testdata", "server.pem")
	serverKey  = filepath.Join("testdata", "server-key.pem")
	ca         = filepath.Join("testdata", "ca.pem")
)

func TestNewClientTLS(t *testing.T) {
	keyPair, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}

	caData, err := ioutil.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caData)
	certs := &CertConfig{CertFile: clientCert, KeyFile: clientKey, CAFile: ca}
	config := kritisv1beta1.GrafeasConfigSpec{Addr: "127.0.0.1:9995"}
	lis, err := net.Listen("tcp", config.Addr)
	if err != nil {
		t.Fatal(err)
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{keyPair},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})

	gs := grpc.NewServer(grpc.Creds(creds))
	grafeasMock := newGrafeasServerMock()
	grafeas.RegisterGrafeasV1Beta1Server(gs, grafeasMock)
	go func() {
		if err := gs.Serve(lis); err != nil {
			t.Fatal(err)
		}
	}()
	defer func() {
		gs.GracefulStop()
	}()
	client, err := New(config, certs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.client.CreateOccurrence(context.Background(), &grafeas.CreateOccurrenceRequest{
		Occurrence: &grafeas.Occurrence{},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateConfig(t *testing.T) {
	for _, tt := range []struct {
		config      kritisv1beta1.GrafeasConfigSpec
		expectedErr bool
	}{
		{config: kritisv1beta1.GrafeasConfigSpec{Addr: "/socketaddr"}, expectedErr: false},
		// Missing address
		{config: kritisv1beta1.GrafeasConfigSpec{}, expectedErr: true},
	} {
		err := ValidateConfig(tt.config)
		if err != nil && !tt.expectedErr {
			t.Fatalf("Expected no error but got %v", err)
		} else if err == nil && tt.expectedErr {
			t.Fatalf("Expected error but got none")
		}
	}
}

func TestCreateAttestationNoteAndOccurrence(t *testing.T) {
	socketPath, err := filepath.Abs(".grafeas.sock")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	grafeasMock := newGrafeasServerMock()
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to listen on socket %v", err)
	}
	_, err = os.Stat(socketPath)
	if err != nil {
		t.Logf("File %v", err)
	}
	grafeas.RegisterGrafeasV1Beta1Server(server, grafeasMock)
	go func() {
		if err := server.Serve(lis); err != nil {
			t.Fatalf("Failed to server %v", err)
		}
	}()
	defer func() {
		server.GracefulStop()
		os.Remove(socketPath)
	}()
	client, err := New(kritisv1beta1.GrafeasConfigSpec{Addr: socketPath}, nil)
	if err != nil {
		t.Fatalf("Could not initialize the client %v", err)
	}
	aa := &kritisv1beta1.AttestationAuthority{
		Spec: kritisv1beta1.AttestationAuthoritySpec{
			NoteReference: fmt.Sprintf("projects/%s/notes/note1", DefaultProject),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "note1",
		},
	}
	if _, err := client.CreateAttestationNote(aa); err != nil {
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
	pgpKey, err := secrets.NewPgpKey(priv, "", pub)
	if err != nil {
		t.Fatalf("Unexpected error while creating PGP key %v", err)
	}
	secret := &secrets.PGPSigningSecret{
		PgpKey:     pgpKey,
		SecretName: "test",
	}
	occ, err := client.CreateAttestationOccurrence(note.GetName(), testutil.IntTestImage, secret, DefaultProject)
	if err != nil {
		t.Fatalf("Unexpected error while creating Occurrence %v", err)
	}
	expectedPgpKeyID := pgpKey.Fingerprint()
	if err != nil {
		t.Fatalf("Unexpected error while extracting PGP key id %v", err)
	}

	pgpKeyID := occ.GetAttestation().GetAttestation().GetPgpSignedAttestation().GetPgpKeyId()
	if pgpKeyID != expectedPgpKeyID {
		t.Errorf("Expected PGP key id: %q, got %q", expectedPgpKeyID, pgpKeyID)
	}

	occurrences, err := client.Attestations(testutil.IntTestImage, aa)
	if err != nil {
		t.Fatalf("Unexpected error while listing Occ %v", err)
	}
	if occurrences == nil {
		t.Fatal("Should have created at least 1 occurrence")
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
	var resp grafeas.ListNoteOccurrencesResponse
	for _, occ := range g.occurrences {
		resp.Occurrences = append(resp.Occurrences, occ)
	}
	return &resp, nil
}

func (g *grafeasServerMock) GetVulnerabilityOccurrencesSummary(context.Context, *grafeas.GetVulnerabilityOccurrencesSummaryRequest) (*grafeas.VulnerabilityOccurrencesSummary, error) {
	return nil, nil
}
