/*
Copyright 2019 Google LLC

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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/attestation"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	certFile             = "kritis.crt"
	keyFile              = "kritis.key"
	caFile               = "ca.crt"
	AttestationAuthority = "ATTESTATION_AUTHORITY"
	DefaultProject       = "kritis"
	Image                = "gcr.io/kritis-tutorial/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a"
)

func main() {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial("grafeas-server:443", grpc.WithTransportCredentials(creds))
	defer conn.Close()

	client := grafeas.NewGrafeasV1Beta1Client(conn)
	log.Println("Connecting to Grafeas server")

	ctx := context.Background()
	req := createNoteRequest()
	if note, err := client.CreateNote(ctx, req); err != nil {
		log.Fatalf("Failed to create note: %v", err)
	} else {
		log.Printf("Created note %v in project %s", note, DefaultProject)
	}

	// List notes
	resp, err := client.ListNotes(ctx,
		&grafeas.ListNotesRequest{
			Parent: "projects/kritis",
		})
	if err != nil {
		log.Fatal(err)
	}

	if len(resp.Notes) != 0 {
		log.Println("Listing notes...")
		log.Println(resp.Notes)
	} else {
		log.Println("Project does not contain any notes")
	}

	if occ, err := client.CreateOccurrence(ctx, createOccRequest(req.Note)); err != nil {
		log.Fatal(err)
	} else {
		log.Println(occ)
	}
}

func createNoteRequest() *grafeas.CreateNoteRequest {
	aaNote := &attestation.Authority{
		Hint: &attestation.Authority_Hint{
			HumanReadableName: "attestation",
		},
	}
	note := grafeas.Note{
		Name:             fmt.Sprintf("projects/%s/notes/%s", DefaultProject, "att"),
		ShortDescription: fmt.Sprintf("Generic Attestation Policy Attestor"),
		LongDescription:  fmt.Sprintf("Generic Attestation Policy Attestor deployed in %s namespace", "default"),
		Type: &grafeas.Note_AttestationAuthority{
			AttestationAuthority: aaNote,
		},
	}

	return &grafeas.CreateNoteRequest{
		Note:   &note,
		NoteId: "att",
		Parent: fmt.Sprintf("projects/%s", DefaultProject),
	}
}

func createOccRequest(note *grafeas.Note) *grafeas.CreateOccurrenceRequest {
	s, err := secrets.Fetch("default", "attestor")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Retrieved secret for 'attestor': %v", s)

	// Create Attestation Signature
	att, err := util.CreateAttestation(Image, s)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	log.Printf("Created attestation signature: %q", att.Signature)

	pgpSignedAttestation := &attestation.PgpSignedAttestation{
		Signature: string(att.Signature),
		KeyId: &attestation.PgpSignedAttestation_PgpKeyId{
			PgpKeyId: att.PublicKeyID,
		},
		ContentType: attestation.PgpSignedAttestation_SIMPLE_SIGNING_JSON,
	}
	log.Printf("PGP signed attestation: %v", pgpSignedAttestation)

	attestationDetails := &grafeas.Occurrence_Attestation{
		Attestation: &attestation.Details{
			Attestation: &attestation.Attestation{
				Signature: &attestation.Attestation_PgpSignedAttestation{
					PgpSignedAttestation: pgpSignedAttestation,
				}},
		},
	}
	occ := &grafeas.Occurrence{
		Resource: &grafeas.Resource{Uri: Image},
		NoteName: note.GetName(),
		Details:  attestationDetails,
	}
	return &grafeas.CreateOccurrenceRequest{
		Occurrence: occ,
		Parent:     fmt.Sprintf("projects/%s", DefaultProject),
	}
}
