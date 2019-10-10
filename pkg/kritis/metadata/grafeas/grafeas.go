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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc/credentials"

	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"golang.org/x/net/context"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/attestation"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	"google.golang.org/grpc"
)

const (
	PkgVulnerability     = "PACKAGE_VULNERABILITY"
	AttestationAuthority = "ATTESTATION_AUTHORITY"
	DefaultProject       = "kritis" // DefaultProject is the default project name, only single project is supported
)

// Client implements the Fetcher interface using grafeas API.
type Client struct {
	client grafeas.GrafeasV1Beta1Client
	ctx    context.Context
}

// ValidateConfig checks whether the specified configuration is valid
func ValidateConfig(config kritisv1beta1.GrafeasConfigSpec) error {
	if config.Addr == "" {
		return fmt.Errorf("missing Grafeas address")
	}
	if strings.HasPrefix(config.Addr, "/") { // Unix socket address
		return nil
	}
	return nil
}

func New(config kritisv1beta1.GrafeasConfigSpec, certs *CertConfig) (*Client, error) {
	if err := ValidateConfig(config); err != nil {
		return nil, err
	}
	ctx := context.Background()
	var conn *grpc.ClientConn
	if strings.HasPrefix(config.Addr, "/") {
		var err error
		conn, err = grpc.Dial(config.Addr,
			grpc.WithInsecure(),
			grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
				return net.DialTimeout("unix", addr, timeout)
			}))
		if err != nil {
			return nil, err
		}
	} else {
		certificate, err := tls.LoadX509KeyPair(certs.CertFile, certs.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("could not load client key pair: %s", err)
		}
		certPool := x509.NewCertPool()
		ca, err := ioutil.ReadFile(certs.CAFile)
		if err != nil {
			return nil, fmt.Errorf("could not read ca certificate: %s", err)
		}

		if ok := certPool.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("failed to append ca certs")
		}
		server, _, err := net.SplitHostPort(config.Addr)
		if err != nil {
			return nil, err
		}
		creds := credentials.NewTLS(&tls.Config{
			ServerName:   server,
			Certificates: []tls.Certificate{certificate},
			RootCAs:      certPool,
		})
		conn, err = grpc.Dial(config.Addr, grpc.WithTransportCredentials(creds))
		if err != nil {
			return nil, err
		}
	}
	return &Client{
		client: grafeas.NewGrafeasV1Beta1Client(conn),
		ctx:    ctx,
	}, nil
}

// Close closes client connections
func (c Client) Close() {
	// Not Implemented.
	// grafeas.GrafeasV1Beta1Client does not expose Close() method for conn.
}

// Vulnerabilities gets Package Vulnerabilities Occurrences for a specified image.
func (c Client) Vulnerabilities(containerImage string) ([]metadata.Vulnerability, error) {
	occs, err := c.fetchVulnerabilityOccurrence(containerImage, PkgVulnerability)
	if err != nil {
		return nil, err
	}
	var vulnz []metadata.Vulnerability
	for _, occ := range occs {
		if v := util.GetVulnerabilityFromOccurrence(occ); v != nil {
			vulnz = append(vulnz, *v)
		}
	}
	return vulnz, nil
}

// Attestations gets AttesationAuthority Occurrences for a specified image.
func (c Client) Attestations(containerImage string, aa *kritisv1beta1.AttestationAuthority) ([]metadata.PGPAttestation, error) {
	var p []metadata.PGPAttestation

	occs, err := c.fetchAttestationOccurrence(containerImage, AttestationAuthority, aa)
	if err != nil {
		return nil, err
	}
	for _, occ := range occs {
		p = append(p, util.GetPgpAttestationFromOccurrence(occ))
	}

	return p, nil
}

// CreateAttestationNote creates an attestation note from AttestationAuthority
func (c Client) CreateAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeas.Note, error) {
	noteProject, err := getProjectFromNoteReference(aa.Spec.NoteReference)
	if err != nil {
		return nil, err
	}

	aaNote := &attestation.Authority{
		Hint: &attestation.Authority_Hint{
			HumanReadableName: aa.Name,
		},
	}
	note := grafeas.Note{
		Name:             fmt.Sprintf("projects/%s/notes/%s", noteProject, aa.Name),
		ShortDescription: fmt.Sprintf("Image Policy Security Attestor"),
		LongDescription:  fmt.Sprintf("Image Policy Security Attestor deployed in %s namespace", aa.Namespace),
		Type: &grafeas.Note_AttestationAuthority{
			AttestationAuthority: aaNote,
		},
	}

	req := &grafeas.CreateNoteRequest{
		Note:   &note,
		NoteId: aa.Name,
		Parent: fmt.Sprintf("projects/%s", noteProject),
	}
	return c.client.CreateNote(c.ctx, req)
}

//AttestationNote returns a note if it exists for given AttestationAuthority
func (c Client) AttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeas.Note, error) {
	noteProject, err := getProjectFromNoteReference(aa.Spec.NoteReference)
	if err != nil {
		return nil, err
	}

	req := &grafeas.GetNoteRequest{
		Name: fmt.Sprintf("projects/%s/notes/%s", noteProject, aa.Name),
	}
	return c.client.GetNote(c.ctx, req)
}

// CreateAttestationOccurence creates an Attestation occurrence for a given image and secret.
func (c Client) CreateAttestationOccurence(note *grafeas.Note,
	containerImage string,
	pgpSigningKey *secrets.PGPSigningSecret, proj string) (*grafeas.Occurrence, error) {
	fingerprint := util.GetAttestationKeyFingerprint(pgpSigningKey)

	// Create Attestation Signature
	sig, err := util.CreateAttestationSignature(containerImage, pgpSigningKey)
	if err != nil {
		return nil, err
	}
	pgpSignedAttestation := &attestation.PgpSignedAttestation{
		Signature: sig,
		KeyId: &attestation.PgpSignedAttestation_PgpKeyId{
			PgpKeyId: fingerprint,
		},
		ContentType: attestation.PgpSignedAttestation_SIMPLE_SIGNING_JSON,
	}

	attestationDetails := &grafeas.Occurrence_Attestation{
		Attestation: &attestation.Details{
			Attestation: &attestation.Attestation{
				Signature: &attestation.Attestation_PgpSignedAttestation{
					PgpSignedAttestation: pgpSignedAttestation,
				}},
		},
	}
	occ := &grafeas.Occurrence{
		Resource: util.GetResource(containerImage),
		NoteName: note.GetName(),
		Details:  attestationDetails,
	}
	// Create the AttestationAuthority Occurrence in the Project AttestationAuthority Note.
	req := &grafeas.CreateOccurrenceRequest{
		Occurrence: occ,
		Parent:     fmt.Sprintf("projects/%s", proj),
	}
	return c.client.CreateOccurrence(c.ctx, req)
}

func (c Client) fetchVulnerabilityOccurrence(containerImage string, kind string) ([]*grafeas.Occurrence, error) {
	req := &grafeas.ListOccurrencesRequest{
		Filter:   fmt.Sprintf("resource_url=%q AND kind=%q", util.GetResourceURL(containerImage), kind),
		PageSize: constants.PageSize,
		Parent:   fmt.Sprintf("projects/%s", DefaultProject),
	}
	var occs []*grafeas.Occurrence
	var nextPageToken string
	for {
		req.PageToken = nextPageToken
		resp, err := c.client.ListOccurrences(c.ctx, req)
		if err != nil {
			return nil, err
		}
		occs = append(occs, resp.Occurrences...)
		nextPageToken = resp.NextPageToken
		if len(occs) == 0 || nextPageToken == "" {
			break
		}
	}
	return occs, nil
}

func (c Client) fetchAttestationOccurrence(containerImage string, kind string, aa *kritisv1beta1.AttestationAuthority) ([]*grafeas.Occurrence, error) {
	noteProject, err := getProjectFromNoteReference(aa.Spec.NoteReference)
	if err != nil {
		return nil, err
	}

	req := &grafeas.ListOccurrencesRequest{
		Filter:   fmt.Sprintf("resource_url=%q AND kind=%q", util.GetResourceURL(containerImage), kind),
		PageSize: constants.PageSize,
		Parent:   fmt.Sprintf("projects/%s", noteProject),
	}
	var occs []*grafeas.Occurrence
	var nextPageToken string
	for {
		req.PageToken = nextPageToken
		resp, err := c.client.ListOccurrences(c.ctx, req)
		if err != nil {
			return nil, err
		}
		occs = append(occs, resp.Occurrences...)
		nextPageToken = resp.NextPageToken
		if len(occs) == 0 || nextPageToken == "" {
			break
		}
	}
	return occs, nil
}

func getProjectFromNoteReference(ref string) (string, error) {
	str := strings.Split(ref, "/")
	if len(str) < 3 {
		return "", fmt.Errorf("invalid Note Reference. should be in format <api>/projects/<project_id>")
	}
	return str[2], nil
}
