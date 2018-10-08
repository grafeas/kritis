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
	"strings"

	ca "cloud.google.com/go/containeranalysis/apiv1beta1"
	"github.com/golang/glog"
	"github.com/google/go-containerregistry/pkg/name"
	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/attestation"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	pkg "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/package"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/vulnerability"
)

// Container Analysis Library Specific Constants.
const (
	PkgVulnerability     = "PACKAGE_VULNERABILITY"
	AttestationAuthority = "ATTESTATION_AUTHORITY"
)

// Client struct implements Fetcher Interface.
type Client struct {
	client *ca.GrafeasV1Beta1Client
	ctx    context.Context
}

func New() (*Client, error) {
	ctx := context.Background()
	client, err := ca.NewGrafeasV1Beta1Client(ctx)
	if err != nil {
		return nil, err
	}
	return &Client{
		client: client,
		ctx:    ctx,
	}, nil
}

//Vulnerabilities gets Package Vulnerabilities Occurrences for a specified image.
func (c Client) Vulnerabilities(containerImage string) ([]metadata.Vulnerability, error) {
	occs, err := c.fetchOccurrence(containerImage, PkgVulnerability)
	if err != nil {
		return nil, err
	}
	vulnz := []metadata.Vulnerability{}
	for _, occ := range occs {
		if v := getVulnerabilityFromOccurence(occ); v != nil {
			vulnz = append(vulnz, *v)
		}
	}
	return vulnz, nil
}

//Attestations gets AttesationAuthority Occurrences for a specified image.
func (c Client) Attestations(containerImage string) ([]metadata.PGPAttestation, error) {
	occs, err := c.fetchOccurrence(containerImage, AttestationAuthority)
	if err != nil {
		return nil, err
	}
	p := make([]metadata.PGPAttestation, len(occs))
	for i, occ := range occs {
		p[i] = getPgpAttestationFromOccurrence(occ)
	}
	return p, nil
}

func (c Client) fetchOccurrence(containerImage string, kind string) ([]*grafeas.Occurrence, error) {
	// Make sure container image valid and is a GCR image
	if !isValidImageOnGCR(containerImage) {
		return nil, fmt.Errorf("%s is not a valid image hosted in GCR", containerImage)
	}
	req := &grafeas.ListOccurrencesRequest{
		Filter:   fmt.Sprintf("resource_url=%q AND kind=%q", getResourceURL(containerImage), kind),
		PageSize: constants.PageSize,
		Parent:   fmt.Sprintf("projects/%s", getProjectFromContainerImage(containerImage)),
	}
	it := c.client.ListOccurrences(c.ctx, req)
	occs := []*grafeas.Occurrence{}
	for {
		occ, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		occs = append(occs, occ)
	}
	return occs, nil
}

func getVulnerabilityFromOccurence(occ *grafeas.Occurrence) *metadata.Vulnerability {
	vulnDetails := occ.GetVulnerability()
	if vulnDetails == nil {
		return nil
	}
	hasFixAvailable := isFixAvailable(vulnDetails.GetPackageIssue())
	vulnerability := metadata.Vulnerability{
		Severity:        vulnerability.Severity_name[int32(vulnDetails.Severity)],
		HasFixAvailable: hasFixAvailable,
		CVE:             occ.GetNoteName(),
	}
	return &vulnerability
}

func isFixAvailable(pis []*vulnerability.PackageIssue) bool {
	for _, pi := range pis {
		if pi.GetFixedLocation().GetVersion().Kind == pkg.Version_MAXIMUM {
			// If FixedLocation.Version.Kind = MAXIMUM then no fix is available. Return false
			return false
		}
	}
	return true
}

func isValidImageOnGCR(containerImage string) bool {
	ref, err := name.ParseReference(containerImage, name.WeakValidation)
	if err != nil {
		glog.Warning(err)
		return false
	}
	return isRegistryGCR(ref.Context().RegistryStr())
}

func isRegistryGCR(r string) bool {
	registry := strings.Split(r, ".")
	if len(registry) < 2 {
		return false
	}
	if registry[len(registry)-2] != "gcr" || registry[len(registry)-1] != "io" {
		return false
	}
	return true
}

func getResourceURL(containerImage string) string {
	return fmt.Sprintf("%s%s", constants.ResourceURLPrefix, containerImage)
}

func getResource(image string) *grafeas.Resource {
	return &grafeas.Resource{Uri: getResourceURL(image)}
}

func getProjectFromNoteReference(ref string) (string, error) {
	str := strings.Split(ref, "/")
	if len(str) < 3 {
		return "", fmt.Errorf("invalid Note Reference. should be in format <api>/projects/<project_id>")
	}
	return str[2], nil
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
	pgpSigningKey *secrets.PGPSigningSecret) (*grafeas.Occurrence, error) {
	if !isValidImageOnGCR(containerImage) {
		return nil, fmt.Errorf("%s is not a valid image hosted in GCR", containerImage)
	}
	fingerprint, err := util.GetAttestationKeyFingerprint(pgpSigningKey)
	if err != nil {
		return nil, fmt.Errorf("Can't get fingerprint from PGP siging key %s: %v", pgpSigningKey.SecretName, err)
	}

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
		Resource: getResource(containerImage),
		NoteName: note.GetName(),
		Details:  attestationDetails,
	}
	// Create the AttestationAuthrity Occurrence in the Project AttestationAuthority Note.
	req := &grafeas.CreateOccurrenceRequest{
		Occurrence: occ,
		Parent:     fmt.Sprintf("projects/%s", getProjectFromContainerImage(containerImage)),
	}
	// Call create Occurrence Api
	return c.client.CreateOccurrence(c.ctx, req)
}

func getPgpAttestationFromOccurrence(occ *grafeas.Occurrence) metadata.PGPAttestation {
	pgp := occ.GetAttestation().GetAttestation().GetPgpSignedAttestation()
	return metadata.PGPAttestation{
		Signature: pgp.GetSignature(),
		KeyID:     pgp.GetPgpKeyId(),
		OccID:     occ.GetName(),
	}
}

func getProjectFromContainerImage(image string) string {
	tok := strings.Split(image, "/")
	if len(tok) < 2 {
		return ""
	}
	return tok[1]
}

// The following methods are used for Testing

// DeleteAttestationNote deletes a note for given AttestationAuthority
func (c Client) DeleteAttestationNote(aa *kritisv1beta1.AttestationAuthority) error {
	noteProject, err := getProjectFromNoteReference(aa.Spec.NoteReference)
	if err != nil {
		return err
	}
	req := &grafeas.DeleteNoteRequest{
		Name: fmt.Sprintf("projects/%s/notes/%s", noteProject, aa.Name),
	}
	return c.client.DeleteNote(c.ctx, req)
}

// DeleteOccurrence deletes an occurrence with given ID
func (c Client) DeleteOccurrence(ID string) error {
	req := &grafeas.DeleteOccurrenceRequest{
		Name: ID,
	}
	return c.client.DeleteOccurrence(c.ctx, req)
}
