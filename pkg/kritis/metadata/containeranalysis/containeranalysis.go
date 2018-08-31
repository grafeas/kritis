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

	"github.com/golang/glog"

	gen "cloud.google.com/go/devtools/containeranalysis/apiv1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
	cpb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
)

// Container Analysis Library Specific Constants.
const (
	PkgVulnerability     = "PACKAGE_VULNERABILITY"
	AttestationAuthority = "ATTESTATION_AUTHORITY"
)

// The ContainerAnalysis struct implements Fetcher Interface.
type Client struct {
	client *gen.Client
	ctx    context.Context
}

func New() (*Client, error) {
	ctx := context.Background()
	client, err := gen.NewClient(ctx)
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
		vulnz = append(vulnz, getVulnerabilityFromOccurence(occ))
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

func (c Client) fetchOccurrence(containerImage string, kind string) ([]*cpb.Occurrence, error) {
	// Make sure container image valid and is a GCR image
	if !isValidImageOnGCR(containerImage) {
		return nil, fmt.Errorf("%s is not a valid image hosted in GCR", containerImage)
	}
	project := strings.Split(containerImage, "/")[1]
	req := &cpb.ListOccurrencesRequest{
		Filter:   fmt.Sprintf("resource_url=%q AND kind=%q", getResourceURL(containerImage), kind),
		PageSize: constants.PageSize,
		Parent:   fmt.Sprintf("projects/%s", project),
	}
	it := c.client.ListOccurrences(c.ctx, req)
	occs := []*cpb.Occurrence{}
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

func getVulnerabilityFromOccurence(occ *cpb.Occurrence) metadata.Vulnerability {
	vulnDetails := occ.GetDetails().(*cpb.Occurrence_VulnerabilityDetails).VulnerabilityDetails
	hasFixAvailable := isFixAvaliable(vulnDetails.GetPackageIssue())
	vulnerability := metadata.Vulnerability{
		Severity:        cpb.VulnerabilityType_Severity_name[int32(vulnDetails.Severity)],
		HasFixAvailable: hasFixAvailable,
		CVE:             occ.GetNoteName(),
	}
	return vulnerability
}

func isFixAvaliable(pis []*cpb.VulnerabilityType_PackageIssue) bool {
	for _, pi := range pis {
		if pi.GetFixedLocation().GetVersion().Kind == cpb.VulnerabilityType_Version_MAXIMUM {
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

func getProjectFromNoteReference(ref string) (string, error) {
	str := strings.Split(ref, "/")
	if len(str) < 3 {
		return "", fmt.Errorf("invalid Note Reference. should be in format <api>/projects/<project_id>")
	}
	return str[2], nil
}

// CreateAttestationNote creates an attestation note from AttestationAuthority
func (c Client) CreateAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*cpb.Note, error) {
	noteProject, err := getProjectFromNoteReference(aa.Spec.NoteReference)
	if err != nil {
		return nil, err
	}
	aaNote := &cpb.AttestationAuthority{
		Hint: &cpb.AttestationAuthority_AttestationAuthorityHint{
			HumanReadableName: aa.Name,
		},
	}
	note := cpb.Note{
		Name:             fmt.Sprintf("projects/%s/notes/%s", noteProject, aa.Name),
		ShortDescription: fmt.Sprintf("Image Policy Security Attestor"),
		LongDescription:  fmt.Sprintf("Image Policy Security Attestor deployed in %s namespace", aa.Namespace),
		NoteType: &cpb.Note_AttestationAuthority{
			AttestationAuthority: aaNote,
		},
	}

	req := &cpb.CreateNoteRequest{
		Note:   &note,
		NoteId: aa.Name,
		Parent: fmt.Sprintf("projects/%s", noteProject),
	}
	return c.client.CreateNote(c.ctx, req)
}

//AttestationNote returns a note if it exists for given AttestationAuthority
func (c Client) AttestationNote(aa *kritisv1beta1.AttestationAuthority) (*cpb.Note, error) {
	noteProject, err := getProjectFromNoteReference(aa.Spec.NoteReference)
	if err != nil {
		return nil, err
	}
	req := &cpb.GetNoteRequest{
		Name: fmt.Sprintf("projects/%s/notes/%s", noteProject, aa.Name),
	}
	return c.client.GetNote(c.ctx, req)
}

// CreateAttestationOccurence creates an Attestation occurrence for a given image and secret.
func (c Client) CreateAttestationOccurence(note *cpb.Note,
	containerImage string,
	pgpSigningKey *secrets.PGPSigningSecret) (*cpb.Occurrence, error) {
	if !isValidImageOnGCR(containerImage) {
		return nil, fmt.Errorf("%s is not a valid image hosted in GCR", containerImage)
	}
	// Create Attestation Signature
	sig, err := util.CreateAttestationSignature(containerImage, pgpSigningKey)
	if err != nil {
		return nil, err
	}
	pgpSignedAttestation := &cpb.PgpSignedAttestation{
		Signature: sig,
		KeyId: &cpb.PgpSignedAttestation_PgpKeyId{
			PgpKeyId: pgpSigningKey.SecretName,
		},
	}

	attestationDetails := &cpb.Occurrence_Attestation{
		Attestation: &cpb.AttestationAuthority_Attestation{
			Signature: &cpb.AttestationAuthority_Attestation_PgpSignedAttestation{
				PgpSignedAttestation: pgpSignedAttestation,
			},
		},
	}
	occ := &cpb.Occurrence{
		ResourceUrl: getResourceURL(containerImage),
		NoteName:    note.GetName(),
		Details:     attestationDetails,
	}
	// Create the AttestationAuthrity Occurrence in the Project AttestationAuthority Note.
	req := &cpb.CreateOccurrenceRequest{
		Occurrence: occ,
		Parent:     fmt.Sprintf("projects/%s", strings.Split(containerImage, "/")[1]),
	}
	// Call create Occurrence Api
	return c.client.CreateOccurrence(c.ctx, req)
}

func getPgpAttestationFromOccurrence(occ *cpb.Occurrence) metadata.PGPAttestation {
	pgp := occ.GetDetails().(*cpb.Occurrence_Attestation).Attestation.GetPgpSignedAttestation()
	return metadata.PGPAttestation{
		Signature: pgp.GetSignature(),
		KeyID:     pgp.GetPgpKeyId(),
		OccID:     occ.GetName(),
	}
}

// The following methods are used for Testing

// DeleteAttestationNote deletes a note for given AttestationAuthority
func (c Client) DeleteAttestationNote(aa *kritisv1beta1.AttestationAuthority) error {
	noteProject, err := getProjectFromNoteReference(aa.Spec.NoteReference)
	if err != nil {
		return err
	}
	req := &cpb.DeleteNoteRequest{
		Name: fmt.Sprintf("projects/%s/notes/%s", noteProject, aa.Name),
	}
	return c.client.DeleteNote(c.ctx, req)
}

// DeleteOccurrence deletes an occurrence with given ID
func (c Client) DeleteOccurrence(ID string) error {
	req := &cpb.DeleteOccurrenceRequest{
		Name: ID,
	}
	return c.client.DeleteOccurrence(c.ctx, req)
}
