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
)

// Container Analysis Library Specific Constants.
const (
	PkgVulnerability     = "PACKAGE_VULNERABILITY"
	AttestationAuthority = "ATTESTATION_AUTHORITY"
)

// Client struct implements Fetcher and ReadOnlyClient interfaces.
type Client struct {
	client *ca.GrafeasV1Beta1Client
	ctx    context.Context
}

// TODO: separate constructor methods for r/w and r/o clients
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

// Close closes client connections
func (c Client) Close() {
	c.client.Close()
}

//Vulnerabilities gets Package Vulnerabilities Occurrences for a specified image.
func (c Client) Vulnerabilities(containerImage string) ([]metadata.Vulnerability, error) {
	occs, err := c.fetchVulnerabilityOccurrence(containerImage, PkgVulnerability)
	if err != nil {
		return nil, err
	}
	vulnz := []metadata.Vulnerability{}
	for _, occ := range occs {
		if v := util.GetVulnerabilityFromOccurrence(occ); v != nil {
			vulnz = append(vulnz, *v)
		}
	}

	return vulnz, nil
}

//Attestations gets AttesationAuthority Occurrences for a specified image, using the note specified in the AttestationAuthority provided.
// This may take a few seconds to retrieve an attestation occurrence, if it was created very recently.
// For GenericAttestationPolicy, this has little impact as it's expected that attestations will be created before a pod admission request is sent.
// For ImageSecurityPolicy, which effectively caches the previous policy decision in an attestation, the policy will be re-evaluated if an attestation occurrence has not yet been retrieved.
// In most cases, it's expected that ImageSecurityPolicy will return the same decision, as vulnerability scannig process takes longer than a few seconds to run and update metadata.
func (c Client) Attestations(containerImage string, aa *kritisv1beta1.AttestationAuthority) ([]metadata.PGPAttestation, error) {
	var p []metadata.PGPAttestation

	occs, err := c.fetchAttestationOccurrence(containerImage, AttestationAuthority, aa)
	if err != nil {
		return nil, err
	}
	for _, occ := range occs {
		pgp := util.GetPgpAttestationFromOccurrence(occ)
		p = append(p, pgp)
	}

	return p, nil
}

func (c Client) fetchVulnerabilityOccurrence(containerImage string, kind string) ([]*grafeas.Occurrence, error) {
	// Make sure container image valid and is a GCR image
	if !isValidImageOnGCR(containerImage) {
		return nil, fmt.Errorf("%s is not a valid image hosted in GCR", containerImage)
	}

	req := &grafeas.ListOccurrencesRequest{
		Filter:   fmt.Sprintf("resourceUrl=%q AND kind=%q", util.GetResourceURL(containerImage), kind),
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

func (c Client) fetchAttestationOccurrence(containerImage string, kind string, auth *kritisv1beta1.AttestationAuthority) ([]*grafeas.Occurrence, error) {
	// Make sure container image valid and is a GCR image
	if !isValidImageOnGCR(containerImage) {
		return nil, fmt.Errorf("%s is not a valid image hosted in GCR", containerImage)
	}

	noteName := fmt.Sprintf("%s/notes/%s", auth.Spec.NoteReference, auth.Name)
	req := &grafeas.ListNoteOccurrencesRequest{
		Name: noteName,
		// Example:
		// 		Filter:  fmt.Sprintf("resourceUrl=%q AND kind=%q", util.GetResourceURL(containerImage), kind),
		Filter:   fmt.Sprintf("resourceUrl=%q", util.GetResourceURL(containerImage)),
		PageSize: constants.PageSize,
	}

	occs := []*grafeas.Occurrence{}
	it := c.client.ListNoteOccurrences(c.ctx, req)
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

// CreateAttestationNote creates an attestation note from AttestationAuthority
func (c Client) CreateAttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeas.Note, error) {
	noteProject, err := metadata.GetProjectFromNoteReference(aa.Spec.NoteReference)
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
	noteProject, err := metadata.GetProjectFromNoteReference(aa.Spec.NoteReference)
	if err != nil {
		return nil, err
	}
	req := &grafeas.GetNoteRequest{
		Name: fmt.Sprintf("projects/%s/notes/%s", noteProject, aa.Name),
	}
	return c.client.GetNote(c.ctx, req)
}

// CreateAttestationOccurrence creates an Attestation occurrence for a given image and secret.
func (c Client) CreateAttestationOccurrence(note *grafeas.Note,
	containerImage string,
	pgpSigningKey *secrets.PGPSigningSecret, proj string) (*grafeas.Occurrence, error) {
	if !isValidImageOnGCR(containerImage) {
		return nil, fmt.Errorf("%s is not a valid image hosted in GCR", containerImage)
	}
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
	// Create the AttestationAuthrity Occurrence.
	req := &grafeas.CreateOccurrenceRequest{
		Occurrence: occ,
		Parent:     fmt.Sprintf("projects/%s", proj),
	}
	// Call create Occurrence Api
	return c.client.CreateOccurrence(c.ctx, req)
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
	noteProject, err := metadata.GetProjectFromNoteReference(aa.Spec.NoteReference)
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
	glog.Infof("executed deletion of occurrence=%s", ID)
	return c.client.DeleteOccurrence(c.ctx, req)
}
