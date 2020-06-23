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
	"time"

	"github.com/grafeas/kritis/pkg/kritis/cryptolib"

	"google.golang.org/api/option"

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
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/discovery"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
)

// Container Analysis Library Specific Constants.
const (
	PkgVulnerability               = "PACKAGE_VULNERABILITY"
	AttestationAuthority           = "ATTESTATION_AUTHORITY"
	DEFAULT_DISCOVERY_NOTE_PROJECT = "goog-analysis"
)

// For testing -- injectable functions
var (
	createListOccurrencesRequest = defaultListOccurrencesRequest
)

// Client struct implements ReadWriteClient and ReadOnlyClient interfaces.
type Client struct {
	client *ca.GrafeasV1Beta1Client
	ctx    context.Context
}

func defaultListOccurrencesRequest(containerImage, kind string) *grafeas.ListOccurrencesRequest {
	return &grafeas.ListOccurrencesRequest{
		Filter:   fmt.Sprintf("resourceUrl=%q AND kind=%q", util.GetResourceURL(containerImage), kind),
		Parent:   fmt.Sprintf("projects/%s", getProjectFromContainerImage(containerImage)),
		PageSize: constants.PageSize,
	}
}

// TODO: separate constructor methods for r/w and r/o clients
func New(opts ...option.ClientOption) (*Client, error) {
	ctx := context.Background()
	client, err := ca.NewGrafeasV1Beta1Client(ctx, opts...)
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
		if v := metadata.GetVulnerabilityFromOccurrence(occ); v != nil {
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
func (c Client) Attestations(containerImage string, aa *kritisv1beta1.AttestationAuthority) ([]cryptolib.Attestation, error) {
	occs, err := c.fetchAttestationOccurrence(containerImage, AttestationAuthority, aa)
	if err != nil {
		return nil, err
	}

	atts := []cryptolib.Attestation{}
	for _, occ := range occs {
		att, err := metadata.GetAttestationsFromOccurrence(occ)
		if err != nil {
			return nil, err
		}
		atts = append(atts, att...)
	}
	return atts, nil
}

func (c Client) fetchVulnerabilityOccurrence(containerImage string, kind string) ([]*grafeas.Occurrence, error) {
	// Make sure container image valid and is a GCR image
	if !isValidImageOnGCR(containerImage) {
		return nil, fmt.Errorf("%s is not a valid image hosted in GCR", containerImage)
	}

	req := createListOccurrencesRequest(containerImage, kind)

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

	req := &grafeas.ListNoteOccurrencesRequest{
		Name: auth.Spec.NoteReference,
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
	noteProject, noteId, err := metadata.ParseNoteReference(aa.Spec.NoteReference)
	if err != nil {
		return nil, err
	}
	aaNote := &attestation.Authority{
		Hint: &attestation.Authority_Hint{
			HumanReadableName: aa.Name,
		},
	}
	note := grafeas.Note{
		Name:             aa.Spec.NoteReference,
		ShortDescription: fmt.Sprintf("Image Policy Security Attestor"),
		LongDescription:  fmt.Sprintf("Image Policy Security Attestor deployed in %s namespace", aa.Namespace),
		Type: &grafeas.Note_AttestationAuthority{
			AttestationAuthority: aaNote,
		},
	}

	req := &grafeas.CreateNoteRequest{
		Note:   &note,
		NoteId: noteId,
		Parent: fmt.Sprintf("projects/%s", noteProject),
	}
	return c.client.CreateNote(c.ctx, req)
}

// AttestationNote returns a note if it exists for given AttestationAuthority
func (c Client) AttestationNote(aa *kritisv1beta1.AttestationAuthority) (*grafeas.Note, error) {
	req := &grafeas.GetNoteRequest{
		Name: aa.Spec.NoteReference,
	}
	return c.client.GetNote(c.ctx, req)
}

// CreateAttestationOccurrence creates an Attestation occurrence for a given image and secret.
// TODO: refactor to reuse UploadAttestationOccurrence once #533 is merged.
func (c Client) CreateAttestationOccurrence(noteName string, containerImage string, pgpSigningKey *secrets.PGPSigningSecret, proj string) (*grafeas.Occurrence, error) {
	if !isValidImageOnGCR(containerImage) {
		return nil, fmt.Errorf("%s is not a valid image hosted in GCR", containerImage)
	}

	// Create Attestation Signature
	att, err := util.CreateAttestation(containerImage, pgpSigningKey)
	if err != nil {
		return nil, err
	}
	pgpSignedAttestation := &attestation.PgpSignedAttestation{
		Signature: string(att.Signature),
		KeyId: &attestation.PgpSignedAttestation_PgpKeyId{
			PgpKeyId: att.PublicKeyID,
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
		NoteName: noteName,
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

// UploadAttestationOccurrence uploads an Attestation occurrence for a given note, image and project.
func (c Client) UploadAttestationOccurrence(noteName string, containerImage string, att cryptolib.Attestation, proj string) (*grafeas.Occurrence, error) {
	if !isValidImageOnGCR(containerImage) {
		return nil, fmt.Errorf("%s is not a valid image hosted in GCR", containerImage)
	}

	pgpSignedAttestation := &attestation.PgpSignedAttestation{
		Signature: string(att.Signature),
		KeyId: &attestation.PgpSignedAttestation_PgpKeyId{
			PgpKeyId: att.PublicKeyID,
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
		NoteName: noteName,
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
	req := &grafeas.DeleteNoteRequest{
		Name: aa.Spec.NoteReference,
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

// Poll discovery occurrence for an image and wait until container analysis
// finishes. Throws an error if analysis is not successful or timeouts.
func (c Client) WaitForVulnzAnalysis(containerImage string, timeout time.Duration) error {
	// resourceURL := fmt.Sprintf("https://gcr.io/my-project/my-image")
	// timeout := time.Duration(5) * time.Second

	// Backoff time between tries, exponentially grows after each failure.
	nextTryWait := 1
	// Timeout clock.
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	// Find the discovery occurrence using a filter string.
	var discoveryOccurrence *grafeas.Occurrence
	for {
		// Waiting for discovery occurrence to appear.
		if discoveryOccurrence == nil {
			req := &grafeas.ListOccurrencesRequest{
				Parent: fmt.Sprintf("projects/%s", util.GetProjectFromContainerImage(containerImage)),
				// Vulnerability discovery occurrences are always associated with the
				// PACKAGE_VULNERABILITY note in the "goog-analysis" GCP project.
				Filter: fmt.Sprintf(`resourceUrl=%q AND noteProjectId=%q AND noteId="PACKAGE_VULNERABILITY"`, util.GetResourceURL(containerImage), DEFAULT_DISCOVERY_NOTE_PROJECT),
			}
			it := c.client.ListOccurrences(c.ctx, req)
			// Only one occurrence should ever be returned by ListOccurrences
			// and the given filter.
			result, err := it.Next()
			if err == iterator.Done {
				continue
			}
			if err != nil {
				return fmt.Errorf("it.Next: %v", err)
			}
			if result.GetDiscovered() != nil {
				discoveryOccurrence = result
			}
		}

		// Update analysis status and check.
		if discoveryOccurrence != nil {
			// Update the occurrence.
			req := &grafeas.GetOccurrenceRequest{Name: discoveryOccurrence.GetName()}
			updated, err := c.client.GetOccurrence(c.ctx, req)
			if err != nil {
				return fmt.Errorf("GetOccurrence: %v", err)
			}
			switch updated.GetDiscovered().GetDiscovered().GetAnalysisStatus() {
			case discovery.Discovered_FINISHED_SUCCESS:
				return nil
			case discovery.Discovered_FINISHED_FAILED:
				return fmt.Errorf("container analysis has finished unsuccessfully")
			case discovery.Discovered_FINISHED_UNSUPPORTED:
				return fmt.Errorf("container analysis resource is known not to be supported")
			}
		}

		select {
		case <-timeoutTimer.C:
			return fmt.Errorf("timeout while retrieving discovery occurrence")
		case <-time.Tick(time.Duration(nextTryWait)):
			// exponential backoff
			nextTryWait = nextTryWait * 2
		}
	}
}
