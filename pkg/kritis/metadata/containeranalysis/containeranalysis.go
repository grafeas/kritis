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
<<<<<<< HEAD
	"github.com/google/go-containerregistry/pkg/name"
=======
	"strings"

	gen "cloud.google.com/go/devtools/containeranalysis/apiv1alpha1"
	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
>>>>>>> set
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
)

const (
	PkgVulnerability = "PACKAGE_VULNERABILITY"
	PageSize         = int32(100)
)

// The ContainerAnalysis struct implements MetadataFetcher Interface.
type ContainerAnalysis struct {
	client *gen.Client
	ctx    context.Context
}

func NewContainerAnalysisClient() (*ContainerAnalysis, error) {
	ctx := context.Background()
	client, err := gen.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return &ContainerAnalysis{
		client: client,
		ctx:    ctx,
	}, nil
}

// GetVulnerabilites gets Package Vulnerabilities Occurrences for a specified image.
func (c ContainerAnalysis) GetVulnerabilities(containerImage string) ([]metadata.Vulnerability, error) {
	// Make sure container image is a GCR image
	ref, err := name.ParseReference(containerImage, name.WeakValidation)
	if err != nil {
		return nil, err
	}
	if !isRegistryGCR(ref.Context().RegistryStr()) {
		return nil, fmt.Errorf("%s is not a valid image hosted in GCR", containerImage)
	}
	project := strings.Split(containerImage, "/")[1]

	req := &containeranalysispb.ListOccurrencesRequest{
		Filter:   fmt.Sprintf("resource_url=%q AND kind=%q", fmt.Sprintf("https://%s", containerImage), PkgVulnerability),
		PageSize: PageSize,
		Parent:   fmt.Sprintf("projects/%s", project),
	}
	it := c.client.ListOccurrences(c.ctx, req)
	vulnz := []metadata.Vulnerability{}
	for {
		occ, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		vulnz = append(vulnz, GetVulnerabilityFromOccurence(occ))
	}
	return vulnz, nil
}

func GetVulnerabilityFromOccurence(occ *containeranalysispb.Occurrence) metadata.Vulnerability {
	vulnDetails := occ.GetDetails().(*containeranalysispb.Occurrence_VulnerabilityDetails).VulnerabilityDetails
	hasFixAvailable := isFixAvaliable(vulnDetails.GetPackageIssue())
	vulnerability := metadata.Vulnerability{
		Severity:        containeranalysispb.VulnerabilityType_Severity_name[int32(vulnDetails.Severity)],
		HasFixAvailable: hasFixAvailable,
		CVE:             occ.GetNoteName(),
	}
	return vulnerability
}

func isFixAvaliable(pis []*containeranalysispb.VulnerabilityType_PackageIssue) bool {
	for _, pi := range pis {
		if pi.GetFixedLocation().GetVersion().Kind == containeranalysispb.VulnerabilityType_Version_MAXIMUM {
			// If FixedLocation.Version.Kind = MAXIMUM then no fix is available. Return false
			return false
		}
	}
	return true
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

func getProjectFromNotReference(ref string) (string, error) {
	if str := strings.Split(ref, "/"); len(str) < 3 {
		return "", fmt.Errorf("Invalid Note Reference. Should be in format <api>/projects/<project_id")
	}
	return strings.Split(ref, "/")[2], nil
}

func (c ContainerAnalysis) CreateAttestationNote(aa kritisv1beta1.AttestationAuthority) error {
	noteProject, err := getProjectFromNotReference(aa.NoteReference)
	if err != nil {
		return err
	}
	aaNote := &containeranalysispb.AttestationAuthority{
		Hint: &containeranalysispb.AttestationAuthority_AttestationAuthorityHint{
			HumanReadableName: aa.Name,
		},
	}
	note := containeranalysispb.Note{
		Name:             fmt.Sprintf("projects/%s/notes/%s", noteProject, aa.Name),
		ShortDescription: fmt.Sprintf("Image Policy Security Attestor"),
		LongDescription:  fmt.Sprintf("Image Policy Security Attestor deployed in %s namespace", aa.Namespace),
		NoteType: &containeranalysispb.Note_AttestationAuthority{
			AttestationAuthority: aaNote,
		},
	}

	req := &containeranalysispb.CreateNoteRequest{
		Note:   &note,
		NoteId: aa.Name,
		Parent: fmt.Sprintf("projects/%s", noteProject),
	}
	_, err = c.client.CreateNote(c.ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (c ContainerAnalysis) GetAttestationNote(aa kritisv1beta1.AttestationAuthority) (*containeranalysispb.Note, error) {
	noteProject, err := getProjectFromNotReference(aa.NoteReference)
	if err != nil {
		return nil, err
	}
	req := &containeranalysispb.GetNoteRequest{
		Name: fmt.Sprintf("projects/%s/notes/%s", noteProject, aa.Name),
	}
	resp, err := c.client.GetNote(c.ctx, req)
	return resp, nil
}

// This is used for Testing.
func (c ContainerAnalysis) DeleteAttestationNote(aa kritisv1beta1.AttestationAuthority) error {
	noteProject, err := getProjectFromNotReference(aa.NoteReference)
	if err != nil {
		return err
	}
	req := &containeranalysispb.DeleteNoteRequest{
		Name: fmt.Sprintf("projects/%s/notes/%s", noteProject, aa.Name),
	}
	return c.client.DeleteNote(c.ctx, req)
}
