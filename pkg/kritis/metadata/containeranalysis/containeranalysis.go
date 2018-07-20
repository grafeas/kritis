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
	gen "cloud.google.com/go/devtools/containeranalysis/apiv1alpha1"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
	"strings"
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
	if !strings.HasSuffix(ref.Context().RegistryStr(), "gcr.io") {
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
