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
	"testing"
)

// func TestGetVulnerabilityFromOccurence(t *testing.T) {
// 	vulnerability := containeranalysispb.VulnerabilityType_VulnerabilityDetails{
// 		Severity: "LOW",
// 		PackageIssue: VulnerabilityType_PackageIssue{
// 			AffectedLocation: VulnerabilityType_VulnerabilityLocation{
// 				CpeUri:  "cpe:/o:debian:debian_linux:7",
// 				Package: "openssl",
// 			},
// 		},
// 	}
// }

func TestGetVulnerabilities(t *testing.T) {
	d, err := GetClient()
	if err != nil {
		t.Fatal("Could not initialize the client")
	}
	vuln, err := d.GetVulnerabilities("tejaldesai-personal", "https://gcr.io/gcp-runtimes/go1-builder@sha256:81540dfae4d3675c06113edf90c6658a1f290c2c8ebccd19902ddab3f959aa71")
	if err != nil {
		t.Fatal("Could not initialize the client")
	}
	fmt.Println(vuln)
}
