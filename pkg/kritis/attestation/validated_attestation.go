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

package attestation

// ValidatedAttestation represents a trusted and verified attestation made by
// the named attestation authority about the named container image.  The
// payload is a JSON object (represented as a map) which the attestation
// contains.  The payload can be thought of as a set of claims that the creator
// of the attestation asserts.  This is similar to JWT claims.
// An example ValidateAttestation may look like:
// {
//   AttestorName: "build-attestor",
//   Image: "gcr.io/img@sha256:abcd",
//   Payload: { "source_path": "github.com/some-repo" }
// }
type ValidatedAttestation struct {
	AttestorName string
	Image string
	Payload      map[string]interface{}
}
