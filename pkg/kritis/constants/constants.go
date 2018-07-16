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

package constants

const (
	// Used for blocking all images with CVEs, except for whitelisted CVEs
	BLOCKALL = "BLOCKALL"

	// InvalidImageSecPolicy is the key for labels and annotations
	InvalidImageSecPolicy = "invalidImageSecPolicy"

	// A list of label values
	InvalidDigestLabel      = "Image not resolved to digest."
	PreviouslyAttestedLabel = "Previously attested."
	NoAttestationsLabel     = "No valid attestations present. This pod will not be able to restart in future"
)
