/*
Copyright 2020 Google LLC

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

import (
	"github.com/grafeas/kritis/pkg/kritis/container"
)

// AtomicContainerPayload creates an attestation payload
// which can be signed by a attestlib.Signer to obtain a
// attestlib.Attestation.
//
// This payload is in the Red Hat's Atomic Host format:
// https://github.com/aweiteka/image/blob/e5a20d98fe698732df2b142846d007b45873627f/docs/signature.md
func AtomicContainerPayload(imageUri string) ([]byte, error) {
	acs, err := container.NewAtomicContainerSig(imageUri, nil)
	if err != nil {
		return nil, err
	}
	bytes, err := acs.JSONBytes()
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
