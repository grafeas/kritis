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

package util

import (
	"os"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/spf13/cobra"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
)

func ExitIfErr(cmd *cobra.Command, err error) {
	if err != nil {
		cmd.Println(err)
		os.Exit(1)
	}
}

func CreateAttestationSignature(image string, pgpSigningKey *secrets.PGPSigningSecret) (string, error) {
	hostSig, err := container.NewAtomicContainerSig(image, map[string]string{})
	if err != nil {
		return "", err
	}
	hostStr, err := hostSig.JSON()
	if err != nil {
		return "", err
	}
	return attestation.CreateMessageAttestation(pgpSigningKey.PublicKey, pgpSigningKey.PrivateKey, hostStr)
}

// GetOrCreateAttestationNote returns a note if exists and creates one if it does not exist.
func GetOrCreateAttestationNote(c metadata.Fetcher, a *v1beta1.AttestationAuthority) (*containeranalysispb.Note, error) {
	n, err := c.GetAttestationNote(a)
	if err == nil {
		return n, nil
	}
	return c.CreateAttestationNote(a)
}
