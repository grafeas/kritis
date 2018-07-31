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
package container

import (
	"reflect"
	"strings"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
)

var (
	goodImage    = "gcr.io/kritis-project/kritis-server@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8"
	anotherImage = "gcr.io/kritis-project/kritis-server1@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8"
	badImage     = "gcr.io/kritis-project/kritis-server:tag"
)

func Test_ContainerSigCreation(t *testing.T) {
	var tests = []struct {
		name         string
		imageName    string
		imageDigest  string
		concatString string
		shouldErr    bool
	}{
		{
			name:         "GoodImage",
			imageName:    "gcr.io/kritis-project/kritis-server",
			imageDigest:  "sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8",
			concatString: "@",
			shouldErr:    false,
		},
		{
			name:         "BadImage",
			imageName:    "gcr.io/kritis-project/kritis-server",
			imageDigest:  "tag",
			concatString: ":",
			shouldErr:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := strings.Join([]string{test.imageName, test.imageDigest}, test.concatString)
			actual, err := NewAtomicContainerSig(image, nil)
			expected := AtomicContainerSig{
				Critical: &Critical{
					Identity: &ContainerIdentity{
						DockerRef: test.imageName,
					},
					Image: &ContainerImage{
						DockerDigest: test.imageDigest,
					},
					Type: "atomic container signature",
				},
			}
			testutil.CheckError(t, test.shouldErr, err)
			if !test.shouldErr && !reflect.DeepEqual(actual.Critical, expected.Critical) {
				t.Errorf("\nExpected\n%+v\nActual\n%+v", expected.Critical, actual.Critical)
			}
		})
	}
}

func TestCreateAttestationSignature(t *testing.T) {
	container, err := NewAtomicContainerSig(goodImage, map[string]string{})
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	secret := testutil.CreateSecret(t, "test")
	tests := []struct {
		name          string
		signingSecret *secrets.PgpSigningSecret
		shouldErr     bool
	}{
		{
			name:          "Good secret",
			shouldErr:     false,
			signingSecret: secret,
		},
		{
			name:          "bad secret",
			shouldErr:     false,
			signingSecret: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := container.CreateAttestationSignature(secret)
			testutil.CheckError(t, test.shouldErr, err)
		})
	}
}

func TestValidateAttestationSignature(t *testing.T) {
	secret1 := testutil.CreateSecret(t, "test")
	secret2 := testutil.CreateSecret(t, "test-another")

	container, err := NewAtomicContainerSig(goodImage, map[string]string{})
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	inputSig, err := container.CreateAttestationSignature(secret1)
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}

	tests := []struct {
		name      string
		inputSig  string
		shouldErr bool
		testSig   string
	}{
		// {
		// 	name:      "samesecret",
		// 	inputSig:  inputSig,
		// 	shouldErr: false,
		// 	testSig:   inputSig,
		// },
		{
			name:      "anotherSecret",
			inputSig:  inputSig,
			shouldErr: true,
			testSig:   inputSig,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verificationErr := container.VerifyAttestationSignature(secret2.PublicKey, test.inputSig)
			verificationErr = container.VerifyAttestationSignature(secret1.PublicKey, test.inputSig)
			testutil.CheckError(t, test.shouldErr, verificationErr)
		})
	}
}
