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
	goodImage = "gcr.io/kritis-project/kritis-server@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8"
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
		signingSecret *secrets.PGPSigningSecret
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
	secret := testutil.CreateSecret(t, "test")
	container, err := NewAtomicContainerSig(goodImage, map[string]string{})
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	inputSig, err := container.CreateAttestationSignature(secret)
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}

	tests := []struct {
		name      string
		shouldErr bool
		publickey string
	}{
		{
			name:      "verify using same public key",
			shouldErr: false,
			publickey: secret.PublicKey,
		},
		{
			name:      "verify using another public key",
			shouldErr: true,
			publickey: testutil.PublicTestKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verificationErr := container.VerifyAttestationSignature(test.publickey, inputSig)
			testutil.CheckError(t, test.shouldErr, verificationErr)
		})
	}
}

func TestGPGArmorSignVerifyIntegration(t *testing.T) {
	container, err := NewAtomicContainerSig(goodImage, map[string]string{})
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	if err := container.VerifyAttestationSignature(testutil.Base64PublicTestKey(t), expectedSig); err != nil {
		t.Fatalf("unexpected error %s", err)
	}
}

// Base64 encoded signarute.
// Created using gpg --armor --sign -u test@kritis.org <atomic_host_json_representation.txt> | base64
var expectedSig = "LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tCgpvd0did012TXdNVzRyanR6aW1DeTZHTEcwd2Uwa3hpaWszMU9WaXNsRjJXV1pDWW41aWhaVlN0bHBxVG1sV1NXClZJTFlLZm5KMmFsRnVrV3BhYWxGcVhuSnFVcFdTdW5KUlhxWitmclpJQjNGdWdWRitWbXB5U1V3Ym5GcVVWbHEKa1ZLdGpsSm1ibUo2S3BJUnVZbDVtV21weFNXNktabnBRQXBvVUhGR29wR3BtVldTY1pweGFuSnlXb3FSZWJLbApoWm1Kc2FGUllwcXh1YVdaZ1psNXFubEtrcEdGZ1lGNW9xR3BtVm1xWWFxQmlWR3lxWVdaVVdwcWluRmFtbUdTClViSUZ5TEtTeWdLUTB4Skw4bk16a3hXUzgvTktFalB6VW9zVWlqUFQ4eEpMU290U2xXcHJPeG1Qc0RBd2NqSG8KaVNteVhHcGUrdlhyMXplcjVuMXNQUW9MRGxZbVVGQUl5SlFBWGVjQThZNWVmbEU2QXhlbkFFekppK2ZjL3dNeQpDOFVQOFM5WnZzQjVXdmczNVNYNlMrWFNXdlAxanEvYUovek9Za2VkaHVHUm9BdWVwL25rY3Zaa0JQWHN0RlppCmMzcnNwZDl3NktDN2tHOXY3NTc0WSsxWHN2bVAvTGtjWFNYOXNxRnc3ZG5mRXlkVSt5NHhmdi9sUzkycFMzOFcKdjJPNmZWQTEzWFhCNnFlZE1YS3JGMmpvdXUrZWwzMm5ZTEhsdS9BS3FmUyt2d2NtQ1BleHJqK1JkM1A5Vm9HNApLY21yVkp1ZWxpek9uelhWYVpXT1VzQnBqdVJYejN4Vys0bE5YckZ0WWNTVGpoVlI4cE1NNDNXRStlZVUzWCtYCjZSRzR1ZTNNZlptYmxpZmJUM1JYaUY2YyttSnk1Zy96TkFrZHRoMGZRb0k5RnBWL3NWazgvVVRHQmVZSmYrMlkKSTdOa3BwMzRPdW5CaXFpM2RYYWR5NXdNMWVyYWx1ZThPY0ZhVmhJUlZMS3QyS3B2YzJIRys1MC9lVk5aQ2dKZQo3VkxvVzVZcG0vMVg3ZTZKTUNPRFZRL1dxTXlJWWxsbTV6L3pZNmlVWDVVVzc2eWdxdGRUNWxuZGJCS3QzQ041Cm4ySGRoTjJucXo0K3VoRzdVbStWVkdUMXlRS3puOHV1K0hCZnZhdDNMVkh2MDlFVFF1MUMxNXFtWnZheXVWMWkKMWxMeE9jVDBiLzNYTjIyZjdrNFg4MWI3cmdZQQo9ZU9GVwotLS0tLUVORCBQR1AgTUVTU0FHRS0tLS0tCg=="
