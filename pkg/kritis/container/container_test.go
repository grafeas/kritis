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
			i := strings.Join([]string{test.imageName, test.imageDigest}, test.concatString)
			actual, err := NewAtomicContainerSig(i, nil)
			expected := AtomicContainerSig{
				Critical: &critical{
					Identity: &identity{
						DockerRef: test.imageName,
					},
					Image: &image{
						Digest: test.imageDigest,
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

func TestCriticalEquals(t *testing.T) {
	tcs := []struct {
		name    string
		i1      string
		i2      string
		isEqual bool
	}{{"equal", testutil.QualifiedImage, testutil.QualifiedImage, true},
		{"not equal", testutil.QualifiedImage, testutil.IntTestImage, false},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			o1, err := newCritical(tc.i1)
			if err != nil {
				t.Fatalf("unexpected error %s", err)
			}
			o2, err := newCritical(tc.i2)
			if err != nil {
				t.Fatalf("unexpected error %s", err)
			}
			if o2.Equals(o1) != tc.isEqual {
				t.Errorf("expected objects to be equal : %t Got %t", tc.isEqual, !tc.isEqual)
			}
		})
	}
}

// Base64 encoded signarute.
// Created using gpg --armor --sign -u test@kritis.org <atomic_host_json_representation.txt> | base64
var expectedSig = `-----BEGIN PGP MESSAGE-----

owGbwMvMwMW4rjtzimCy6GLG0we0kxiik31OVislF2WWZCYn5ihZVStlpqTmlWSW
VILYKfnJ2alFukWpaalFqXnJqUpWSunJRXqZ+frZIB3FugVF+VmpySUwbnFqUVlq
kVKtjlJmbmJ6KpIRuYl5mWmpxSW6KZnpQApoUHFGopGpmVWScZpxanJyWoqRebKl
hZmJsaFRYpqxuaWZgZl5qnlKkpGFgYF5oqGpmVmqYaqBiVGyqYWZUWpqinFammGS
UbIFyLKSygKQ0xJL8nMzkxWS8/NKEjPzUosUijPT8xJLSotSlWprOxmPsDAwcjHo
iSmyXGpe+vXr1zer5n1sPQoLDlYmUFAIyJQAXecA8Y5eflE6AxenAEzJi+fc/wMy
C8UP8S9ZvsB5Wvg35SX6S+XSWvP1jq/aJ/zOYkedhuGRoAuep/nkcvZkBPXstFZi
c3rspd9w6KC7kG9v7574Y+1XsvmP/LkcXSX9sqFw7dnfEydU+y4xfv/lS92pS38W
v2O6fVA13XXB6qedMXKrF2jouu+el32nYLHlu/AKqfS+vwcmCPexrj+Rd3P9VoG4
KcmrVJuelizOnzXVaZWOUsBpjuRXz3xW+4lNXrFtYcSTjhVR8pMM43WE+eeU3X+X
6RG4ue3MfZmblifbT3RXiF6c+mJy5g/zNAkdth0fQoI9FpV/sVk8/UTGBeYJf+2Y
I7Nkpp34OunBiqi3dXady5wM1eralue8OcFaVhIRVLKt2Kpvc2HG+50/eVNZCgJe
7VLoW5Ypm/1X7e6JMCODVQ/WqMyIYllm5z/zY6iUX5UW76ygqtdT5lndbBKt3CN5
n2HdhN2nqz4+uhG7Um+VVGT1yQKzn8uu+HBfvat3LVHv09ETQu1C15qmZvayuV1i
1lLxOcT0b/3XN22f7k4X81b7rgYA
=eOFW
-----END PGP MESSAGE-----`
