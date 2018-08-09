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
package integration

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	integration_util "github.com/grafeas/kritis/pkg/kritis/integration_util"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// A map of crd type to names of the expected CRDs to create
var CRDS = map[string]string{
	"imagesecuritypolicies.kritis.grafeas.io": "my-isp",
}

var CRD_EXAMPLE_FILES = []string{
	"attestation-authority-example.yaml",
	"image-security-policy-example.yaml",
}
var templateFile = "attestation-authority-example.template.yaml"

// Used in artifacts/integration-examples/attestation-authority-example.template.yaml
var AttestationAuthoritySecret = "test-attestor"

func setUpAttestationSecret(t *testing.T, ns string) {
	// Generate a key value pair
	pubKey, privKey := testutil.CreateKeyPair(t, AttestationAuthoritySecret)
	// get the base encoded value for public key.
	pubKeyEnc := base64.StdEncoding.EncodeToString([]byte(pubKey))

	// create a tmp dir for keys
	d, err := ioutil.TempDir("", "_keys")
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}
	defer os.RemoveAll(d)

	// create file with contents in dir
	pubFile := createFileWithContents(t, d, pubKey)

	privFile := createFileWithContents(t, d, privKey)

	// Finally create a kubernetes secret.
	cmd := exec.Command("kubectl", "create", "secret", "generic", AttestationAuthoritySecret,
		fmt.Sprintf("--from-file=public=%s", pubFile),
		fmt.Sprintf("--from-file=private=%s", privFile),
		"-n", ns)
	if _, err := integration_util.RunCmdOut(cmd); err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	sCmd := exec.Command("cp", templateFile, CRD_EXAMPLE_FILES[0])
	sCmd.Dir = "../artifacts/integration-examples"
	if _, err := integration_util.RunCmdOut(sCmd); err != nil {
		t.Fatalf("testing error: %v", err)
	}
	sCmd = exec.Command("sed", "-i", fmt.Sprintf("s/$PUB/%s/g", pubKeyEnc), CRD_EXAMPLE_FILES[0])
	sCmd.Dir = "../artifacts/integration-examples"
	if _, err := integration_util.RunCmdOut(sCmd); err != nil {
		t.Fatalf("testing error: %v", err)
	}
}

func createCRDExamples(t *testing.T, ns *v1.Namespace) {
	setUpAttestationSecret(t, ns.Name)
	for _, crd := range CRD_EXAMPLE_FILES {
		crdCmd := exec.Command("kubectl", "create", "-f", crd, "-n", ns.Name)
		crdCmd.Dir = "../artifacts/integration-examples"
		if _, err := integration_util.RunCmdOut(crdCmd); err != nil {
			t.Fatalf("testing error: %v", err)
		}
	}
}

func waitForCRDExamples(t *testing.T, ns *v1.Namespace) {
	for crd, name := range CRDS {
		err := wait.PollImmediate(500*time.Millisecond, time.Minute*2, func() (bool, error) {
			crdCmd := exec.Command("kubectl", "get", crd, name, "-n", ns.Name)
			_, err := integration_util.RunCmdOut(crdCmd)
			return (err == nil), err
		})
		if err != nil {
			t.Fatalf("timeout waiting for crds: %v", err)
		}
	}
}

func createFileWithContents(t *testing.T, d string, c string) string {
	file, err := ioutil.TempFile(d, "gpg")
	if err != nil {
		t.Fatalf("testing error: %v", err)
	}
	if _, err := file.WriteString(c); err != nil {
		t.Fatalf("testing error: %v", err)
	}
	return file.Name()
}
