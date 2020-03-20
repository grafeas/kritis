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
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	integration_util "github.com/grafeas/kritis/pkg/kritis/integration_util"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	testAttesationAuthority = `apiVersion: kritis.grafeas.io/v1beta1
kind: AttestationAuthority
metadata:
  name: test-attestor
spec:
  noteReference: projects/%s/notes/test-attestor
  publicKeys:
  - keyType: PGP_KEY
    keyId: %s
    asciiArmoredPgpPublicKey: %s
`
)

// Secret name in integration/testdata/image-security-policy/my-isp.yaml
var aaSecret = "test-secret"

// CRDs is a map of CRD type to names of the expected CRDs to create.
var crdNames = map[string]string{
	"imagesecuritypolicies.kritis.grafeas.io": "my-isp",
}

func createKeySecret(t *testing.T, secretName string, ns string, pubKey string, privKey string) {
	t.Helper()
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
	cmd := exec.Command("kubectl", "create", "secret", "generic", secretName,
		fmt.Sprintf("--from-file=public=%s", pubFile),
		fmt.Sprintf("--from-file=private=%s", privFile),
		"-n", ns)
	if _, err := integration_util.RunCmdOut(cmd); err != nil {
		t.Fatalf("unexpected error %s", err)
	}
}

// crdNames is a map of CRD type to names of the expected CRDs to create.
func waitForCRDExamples(t *testing.T, ns *v1.Namespace, crdNames map[string]string) {
	t.Helper()
	t.Logf("Waiting for CRD examples ...")
	for crd, name := range crdNames {
		err := wait.PollImmediate(500*time.Millisecond, 2*time.Minute, func() (bool, error) {
			crdCmd := exec.Command("kubectl", "get", crd, name, "-n", ns.Name)
			err := integration_util.RunCmd(crdCmd)
			return (err == nil), err
		})
		if err != nil {
			t.Fatalf("timeout waiting for crds: %v", err)
		}
	}
}

func createFileWithContents(t *testing.T, d string, c string) string {
	t.Helper()
	file, err := ioutil.TempFile(d, "gpg")
	if err != nil {
		t.Fatalf("testing error: %v", err)
	}
	if _, err := file.WriteString(c); err != nil {
		t.Fatalf("testing error: %v", err)
	}
	return file.Name()
}

func createAA(t *testing.T, project, ns, pubkey, fingerprint string) {
	t.Helper()
	// get the base encoded value for public key.
	pubKeyEnc := base64.StdEncoding.EncodeToString([]byte(pubkey))
	cmd := exec.Command("kubectl", "apply", "-n", ns, "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(fmt.Sprintf(testAttesationAuthority, project, fingerprint, pubKeyEnc)))
	if _, err := integration_util.RunCmdOut(cmd); err != nil {
		t.Fatalf("testing error: %v", err)
	}
}
