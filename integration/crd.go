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
	"os/exec"
	"testing"
	"time"

	integration_util "github.com/grafeas/kritis/pkg/kritis/integration_util"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// CRDs is a map of CRD type to names of the expected CRDs to create.
var crdNames = map[string]string{
	"imagesecuritypolicies.kritis.grafeas.io": "my-isp",
}

var crdExamples = []string{
	// TODO(aaron-prindle) add back attestation-authority-example.yaml
	// "attestation-authority-example.yaml",
	"image-security-policy-example.yaml",
}

func createCRDExamples(t *testing.T, ns *v1.Namespace) {
	for _, crd := range crdExamples {
		crdCmd := exec.Command("kubectl", "create", "-f", crd, "-n", ns.Name)
		crdCmd.Dir = "../artifacts/integration-examples"
		_, err := integration_util.RunCmdOut(crdCmd)
		if err != nil {
			t.Fatalf("testing error: %v", err)
		}
	}
}

func waitForCRDExamples(t *testing.T, ns *v1.Namespace) {
	for crd, name := range crdNames {
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
