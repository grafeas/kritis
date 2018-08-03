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

	integration_util "github.com/grafeas/kritis/pkg/kritis/integration_util"
	"k8s.io/api/core/v1"
)

var CRD_EXAMPLES = []string{
	// TODO(aaron-prindle) add back attestation-authority-example.yaml
	// "attestation-authority-example.yaml",
	"image-security-policy-example.yaml",
}

func createCRDExamples(t *testing.T, ns *v1.Namespace) {
	for _, crd := range CRD_EXAMPLES {
		crdCmd := exec.Command("kubectl", "create", "-f", crd, "-n", ns.Name)
		crdCmd.Dir = "../artifacts/integration-examples"
		_, err := integration_util.RunCmdOut(crdCmd)
		if err != nil {
			t.Fatalf("testing error: %v", err)
		}
	}
}
