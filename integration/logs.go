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

func getPodLogs(t *testing.T, pod string, ns *v1.Namespace) string {
	cmd := exec.Command("kubectl", "logs", pod, "-n", ns.Name)
	cmd.Dir = "../"
	output, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Errorf("%s: %s %v", pod, output, err)
	}
	return string(output)
}

func getKritisLogs(t *testing.T) string {
	cmd := exec.Command("kubectl", "logs", "-l",
		"app=kritis-validation-hook")
	cmd.Dir = "../"
	output, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Fatalf("kritis: %s %v", output, err)
	}
	cmd = exec.Command("kubectl", "get", "imagesecuritypolicy")
	cmd.Dir = "../"
	output2, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Fatalf("kritis: %s %v", output2, err)
	}
	return string(output[:]) + "\n" + string(output2[:])
}
