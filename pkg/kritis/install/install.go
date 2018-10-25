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

package install

import (
	"bytes"
	"io/ioutil"
	"os/exec"

	"github.com/sirupsen/logrus"
)

// RetrieveNamespace returns the Kubernetes namespace written to disk.
func RetrieveNamespace() string {
	namespaceFile := "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	contents, err := ioutil.ReadFile(namespaceFile)
	if err != nil {
		logrus.Fatalf("error trying to get namespace from %s: %v", namespaceFile, err)
	}
	logrus.Infof("contents of %s: %s", namespaceFile, contents)
	return string(contents)
}

// RunCommand executes a command
func RunCommand(cmd *exec.Cmd) []byte {
	stderr := bytes.NewBuffer([]byte{})
	cmd.Stderr = stderr
	output, err := cmd.Output()
	logrus.Info(cmd.Args)
	logrus.Info(string(output))
	if err != nil {
		logrus.Error(stderr.String())
		// TODO: address - libraries should never panic.
		logrus.Fatal(err)
	}
	return output
}
