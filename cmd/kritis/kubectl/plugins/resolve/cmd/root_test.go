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
package cmd

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

var testYaml = `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: kaniko
    image: %s
`

func Test_RootCmd(t *testing.T) {
	/* WARNING: This test is non-hermetic: it requires access to resolve tags against kritis-int-test */
	initial := fmt.Sprintf(testYaml, "gcr.io/kritis-int-test/resolve-tags-test-image")
	file, err := ioutil.TempFile("", "")
	if err != nil {
		t.Error(err)
	}
	expected := fmt.Sprintf("---%s---"+"\n"+testYaml+"\n", file.Name(), "gcr.io/kritis-int-test/resolve-tags-test-image@sha256:3e2e946cb834c4538b789312d566eb16f4a27734fc6b140a3b3f85baafce965f")
	if _, err := io.Copy(file, bytes.NewReader([]byte(initial))); err != nil {
		t.Error(err)
	}
	defer os.Remove(file.Name())
	var output bytes.Buffer
	RootCmd.SetOutput(&output)
	RootCmd.SetArgs([]string{fmt.Sprintf("--filename=%s", file.Name())})
	if err = RootCmd.Execute(); err != nil {
		t.Fatalf("error executing command: %v", err)
	}

	if output.String() != expected {
		t.Errorf("%T differ.\nExpected\n%+v\nActual\n%+v", expected, expected, output.String())
	}
}

func Test_resolveFilepaths(t *testing.T) {
	originalKPLFF := os.Getenv(localFlagFilenameEnv)
	defer os.Setenv(localFlagFilenameEnv, originalKPLFF)

	file, err := ioutil.TempFile("", "")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(file.Name())

	base := filepath.Base(file.Name())
	dir := filepath.Dir(file.Name())
	if err := os.Setenv(localFlagFilenameEnv, base); err != nil {
		t.Error(err)
	}
}
