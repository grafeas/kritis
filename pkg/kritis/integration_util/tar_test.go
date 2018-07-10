/*
Copyright 2018 The Skaffold Authors

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

package util

import (
	"archive/tar"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/grafeas/kritis/pkg/skaffold/testutil"
)

func Test_addFileToTar(t *testing.T) {
	// Setup a few files in a tempdir. We can't use afero here because it doesn't support symlinks.
	testDir, cleanup := testutil.TempDir(t)
	defer cleanup()

	files := map[string]string{
		"foo":     "baz1",
		"bar/bat": "baz2",
		"bar/baz": "baz3",
	}
	if err := setupFiles(testDir, files); err != nil {
		t.Fatalf("Error setting up fs: %s", err)
	}

	// Add all the files to a tar.
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for p := range files {
		path := filepath.Join(testDir, p)
		if err := addFileToTar(path, p, tw); err != nil {
			t.Fatalf("addFileToTar() error = %v", err)
		}
	}
	tw.Close()

	// Make sure the contents match.
	tr := tar.NewReader(&b)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("Error reading tar: %s", err)
		}
		expectedContents, ok := files[hdr.Name]
		if !ok {
			t.Errorf("Unexpected file in tar: %s", hdr.Name)
		}
		actualContents, err := ioutil.ReadAll(tr)
		if err != nil {
			t.Errorf("Error %s reading file %s from tar", err, hdr.Name)
		}
		if expectedContents != string(actualContents) {
			t.Errorf("File contents don't match. %s != %s", actualContents, expectedContents)
		}
	}
}

func setupFiles(path string, files map[string]string) error {
	for p, c := range files {
		path := filepath.Join(path, p)
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return err
		}
		if err := ioutil.WriteFile(path, []byte(c), 0644); err != nil {
			return err
		}
	}
	return nil
}
