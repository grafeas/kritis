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

package containeranalysis

import (
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/testutil"
)

func Test_isRegistryGCR(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		expected bool
	}{
		{
			name:     "gcr image",
			registry: "gcr.io",
			expected: true,
		},
		{
			name:     "eu gcr image",
			registry: "eu.gcr.io",
			expected: true,
		},
		{
			name:     "invalid gcr image",
			registry: "foogcr.io",
			expected: false,
		},
		{
			name:     "non gcr image",
			registry: "index.docker.io",
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := isRegistryGCR(test.registry)
			testutil.DeepEqual(t, test.expected, actual)
		})
	}
}

func Test_getProjectFromContainerImage(t *testing.T) {
	tests := []struct {
		image   string
		project string
	}{
		{"gcr.io/project/1", "project"},
		{"gcr.io/project", "project"},
		{"gcr.io", ""},
	}
	for _, tc := range tests {
		t.Run(tc.image, func(t *testing.T) {
			testutil.DeepEqual(t, tc.project, getProjectFromContainerImage(tc.image))
		})
	}
}

func TestGetProjectFromNoteRef(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		shdErr bool
		output string
	}{
		{"good", "v1aplha1/projects/name", false, "name"},
		{"bad1", "some", true, ""},
		{"bad2", "some/t", true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := getProjectFromNoteReference(tc.input)
			testutil.CheckErrorAndDeepEqual(t, tc.shdErr, err, tc.output, actual)
		})
	}
}
