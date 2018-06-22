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
package resolve

import (
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"gopkg.in/yaml.v2"
	"sort"
	"testing"
)

var testYaml1 = `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: docker
    image: golang:1.10
`

var testYaml2 = `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: digest
    image: gcr.io/google-appengine/debian9@sha256:547f82a1a5a194b22d1178f4c6aae3de006152757c0da267fd3a68b03e8b6d85
    env: 
    key: ENV
    value: ENV_VALUE
    moreImages:
        image: gcr.io/distroless/base:debug
  - name: no-tag
    image: gcr.io/distroless/base
  - name: docker
    image: busybox
`

func Test_recursiveGetTaggedImages(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		expected []string
	}{
		{
			name: "test one tagged image",
			yaml: testYaml1,
			expected: []string{
				"golang:1.10",
			},
		},
		{
			name: "test multiple tagged images",
			yaml: testYaml2,
			expected: []string{
				"busybox",
				"gcr.io/distroless/base",
				"gcr.io/distroless/base:debug",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := yaml.MapSlice{}
			if err := yaml.Unmarshal([]byte(test.yaml), &m); err != nil {
				t.Fatalf("couldn't unmarshal yaml: %v", err)
			}
			actual := recursiveGetTaggedImages(m)
			sort.Strings(actual)
			testutil.CheckErrorAndDeepEqual(t, false, nil, test.expected, actual)
		})
	}
}

func Test_resolveTagsToDigests(t *testing.T) {
	tests := []struct {
		name     string
		images   []string
		expected map[string]string
	}{
		{
			name: "gcr image",
			images: []string{
				"gcr.io/google-appengine/debian9:2017-09-07-161610",
			},
			expected: map[string]string{
				"gcr.io/google-appengine/debian9:2017-09-07-161610": "gcr.io/google-appengine/debian9@sha256:a97266ab2bbfb8504b636d2b7aa6535323558fd3f859ce6773363757fa7142cb",
			},
		},
		{
			name: "docker registry image",
			images: []string{
				"golang:1.10",
			},
			expected: map[string]string{
				"golang:1.10": "index.docker.io/library/golang@sha256:e87d3a74df05105c219ab0d54034bf22a629b98b884efd5fe4211e198a0da43b",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := resolveTagsToDigests(test.images)
			testutil.CheckErrorAndDeepEqual(t, false, err, test.expected, actual)
		})
	}
}
