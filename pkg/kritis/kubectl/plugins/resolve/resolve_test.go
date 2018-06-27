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
	"bufio"
	"bytes"
	"fmt"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"sort"
	"testing"
)

var testYaml1 = `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: debian
    image: gcr.io/google-appengine/debian9:2017-09-07-161610
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
				"gcr.io/google-appengine/debian9:2017-09-07-161610",
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
				"alpine:3.4",
			},
			expected: map[string]string{
				"alpine:3.4": "index.docker.io/library/alpine@sha256:2441496fb9f0d938e5f8b27aba5cc367b24078225ceed82a9a5e67f0d6738c80",
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

func Test_recursiveReplaceImage(t *testing.T) {
	tests := []struct {
		name         string
		yaml         interface{}
		replacements map[string]string
		expected     interface{}
	}{
		{
			name: "replace one image",
			yaml: yaml.MapSlice{
				yaml.MapItem{
					Key:   "image",
					Value: "image:tag",
				},
			},
			replacements: map[string]string{
				"image:tag": "image:digest",
			},
			expected: yaml.MapSlice{
				yaml.MapItem{
					Key:   "image",
					Value: "image:digest",
				},
			},
		},
		{
			name: "yaml without image field",
			yaml: yaml.MapSlice{
				yaml.MapItem{
					Key:   "key",
					Value: "image:tag",
				},
			},
			replacements: map[string]string{
				"image:tag": "image:digest",
			},
			expected: yaml.MapSlice{
				yaml.MapItem{
					Key:   "key",
					Value: "image:tag",
				},
			},
		},
		{
			name: "replace some images",
			yaml: formatMapSlice([]string{"image:tag", "something", "image:tag2"}),
			replacements: map[string]string{
				"image:tag":  "image:digest",
				"image:tag2": "image:digest2",
			},
			expected: formatMapSlice([]string{"image:digest", "something", "image:digest2"}),
		},
		{
			name:         "replace no images",
			yaml:         formatTestYaml1(),
			replacements: map[string]string{},
			expected:     formatTestYaml1(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := recursiveReplaceImage(test.yaml, test.replacements)
			testutil.CheckErrorAndDeepEqual(t, false, nil, test.expected, actual)
		})
	}
}

func Test_Execute(t *testing.T) {
	testYaml := `apiVersion: v1
kind: Pod
metadata:
    name: test
spec:
    containers:
    - name: debian
      image: %s`
	initial := fmt.Sprintf(testYaml, "gcr.io/google-appengine/debian9:2017-09-07-161610")
	expected := fmt.Sprintf(testYaml, "gcr.io/google-appengine/debian9@sha256:a97266ab2bbfb8504b636d2b7aa6535323558fd3f859ce6773363757fa7142cb")
	file, err := ioutil.TempFile("", "")
	if err != nil {
		t.Error(err)
	}
	if _, err := io.Copy(file, bytes.NewReader([]byte(initial))); err != nil {
		t.Error(err)
	}
	defer file.Close()
	var b bytes.Buffer
	writer := bufio.NewWriter(&b)
	if err := Execute([]string{file.Name()}, writer); err != nil {
		t.Errorf("error executing resolve-tags: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Error(err)
	}
	contents, err := ioutil.ReadAll(&b)
	if err != nil {
		t.Error(err)
	}
	if expected != string(contents) {
		t.Fatalf("expected: %s, actual: %s", expected, string(contents))
	}

}

func formatTestYaml1() yaml.MapSlice {
	m := yaml.MapSlice{}
	yaml.Unmarshal([]byte(testYaml1), &m)
	return m
}

func formatMapSlice(args []string) yaml.MapSlice {
	testYaml := `apiVersion: v1
kind: Pod
metadata:
    name: test
    label: test
spec:
    containers:
    - name: tag
      image: %s
    env: 
        key: ENV
        value: ENV_VALUE 
    containers:
    - name: key1
        values: 
        image: image:digest	   
    - name: key2
        value: value 
    - name: key3
        value: 6
    moreImages:
    image: %s
    nest:
        value:  0
        value1: 1
        value2: 2
        nest:
        nest:
            nest:
            - name: digest
            image: %s
`
	y := fmt.Sprintf(testYaml, args[0], args[1], args[2])

	m := yaml.MapSlice{}
	yaml.Unmarshal([]byte(y), &m)
	return m
}
