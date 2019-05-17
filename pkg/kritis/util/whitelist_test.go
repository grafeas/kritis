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
package util

import (
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/testutil"
)

func Test_RemoveGloballyWhitelistedImages(t *testing.T) {
	tests := []struct {
		name     string
		images   []string
		expected []string
	}{
		{
			name: "images in whitelist",
			images: []string{
				"gcr.io/kritis-project/kritis-server:tag",
				"gcr.io/kritis-project/kritis-server@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			expected: []string{},
		},
		{
			name: "some images not whitelisted",
			images: []string{
				"gcr.io/kritis-project/kritis-server:tag",
				"gcr.io/some/image@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			expected: []string{"gcr.io/some/image@sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := RemoveGloballyWhitelistedImages(test.images)
			testutil.DeepEqual(t, test.expected, actual)
		})
	}
}

func Test_ImageInWhitelist(t *testing.T) {
	tests := []struct {
		name      string
		image     string
		whitelist []string
		expected  bool
	}{
		{
			name:  "test image with tag in whitelist",
			image: "gcr.io/kritis-project/kritis-server:tag",
			whitelist: []string{
				"gcr.io/kritis-project/kritis-server",
				"nginx",
			},
			expected: true,
		},
		{
			name:  "test image with digest in whitelist",
			image: "gcr.io/kritis-project/kritis-server@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			whitelist: []string{
				"gcr.io/kritis-project/kritis-server",
				"nginx",
			},
			expected: true,
		},
		{
			name:  "test public image in whitelist",
			image: "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			whitelist: []string{
				"gcr.io/kritis-project/kritis-server",
				"nginx",
			},
			expected: true,
		},
		{
			name:  "test image not in whitelist",
			image: "some/image",
			whitelist: []string{
				"gcr.io/kritis-project/kritis-server",
				"nginx",
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := ImageInWhitelist(test.whitelist, test.image)
			testutil.CheckErrorAndDeepEqual(t, false, err, test.expected, actual)
		})
	}
}
