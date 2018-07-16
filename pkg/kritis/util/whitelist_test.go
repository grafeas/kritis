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
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"testing"
)

func Test_CheckGlobalWhitelist(t *testing.T) {
	tests := []struct {
		name     string
		images   []string
		expected bool
	}{
		{
			name: "images in whitelist",
			images: []string{
				"gcr.io/kritis-project/kritis-server:tag",
				"gcr.io/kritis-project/kritis-server@sha256:digest",
			},
			expected: true,
		},
		{
			name: "some images not whitelisted",
			images: []string{
				"gcr.io/kritis-project/kritis-server:tag",
				"gcr.io/kritis-project/kritis-server@sha256:digest",
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := CheckGlobalWhitelist(test.images)
			testutil.CheckErrorAndDeepEqual(t, false, nil, test.expected, actual)
		})
	}
}

func Test_imageInWhitelist(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		expected bool
	}{
		{
			name:     "test image in whitelist",
			image:    "gcr.io/kritis-project/kritis-server:tag",
			expected: true,
		},
		{
			name:     "test image not in whitelist",
			image:    "some/image",
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := imageInWhitelist(test.image)
			testutil.CheckErrorAndDeepEqual(t, false, err, test.expected, actual)
		})
	}
}
