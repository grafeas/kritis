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

func Test_RemoveGloballyAllowedImages(t *testing.T) {
	tests := []struct {
		name           string
		images         []string
		notAllowlisted []string
		allowlisted    []string
	}{
		{
			name: "images in allowlist",
			images: []string{
				"gcr.io/kritis-project/kritis-server:tag",
				"gcr.io/kritis-project/kritis-server@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			notAllowlisted: []string{},
			allowlisted: []string{
				"gcr.io/kritis-project/kritis-server:tag",
				"gcr.io/kritis-project/kritis-server@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
		{
			name: "some images not allowlisted",
			images: []string{
				"gcr.io/kritis-project/kritis-server:tag",
				"gcr.io/some/image@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			notAllowlisted: []string{"gcr.io/some/image@sha256:0000000000000000000000000000000000000000000000000000000000000000"},
			allowlisted:    []string{"gcr.io/kritis-project/kritis-server:tag"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			images, removed := RemoveGloballyAllowedImages(test.images)
			testutil.DeepEqual(t, test.notAllowlisted, images)
			testutil.DeepEqual(t, test.allowlisted, removed)
		})
	}
}

func Test_RemoveGapAllowedImages(t *testing.T) {
	allowlist := []string{
		"gcr.io/1-my-image*",
	}
	tests := []struct {
		name           string
		images         []string
		notAllowlisted []string
		allowlisted    []string
	}{
		{
			name: "remove gap allowed images",
			images: []string{
				"gcr.io/1-my-image@sha256:0000000000000000000000000000000000000000000000000000000000000000",
				"gcr.io/1-my-image:tag",
				"gcr.io/2-my-image:latest",
				"gcr.io/1-my-image2:latest",
				"gcr.io/1-my-image/a:latest",
			},
			notAllowlisted: []string{
				"gcr.io/2-my-image:latest",
				"gcr.io/1-my-image/a:latest",
			},
			allowlisted: []string{
				"gcr.io/1-my-image@sha256:0000000000000000000000000000000000000000000000000000000000000000",
				"gcr.io/1-my-image:tag",
				"gcr.io/1-my-image2:latest",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			images, removed := RemoveGapAllowedImages(test.images, allowlist)
			testutil.DeepEqual(t, test.notAllowlisted, images)
			testutil.DeepEqual(t, test.allowlisted, removed)
		})
	}
}

func Test_imageInGapAllowlist(t *testing.T) {
	allowlist := []string{
		"gcr.io/1-my-image*",
		"gcr.io/2-my-image-any-tag:*",
		"gcr.io/3-my-untagged-image",
		"gcr.io/4-my-image-tag-prefix:1.*",
		"gcr.io/5/long/path/my-image*",
		"gcr.io/6-my-image-w-tag:latest",
		"gcr.io/7-my-image@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"gcr.io/8-my-image@sha256:*",
		"local-image-1:*",
		"local-image-2:tag",
		"local-image-3:tag*",
	}
	tests := []struct {
		name     string
		image    string
		expected bool
	}{
		{
			name:     "test image exact name and tag match",
			image:    "gcr.io/6-my-image-w-tag:latest",
			expected: true,
		},
		{
			name:     "test image name match but tag mismatch",
			image:    "gcr.io/6-my-image-w-tag:some",
			expected: false,
		},
		{
			name:     "test image any tag match",
			image:    "gcr.io/2-my-image-any-tag:any",
			expected: true,
		},
		{
			name:     "test image wildcard name match",
			image:    "gcr.io/1-my-image-abc",
			expected: true,
		},
		{
			name:     "test image wildcard name and tag match",
			image:    "gcr.io/1-my-image-abc:tag",
			expected: true,
		},
		{
			name:     "test untagged pattern exact match",
			image:    "gcr.io/3-my-untagged-image",
			expected: true,
		},
		{
			name:     "test untagged pattern mismatch",
			image:    "gcr.io/3-my-untagged-image:tag",
			expected: false,
		},
		{
			name:     "test tag wildcard pattern match",
			image:    "gcr.io/4-my-image-tag-prefix:1.3",
			expected: true,
		},
		{
			name:     "test tag wildcard pattern mismatch",
			image:    "gcr.io/4-my-image-tag-prefix:2.3",
			expected: false,
		},
		{
			name:     "test image long path match",
			image:    "gcr.io/5/long/path/my-image-1:tag",
			expected: true,
		},
		{
			name:     "test wildcard does not match slash",
			image:    "gcr.io/5/long/path/my-image/image",
			expected: false,
		},
		{
			name:     "test image sha exact match",
			image:    "gcr.io/7-my-image@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			expected: true,
		},
		{
			name:     "test image sha mismatch",
			image:    "gcr.io/7-my-image@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			expected: false,
		},
		{
			name:     "test wildcard sha match",
			image:    "gcr.io/8-my-image@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			expected: true,
		},
		{
			name:     "test local image exact match",
			image:    "local-image-2:tag",
			expected: true,
		},
		{
			name:     "test local image tag mismatch",
			image:    "local-image-2:tag2",
			expected: false,
		},
		{
			name:     "test local image any tag match",
			image:    "local-image-1:any-tag",
			expected: true,
		},
		{
			name:     "test local image tag wildcard match",
			image:    "local-image-3:tag-any",
			expected: true,
		},
		{
			name:     "test local image tag wildcard mismatch",
			image:    "local-image-3:1tag",
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := imageInGapAllowlist(test.image, allowlist)
			testutil.CheckErrorAndDeepEqual(t, false, err, test.expected, actual)
		})
	}
}

func Test_imageInGlobalAllowlist(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		expected bool
	}{
		{
			name:     "test image in allowlist",
			image:    "gcr.io/kritis-project/kritis-server:tag",
			expected: true,
		},
		{
			name:     "test image with digest in allowlist",
			image:    "gcr.io/kritis-project/kritis-server@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			expected: true,
		},
		{
			name:     "test image not in allowlist",
			image:    "some/image",
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := imageInGlobalAllowlist(test.image)
			testutil.CheckErrorAndDeepEqual(t, false, err, test.expected, actual)
		})
	}
}
