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

package admission

import (
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/testutil"
)

func Test_imagesAreValid(t *testing.T) {
	tests := []struct {
		name            string
		dependentImages []string
		ownerImages     []string
		expected        bool
	}{
		{
			name: "all dependent images are valid",
			dependentImages: []string{
				testutil.QualifiedImage,
			},
			ownerImages: []string{
				testutil.QualifiedImage,
				"gcr.io/another/image",
			},
			expected: true,
		},
		{
			name: "all dependent images are valid or globally allowed",
			dependentImages: []string{
				testutil.QualifiedImage,
				"gcr.io/kritis-project/postinstall",
			},
			ownerImages: []string{
				testutil.QualifiedImage,
				"gcr.io/another/image",
			},
			expected: true,
		},
		{
			name: "dependent has an unqualified image",
			dependentImages: []string{
				"gcr.io/some/image",
			},
			ownerImages: []string{
				testutil.QualifiedImage,
			},
			expected: false,
		},
		{
			name: "dependent's images aren't a subset of owner's images",
			dependentImages: []string{
				testutil.QualifiedImage,
			},
			ownerImages: []string{
				"gcr.io/some/image",
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := imagesAreValid(test.dependentImages, test.ownerImages)
			if actual != test.expected {
				t.Fatalf("unexpected result: got %t expected %t", actual, test.expected)
			}
		})
	}
}

func Test_imageInList(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		images   []string
		expected bool
	}{
		{
			name:   "image in list",
			target: "gcr.io/my-repo/image",
			images: []string{
				"gcr.io/my-repo/image",
				"gcr.io/my-repo/image2",
			},
			expected: true,
		},
		{
			name:   "image not in list",
			target: "gcr.io/my-repo/image",
			images: []string{
				"gcr.io/my-repo/image2",
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := imageInList(test.target, test.images)
			if actual != test.expected {
				t.Fatalf("unexpected result, expected %t got %t", test.expected, actual)
			}
		})
	}
}
