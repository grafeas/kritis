package util

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
			name:     "us gcr image",
			registry: "us.gcr.io",
			expected: true,
		},
		{
			name:     "asia gcr image",
			registry: "asia.gcr.io",
			expected: true,
		},
		{
			name:     "invalid gcr image",
			registry: "foogcr.io",
			expected: false,
		},
		{
			name:     "invalid gcr image",
			registry: "foo.gcr.io",
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

func Test_isRefDigest(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		expected bool
	}{
		{
			name:     "valid fully qualified image",
			image:    "index.docker.io/nginx@sha256:1234cc2d8ea3d7c8a456caeffbaedcc946ab3fcf9be25af4b1b2658099425e03",
			expected: true,
		},
		{
			name:     "shortened image with valid digest",
			image:    "nginx@sha256:1234cc2d8ea3d7c8a456caeffbaedcc946ab3fcf9be25af4b1b2658099425e03",
			expected: true,
		},
		{
			name:     "digest with invalid length",
			image:    "nginx@sha256:2345678ea3d7c8a456caeffbaedcc946ab3fcf9be25af4b1b2658099425e03",
			expected: false,
		},
		{
			name:     "valid tag",
			image:    "image:v1.0.0",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := isRefDigest(test.image)
			testutil.DeepEqual(t, test.expected, actual)
		})
	}
}
