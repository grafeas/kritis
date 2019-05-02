package kritisconfig

import (
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
)

func Test_imageInWhitelist(t *testing.T) {
	cases := map[string]struct {
		whitelist []string
		image     string
		wanted    bool
	}{
		"empty whitelist": {
			[]string{},
			"gcr.io/foo/bar",
			false,
		},
		"gcr image is in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"gcr.io/foo/bar",
			true,
		},
		"gcr image with tag is in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"gcr.io/foo/bar:0.0.1",
			true,
		},
		"gcr image with digest is in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"gcr.io/foo/bar@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			true,
		},
		"gcr image is NOT in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"gcr.io/foo/baz",
			false,
		},
		"gcr image with tag is NOT in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"gcr.io/foo/baz:0.0.1",
			false,
		},
		"gcr image with digest is NOT in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"gcr.io/foo/baz@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			false,
		},
		"public image is in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"datawire/telepresence-k8s",
			true,
		},
		"public image with tag is in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"datawire/telepresence-k8s:0.0.1",
			true,
		},
		"public image with digest is in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"datawire/telepresence-k8s@sha256:1aeb301df7a2e53c6b9b5b16ed9b123ebd584bfa6ad0325e54118e377b2d8d52",
			true,
		},
		"public image is NOT in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"datawire/telepresence-foo",
			false,
		},
		"public image with tag is NOT in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"datawire/telepresence-foo:0.0.1",
			false,
		},
		"public image with digest is NOT in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s"},
			"datawire/telepresence-foo@sha256:1aeb301df7a2e53c6b9b5b16ed9b123ebd584bfa6ad0325e54118e377b2d8d52",
			false,
		},
		"public library image is in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s", "nginx"},
			"nginx",
			true,
		},
		"public library image with tag is in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s", "nginx"},
			"nginx:1.0.0",
			true,
		},
		"public library image with digest is in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s", "nginx"},
			"nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			true,
		},
		"public library image is NOT in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s", "nginx"},
			"apache",
			false,
		},
		"public library image with tag is NOT in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s", "nginx"},
			"apache:1.0.0",
			false,
		},
		"public library image with digest is NOT in whitelist": {
			[]string{"gcr.io/foo/bar", "datawire/telepresence-k8s", "nginx"},
			"apache@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			false,
		},
	}

	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			yes, err := imageInWhitelist(&v1beta1.KritisConfig{
				Spec: v1beta1.KritisConfigSpec{
					ImageWhitelist: c.whitelist,
				},
			}, c.image)
			if err != nil {
				t.Errorf("got unexpected error: %+v", err)
			}
			if yes != c.wanted {
				t.Errorf("wanted %t but got %t", c.wanted, yes)
			}
		})
	}
}
