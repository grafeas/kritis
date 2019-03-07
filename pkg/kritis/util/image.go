package util

import (
	"fmt"
	"strings"

	"github.com/golang/glog"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
)

func ResolveImageToDigest(image string) (string, error) {
	if isRefDigest(image) {
		// Image already has a digest
		return image, nil
	}

	// WeakValidation allow images without tags and consider it as `latest`
	tag, err := name.NewTag(image, name.WeakValidation)
	if err != nil {
		return "", errors.Wrap(err, "failed to create new image tag.")
	}

	if !isRegistryGCR(tag.RegistryStr()) {
		// Ignore if registry is not GCR
		// TODO (@vbanthia): Support other registry also
		glog.Warningf("Only GCR images are supported. Found %s registry instead.", tag.RegistryStr())
		return image, nil
	}

	auth, err := google.NewEnvAuthenticator()
	if err != nil {
		return "", errors.Wrap(err, "failed to authenticate GCR.")
	}

	img, err := remote.Image(tag, remote.WithAuth(auth))
	if err != nil {
		return "", errors.Wrap(err, "failed to create remote image.")
	}

	digest, err := img.Digest()
	if err != nil {
		return "", errors.Wrap(err, "failed to get image digest.")
	}

	return fmt.Sprintf("%s@%s", tag.Context(), digest.String()), nil
}

func isRegistryGCR(registry string) bool {
	r := strings.Split(registry, ".")

	switch len(r) {
	case 2:
		if r[0] == "gcr" && r[1] == "io" {
			return true
		}
		return false
	case 3:
		if r[0] == "asia" || r[0] == "us" || r[0] == "eu" {
			if r[1] == "gcr" && r[2] == "io" {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func isRefDigest(image string) bool {
	// WeakValidation allow images without registries
	_, err := name.NewDigest(image, name.WeakValidation)
	if err == nil {
		return true
	}
	return false
}
