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
	"errors"
	"reflect"
	"strings"

	"github.com/golang/glog"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/grafeas/kritis/pkg/kritis/constants"
)

// SplitGloballyAllowedImages returns:
// -- list of all images that aren't in a global allowlist
// -- list of images that are in a global allowlist
func SplitGloballyAllowedImages(images []string) ([]string, []string) {
	notAllowlistedImages := []string{}
	removedImages := []string{}
	for _, image := range images {
		isAllowlisted, err := imageInGlobalAllowlist(image)
		if err != nil {
			glog.Errorf("couldn't check if %s is in global allowlist: %v", image, err)
		}
		if !isAllowlisted {
			notAllowlistedImages = append(notAllowlistedImages, image)
		} else {
			removedImages = append(removedImages, image)
		}
	}
	return notAllowlistedImages, removedImages
}

// SplitGapAllowedImages returns:
// -- list of all images that aren't in gap allowlists
// -- list of images that are in gap allowlists
func SplitGapAllowedImages(images []string, allowlist []string) ([]string, []string) {
	notAllowlistedImages := []string{}
	removedImages := []string{}
	for _, image := range images {
		isAllowlisted, err := imageInGapAllowlist(image, allowlist)
		if err != nil {
			glog.Errorf("couldn't check if %s is in gap allowlist: %v", image, err)
		}
		if !isAllowlisted {
			notAllowlistedImages = append(notAllowlistedImages, image)
		} else {
			removedImages = append(removedImages, image)
		}
	}
	return notAllowlistedImages, removedImages
}

// Do an image match based on reference.
// It checks whether the image and the pattern resolves to same URL,
// e.g., gcr.io/kritis-project/preinstall.
// Note that it does not check digest or tag in the pattern.
// For example, a pattern of gcr.io/hello/world:latest will match any image
// in the gcr.io/hello/world repository.
func imageRefMatch(image string, pattern string) (bool, error) {
	allowRef, err := name.ParseReference(pattern, name.WeakValidation)
	if err != nil {
		return false, err
	}
	imageRef, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return false, err
	}
	// Make sure both resolve to same URL
	if reflect.DeepEqual(allowRef.Context(), imageRef.Context()) {
		return true, nil
	}
	return false, nil
}

// Do an image match based on name pattern.
// This method uses name pattern matching,
// where a pattern is a path to a single image by
// exact match, or to any images matching a pattern using the wildcard symbol
// (`*`). The wildcards may only be present in the end, and not anywhere
// else in the pattern, e.g., `gcr.io/n*x` is not allowed,
// but `gcr.io/nginx*` is allowed. Also wilcards cannot be used to match `/`,
// e.g., `gcr.io/nginx*` matches `gcr.io/nginx@latest`,
// but it does not match `gcr.io/nginx/image`.
// See more at https://cloud.google.com/binary-authorization/docs/policy-yaml-reference#admissionwhitelistpatterns
func imageNamePatternMatch(image string, pattern string) (bool, error) {
	if len(pattern) == 0 {
		return false, errors.New("empty pattern")
	}
	if pattern[len(pattern)-1] == '*' {
		pattern = pattern[:len(pattern)-1]
		if strings.HasPrefix(image, pattern) &&
			strings.LastIndex(image, "/") < len(pattern) {
			return true, nil
		}
	} else {
		if image == pattern {
			return true, nil
		}
	}
	return false, nil
}

func imageInAllowlistByReference(image string, allowList []string) (bool, error) {
	for _, w := range allowList {
		match, err := imageRefMatch(image, w)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

func imageInAllowlistByPattern(image string, allowList []string) (bool, error) {
	for _, w := range allowList {
		match, err := imageNamePatternMatch(image, w)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// Check if image is allowed by global allowlist.
// This method uses reference matching.
func imageInGlobalAllowlist(image string) (bool, error) {
	return imageInAllowlistByReference(image, constants.GlobalImageAllowlist)
}

// Check if image is allowed by a GAP allowlist.
func imageInGapAllowlist(image string, allowlist []string) (bool, error) {
	return imageInAllowlistByPattern(image, allowlist)
}
