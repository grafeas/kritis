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

// RemoveGloballyAllowedImages returns all images that aren't in a global allowlist
func RemoveGloballyAllowedImages(images []string) []string {
	notAllowlisted := []string{}
	for _, image := range images {
		allowlisted, err := imageInGlobalAllowlist(image)
		if err != nil {
			glog.Errorf("couldn't check if %s is in global allowlist: %v", image, err)
		}
		if !allowlisted {
			notAllowlisted = append(notAllowlisted, image)
		}
	}
	return notAllowlisted
}

// RemoveGloballyAllowedImages returns all images that aren't in gap allowlists
func RemoveGapAllowedImages(images []string, allowlist []string) []string {
	notAllowlisted := []string{}
	for _, image := range images {
		allowlisted, err := imageInGapAllowlist(image, allowlist)
		if err != nil {
			glog.Errorf("couldn't check if %s is in gap allowlist: %v", image, err)
		}
		if !allowlisted {
			notAllowlisted = append(notAllowlisted, image)
		}
	}
	return notAllowlisted
}

// Do an image match based on reference.
func imageRefMatch(image string, pattern string) (bool, error) {
	allowRef, err := name.ParseReference(pattern, name.WeakValidation)
	if err != nil {
		return false, err
	}
	imageRef, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return false, err
	}
	// Make sure c
	if reflect.DeepEqual(allowRef.Context(), imageRef.Context()) {
		return true, nil
	}
	return false, nil
}

// Do an image match based on name pattern.
// This method uses name pattern matching,
// where the pattern is the path to a single image by
// exact match, or to any images matching a pattern using the wildcard symbol
// (`*`). The wildcards may only be present in the end, and not anywhere
// else in the pattern, i.e., `gcr.io/n*x` is not allowed,
// but `gcr.io/nginx*` is allowed. Also wilcards can be not used to match `/`,
// i.e., `gcr.io/nginx*` matches `gcr.io/nginx@latest`,
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
