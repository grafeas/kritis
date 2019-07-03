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
	"reflect"

	"github.com/golang/glog"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/grafeas/kritis/pkg/kritis/constants"
)

// RemoveGloballyAllowedImages returns all images that aren't in a global allowlist
func RemoveGloballyAllowedImages(images []string) []string {
	notAllowlisted := []string{}
	for _, image := range images {
		allowlisted, err := imageInAllowlist(image)
		if err != nil {
			glog.Errorf("couldn't check if %s is in global allowlist: %v", image, err)
		}
		if !allowlisted {
			notAllowlisted = append(notAllowlisted, image)
		}
	}
	return notAllowlisted
}

func imageInAllowlist(image string) (bool, error) {
	for _, w := range constants.GlobalImageAllowlist {
		allowlistRef, err := name.ParseReference(w, name.WeakValidation)
		if err != nil {
			return false, err
		}
		imageRef, err := name.ParseReference(image, name.WeakValidation)
		if err != nil {
			return false, err
		}
		// Make sure images have the same context
		if reflect.DeepEqual(allowlistRef.Context(), imageRef.Context()) {
			return true, nil
		}
	}
	return false, nil
}
