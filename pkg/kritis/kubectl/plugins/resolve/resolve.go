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

package resolve

import (
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"gopkg.in/yaml.v2"
)

func Execute() error {
	// TODO (priyawadhwa): fill in this function
	//	1. Resolve relative paths in files to absolute paths
	//	2. Get tagged images using recursiveGetTaggedImages
	// 	3. Resolve tagged images using resolveTagsToDigests
	//	4. Write recursive function to replace images
	//	5. Print to STDOUT
	return nil
}

// recursiveGetTaggedImages recursively gets all images referenced by tags
// instead of digests
func recursiveGetTaggedImages(m interface{}) []string {
	images := []string{}
	switch t := m.(type) {
	case yaml.MapSlice:
		for _, v := range t {
			images = append(images, recursiveGetTaggedImages(v)...)
		}
	case yaml.MapItem:
		if t.Key.(string) == "image" {
			image := t.Value.(string)
			_, err := name.NewDigest(image, name.WeakValidation)
			if err != nil {
				images = append(images, image)
			}
		} else {
			images = append(images, recursiveGetTaggedImages(t.Value)...)
		}
	case []interface{}:
		for _, v := range t {
			images = append(images, recursiveGetTaggedImages(v)...)
		}
	}
	return images
}

// resolveTagsToDigests resolves all images specified by tag to digest
// It returns a map of the form [image:tag]:[image@sha256:digest]
func resolveTagsToDigests(images []string) (map[string]string, error) {
	resolvedImages := map[string]string{}
	for _, image := range images {
		tag, err := name.NewTag(image, name.WeakValidation)
		if err != nil {
			return nil, err
		}
		sourceImage, err := remote.Image(tag)
		if err != nil {
			return nil, err
		}
		digest, err := sourceImage.Digest()
		if err != nil {
			return nil, err
		}
		digestName := fmt.Sprintf("%s@sha256:%s", tag.Context(), digest.Hex)
		resolvedImages[image] = digestName
	}
	return resolvedImages, nil
}

// recursiveReplaceImage recursively replaces image:tag to the corresponding image@sha256:digest
func recursiveReplaceImage(i interface{}, replacements map[string]string) interface{} {
	switch t := i.(type) {
	case yaml.MapSlice:
		// For each MapItem in the MapSlice, we want to replace any images and replace
		for index, mapItem := range t {
			replacedMapItem := recursiveReplaceImage(mapItem, replacements)
			t[index] = replacedMapItem.(yaml.MapItem)
		}
		return t
	case yaml.MapItem:
		if val, ok := t.Value.(string); ok {
			if t.Key.(string) == "image" {
				if img, present := replacements[val]; present {
					t.Value = img
				}
			}
			return t
		}
		return yaml.MapItem{
			Key:   t.Key,
			Value: recursiveReplaceImage(t.Value, replacements),
		}
	case []interface{}:
		// Since []interface is actually []yaml.MapSlice, for each mapSlice, recursively replace images and replace
		for index, mapSlice := range t {
			replacedMapSlice := recursiveReplaceImage(mapSlice, replacements)
			t[index] = replacedMapSlice
		}
		return t
	}
	return nil
}
