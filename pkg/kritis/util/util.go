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
	"os"

	"github.com/spf13/cobra"
)

func ExitIfErr(cmd *cobra.Command, err error) {
	if err != nil {
		cmd.Println(err)
		os.Exit(1)
	}
}

func GetUniqueImages(images []string) []string {
	imagesMap := map[string]bool{}
	for _, image := range images {
		imagesMap[image] = true
	}
	uniqueImages := make([]string, len(imagesMap))
	i := 0
	for image := range imagesMap {
		uniqueImages[i] = image
		i++
	}
	return uniqueImages
}
