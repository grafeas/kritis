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

package cmd

import (
	"fmt"
	"github.com/grafeas/kritis/pkg/kritis/kubectl/plugins/resolve"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

var (
	files multiArg
)

func init() {
	RootCmd.PersistentFlags().VarP(&files, "filename", "f", "Filename to resolve. Set it repeatedly for multiple filenames.")
}

var RootCmd = &cobra.Command{
	Use: "resolve-tags",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return resolveFilepaths(args[0])
	},
	Run: func(cmd *cobra.Command, args []string) {
		if err := resolve.Execute(files, os.Stdout); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func resolveFilepaths(cwd string) error {
	if len(files) == 0 {
		return fmt.Errorf("please pass in at least one path to a yaml file to resolve")
	}
	for index, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			fullPath := filepath.Join(cwd, file)
			if _, err := os.Stat(fullPath); err != nil {
				return err
			}
			files[index] = fullPath
		}
	}
	return nil
}
