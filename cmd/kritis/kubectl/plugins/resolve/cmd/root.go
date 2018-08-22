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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/kubectl/plugins/resolve"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"github.com/spf13/cobra"
)

const (
	localFlagFilenameEnv = "KUBECTL_PLUGINS_LOCAL_FLAG_FILENAME"
	localFlagApplyEnv    = "KUBECTL_PLUGINS_LOCAL_FLAG_APPLY"
	callerEnv            = "KUBECTL_PLUGINS_CALLER"
)

var (
	files multiArg
	apply bool
)

func init() {
	RootCmd.PersistentFlags().VarP(&files, "filename", "f", "Filename to resolve. Set it repeatedly for multiple filenames.")
	RootCmd.PersistentFlags().BoolVarP(&apply, "apply", "a", false, "Apply changes using 'kubectl apply -f'.")
}

var RootCmd = &cobra.Command{
	Use:   "resolve-tags",
	Short: "resolve-tags is a tool for replacing tagged images with fully qualified images in Kubernetes yamls",
	Long: `resolve-tags can be run as either a kubectl plugin or as a binary. It takes in paths to file and
		   prints new manfifests to STDOUT. 
		   
		   Note: When running as a binary, if the KUBECTL_PLUGINS_LOCAL_FLAG_FILENAME env variable is set,
		   it will override any files passed in.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		resolveApply()
		cwd, err := os.Getwd()
		if err != nil {
			util.ExitIfErr(cmd, err)
		}
		return resolveFilepaths(cwd)
	},
	Run: func(cmd *cobra.Command, args []string) {
		substitutes, err := resolve.Execute(files)
		if err != nil {
			util.ExitIfErr(cmd, err)
		}
		if err := outputResults(substitutes, cmd.OutOrStdout()); err != nil {
			util.ExitIfErr(cmd, err)
		}
	},
}

func resolveApply() {
	apply = apply || (os.Getenv(localFlagApplyEnv) != "")
}

func resolveFilepaths(relativeDir string) error {
	if pluginFile := os.Getenv(localFlagFilenameEnv); pluginFile != "" {
		files = []string{pluginFile}
	}
	if len(files) == 0 {
		return fmt.Errorf("please pass in a path to a file to resolve")
	}
	glog.Infof("Resolving: %s", files)
	for index, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			fullPath := filepath.Join(relativeDir, file)
			if _, err := os.Stat(fullPath); err != nil {
				return err
			}
			files[index] = fullPath
		}
	}
	return nil
}

func outputResults(substitutes map[string]string, writer io.Writer) error {
	if apply {
		return applyChanges(substitutes, writer)
	}
	print(substitutes, writer)
	return nil
}

// prints the final replaced kubernetes manifest to given writer
func print(substitutes map[string]string, writer io.Writer) {
	for file, contents := range substitutes {
		fmt.Fprintln(writer, fmt.Sprintf("---%s---", file))
		fmt.Fprintf(writer, contents)
		fmt.Fprintln(writer)
	}
}

func applyChanges(substitutes map[string]string, writer io.Writer) error {
	// Use full path to kubectl binary if we can get it, otherwise assume it's on $PATH
	kubectl := os.Getenv(callerEnv)
	if kubectl == "" {
		kubectl = "kubectl"
	}

	for _, contents := range substitutes {
		cmd := exec.Command(kubectl, "apply", "-f", "-")
		glog.Infof("Executing %s ...", cmd.Args)
		cmd.Stdin = strings.NewReader(contents)
		output, err := cmd.CombinedOutput()
		fmt.Fprintln(writer, string(output))
		if err != nil {
			return err
		}
	}
	return nil
}
