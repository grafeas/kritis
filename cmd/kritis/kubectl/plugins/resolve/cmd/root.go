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
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/kubectl/plugins/resolve"
	"github.com/spf13/cobra"
)

const (
	localFlagFilenameEnv = "KUBECTL_PLUGINS_LOCAL_FLAG_FILENAME"
	localFlagApplyEnv    = "KUBECTL_PLUGINS_LOCAL_FLAG_APPLY"
	callerEnv            = "KUBECTL_PLUGINS_CALLER"
)

var (
	// flag values
	files multiArg
	apply bool
)

func init() {
	RootCmd.PersistentFlags().VarP(&files, "filename", "f", "Filename to resolve. Set it repeatedly for multiple filenames.")
	RootCmd.PersistentFlags().BoolVarP(&apply, "apply", "a", false, "Apply changes using 'kubectl apply -f'.")

	// Populate Go flags into pflags so that glog -v works
	RootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
}

// RootCmd implements the resolve-tags command.
var RootCmd = &cobra.Command{
	Use:   "resolve-tags",
	Short: "resolve-tags is a tool for replacing tagged images with fully qualified images in Kubernetes yamls",
	Long: `resolve-tags can be run as either a kubectl plugin or as a binary. It takes in paths to file and
		   prints new manifests to STDOUT.

		   Note: When running as a binary, if the KUBECTL_PLUGINS_LOCAL_FLAG_FILENAME env variable is set,
		   it will override any files passed in.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Place here so it is first run before anything else, but after init() so that
		// it does not silently break tests.
		flag.CommandLine.Parse([]string{})
		resolveApply()
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		return resolveFilepaths(cwd)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		substitutes, err := resolve.Execute(files)
		if err != nil {
			return fmt.Errorf("unable to resolve: %v", err)
		}
		return outputResults(substitutes, cmd.OutOrStdout())
	},
	// Otherwise, the default Run() shows usage if RunE returns an error.
	SilenceUsage: true,
}

func resolveApply() {
	apply = apply || (os.Getenv(localFlagApplyEnv) != "")
}

func resolveFilepaths(relativeDir string) error {
	if pluginFile := os.Getenv(localFlagFilenameEnv); pluginFile != "" {
		files = []string{pluginFile}
	}
	if len(files) == 0 {
		return fmt.Errorf("Please specify a path to resolve using --filename")
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
		cmd.Stdin = strings.NewReader(contents)
		glog.Infof("Sending to kubectl via stdin:\n%s", contents)
		glog.Infof("Executing %s ...", cmd.Args)

		output, err := cmd.CombinedOutput()
		// Copy stderr/stdout stream from kubectl to our own stdout
		fmt.Fprintln(writer, string(output))
		if err != nil {
			return fmt.Errorf("kubectl: %v", err)
		}
	}
	return nil
}
