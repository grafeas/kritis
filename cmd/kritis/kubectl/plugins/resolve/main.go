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

package main

import (
	"fmt"
	"github.com/grafeas/kritis/pkg/kritis/kubectl/plugins/resolve"
	"os"
	"path"
	"path/filepath"
	"runtime"
)

var (
	files = os.Args[1:]
)

func main() {
	if err := resolveFilepaths(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := resolve.Execute(files); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func resolveFilepaths() error {
	if len(files) == 0 {
		return fmt.Errorf("please pass in at least one path to a yaml file to resolve")
	}
	dir, err := getWorkingDirectory()
	if err != nil {
		return err
	}
	for index, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			fullPath := filepath.Join(dir, file)
			if _, err := os.Stat(fullPath); err != nil {
				return err
			}
			files[index] = fullPath
		}
	}
	return nil
}

// getWorkingDirectory gets the directory that the kubectl plugin was called from
func getWorkingDirectory() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	fmt.Println("Calling from", filename)
	if !ok {
		return "", fmt.Errorf("no caller information")
	}
	return path.Dir(filename), nil
}
