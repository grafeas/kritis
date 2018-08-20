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

package buildpolicy

import (
	"fmt"
	"regexp"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	clientset "github.com/grafeas/kritis/pkg/kritis/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// ValidateFunc defines the type for Validating Build Policies
type ValidateFunc func(bp v1beta1.BuildPolicy, buildFrom string) error

// BuildPolicies returns all ISP's in the specified namespaces
// Pass in an empty string to get all ISPs in all namespaces
func BuildPolicies(namespace string) ([]v1beta1.BuildPolicy, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error building config: %v", err)
	}

	client, err := clientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error building clientset: %v", err)
	}
	list, err := client.KritisV1beta1().BuildPolicies(namespace).List(metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing all image policy requirements: %v", err)
	}
	return list.Items, nil
}

// ValidateBuildPolicy checks if an image satisfies BP requirements.
// It returns an error if an image does not pass,
func ValidateBuildPolicy(bp v1beta1.BuildPolicy, builtFrom string) error {
	ok, err := regexp.MatchString(bp.Spec.BuildRequirements.BuiltFrom, builtFrom)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Source %q does not match required %q", builtFrom, bp.Spec.BuildRequirements.BuiltFrom)
	}
	return nil
}
