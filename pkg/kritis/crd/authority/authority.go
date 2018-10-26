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

package authority

import (
	"fmt"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	clientset "github.com/grafeas/kritis/pkg/kritis/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// Lister describes a function signature which may be used to list AttestationAuthorities
type Lister func(namespace string) ([]v1beta1.AttestationAuthority, error)

// Fetcher describes a function signature which may be used to fetch a specify AttestationAuthority
type Fetcher func(namespace string, name string) (v1beta1.AttestationAuthority, error)

// Authorities returns all AttestationAuthority in the specified namespaces
// Pass in an empty string to get all ISPs in all namespaces
func Authorities(namespace string) ([]v1beta1.AttestationAuthority, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error building config: %v", err)
	}

	client, err := clientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error building clientset: %v", err)
	}
	list, err := client.KritisV1beta1().AttestationAuthorities(namespace).List(metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing all attestation authorities: %v", err)
	}
	return list.Items, nil
}

// Authority returns the AttestationAuthority in the specified namespace.
// Returns error if AttestationAuthority not found
func Authority(namespace string, name string) (*v1beta1.AttestationAuthority, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error building config: %v", err)
	}

	client, err := clientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error building clientset: %v", err)
	}
	return client.KritisV1beta1().AttestationAuthorities(namespace).Get(name, metav1.GetOptions{})
}
