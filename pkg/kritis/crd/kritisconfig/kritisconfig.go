package kritisconfig

import (
	"fmt"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	clientset "github.com/grafeas/kritis/pkg/kritis/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// KritisConfigs returns all KritisConfigs in the specified namespace
// Pass in an empty string to get all KritisConfigs in all namespaces
func KritisConfigs(namespace string) ([]v1beta1.KritisConfig, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error building config: %v", err)
	}

	client, err := clientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error building clientset: %v", err)
	}
	list, err := client.KritisV1beta1().KritisConfigs(namespace).List(metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing all kritis configs: %v", err)
	}
	return list.Items, nil
}

// KritisConfig returns the KritisConfig in the specified namespace and with the given name
// Returns error if KritisConfig is not found
func KritisConfig(namespace string, name string) (*v1beta1.KritisConfig, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error building config: %v", err)
	}

	client, err := clientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error building clientset: %v", err)
	}
	return client.KritisV1beta1().KritisConfigs(namespace).Get(name, metav1.GetOptions{})
}
