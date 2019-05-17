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

package kritisconfig

import (
	"github.com/pkg/errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	clientset "github.com/grafeas/kritis/pkg/kritis/client/clientset/versioned"
	"github.com/grafeas/kritis/pkg/kritis/util"
)

type ClusterWhitelistedImagesRemover func(images []string) ([]string, error)

// KritisConfig returns KritisConfig in the cluster
func KritisConfig() (*v1beta1.KritisConfig, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, errors.Wrap(err, "error building config")
	}

	client, err := clientset.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "error building clientset")
	}

	list, err := client.KritisV1beta1().KritisConfigs().List(metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "error listing all kritis configs")
	}

	if len(list.Items) > 1 {
		return nil, errors.New("more than 1 KritisConfig found, expected to have only 1 in the cluster")
	} else if len(list.Items) == 0 {
		return nil, nil
	}

	return &list.Items[0], nil
}

func RemoveWhitelistedImages(images []string) ([]string, error) {
	config, err := KritisConfig()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get KritisConfig")
	}
	if config == nil {
		return images, nil
	}

	notWhitelisted := []string{}
	for _, image := range images {
		whitelisted, err := imageInWhitelist(config, image)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to check if image is in whitelist: %s", image)
		}
		if !whitelisted {
			notWhitelisted = append(notWhitelisted, image)
		}
	}
	return notWhitelisted, nil
}

func imageInWhitelist(config *v1beta1.KritisConfig, image string) (bool, error) {
	return util.ImageInWhitelist(config.Spec.ImageWhitelist, image)
}
