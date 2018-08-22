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

package admission

import (
	"fmt"

	"github.com/grafeas/kritis/pkg/kritis/admission/constants"
	"github.com/grafeas/kritis/pkg/kritis/kubectl/plugins/resolve"
	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	"github.com/grafeas/kritis/pkg/kritis/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func checkOwners(dependentImages []string, meta *metav1.ObjectMeta) bool {
	owners := meta.GetOwnerReferences()
	if owners == nil {
		return false
	}
	for _, o := range owners {
		ownerImages, err := retrieveOwnersImages(meta.Namespace, o)
		if err != nil {
			return false
		}
		if !imagesAreValid(dependentImages, ownerImages) {
			return false
		}
	}
	return true
}

func retrieveOwnersImages(ns string, or metav1.OwnerReference) ([]string, error) {
	clientset, err := kubernetesutil.GetClientset()
	if err != nil {
		return nil, err
	}

	switch or.Kind {
	case constants.Pod:
		pod, err := clientset.CoreV1().Pods(ns).Get(or.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return PodImages(*pod), nil
	case constants.Deployment:
		d, err := clientset.AppsV1().Deployments(ns).Get(or.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return DeploymentImages(*d), nil
	case constants.ReplicaSet:
		rs, err := clientset.AppsV1().ReplicaSets(ns).Get(or.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return ReplicaSetImages(*rs), nil
	default:
		return nil, fmt.Errorf("%s is not a supported kind", or.Kind)
	}
}

func imagesAreValid(dependentImages, ownerImages []string) bool {
	dependentImages = util.RemoveGloballyWhitelistedImages(dependentImages)
	for _, d := range dependentImages {
		if !resolve.FullyQualifiedImage(d) {
			return false
		}
		if !imageInList(d, ownerImages) {
			return false
		}
	}
	return true
}

func imageInList(target string, images []string) bool {
	for _, i := range images {
		if target == i {
			return true
		}
	}
	return false
}
