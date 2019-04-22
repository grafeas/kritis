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
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

// PodImages returns a list of images in a pod
func PodImages(pod v1.Pod) []string {
	images := []string{}
	for _, ic := range pod.Spec.InitContainers {
		images = append(images, ic.Image)
	}
	for _, c := range pod.Spec.Containers {
		images = append(images, c.Image)
	}
	return images
}

// DeploymentImages returns a list of images in a deployment
func DeploymentImages(deployment appsv1.Deployment) []string {
	images := []string{}
	for _, ic := range deployment.Spec.Template.Spec.InitContainers {
		images = append(images, ic.Image)
	}
	for _, c := range deployment.Spec.Template.Spec.Containers {
		images = append(images, c.Image)
	}
	return images
}

// ReplicaSetImages returns a list of images in a replica set
func ReplicaSetImages(rs appsv1.ReplicaSet) []string {
	images := []string{}
	for _, ic := range rs.Spec.Template.Spec.InitContainers {
		images = append(images, ic.Image)
	}
	for _, c := range rs.Spec.Template.Spec.Containers {
		images = append(images, c.Image)
	}
	return images
}
