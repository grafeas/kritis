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

package pods

import (
	"encoding/json"

	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	patch "k8s.io/apimachinery/pkg/util/strategicpatch"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

var (
	// For testing
	patchFunction = applyPatch
)

// Pods returns a list of pods in a namespace
func Pods(namespace string) ([]corev1.Pod, error) {
	clientset, err := kubernetesutil.GetClientset()
	if err != nil {
		return nil, err
	}
	pods, err := clientset.CoreV1().Pods(namespace).List(metav1.ListOptions{})
	return pods.Items, err
}

// Images returns a list of images in a pod
func Images(pod corev1.Pod) []string {
	images := []string{}
	for _, ic := range pod.Spec.InitContainers {
		images = append(images, ic.Image)
	}
	for _, c := range pod.Spec.Containers {
		images = append(images, c.Image)
	}
	return images
}

func getPatch(modifiedPod *corev1.Pod, originalJSON []byte) ([]byte, error) {
	modifiedJSON, err := json.Marshal(modifiedPod)
	if err != nil {
		return nil, err
	}
	return patch.CreateTwoWayMergePatch(originalJSON, modifiedJSON, modifiedPod)
}

// applyPatch applies the patches in the modified pod to the running pod
func applyPatch(modifiedPod *corev1.Pod, originalJSON []byte) error {
	p, err := getPatch(modifiedPod, originalJSON)
	if err != nil {
		return err
	}
	clientset, err := getClientSet()
	if err != nil {
		return err
	}
	_, err = clientset.CoreV1().Pods(modifiedPod.Namespace).Patch(modifiedPod.GetName(), types.StrategicMergePatchType, p)
	return err
}

// AddLabelsAndAnnotations adds labels and annotations to a pod
func AddLabelsAndAnnotations(pod corev1.Pod, labels map[string]string, annotations map[string]string) error {
	originalJSON, err := json.Marshal(pod)
	if err != nil {
		return err
	}
	modifiedPod := pod.DeepCopyObject().(*corev1.Pod)

	// First, update labels
	if modifiedPod.Labels == nil {
		modifiedPod.Labels = labels
	} else {
		for k, v := range labels {
			modifiedPod.Labels[k] = v
		}
	}
	// Then, update annotations
	if modifiedPod.Annotations == nil {
		modifiedPod.Annotations = annotations
	} else {
		for k, v := range annotations {
			modifiedPod.Annotations[k] = v
		}
	}
	return patchFunction(modifiedPod, originalJSON)
}

// DeleteLabelsAndAnnotations deletes labels and annotations from a pod
func DeleteLabelsAndAnnotations(pod corev1.Pod, labels []string, annotations []string) error {
	originalJSON, err := json.Marshal(pod)
	if err != nil {
		return err
	}
	modifiedPod := pod.DeepCopyObject().(*corev1.Pod)

	// First, update labels
	for _, l := range labels {
		if _, ok := modifiedPod.Labels[l]; ok {
			delete(modifiedPod.Labels, l)
		}
	}
	// Then, update annotations
	for _, a := range annotations {
		if _, ok := modifiedPod.Annotations[a]; ok {
			delete(modifiedPod.Annotations, a)
		}
	}
	return patchFunction(modifiedPod, originalJSON)
}
