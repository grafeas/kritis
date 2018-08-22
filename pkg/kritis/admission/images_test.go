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
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/testutil"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
)

func Test_PodImages(t *testing.T) {
	pod := v1.Pod{
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Image: "image1",
				},
				{
					Image: "image2",
				},
			},
			InitContainers: []v1.Container{
				{
					Image: "image3",
				},
			},
		},
	}
	expected := []string{"image3", "image1", "image2"}
	actual := PodImages(pod)
	testutil.CheckErrorAndDeepEqual(t, false, nil, expected, actual)
}

func Test_DeploymentImages(t *testing.T) {
	deployment := appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					InitContainers: []v1.Container{
						{
							Image: "image1",
						},
						{
							Image: "image2",
						},
					},
					Containers: []v1.Container{
						{
							Image: "image3",
						},
					},
				},
			},
		},
	}
	expected := []string{"image1", "image2", "image3"}
	actual := DeploymentImages(deployment)
	testutil.CheckErrorAndDeepEqual(t, false, nil, expected, actual)
}

func Test_ReplicaSetImages(t *testing.T) {
	rs := appsv1.ReplicaSet{
		Spec: appsv1.ReplicaSetSpec{
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					InitContainers: []v1.Container{
						{
							Image: "image1",
						},
						{
							Image: "image2",
						},
					},
					Containers: []v1.Container{
						{
							Image: "image3",
						},
					},
				},
			},
		},
	}
	expected := []string{"image1", "image2", "image3"}
	actual := ReplicaSetImages(rs)
	testutil.CheckErrorAndDeepEqual(t, false, nil, expected, actual)
}
