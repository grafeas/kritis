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
	"fmt"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_Images(t *testing.T) {
	pod := corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Image: "image1",
				},
				{
					Image: "image2",
				},
			},
			InitContainers: []corev1.Container{
				{
					Image: "image3",
				},
			},
		},
	}
	expected := []string{"image3", "image1", "image2"}
	actual := Images(pod)
	testutil.CheckErrorAndDeepEqual(t, false, nil, expected, actual)
}

func Test_AddPatch(t *testing.T) {
	tests := []struct {
		name                string
		labels              map[string]string
		annotations         map[string]string
		newLabels           map[string]string
		newAnnotations      map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name:                "create label and annotation",
			labels:              nil,
			annotations:         map[string]string{},
			newLabels:           map[string]string{"label": "new label"},
			newAnnotations:      map[string]string{"annotation": "new annotation"},
			expectedLabels:      map[string]string{"label": "new label"},
			expectedAnnotations: map[string]string{"annotation": "new annotation"},
		},
		{
			name:                "update label and annotation",
			labels:              map[string]string{"label": "label"},
			annotations:         map[string]string{"annotation": "annotation"},
			newLabels:           map[string]string{"label": "new label"},
			newAnnotations:      map[string]string{"annotation": "new annotation"},
			expectedLabels:      map[string]string{"label": "new label"},
			expectedAnnotations: map[string]string{"annotation": "new annotation"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "pod",
					Labels:      test.labels,
					Annotations: test.annotations,
				},
			}
			originalPatchFunction := patchFunction
			defer func() {
				patchFunction = originalPatchFunction
			}()
			patch := []byte{}
			mockApplyPatch := func(modifiedPod *corev1.Pod, originalJSON []byte) error {
				var err error
				patch, err = getPatch(modifiedPod, originalJSON)
				return err
			}
			patchFunction = mockApplyPatch
			if err := AddLabelsAndAnnotations(pod, test.newLabels, test.newAnnotations); err != nil {
				t.Error(err)
			}
			annotations, err := json.Marshal(test.expectedAnnotations)
			if err != nil {
				t.Error(err)
			}
			labels, err := json.Marshal(test.expectedLabels)
			if err != nil {
				t.Error(err)
			}
			expected := fmt.Sprintf(`{"metadata":{"annotations":%s,"labels":%s}}`, annotations, labels)
			testutil.CheckErrorAndDeepEqual(t, false, err, expected, string(patch))
		})
	}
}

func Test_DeletePatch(t *testing.T) {
	tests := []struct {
		name                string
		labels              map[string]string
		annotations         map[string]string
		deleteLabels        []string
		deleteAnnotations   []string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		noChange            bool
	}{
		{
			name:                "delete label and annotation",
			labels:              map[string]string{"label": "some label"},
			annotations:         map[string]string{"annotation": "some annotation"},
			deleteLabels:        []string{"label"},
			deleteAnnotations:   []string{"annotation"},
			expectedLabels:      nil,
			expectedAnnotations: nil,
		},
		{
			name:              "delete non-existant label and annotation",
			labels:            map[string]string{"label": "label"},
			annotations:       map[string]string{"annotation": "annotation"},
			deleteLabels:      []string{"something"},
			deleteAnnotations: []string{"something"},
			noChange:          true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "pod",
					Labels:      test.labels,
					Annotations: test.annotations,
				},
			}
			originalPatchFunction := patchFunction
			defer func() {
				patchFunction = originalPatchFunction
			}()
			patch := []byte{}
			mockApplyPatch := func(modifiedPod *corev1.Pod, originalJSON []byte) error {
				var err error
				patch, err = getPatch(modifiedPod, originalJSON)
				return err
			}
			patchFunction = mockApplyPatch
			if err := DeleteLabelsAndAnnotations(pod, test.deleteLabels, test.deleteAnnotations); err != nil {
				t.Error(err)
			}
			annotations, err := json.Marshal(test.expectedAnnotations)
			if err != nil {
				t.Error(err)
			}
			labels, err := json.Marshal(test.expectedLabels)
			if err != nil {
				t.Error(err)
			}
			expected := fmt.Sprintf(`{"metadata":{"annotations":%s,"labels":%s}}`, annotations, labels)
			if test.noChange {
				expected = "{}"
			}
			testutil.CheckErrorAndDeepEqual(t, false, err, expected, string(patch))
		})
	}
}
