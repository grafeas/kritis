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
package violation

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/pods"
	"k8s.io/api/core/v1"
)

type Strategy interface {
	HandleViolation(image string, pod *v1.Pod, violations []securitypolicy.SecurityPolicyViolation) error
}

type LoggingStrategy struct {
}

func (l *LoggingStrategy) HandleViolation(image string, ns string, violations []securitypolicy.SecurityPolicyViolation) error {
	glog.Info("HandleViolation via LoggingStrategy")
	if len(violations) == 0 {
		return nil
	}
	glog.Warning("Found violations in image %s, ns %s", image, ns)
	for _, v := range violations {
		glog.Warning(v.Reason)
	}
	return nil
}

// AnnotationStrategy adds "InvalidImageSecPolicy" as a label and an annotation, with detailed info in the annotations
type AnnotationStrategy struct {
}

func (a *AnnotationStrategy) HandleViolation(image string, pod *v1.Pod, violations []securitypolicy.SecurityPolicyViolation) error {
	// First, remove "kritis.grafeas.io/invalidImageSecPolicy" label/annotation in case it doesn't apply anymore
	if err := pods.DeleteLabelsAndAnnotations(*pod, []string{constants.InvalidImageSecPolicy}, []string{constants.InvalidImageSecPolicy}); err != nil {
		return err
	}
	if len(violations) == 0 {
		return nil
	}
	// Now, construct labels and annotations
	var labelValue string
	var annotationValue string
	for _, v := range violations {
		if v.Violation == securitypolicy.UnqualifiedImageViolation {
			labelValue = constants.InvalidImageSecPolicyLabelValue
		}
		annotationValue += string(v.Reason) + "\n"
	}
	labels := map[string]string{constants.InvalidImageSecPolicy: labelValue}
	annotations := map[string]string{constants.InvalidImageSecPolicy: annotationValue}
	glog.Info(fmt.Sprintf("Adding label %s and annotation %s", labelValue, annotationValue))
	return pods.AddLabelsAndAnnotations(*pod, labels, annotations)
}

// For unit testing.
type MemoryStrategy struct {
	Violations map[string]bool
}

func (ms *MemoryStrategy) HandleViolation(image string, p *v1.Pod, v []securitypolicy.SecurityPolicyViolation) error {
	ms.Violations[image] = true
	return nil
}
