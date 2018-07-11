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
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
)

type Strategy interface {
	HandleViolation(image string, pod *v1.Pod, violations []metadata.Vulnerability) error
}

type LoggingStrategy struct {
}

func (l *LoggingStrategy) HandleViolation(image string, pod *v1.Pod, violations []metadata.Vulnerability) error {
	logrus.Warn("violations %v found in image %s, pod %s, ns %s", violations, image, pod.Name, pod.Namespace)
	return nil
}

// For unit testing.
type MemoryStrategy struct {
	Violations map[string]bool
}

func (ms *MemoryStrategy) HandleViolation(image string, p *v1.Pod, v []metadata.Vulnerability) error {
	ms.Violations[image] = true
	return nil
}
