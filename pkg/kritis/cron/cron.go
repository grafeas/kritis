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

package cron

import (
	"context"
	"time"

	"github.com/grafeas/kritis/pkg/kritis/pods"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
	"github.com/grafeas/kritis/pkg/kritis/violation"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/sirupsen/logrus"
)

// For testing
var (
	checkInterval = 1 * time.Hour
	podChecker    = CheckPods
)

// For testing.
type podLister func(string) ([]corev1.Pod, error)
type violationChecker func(string, v1beta1.ImageSecurityPolicy) ([]metadata.Vulnerability, error)

type Config struct {
	PodLister            podLister
	ViolationChecker     violationChecker
	ViolationStrategy    violation.Strategy
	SecurityPolicyLister func() ([]v1beta1.ImageSecurityPolicy, error)
}

var (
	defaultViolationStrategy = &violation.LoggingStrategy{}
)

func NewCronConfig(cs *kubernetes.Clientset, ca containeranalysis.ContainerAnalysis) *Config {

	vc := func(image string, isp v1beta1.ImageSecurityPolicy) ([]metadata.Vulnerability, error) {
		return securitypolicy.ValidateImageSecurityPolicy(isp, "", image, ca)
	}

	cfg := Config{
		PodLister:            pods.Pods,
		ViolationChecker:     vc,
		ViolationStrategy:    defaultViolationStrategy,
		SecurityPolicyLister: securitypolicy.ImageSecurityPolicies,
	}
	return &cfg
}

// Start starts the background processing of image security policies.
func Start(ctx context.Context, cfg Config) {
	c := time.NewTicker(checkInterval)
	done := ctx.Done()

	for {
		select {
		case <-c.C:
			isps, err := cfg.SecurityPolicyLister()
			if err != nil {
				logrus.Errorf("fetching image security policies: %s", err)
				continue
			}
			if err := podChecker(cfg, isps); err != nil {
				logrus.Errorf("error checking pods: %s", err)
			}
		case <-done:
			return
		}
	}
}

// CheckPods checks all running pods against defined policies.
func CheckPods(cfg Config, isps []v1beta1.ImageSecurityPolicy) error {
	for _, isp := range isps {
		ps, err := cfg.PodLister(isp.Namespace)
		if err != nil {
			return err
		}
		for _, p := range ps {
			for _, c := range pods.Images(p) {
				v, err := cfg.ViolationChecker(c, isp)
				if err != nil {
					return err
				}
				if len(v) != 0 {
					if err := cfg.ViolationStrategy.HandleViolation(c, &p, v); err != nil {
						logrus.Errorf("handling violations: %s", err)
					}
				}
			}
		}
	}
	return nil
}
