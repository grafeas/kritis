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

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/pods"
	"github.com/grafeas/kritis/pkg/kritis/review"
	"github.com/grafeas/kritis/pkg/kritis/secrets"

	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/violation"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// For testing
var (
	podChecker = CheckPods
)

// For testing.
type podLister func(string) ([]corev1.Pod, error)

type Config struct {
	PodLister            podLister
	Client               metadata.MetadataFetcher
	ReviewConfig         *review.Config
	SecurityPolicyLister func(namespace string) ([]v1beta1.ImageSecurityPolicy, error)
}

var (
	defaultViolationStrategy = &violation.AnnotationStrategy{}
)

func NewCronConfig(cs *kubernetes.Clientset, client metadata.MetadataFetcher) *Config {

	cfg := Config{
		PodLister: pods.Pods,
		Client:    client,
		ReviewConfig: &review.Config{
			Secret:    secrets.Fetch,
			Strategy:  defaultViolationStrategy,
			IsWebhook: false,
			Validate:  securitypolicy.ValidateImageSecurityPolicy,
		},
		SecurityPolicyLister: securitypolicy.ImageSecurityPolicies,
	}
	return &cfg
}

// Start starts the background processing of image security policies.
func Start(ctx context.Context, cfg Config, checkInterval time.Duration) {
	c := time.NewTicker(checkInterval)
	done := ctx.Done()

	for {
		glog.Info("Checking pods.")
		select {
		case <-c.C:
			isps, err := cfg.SecurityPolicyLister("")
			if err != nil {
				glog.Errorf("fetching image security policies: %s", err)
				continue
			}
			if err := podChecker(cfg, isps); err != nil {
				glog.Errorf("error checking pods: %s", err)
			}
		case <-done:
			return
		}
	}
}

// CheckPods checks all running pods against defined policies.
func CheckPods(cfg Config, isps []v1beta1.ImageSecurityPolicy) error {
	r := review.New(cfg.Client, cfg.ReviewConfig)
	for _, isp := range isps {
		ps, err := cfg.PodLister(isp.Namespace)
		if err != nil {
			return err
		}
		for _, p := range ps {
			glog.Infof("Checking po %s", p.Name)
			if err := r.Review(pods.Images(p), isps, &p); err != nil {
				glog.Error(err)
			}
		}
	}
	return nil
}

// RunInForeground checks Pods in foreground.
func RunInForeground(cfg Config) error {
	isps, err := cfg.SecurityPolicyLister("")
	if err != nil {
		return err
	}
	glog.Infof("Got isps %v", isps)
	return podChecker(cfg, isps)
}
