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
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"testing"
	"time"

	"github.com/grafeas/kritis/pkg/kritis/violation"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/api/core/v1"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
)

func TestStartCancels(t *testing.T) {

	// Speed up the checks for testing.
	checkInterval = 2 * time.Millisecond

	checked := false

	// Mock the check function and reset after the test.
	originalChecker := podChecker
	podChecker = func(cfg Config, isps []v1beta1.ImageSecurityPolicy) error {
		checked = true
		return nil
	}
	defer func() {
		podChecker = originalChecker
	}()

	// Set a deadline of longer than the check interval
	ctx := context.Background()
	c, cancel := context.WithDeadline(ctx, time.Now().Add(10*checkInterval))
	defer cancel()

	// Make sure the checker is called and Start cancels correctly when the deadline expires.
	Start(c, Config{
		SecurityPolicyLister: func() ([]v1beta1.ImageSecurityPolicy, error) {
			return nil, nil
		},
	})

	if !checked {
		t.Fatalf("check function not called")
	}
}

type imageViolations struct {
	imageMap map[string]bool
}

func (iv *imageViolations) violationChecker(image string, isp v1beta1.ImageSecurityPolicy) ([]securitypolicy.SecurityPolicyViolation, error) {
	if ok := iv.imageMap[image]; ok {
		return []securitypolicy.SecurityPolicyViolation{
			{
				Vulnerability: metadata.Vulnerability{
					Severity: "foo",
				},
			},
		}, nil
	}
	return nil, nil
}

type testLister struct {
	pl []v1.Pod
}

func (tl *testLister) list(ns string) ([]v1.Pod, error) {
	return tl.pl, nil
}

var testPods = testLister{
	pl: []v1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "bar",
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{
						Image: "gcr.io/foo/bar@sha256:baz",
					},
				},
			},
		},
	},
}

var noPods = testLister{}

var noVulnz = imageViolations{}
var someVulnz = imageViolations{
	imageMap: map[string]bool{
		"gcr.io/foo/bar@sha256:baz": true,
	},
}

var isps = []v1beta1.ImageSecurityPolicy{
	{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "foo",
		},
	},
}

func TestCheckPods(t *testing.T) {
	type args struct {
		cfg  Config
		isps []v1beta1.ImageSecurityPolicy
	}
	tests := []struct {
		name           string
		args           args
		wantViolations bool
	}{
		{
			name: "no vulnz",
			args: args{
				cfg: Config{
					ViolationChecker: noVulnz.violationChecker,
					PodLister:        testPods.list,
				},
				isps: isps,
			},
			wantViolations: false,
		},
		{
			name: "vulnz",
			args: args{
				cfg: Config{
					ViolationChecker: someVulnz.violationChecker,
					PodLister:        testPods.list,
				},
				isps: isps,
			},
			wantViolations: true,
		},
		{
			name: "no isps",
			args: args{
				cfg: Config{
					ViolationChecker: someVulnz.violationChecker,
					PodLister:        testPods.list,
				},
				isps: []v1beta1.ImageSecurityPolicy{},
			},
			wantViolations: false,
		},
		{
			name: "no pods",
			args: args{
				cfg: Config{
					ViolationChecker: someVulnz.violationChecker,
					PodLister:        noPods.list,
				},
				isps: isps,
			},
			wantViolations: false,
		},
	}
	for _, tt := range tests {
		th := violation.MemoryStrategy{
			Violations: map[string]bool{},
		}
		tt.args.cfg.ViolationStrategy = &th
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckPods(tt.args.cfg, tt.args.isps); err != nil {
				t.Errorf("CheckPods() error = %v", err)
			}
		})
		if (len(th.Violations) != 0) != tt.wantViolations {
			t.Errorf("got violations %v, expected to have %v", th.Violations, tt.wantViolations)
		}
	}
}
