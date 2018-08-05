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

package review

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"github.com/grafeas/kritis/pkg/kritis/violation"
	"k8s.io/api/core/v1"
)

type Reviewer struct {
	client   metadata.MetadataFetcher
	vs       violation.Strategy
	validate securitypolicy.ValidateFunc
}

func New(client metadata.MetadataFetcher, vs violation.Strategy, validate securitypolicy.ValidateFunc) Reviewer {
	return Reviewer{
		client:   client,
		vs:       vs,
		validate: validate,
	}
}

// Review reviews a set of images against a set of policies
// Returns error if violations are found and handles them as per violation strategy
func (r Reviewer) Review(images []string, isps []v1beta1.ImageSecurityPolicy, pod *v1.Pod) error {
	images = util.RemoveGloballyWhitelistedImages(images)
	if len(images) == 0 {
		glog.Info("images are all globally whitelisted, returning successful status", images)
		return nil
	}
	for _, isp := range isps {
		for _, image := range images {
			glog.Infof("Getting vulnz for %s", image)
			violations, err := r.validate(isp, image, r.client)
			if err != nil {
				return fmt.Errorf("error validating image security policy %v", err)
			}
			if len(violations) != 0 {
				errMsg := fmt.Sprintf("found violations in %s", image)
				// Check if one of the violations is that the image is not fully qualified
				for _, v := range violations {
					if v.Violation == securitypolicy.UnqualifiedImageViolation {
						errMsg = fmt.Sprintf("%s is not a fully qualified image", image)
					}
				}
				if err := r.vs.HandleViolation(image, pod, violations); err != nil {
					return fmt.Errorf("%s. error handling violation %v", errMsg, err)
				}
				return fmt.Errorf(errMsg)
			}
		}
	}
	return nil
}
