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
	"github.com/grafeas/kritis/pkg/kritis/crd/authority"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/policy"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"github.com/grafeas/kritis/pkg/kritis/violation"

	v1 "k8s.io/api/core/v1"
)

type Reviewer struct {
	config *Config
	client metadata.Fetcher
}

type Config struct {
	Validate  securitypolicy.ValidateFunc
	Secret    secrets.Fetcher
	Auths     authority.Fetcher
	Strategy  violation.Strategy
	IsWebhook bool
}

func New(client metadata.Fetcher, c *Config) Reviewer {
	return Reviewer{
		client: client,
		config: c,
	}
}

// ReviewGAP reviews images against generic attestation policies
// Returns error if violations are found and handles them per violation strategy
func (r Reviewer) ReviewGAP(images []string, gaps []v1beta1.GenericAttestationPolicy, pod *v1.Pod) error {
	if len(gaps) == 0 {
		glog.Info("No Generic Attestation Policies found")
		return nil
	}

	for _, image := range images {
		glog.Infof("Check if %s has valid Attestations.", image)
		var imgAttested bool
		for _, gap := range gaps {
			glog.Infof("Validating against GenericAttestationPolicy %s", gap.Name)
			// Get all AttestationAuthorities in this policy.
			auths, err := r.getAttestationAuthoritiesForGAP(gap)
			if err != nil {
				return err
			}
			notAttestedBy := r.findUnsatisfiedAuths(image, auths)
			imgAttested = len(notAttestedBy) == 0
		}
		if err := r.config.Strategy.HandleAttestation(image, pod, imgAttested); err != nil {
			glog.Errorf("error handling attestations %v", err)
		}
		if !imgAttested {
			return fmt.Errorf("image %s is not attested", image)
		}
	}
	return nil
}

// ReviewISP reviews images against image security policies
// Returns error if violations are found and handles them per violation strategy
func (r Reviewer) ReviewISP(images []string, isps []v1beta1.ImageSecurityPolicy, pod *v1.Pod) error {
	images = util.RemoveGloballyWhitelistedImages(images)
	if len(images) == 0 {
		glog.Infof("images are all globally whitelisted, returning successful status: %s", images)
		return nil
	}
	if len(isps) == 0 {
		return nil
	}

	for _, isp := range isps {
		glog.Infof("Validating against ImageSecurityPolicy %s", isp.Name)
		// Get all AttestationAuthorities in this policy.
		auths, err := r.getAttestationAuthoritiesForISP(isp)
		if err != nil {
			return err
		}
		for _, image := range images {
			glog.Infof("Check if %s as valid Attestations.", image)
			notAttestedBy := r.findUnsatisfiedAuths(image, auths)
			imgAttested := len(notAttestedBy) == 0

			if err := r.config.Strategy.HandleAttestation(image, pod, imgAttested); err != nil {
				glog.Errorf("error handling attestations %v", err)
			}

			// Skip vulnerability check for Webhook if attestations found.
			if imgAttested && r.config.IsWebhook {
				continue
			}

			glog.Infof("Getting vulnz for %s", image)
			violations, err := r.config.Validate(isp, image, r.client)
			if err != nil {
				return fmt.Errorf("error validating image security policy %v", err)
			}
			if len(violations) != 0 {
				return r.handleViolations(image, pod, violations)
			}
			if r.config.IsWebhook {
				if err := r.addAttestations(image, isp, notAttestedBy); err != nil {
					glog.Errorf("error adding attestations %s", err)
				}
			}
			glog.Infof("Found no violations for %s within ISP %s", image, isp.Name)
		}
	}
	return nil
}

// Returns a subset of 'auths' for which there are no attestations for 'image'.
// In particular, if this returns an empty result, then 'image' has at least one attestation by every AttestationAuthority from 'auths'.
func (r Reviewer) findUnsatisfiedAuths(image string, auths []v1beta1.AttestationAuthority) []v1beta1.AttestationAuthority {
	notAttestedBy := []v1beta1.AttestationAuthority{}
	for _, auth := range auths {
		transport := AttestorValidatingTransport{Client: r.client, Attestor: auth}
		attestations, err := transport.GetValidatedAttestations(image)
		if err != nil {
			glog.Errorf("Error fetching validated attestations for %s: %v", image, err)
		}
		if len(attestations) == 0 {
			notAttestedBy = append(notAttestedBy, auth)
		}
	}
	return notAttestedBy
}

func (r Reviewer) handleViolations(image string, pod *v1.Pod, violations []policy.Violation) error {
	errMsg := fmt.Sprintf("found violations in %s", image)
	// Check if one of the violations is that the image is not fully qualified
	for _, v := range violations {
		if v.Type() == policy.UnqualifiedImageViolation {
			errMsg = fmt.Sprintf(`%s is not a fully qualified image.
			  You can run 'kubectl plugin resolve-tags' to qualify all images with a digest.
			  Instructions for installing the plugin can be found at https://github.com/grafeas/kritis/blob/master/cmd/kritis/kubectl/plugins/resolve`, image)
		}
	}
	if err := r.config.Strategy.HandleViolation(image, pod, violations); err != nil {
		return fmt.Errorf("%s. error handling violation %v", errMsg, err)
	}
	return fmt.Errorf(errMsg)
}

func (r Reviewer) addAttestations(image string, isp v1beta1.ImageSecurityPolicy, auths []v1beta1.AttestationAuthority) error {
	// Get all AttestationAuthorities in this policy.
	errMsgs := []string{}
	for _, a := range auths {
		// Get or Create Note for this this Authority
		n, err := util.GetOrCreateAttestationNote(r.client, &a)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
		// Get secret for this Authority
		s, err := r.config.Secret(isp.Namespace, a.Spec.PrivateKeySecretName)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
		// Create Attestation Signature
		if _, err := r.client.CreateAttestationOccurence(n, image, s); err != nil {
			errMsgs = append(errMsgs, err.Error())
		}

	}
	if len(errMsgs) == 0 {
		return nil
	}
	return fmt.Errorf("one or more errors adding attestations: %s", errMsgs)
}

func (r Reviewer) getAttestationAuthoritiesForISP(isp v1beta1.ImageSecurityPolicy) ([]v1beta1.AttestationAuthority, error) {
	auths := make([]v1beta1.AttestationAuthority, len(isp.Spec.AttestationAuthorityNames))
	for i, aName := range isp.Spec.AttestationAuthorityNames {
		a, err := r.config.Auths(isp.Namespace, aName)
		if err != nil {
			return nil, fmt.Errorf("Error getting attestors: %v", err)
		}
		auths[i] = *a
	}
	return auths, nil
}

func (r Reviewer) getAttestationAuthoritiesForGAP(gap v1beta1.GenericAttestationPolicy) ([]v1beta1.AttestationAuthority, error) {
	auths := make([]v1beta1.AttestationAuthority, len(gap.Spec.AttestationAuthorityNames))
	for i, aName := range gap.Spec.AttestationAuthorityNames {
		a, err := r.config.Auths(gap.Namespace, aName)
		if err != nil {
			return nil, fmt.Errorf("Error getting attestors: %v", err)
		}
		auths[i] = *a
	}
	return auths, nil
}
