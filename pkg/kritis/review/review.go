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
	"github.com/grafeas/kritis/pkg/kritis/metadata/grafeas"
	"github.com/grafeas/kritis/pkg/kritis/policy"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"github.com/grafeas/kritis/pkg/kritis/violation"
	v1 "k8s.io/api/core/v1"
)

type Reviewer struct {
	config *Config
}

type Config struct {
	Validate  securitypolicy.ValidateFunc
	Secret    secrets.Fetcher
	Auths     authority.Fetcher
	Strategy  violation.Strategy
	IsWebhook bool
}

func New(c *Config) Reviewer {
	return Reviewer{
		config: c,
	}
}

// Flatten allowlist from a list of generic attestation policies
func generateGapAllowlist(gaps []v1beta1.GenericAttestationPolicy) []string {
	allowlist := []string{}
	for _, gap := range gaps {
		for _, pattern := range gap.Spec.AdmissionAllowlistPatterns {
			allowlist = append(allowlist, pattern.NamePattern)
		}
	}
	return allowlist
}

// reviewImageWithGAP reviews single image against a single generic attestation policy
// It returns:
//   - (bool) whether the image is attested
//   - ([] string) a list of unsatisfied attestation authority names
//   - (err) error if fails to get attestation authorities from policy
func (r Reviewer) reviewImageWithGAP(image string, gap v1beta1.GenericAttestationPolicy, c metadata.ReadOnlyClient) (bool, []string, error) {
	glog.Infof("Validating against GenericAttestationPolicy %s", gap.Name)

	// Get all AttestationAuthorities in this policy.
	auths, err := r.getAttestationAuthoritiesForGAP(gap)
	if err != nil {
		return false, nil, err
	}

	notAttestedAuthNames := r.findUnsatisfiedAuthNames(image, auths, c)
	if len(notAttestedAuthNames) == 0 {
		glog.Infof("Image is attested by gap %s", gap.Name)
		return true, make([]string, 0), nil
	}

	glog.Infof("Image is missing attestations from %+q in gap %s", notAttestedAuthNames, gap.Name)
	return false, notAttestedAuthNames, nil
}

func (r Reviewer) checkGAPs(gaps []v1beta1.GenericAttestationPolicy) error {
	for _, gap := range gaps {
		// Get all AttestationAuthorities in this policy.
		auths, err := r.getAttestationAuthoritiesForGAP(gap)
		if err != nil {
			return err
		}
		if len(auths) == 0 {
			return fmt.Errorf("Generic attestation policy %s did not specify any attestation authority.", gap.Name)
		}
	}
	return nil
}

// Helper function to generate an error with a comprehensive message on
// which images are rejected and what attestations they are missing.
func generateRejectedReviewErr(badImages []string, missingAttestations map[string]map[string][]string) error {
	errMsg := fmt.Sprintf("%d images are not attested by all authorities in any GAP policy:\n", len(badImages))
	for _, image := range badImages {
		errMsg = errMsg + fmt.Sprintf("- image %s is not attested by\n", image)
		for gapName, authNames := range missingAttestations[image] {
			errMsg = errMsg + fmt.Sprintf("  - %+q in gap %s\n", authNames, gapName)
		}
	}
	return fmt.Errorf(errMsg)
}

// ReviewGAP reviews images against generic attestation policies
// Return error if policies are not well-formed or violations are found.
func (r Reviewer) ReviewGAP(images []string, gaps []v1beta1.GenericAttestationPolicy, pod *v1.Pod, c metadata.ReadOnlyClient) error {
	// If no policy found, images should be admitted.
	if len(gaps) == 0 {
		glog.Info("No Generic Attestation Policies found")
		return nil
	}

	// Check if all GAPs are well-formed.
	if err := r.checkGAPs(gaps); err != nil {
		return err
	}

	images, removed := util.SplitGloballyAllowedImages(images)
	glog.Infof("%d images are globally allowed: %+q\n", len(removed), removed)

	images, removed = util.SplitGapAllowedImages(images, generateGapAllowlist(gaps))
	glog.Infof("%d images are gap allowed: %+q\n", len(removed), removed)

	// For logging purpose only.
	// we store missing attestations info in the following format:
	// missingAttestations[image][gap] = a list of not attested auth names
	missingAttestations := map[string]map[string][]string{}
	var badImages []string
	for _, image := range images {
		glog.Infof("Check if %s has valid Attestations.", image)
		imgAttestedByAnyGap := false
		missingAttestations[image] = map[string][]string{}
		for _, gap := range gaps {
			isAttested, notAttestedAuthNames, err := r.reviewImageWithGAP(image, gap, c)
			if err != nil {
				return err
			}
			if isAttested {
				imgAttestedByAnyGap = true
				break
			}
			missingAttestations[image][gap.Name] = notAttestedAuthNames
		}
		if err := r.config.Strategy.HandleAttestation(image, pod, imgAttestedByAnyGap); err != nil {
			glog.Errorf("error handling attestations %v", err)
		}
		if !imgAttestedByAnyGap {
			glog.Infof("Image %s is not attested by any gap policy.", image)
			badImages = append(badImages, image)
		}
	}
	if len(badImages) != 0 {
		return generateRejectedReviewErr(badImages, missingAttestations)
	}

	if len(images) == 0 {
		glog.Infof("images are all globally or gap allowed, returning successful status: %s", images)
		return nil
	}

	glog.Infof("%d images are attested: %+q\n", len(images), images)
	glog.Infof("All images are either allowed or attested.")
	return nil
}

// ReviewISP reviews images against image security policies
// Returns error if violations are found and handles them per violation strategy
func (r Reviewer) ReviewISP(images []string, isps []v1beta1.ImageSecurityPolicy, pod *v1.Pod, c metadata.ReadWriteClient) error {
	images, _ = util.SplitGloballyAllowedImages(images)
	if len(images) == 0 {
		glog.Infof("images are all globally allowed, returning successful status: %s", images)
		return nil
	}
	if len(isps) == 0 {
		return nil
	}

	for _, isp := range isps {
		glog.Infof("Validating against ImageSecurityPolicy %s", isp.Name)
		// Get the Attestationauthority in this policy.
		auth, err := r.getAttestationAuthorityForISP(isp)
		if err != nil {
			return err
		}
		// auth will be nil if empty auth name or user does not provide auth name
		authProvided := auth != nil

		for _, image := range images {
			glog.Infof("Check if %s has valid Attestations.", image)
			imgAttested := false
			if authProvided {
				imgAttested = r.isAttestedBy(image, *auth, c)
			}

			if err := r.config.Strategy.HandleAttestation(image, pod, imgAttested); err != nil {
				glog.Errorf("error handling attestations %v", err)
			}

			// Skip vulnerability check for Webhook if attestations found.
			if imgAttested && r.config.IsWebhook {
				continue
			}

			glog.Infof("Getting vulnz for %s", image)
			violations, err := r.config.Validate(isp, image, c)
			if err != nil {
				return fmt.Errorf("error validating image security policy %v", err)
			}
			if len(violations) != 0 {
				return r.handleViolations(image, pod, violations)
			}
			if r.config.IsWebhook && authProvided {
				if err := r.addAttestation(image, isp, *auth, c); err != nil {
					glog.Errorf("error adding attestations %s", err)
				}
			}
			glog.Infof("Found no violations for %s within ISP %s", image, isp.Name)
		}
	}
	return nil
}

// Check if an image is attested by a given attestation authority.
func (r Reviewer) isAttestedBy(image string, auth v1beta1.AttestationAuthority, c metadata.ReadOnlyClient) bool {
	transport := AttestorValidatingTransport{Client: c, Attestor: auth}
	attestations, err := transport.GetValidatedAttestations(image)
	if err != nil {
		glog.Errorf("Error fetching validated attestations for %s: %v", image, err)
	}
	if len(attestations) == 0 {
		return false
	}
	return true
}

// Returns a list of attestation authority names for which there are no attestations for the image.
func (r Reviewer) findUnsatisfiedAuthNames(image string, auths []v1beta1.AttestationAuthority, c metadata.ReadOnlyClient) []string {
	notAttestedAuthNames := make([]string, 0)
	for _, auth := range auths {
		if !r.isAttestedBy(image, auth, c) {
			notAttestedAuthNames = append(notAttestedAuthNames, auth.Name)
		}
	}
	return notAttestedAuthNames
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

// Create attestations for 'image' by ISP auth.
func (r Reviewer) addAttestation(image string, isp v1beta1.ImageSecurityPolicy, auth v1beta1.AttestationAuthority, c metadata.ReadWriteClient) error {
	// Get or Create Note for this this Authority
	n, err := util.GetOrCreateAttestationNote(c, &auth)
	if err != nil {
		return fmt.Errorf("error getting or creating note when adding attestation: %s", err)
	}
	// Get secret for this Authority
	s, err := r.config.Secret(isp.Namespace, isp.Spec.PrivateKeySecretName)
	if err != nil {
		return fmt.Errorf("error getting secret when adding attestation: %s", err)
	}
	// Create Attestation Signature
	if _, err := c.CreateAttestationOccurrence(n.GetName(), image, s, grafeas.DefaultProject); err != nil {
		return fmt.Errorf("error creating occurrence when adding attestation: %s", err)
	}

	return nil
}

func (r Reviewer) getAttestationAuthorityForISP(isp v1beta1.ImageSecurityPolicy) (*v1beta1.AttestationAuthority, error) {
	aName := isp.Spec.AttestationAuthorityName
	if aName == "" {
		glog.Infof("attestationAuthorityName is empty or unset in isp %s", isp.Name)
		return nil, nil
	}
	a, err := r.config.Auths(isp.Namespace, aName)
	if err != nil {
		return nil, fmt.Errorf("error getting attestors: %v", err)
	}
	return a, nil
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
