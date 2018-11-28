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
	"encoding/base64"
	"fmt"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/container"
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
	Auths     authority.Lister
	Strategy  violation.Strategy
	IsWebhook bool
}

func New(client metadata.Fetcher, c *Config) Reviewer {
	return Reviewer{
		client: client,
		config: c,
	}
}

// Review reviews a set of images against a set of policies
// Returns error if violations are found and handles them as per violation strategy
func (r Reviewer) Review(images []string, isps []v1beta1.ImageSecurityPolicy, pod *v1.Pod) error {
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
		auths, err := r.config.Auths(isp.Namespace)
		if err != nil {
			return fmt.Errorf("Error getting attestors: %v", err)
		}
		for _, image := range images {
			glog.Infof("Check if %s as valid Attestations.", image)
			isAttested, attestations := r.fetchAndVerifyAttestations(image, auths, pod)
			// Skip vulnerability check for Webhook if attestations found.
			if isAttested && r.config.IsWebhook {
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
				if err := r.addAttestations(image, attestations, isp.Namespace); err != nil {
					glog.Errorf("error adding attestations %s", err)
				}
			}
			glog.Infof("Found no violations for %s within ISP %s", image, isp.Name)
		}
	}
	return nil
}

func (r Reviewer) fetchAndVerifyAttestations(image string, auths []v1beta1.AttestationAuthority, pod *v1.Pod) (bool, []metadata.PGPAttestation) {
	attestations, err := r.client.Attestations(image)
	if err != nil {
		glog.Errorf("Error while fetching attestations %s", err)
		return false, attestations
	}
	isAttested := r.hasValidImageAttestations(image, attestations, auths)
	if err := r.config.Strategy.HandleAttestation(image, pod, isAttested); err != nil {
		glog.Errorf("error handling attestations %v", err)
	}
	return isAttested, attestations
}

// hasValidImageAttestations return true if any one image attestation is verified.
func (r Reviewer) hasValidImageAttestations(image string, attestations []metadata.PGPAttestation, auths []v1beta1.AttestationAuthority) bool {
	if len(attestations) == 0 {
		glog.Infof(`No attestations found for image %s.
This normally happens when you deploy a pod before kritis or no attestation authority is deployed.
Please see instructions `, image)
	}
	host, err := container.NewAtomicContainerSig(image, map[string]string{})
	if err != nil {
		glog.Error(err)
		return false
	}
	keys := map[string]string{}
	for _, auth := range auths {
		key, fingerprint, err := fingerprint(auth.Spec.PublicKeyData)
		if err != nil {
			glog.Errorf("Error parsing key for %q: %v", auth.Name, err)
			continue
		}
		keys[fingerprint] = key
	}
	for _, a := range attestations {
		if err = host.VerifyAttestationSignature(keys[a.KeyID], a.Signature); err != nil {
			glog.Errorf("Could not find verify attestation for attestation authority %s", a.KeyID)
		} else {
			return true
		}
	}
	return false
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

func (r Reviewer) addAttestations(image string, atts []metadata.PGPAttestation, ns string) error {
	// Get all AttestationAuthorities in this namespace.
	auths, err := r.config.Auths(ns)
	if err != nil {
		return err
	}
	if len(auths) == 0 {
		return fmt.Errorf("no attestation authorities configured for namespace %s", ns)
	}
	keys := map[string]string{}
	for _, auth := range auths {
		_, fingerprint, err := fingerprint(auth.Spec.PublicKeyData)
		if err != nil {
			glog.Errorf("Error parsing key for %q: %v", auth.Name, err)
			continue
		}
		keys[auth.Name] = fingerprint
	}
	// Get all AttestationAuthorities which have not attested the image.
	errMsgs := []string{}
	u := getUnAttested(auths, keys, atts)
	if len(u) == 0 {
		glog.Info("Attestation exists for all authorities")
		return nil
	}
	for _, a := range u {
		// Get or Create Note for this this Authority
		n, err := util.GetOrCreateAttestationNote(r.client, &a)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
		// Get secret for this Authority
		s, err := r.config.Secret(ns, a.Spec.PrivateKeySecretName)
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

func getUnAttested(auths []v1beta1.AttestationAuthority, keys map[string]string, atts []metadata.PGPAttestation) []v1beta1.AttestationAuthority {
	l := []v1beta1.AttestationAuthority{}
	m := map[string]bool{}
	for _, a := range atts {
		m[a.KeyID] = true
	}

	for _, a := range auths {
		_, ok := m[keys[a.Name]]
		if !ok {
			l = append(l, a)
		}
	}
	return l
}

// fingerprint returns the fingerprint and key from the base64 encoded public key data
func fingerprint(publicKeyData string) (key, fingerprint string, err error) {
	publicData, err := base64.StdEncoding.DecodeString(publicKeyData)
	if err != nil {
		return key, fingerprint, err
	}
	s, err := attestation.NewPgpKey("", string(publicData))
	if err != nil {
		return key, fingerprint, err
	}
	return string(publicData), s.Fingerprint(), nil
}
