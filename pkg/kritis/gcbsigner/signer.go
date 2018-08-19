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

package gcbsigner

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/authority"
	"github.com/grafeas/kritis/pkg/kritis/crd/buildpolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
)

type Signer struct {
	config *Config
	client metadata.Fetcher
}

type Config struct {
	Secret   secrets.Fetcher
	Validate buildpolicy.ValidateFunc
}

func New(client metadata.Fetcher, c *Config) Signer {
	return Signer{
		client: client,
		config: c,
	}
}

type ImageBuildInfo struct {
	BuildID   string
	ImageRef  string
	BuiltFrom string
}

// For testing
var (
	authFetcher = authority.Authorities
)

// ValidateAndSign validates builtFrom against the build policies and creates
// attestations for all authorities for the matching policies.
// Returns an error if creating an attestation for any authority fails.
func (r Signer) ValidateAndSign(buildInfo ImageBuildInfo, bps []v1beta1.BuildPolicy) error {
	for _, bp := range bps {
		glog.Infof("Validating %q against BuildPolicy %q", buildInfo.ImageRef, bp.Name)
		if result := r.config.Validate(bp, buildInfo.BuiltFrom); result != nil {
			glog.Errorf("Image %q does not match BuildPolicy %q: %s", buildInfo.ImageRef, bp.ObjectMeta.Name, result)
			continue
		}
		glog.Infof("Image %q matches BuildPolicy %s, creating attestations", buildInfo.ImageRef, bp.Name)
		if err := r.addAttestation(buildInfo.ImageRef, bp.Namespace, bp.Spec.AttestationAuthorityName); err != nil {
			return err
		}
	}
	return nil
}

func (r Signer) addAttestation(image string, ns string, authority string) error {
	// Get all AttestationAuthorities in this namespace.
	auths, err := authFetcher(ns)
	if err != nil {
		return err
	}
	if len(auths) == 0 {
		return fmt.Errorf("no attestation authorities configured for namespace %s", ns)
	}
	errMsgs := []string{}
	for _, a := range auths {
		if a.ObjectMeta.Name == authority {
			glog.Infof("Ceate attestation by %q for %q", image, authority)
			// Get or Create Note for this this Authority
			n, err := r.getOrCreateAttestationNote(&a)
			if err != nil {
				glog.Errorf("Error getting note: %s", err)
				errMsgs = append(errMsgs, err.Error())
				continue
			}
			// Get secret for this Authority
			s, err := r.config.Secret(ns, a.Spec.PrivateKeySecretName)
			if err != nil {
				glog.Errorf("Error getting secret: %s", err)
				errMsgs = append(errMsgs, err.Error())
				continue
			}
			// Create Attestation Signature
			if _, err := r.client.CreateAttestationOccurence(n, image, s); err != nil {
				glog.Errorf("Error creating occurrence: %s", err)
				errMsgs = append(errMsgs, err.Error())
			}
		}
	}
	if len(errMsgs) == 0 {
		return nil
	}
	return fmt.Errorf("one or more errors adding attestations: %s", errMsgs)
}

func (r Signer) getOrCreateAttestationNote(a *v1beta1.AttestationAuthority) (*containeranalysispb.Note, error) {
	n, err := r.client.GetAttestationNote(a)
	if err == nil {
		return n, nil
	}
	return r.client.CreateAttestationNote(a)
}
