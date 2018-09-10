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
	"reflect"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/policy"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"github.com/grafeas/kritis/pkg/kritis/violation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestHasValidAttestations(t *testing.T) {
	successSec := testutil.CreateSecret(t, "test-success")
	sig, err := util.CreateAttestationSignature(testutil.QualifiedImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	anotherSig, err := util.CreateAttestationSignature(testutil.IntTestImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	tcs := []struct {
		name         string
		expected     bool
		attestations []metadata.PGPAttestation
	}{
		{"atleast one valid sig", true, []metadata.PGPAttestation{
			{
				Signature: sig,
				KeyID:     "test-success",
			}, {
				Signature: "invalid-sig",
				KeyID:     "test-sucess",
			}}},
		{"no valid sig", false, []metadata.PGPAttestation{
			{
				Signature: "invalid-sig",
				KeyID:     "test-sucess",
			}}},
		{"invalid secret", false, []metadata.PGPAttestation{
			{
				Signature: "invalid-sig",
				KeyID:     "invalid",
			}}},
		{"valid sig over another host", false, []metadata.PGPAttestation{
			{
				Signature: anotherSig,
				KeyID:     "test-success",
			}}},
	}
	secs := map[string]*secrets.PGPSigningSecret{
		"test-success": successSec,
	}
	sMock := func(namespace string, name string) (*secrets.PGPSigningSecret, error) {
		s, ok := secs[name]
		if !ok {
			return nil, fmt.Errorf("secret not found")
		}
		return s, nil
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cMock := &testutil.MockMetadataClient{
				PGPAttestations: tc.attestations,
			}
			r := New(cMock, &Config{
				Validate:  nil,
				Secret:    sMock,
				IsWebhook: true,
				Strategy:  nil,
			})
			actual := r.hasValidImageAttestations(testutil.QualifiedImage, tc.attestations, "test-namespace")
			if actual != tc.expected {
				t.Fatalf("Expected %v, Got %v", tc.expected, actual)
			}
		})
	}
}

func TestReview(t *testing.T) {
	sec := testutil.CreateSecret(t, "sec")
	vulnImage := testutil.QualifiedImage
	sigVuln, err := util.CreateAttestationSignature(vulnImage, sec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	noVulnImage := testutil.IntTestImage
	sigNoVuln, err := util.CreateAttestationSignature(noVulnImage, sec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	sMock := func(namespace string, name string) (*secrets.PGPSigningSecret, error) {
		return sec, nil
	}
	validAtts := []metadata.PGPAttestation{{Signature: sigVuln, KeyID: "sec"}}
	var isps = []v1beta1.ImageSecurityPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "foo",
			},
		},
	}
	authFetcher = func(ns string) ([]v1beta1.AttestationAuthority, error) {
		return []v1beta1.AttestationAuthority{{
			Spec: v1beta1.AttestationAuthoritySpec{
				NoteReference:        "provider/test",
				PrivateKeySecretName: "test",
				PublicKeyData:        sec.PublicKey,
			}}}, nil
	}
	mockValidate := func(isp v1beta1.ImageSecurityPolicy, image string, client metadata.Fetcher) ([]policy.Violation, error) {
		if image == vulnImage {
			v := securitypolicy.NewViolation(metadata.Vulnerability{Severity: "foo"}, 1, "")
			vs := []policy.Violation{}
			vs = append(vs, v)
			return vs, nil
		}
		return nil, nil
	}
	tests := []struct {
		name              string
		image             string
		isWebhook         bool
		attestations      []metadata.PGPAttestation
		handledViolations int
		isAttested        bool
		shdAttestImage    bool
		shdErr            bool
	}{
		{
			name:              "vulnz w attestation for Webhook shd not handle voilations",
			image:             vulnImage,
			isWebhook:         true,
			attestations:      validAtts,
			handledViolations: 0,
			isAttested:        true,
			shdAttestImage:    false,
			shdErr:            false,
		},
		{
			name:              "vulnz w/o attestation for Webhook shd handle voilations",
			image:             vulnImage,
			isWebhook:         true,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 1,
			isAttested:        false,
			shdAttestImage:    false,
			shdErr:            true,
		},
		{
			name:              "no vulnz w/o attestation for webhook shd add attestation",
			image:             noVulnImage,
			isWebhook:         true,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 0,
			isAttested:        false,
			shdAttestImage:    true,
			shdErr:            false,
		},
		{
			name:              "vulnz w attestation for cron shd handle vuln",
			image:             vulnImage,
			isWebhook:         false,
			attestations:      validAtts,
			handledViolations: 1,
			isAttested:        true,
			shdAttestImage:    false,
			shdErr:            true,
		},
		{
			name:              "vulnz w/o attestation for cron shd handle vuln",
			image:             vulnImage,
			isWebhook:         false,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 1,
			isAttested:        false,
			shdAttestImage:    false,
			shdErr:            true,
		},
		{
			name:              "no vulnz w/o attestation for cron shd verify attestations",
			image:             noVulnImage,
			isWebhook:         false,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 0,
			isAttested:        false,
			shdAttestImage:    false,
			shdErr:            false,
		},
		{
			name:              "no vulnz w attestation for cron shd verify attestations",
			image:             noVulnImage,
			isWebhook:         false,
			attestations:      []metadata.PGPAttestation{{Signature: sigNoVuln, KeyID: "sec"}},
			handledViolations: 0,
			isAttested:        true,
			shdAttestImage:    false,
			shdErr:            false,
		},
	}
	for _, tc := range tests {
		th := violation.MemoryStrategy{
			Violations:   map[string]bool{},
			Attestations: map[string]bool{},
		}
		t.Run(tc.name, func(t *testing.T) {
			cMock := &testutil.MockMetadataClient{
				PGPAttestations: tc.attestations,
			}
			r := New(cMock, &Config{
				Validate:  mockValidate,
				Secret:    sMock,
				IsWebhook: tc.isWebhook,
				Strategy:  &th,
			})
			if err := r.Review([]string{tc.image}, isps, nil); (err != nil) != tc.shdErr {
				t.Errorf("expected review to return error %t, actual error %s", tc.shdErr, err)
			}
			if len(th.Violations) != tc.handledViolations {
				t.Errorf("expected to handle %d violations. Got %d", tc.handledViolations, len(th.Violations))
			}

			if th.Attestations[tc.image] != tc.isAttested {
				t.Errorf("expected to get image attested: %t. Got %t", tc.isAttested, th.Attestations[tc.image])
			}
			if (len(cMock.Occ) != 0) != tc.shdAttestImage {
				t.Errorf("expected an image to be attested, but found none")
			}
		})
	}
}

func TestGetUnAttested(t *testing.T) {
	tcs := []struct {
		name     string
		authIds  []string
		attIds   []string
		eAuthIds []string
	}{
		{"not equal", []string{"a", "b"}, []string{"a"}, []string{"b"}},
		{"equal", []string{"a", "b"}, []string{"a", "b"}, []string{}},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			auths := makeAuth(tc.authIds)
			atts := makeAtt(tc.attIds)
			expected := makeAuth(tc.eAuthIds)
			actual := getUnAttested(auths, atts)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("Expected: %v\n Got: %v", expected, actual)
			}

		})
	}
}

func makeAuth(ids []string) []v1beta1.AttestationAuthority {
	l := make([]v1beta1.AttestationAuthority, len(ids))
	for i, s := range ids {
		l[i] = v1beta1.AttestationAuthority{
			Spec: v1beta1.AttestationAuthoritySpec{
				PrivateKeySecretName: s,
			},
		}
	}
	return l
}

func makeAtt(ids []string) []metadata.PGPAttestation {
	l := make([]metadata.PGPAttestation, len(ids))
	for i, s := range ids {
		l[i] = metadata.PGPAttestation{
			KeyID: s,
		}
	}
	return l
}
