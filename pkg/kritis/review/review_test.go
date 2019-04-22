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
	successSec, pub := testutil.CreateSecret(t, "test-success")
	successFpr := successSec.PgpKey.Fingerprint()
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
				KeyID:     successFpr,
			}, {
				Signature: "invalid-sig",
				KeyID:     successFpr,
			}}},
		{"no valid sig", false, []metadata.PGPAttestation{
			{
				Signature: "invalid-sig",
				KeyID:     successFpr,
			}}},
		{"invalid secret", false, []metadata.PGPAttestation{
			{
				Signature: "invalid-sig",
				KeyID:     "invalid-fpr",
			}}},
		{"valid sig over another host", false, []metadata.PGPAttestation{
			{
				Signature: anotherSig,
				KeyID:     successFpr,
			}}},
	}
	secs := map[string]*secrets.PGPSigningSecret{
		"test-success": successSec,
	}
	sMock := func(_ string, name string) (*secrets.PGPSigningSecret, error) {
		s, ok := secs[name]
		if !ok {
			return nil, fmt.Errorf("secret not found")
		}
		return s, nil
	}

	auths := []v1beta1.AttestationAuthority{
		{
			Spec: v1beta1.AttestationAuthoritySpec{
				PrivateKeySecretName: "test-success",
				PublicKeyData:        base64.StdEncoding.EncodeToString([]byte(pub)),
			},
		},
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
			actual := r.hasValidImageAttestations(testutil.QualifiedImage, tc.attestations, auths)
			if actual != tc.expected {
				t.Fatalf("Expected %v, Got %v", tc.expected, actual)
			}
		})
	}
}

func TestReviewGAP(t *testing.T) {
	sec, pub := testutil.CreateSecret(t, "sec")
	secFpr := sec.PgpKey.Fingerprint()
	img := testutil.QualifiedImage
	sig, err := util.CreateAttestationSignature(img, sec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	sMock := func(_, _ string) (*secrets.PGPSigningSecret, error) {
		return sec, nil
	}
	validAtts := []metadata.PGPAttestation{{Signature: sig, KeyID: secFpr}}

	invalidSig, err := util.CreateAttestationSignature(testutil.IntTestImage, sec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	invalidAtts := []metadata.PGPAttestation{{Signature: invalidSig, KeyID: secFpr}}

	var gap = v1beta1.GenericAttestationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "foo",
		},
		Spec: v1beta1.GenericAttestationPolicySpec{
			AttestationAuthorityNames: []string{"test"},
		},
	}
	var gaps = []v1beta1.GenericAttestationPolicy{gap}
	var twoGaps = []v1beta1.GenericAttestationPolicy{gap,
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "foo",
			},
			Spec: v1beta1.GenericAttestationPolicySpec{
				AttestationAuthorityNames: []string{"unknown"},
			},
		},
	}
	authMock := func(_ string, name string) (*v1beta1.AttestationAuthority, error) {
		return &v1beta1.AttestationAuthority{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: v1beta1.AttestationAuthoritySpec{
				NoteReference:        "provider/test",
				PrivateKeySecretName: "test",
				PublicKeyData:        base64.StdEncoding.EncodeToString([]byte(pub)),
			}}, nil
	}
	mockValidate := func(isp v1beta1.ImageSecurityPolicy, image string, client metadata.Fetcher) ([]policy.Violation, error) {
		return nil, nil
	}

	tests := []struct {
		name         string
		image        string
		policies     []v1beta1.GenericAttestationPolicy
		attestations []metadata.PGPAttestation
		isAttested   bool
		shouldErr    bool
	}{
		{
			name:         "valid image with attestation",
			image:        img,
			policies:     gaps,
			attestations: validAtts,
			isAttested:   true,
			shouldErr:    false,
		},
		{
			name:         "image without attestation",
			image:        img,
			policies:     gaps,
			attestations: []metadata.PGPAttestation{},
			isAttested:   false,
			shouldErr:    true,
		},
		{
			name:         "image without policies",
			image:        img,
			policies:     []v1beta1.GenericAttestationPolicy{},
			attestations: []metadata.PGPAttestation{},
			isAttested:   false,
			shouldErr:    false,
		},
		{
			name:         "image with invalid attestation",
			image:        img,
			policies:     gaps,
			attestations: invalidAtts,
			isAttested:   false,
			shouldErr:    true,
		},
		{
			name:         "image complies 1 policy",
			image:        img,
			policies:     twoGaps,
			attestations: validAtts,
			isAttested:   true,
			shouldErr:    false,
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
				Auths:     authMock,
				IsWebhook: true,
				Strategy:  &th,
			})
			if err := r.ReviewGAP([]string{tc.image}, tc.policies, nil); (err != nil) != tc.shouldErr {
				t.Errorf("expected review to return error %t, actual error %s", tc.shouldErr, err)
			}
			if th.Attestations[tc.image] != tc.isAttested {
				t.Errorf("expected to get image attested: %t. Got %t", tc.isAttested, th.Attestations[tc.image])
			}
		})
	}
}

func TestReviewISP(t *testing.T) {
	sec, pub := testutil.CreateSecret(t, "sec")
	secFpr := sec.PgpKey.Fingerprint()
	vulnImage := testutil.QualifiedImage
	unQualifiedImage := "image:tag"
	sigVuln, err := util.CreateAttestationSignature(vulnImage, sec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	noVulnImage := testutil.IntTestImage
	sigNoVuln, err := util.CreateAttestationSignature(noVulnImage, sec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	sMock := func(_, _ string) (*secrets.PGPSigningSecret, error) {
		return sec, nil
	}
	validAtts := []metadata.PGPAttestation{{Signature: sigVuln, KeyID: secFpr}}
	var isps = []v1beta1.ImageSecurityPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "foo",
			},
			Spec: v1beta1.ImageSecurityPolicySpec{
				AttestationAuthorityNames: []string{"test"},
			},
		},
	}
	authMock := func(_ string, name string) (*v1beta1.AttestationAuthority, error) {
		return &v1beta1.AttestationAuthority{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: v1beta1.AttestationAuthoritySpec{
				NoteReference:        "provider/test",
				PrivateKeySecretName: "test",
				PublicKeyData:        base64.StdEncoding.EncodeToString([]byte(pub)),
			}}, nil
	}
	mockValidate := func(_ v1beta1.ImageSecurityPolicy, image string, _ metadata.Fetcher) ([]policy.Violation, error) {
		if image == vulnImage {
			v := securitypolicy.NewViolation(&metadata.Vulnerability{Severity: "foo"}, 1, "")
			vs := []policy.Violation{}
			vs = append(vs, v)
			return vs, nil
		} else if image == unQualifiedImage {
			v := securitypolicy.NewViolation(nil, policy.UnqualifiedImageViolation, securitypolicy.UnqualifiedImageReason(image))
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
		shouldAttestImage bool
		shouldErr         bool
	}{
		{
			name:              "vulnz w attestation for Webhook should not handle voilations",
			image:             vulnImage,
			isWebhook:         true,
			attestations:      validAtts,
			handledViolations: 0,
			isAttested:        true,
			shouldAttestImage: false,
			shouldErr:         false,
		},
		{
			name:              "vulnz w/o attestation for Webhook should handle voilations",
			image:             vulnImage,
			isWebhook:         true,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 1,
			isAttested:        false,
			shouldAttestImage: false,
			shouldErr:         true,
		},
		{
			name:              "no vulnz w/o attestation for webhook should add attestation",
			image:             noVulnImage,
			isWebhook:         true,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 0,
			isAttested:        false,
			shouldAttestImage: true,
			shouldErr:         false,
		},
		{
			name:              "vulnz w attestation for cron should handle vuln",
			image:             vulnImage,
			isWebhook:         false,
			attestations:      validAtts,
			handledViolations: 1,
			isAttested:        true,
			shouldAttestImage: false,
			shouldErr:         true,
		},
		{
			name:              "vulnz w/o attestation for cron should handle vuln",
			image:             vulnImage,
			isWebhook:         false,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 1,
			isAttested:        false,
			shouldAttestImage: false,
			shouldErr:         true,
		},
		{
			name:              "no vulnz w/o attestation for cron should verify attestations",
			image:             noVulnImage,
			isWebhook:         false,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 0,
			isAttested:        false,
			shouldAttestImage: false,
			shouldErr:         false,
		},
		{
			name:              "no vulnz w attestation for cron should verify attestations",
			image:             noVulnImage,
			isWebhook:         false,
			attestations:      []metadata.PGPAttestation{{Signature: sigNoVuln, KeyID: secFpr}},
			handledViolations: 0,
			isAttested:        true,
			shouldAttestImage: false,
			shouldErr:         false,
		},
		{
			name:              "unqualified image for cron should fail and should not attest any image",
			image:             "image:tag",
			isWebhook:         false,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 1,
			isAttested:        false,
			shouldAttestImage: false,
			shouldErr:         true,
		},
		{
			name:              "unqualified image for webhook should fail should not attest any image",
			image:             "image:tag",
			isWebhook:         true,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 1,
			isAttested:        false,
			shouldAttestImage: false,
			shouldErr:         true,
		},
		{
			name:              "review image in global whitelist",
			image:             "gcr.io/kritis-project/preinstall",
			isWebhook:         true,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 0,
			isAttested:        false,
			shouldAttestImage: false,
			shouldErr:         false,
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
				Auths:     authMock,
				IsWebhook: tc.isWebhook,
				Strategy:  &th,
			})
			if err := r.ReviewISP([]string{tc.image}, isps, nil); (err != nil) != tc.shouldErr {
				t.Errorf("expected review to return error %t, actual error %s", tc.shouldErr, err)
			}
			if len(th.Violations) != tc.handledViolations {
				t.Errorf("expected to handle %d violations. Got %d", tc.handledViolations, len(th.Violations))
			}

			if th.Attestations[tc.image] != tc.isAttested {
				t.Errorf("expected to get image attested: %t. Got %t", tc.isAttested, th.Attestations[tc.image])
			}
			if (len(cMock.Occ) != 0) != tc.shouldAttestImage {
				t.Errorf("expected an image to be attested, but found none")
			}
		})
	}
}

func TestGetUnAttested(t *testing.T) {
	tcs := []struct {
		name     string
		authIds  []string
		keys     map[string]string
		attIds   []string
		eAuthIds []string
	}{
		{
			"not equal",
			[]string{"a", "b"},
			map[string]string{"a": "a-fpr", "b": "b-fpr"},
			[]string{"a-fpr"},
			[]string{"b"},
		},
		{
			"equal",
			[]string{"a", "b"},
			map[string]string{"a": "a-fpr", "b": "b-fpr"},
			[]string{"a-fpr", "b-fpr"},
			[]string{},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			auths := makeAuth(tc.authIds)
			atts := makeAtt(tc.attIds)
			expected := makeAuth(tc.eAuthIds)
			actual := getUnAttested(auths, tc.keys, atts)
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
			ObjectMeta: metav1.ObjectMeta{
				Name: s,
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

func TestGetAttestationAuthoritiesForGAP(t *testing.T) {
	authsMap := map[string]v1beta1.AttestationAuthority{
		"a1": {
			ObjectMeta: metav1.ObjectMeta{Name: "a1"},
			Spec: v1beta1.AttestationAuthoritySpec{
				NoteReference:        "provider/test",
				PrivateKeySecretName: "test",
				PublicKeyData:        "testdata",
			}},
		"a2": {
			ObjectMeta: metav1.ObjectMeta{Name: "a2"},
			Spec: v1beta1.AttestationAuthoritySpec{
				NoteReference:        "provider/test",
				PrivateKeySecretName: "test",
				PublicKeyData:        "testdata",
			}},
	}
	authMock := func(ns string, name string) (*v1beta1.AttestationAuthority, error) {
		a, ok := authsMap[name]
		if !ok {
			return &v1beta1.AttestationAuthority{}, fmt.Errorf("could not find key %s", name)
		}
		return &a, nil
	}

	r := New(nil, &Config{
		Auths: authMock,
	})
	tcs := []struct {
		name        string
		aList       []string
		shouldErr   bool
		expectedLen int
	}{
		{
			name:        "correct authorities list",
			aList:       []string{"a1", "a2"},
			shouldErr:   false,
			expectedLen: 2,
		},
		{
			name:      "one incorrect authority in the list",
			aList:     []string{"a1", "err"},
			shouldErr: true,
		},
		{
			name:        "empty list should return nothing",
			aList:       []string{},
			shouldErr:   false,
			expectedLen: 0,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			gap := v1beta1.GenericAttestationPolicy{
				Spec: v1beta1.GenericAttestationPolicySpec{
					AttestationAuthorityNames: tc.aList,
				},
			}
			auths, err := r.getAttestationAuthoritiesForGAP(gap)
			if (err != nil) != tc.shouldErr {
				t.Errorf("expected review to return error %t, actual error %s", tc.shouldErr, err)
			}
			if len(auths) != tc.expectedLen {
				t.Errorf("expected review to return error %t, actual error %s", tc.shouldErr, err)
			}
		})
	}
}
func TestGetAttestationAuthoritiesForISP(t *testing.T) {
	authsMap := map[string]v1beta1.AttestationAuthority{
		"a1": {
			ObjectMeta: metav1.ObjectMeta{Name: "a1"},
			Spec: v1beta1.AttestationAuthoritySpec{
				NoteReference:        "provider/test",
				PrivateKeySecretName: "test",
				PublicKeyData:        "testdata",
			}},
		"a2": {
			ObjectMeta: metav1.ObjectMeta{Name: "a2"},
			Spec: v1beta1.AttestationAuthoritySpec{
				NoteReference:        "provider/test",
				PrivateKeySecretName: "test",
				PublicKeyData:        "testdata",
			}},
	}
	authMock := func(ns string, name string) (*v1beta1.AttestationAuthority, error) {
		a, ok := authsMap[name]
		if !ok {
			return &v1beta1.AttestationAuthority{}, fmt.Errorf("could not find key %s", name)
		}
		return &a, nil
	}

	r := New(nil, &Config{
		Auths: authMock,
	})
	tcs := []struct {
		name        string
		aList       []string
		shouldErr   bool
		expectedLen int
	}{
		{
			name:        "correct authorities list",
			aList:       []string{"a1", "a2"},
			shouldErr:   false,
			expectedLen: 2,
		},
		{
			name:      "one incorrect authority in the list",
			aList:     []string{"a1", "err"},
			shouldErr: true,
		},
		{
			name:        "empty list should return nothing",
			aList:       []string{},
			shouldErr:   false,
			expectedLen: 0,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			isp := v1beta1.ImageSecurityPolicy{
				Spec: v1beta1.ImageSecurityPolicySpec{
					AttestationAuthorityNames: tc.aList,
				},
			}
			auths, err := r.getAttestationAuthoritiesForISP(isp)
			if (err != nil) != tc.shouldErr {
				t.Errorf("expected review to return error %t, actual error %s", tc.shouldErr, err)
			}
			if len(auths) != tc.expectedLen {
				t.Errorf("expected review to return error %t, actual error %s", tc.shouldErr, err)
			}
		})
	}
}
