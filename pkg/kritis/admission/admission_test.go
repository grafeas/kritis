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

package admission

import (
	"fmt"
	"github.com/grafeas/kritis/pkg/kritis/admission/constants"
	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testConfig struct {
	mockConfig config
	httpStatus int
	allowed    bool
	status     constants.Status
	message    string
}

func Test_BreakglassAnnotation(t *testing.T) {
	mockPod := func(r *http.Request) (*v1.Pod, error) {
		return &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"kritis.grafeas.io/breakglass": "true"},
			},
		}, nil
	}
	mockConfig := config{
		retrievePod: mockPod,
	}
	RunTest(t, testConfig{
		mockConfig: mockConfig,
		httpStatus: http.StatusOK,
		allowed:    true,
		status:     constants.SuccessStatus,
		message:    constants.SuccessMessage,
	})
}

func Test_UnqualifiedImage(t *testing.T) {
	mockPod := func(r *http.Request) (*v1.Pod, error) {
		return &v1.Pod{
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{
						Image: "image:tag",
					},
				},
			},
		}, nil
	}
	mockISP := func(namespace string) ([]kritisv1beta1.ImageSecurityPolicy, error) {
		return []kritisv1beta1.ImageSecurityPolicy{{}}, nil
	}
	mockMetadata := func() (metadata.MetadataFetcher, error) {
		return mockMetadataClient{}, nil
	}
	mockConfig := config{
		retrievePod:                 mockPod,
		fetchMetadataClient:         mockMetadata,
		fetchImageSecurityPolicies:  mockISP,
		validateImageSecurityPolicy: securitypolicy.ValidateImageSecurityPolicy,
	}
	RunTest(t, testConfig{
		mockConfig: mockConfig,
		httpStatus: http.StatusOK,
		allowed:    false,
		status:     constants.FailureStatus,
		message:    "image:tag is not a fully qualified image",
	})
}

func Test_ValidISP(t *testing.T) {
	mockISP := func(namespace string) ([]kritisv1beta1.ImageSecurityPolicy, error) {
		return []kritisv1beta1.ImageSecurityPolicy{
			{
				ImageWhitelist: []string{testutil.QualifiedImage},
			},
		}, nil
	}
	mockConfig := config{
		retrievePod:                 mockValidPod(),
		fetchMetadataClient:         mockMetadata(),
		fetchImageSecurityPolicies:  mockISP,
		validateImageSecurityPolicy: securitypolicy.ValidateImageSecurityPolicy,
	}
	RunTest(t, testConfig{
		mockConfig: mockConfig,
		httpStatus: http.StatusOK,
		allowed:    true,
		status:     constants.SuccessStatus,
		message:    constants.SuccessMessage,
	})
}

func Test_InvalidISP(t *testing.T) {
	mockISP := func(namespace string) ([]kritisv1beta1.ImageSecurityPolicy, error) {
		return []kritisv1beta1.ImageSecurityPolicy{{
			Spec: kritisv1beta1.ImageSecurityPolicySpec{
				PackageVulernerabilityRequirements: kritisv1beta1.PackageVulernerabilityRequirements{
					MaximumSeverity: "LOW",
				},
			},
		}}, nil
	}
	mockMetadata := func() (metadata.MetadataFetcher, error) {
		return mockMetadataClient{
			vulnz: []metadata.Vulnerability{
				{
					Severity: "MEDIUM",
				},
			},
		}, nil
	}
	mockConfig := config{
		retrievePod:                 mockValidPod(),
		fetchMetadataClient:         mockMetadata,
		fetchImageSecurityPolicies:  mockISP,
		validateImageSecurityPolicy: securitypolicy.ValidateImageSecurityPolicy,
	}
	RunTest(t, testConfig{
		mockConfig: mockConfig,
		httpStatus: http.StatusOK,
		allowed:    false,
		status:     constants.FailureStatus,
		message:    fmt.Sprintf("found violations in %s", testutil.QualifiedImage),
	})
}

type mockMetadataClient struct {
	vulnz []metadata.Vulnerability
}

func (m mockMetadataClient) GetVulnerabilities(containerImage string) ([]metadata.Vulnerability, error) {
	return m.vulnz, nil
}

func mockMetadata() func() (metadata.MetadataFetcher, error) {
	return func() (metadata.MetadataFetcher, error) {
		return nil, nil
	}
}

func mockValidPod() func(r *http.Request) (*v1.Pod, error) {
	return func(r *http.Request) (*v1.Pod, error) {
		return &v1.Pod{
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{
						Image: testutil.QualifiedImage,
					},
				},
			},
		}, nil
	}
}

func RunTest(t *testing.T, tc testConfig) {
	// Create a request to pass to our handler.
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Create mocks
	original := admissionConfig
	defer func() {
		admissionConfig = original
	}()
	admissionConfig = tc.mockConfig
	// Create a ResponseRecorder to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(AdmissionReviewHandler)
	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != tc.httpStatus {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, tc.httpStatus)
	}
	// Check the response body is what we expect.
	expected := `{"response":{"uid":"","allowed":%t,"status":{"metadata":{},"status":"%s","message":"%s"}}}`
	expected = fmt.Sprintf(expected, tc.allowed, tc.status, tc.message)
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}
