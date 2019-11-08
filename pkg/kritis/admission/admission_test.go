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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/cmd/kritis/version"
	kritis "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type testConfig struct {
	mockConfig config
	httpStatus int
	allowed    bool
	status     Status
	message    string
}

func Test_BreakglassAnnotation(t *testing.T) {
	mockPod := func(r *http.Request) (*v1.Pod, v1beta1.AdmissionReview, error) {
		return &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"kritis.grafeas.io/breakglass": "true"},
			},
		}, v1beta1.AdmissionReview{}, nil
	}
	mockConfig := config{
		retrievePod: mockPod,
	}
	RunTest(t, testConfig{
		mockConfig: mockConfig,
		httpStatus: http.StatusOK,
		allowed:    true,
		status:     successStatus,
		message:    successMessage,
	})
}

func TestReviewHandler(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ReviewHandler(w, r, &Config{})
	}))
	defer s.Close()

	ar := v1beta1.AdmissionReview{
		Request: &v1beta1.AdmissionRequest{},
	}
	blob, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("%v", err)
	}
	// Query admission control with valid request
	resp, err := http.Post(s.URL, "", bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected OK status code, actual %s", resp.Status)
	}
	// Query admission control with invalid request
	resp, err = http.Post(s.URL, "", nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected bad request status code, actual %s", resp.Status)
	}
}

func Test_AdmissionResponse(t *testing.T) {
	tcs := []struct {
		name         string
		reviewGAPErr bool
		reviewISPErr bool
		status       Status
		expectedMsg  string
	}{
		{"valid response when no review error", false, false, successStatus, successMessage},
		{"invalid response when GAP review error", true, false, failureStatus, fmt.Sprintf("found violations in %s", testutil.QualifiedImage)},
		{"valid response when ISP review error", false, true, failureStatus, fmt.Sprintf("found violations in %s", testutil.QualifiedImage)},
	}
	mockGAP := func(namespace string) ([]kritis.GenericAttestationPolicy, error) {
		return []kritis.GenericAttestationPolicy{{Spec: kritis.GenericAttestationPolicySpec{}}}, nil
	}
	mockISP := func(namespace string) ([]kritis.ImageSecurityPolicy, error) {
		return []kritis.ImageSecurityPolicy{{Spec: kritis.ImageSecurityPolicySpec{}}}, nil
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			mReviewer := func() reviewer {
				return testutil.NewReviewer(tc.reviewGAPErr, tc.reviewISPErr, tc.expectedMsg)
			}
			mockConfig := config{
				retrievePod: mockValidPod(),
				fetchMetadataClient: func(config *Config) (metadata.Fetcher, error) {
					return testutil.NilFetcher()()
				},
				fetchMetadataReadOnlyClient: func(config *Config) (metadata.ReadOnlyClient, error) {
					return testutil.NilReadOnlyClient()()
				},
				fetchGenericAttestationPolicies: mockGAP,
				fetchImageSecurityPolicies:      mockISP,
				reviewer:                        mReviewer,
			}
			RunTest(t, testConfig{
				mockConfig: mockConfig,
				httpStatus: http.StatusOK,
				allowed:    !tc.reviewISPErr && !tc.reviewGAPErr,
				status:     tc.status,
				message:    tc.expectedMsg,
			})
		})
	}
}

func mockValidPod() func(r *http.Request) (*v1.Pod, v1beta1.AdmissionReview, error) {
	return func(r *http.Request) (*v1.Pod, v1beta1.AdmissionReview, error) {
		return &v1.Pod{
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{
						Image: testutil.QualifiedImage,
					},
				},
			},
		}, v1beta1.AdmissionReview{}, nil
	}
}

func RunTest(t *testing.T, tc testConfig) {
	// TODO(tstromberg): Refactor function so that it isn't a test helper.
	t.Helper()

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
	handler := http.HandlerFunc(PodTestReviewHandler)
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
		t.Errorf("unexpected response: got:\n%v\nwant:\n%v", rr.Body.String(), expected)
	}
}

// This admission controller looks for the breakglass annotation
// If one is not found, it validates against image security policies
// TODO: Check for attestations
func PodTestReviewHandler(w http.ResponseWriter, r *http.Request) {
	glog.Infof("Starting admission review handler version %s ...", version.Commit)
	pod, _, err := admissionConfig.retrievePod(r)
	if err != nil {
		glog.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	admitResponse := &v1beta1.AdmissionReview{
		Response: &v1beta1.AdmissionResponse{
			UID:     types.UID(""),
			Allowed: true,
			Result: &metav1.Status{
				Status:  string(successStatus),
				Message: successMessage,
			},
		},
	}
	reviewPod(pod, admitResponse, &Config{Metadata: constants.ContainerAnalysisMetadata})
	// Send response
	w.Header().Set("Content-Type", "application/json")
	payload, err := json.Marshal(admitResponse)
	if err != nil {
		glog.Errorf("unable to marshal %s: %v", admitResponse, err)
	}
	if _, err := w.Write(payload); err != nil {
		glog.Errorf("unable to write payload: %v", err)
	}
}
