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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/cmd/kritis/version"
	"github.com/grafeas/kritis/pkg/kritis/admission/constants"
	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	kritisconstants "github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
	"github.com/grafeas/kritis/pkg/kritis/pods"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"github.com/grafeas/kritis/pkg/kritis/violation"
	"k8s.io/api/admission/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type config struct {
	retrievePod                 func(r *http.Request) (*v1.Pod, v1beta1.AdmissionReview, error)
	retrieveDeployment          func(r *http.Request) (*appsv1.Deployment, v1beta1.AdmissionReview, error)
	fetchMetadataClient         func() (metadata.MetadataFetcher, error)
	fetchImageSecurityPolicies  func(namespace string) ([]kritisv1beta1.ImageSecurityPolicy, error)
	validateImageSecurityPolicy func(isp kritisv1beta1.ImageSecurityPolicy, image string, client metadata.MetadataFetcher) ([]securitypolicy.SecurityPolicyViolation, error)
}

var (
	// For testing
	admissionConfig = config{
		retrievePod:                 unmarshalPod,
		retrieveDeployment:          unmarshalDeployment,
		fetchMetadataClient:         metadataClient,
		fetchImageSecurityPolicies:  securitypolicy.ImageSecurityPolicies,
		validateImageSecurityPolicy: securitypolicy.ValidateImageSecurityPolicy,
	}

	defaultViolationStrategy = violation.LoggingStrategy{}
)

// This admission controller looks for the breakglass annotation
// If one is not found, it validates against image security policies
// TODO: Check for attestations
func AdmissionReviewHandler(w http.ResponseWriter, r *http.Request) {
	glog.Infof("Starting admission review handler, version: %s",
		version.Commit)

	ar, err := deserializeRequest(w, r)
	if err != nil {
		glog.Errorf("Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	admitResponse := &v1beta1.AdmissionReview{
		Response: &v1beta1.AdmissionResponse{
			UID:     ar.Request.UID,
			Allowed: true,
			Result: &metav1.Status{
				Status:  string(constants.SuccessStatus),
				Message: constants.SuccessMessage,
			},
		},
	}

	for k8sType, handler := range handlers {
		if ar.Request.Kind.Kind == k8sType {
			handler(&ar, admitResponse)
		}
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	payload, err := json.Marshal(admitResponse)
	if err != nil {
		glog.Info(err)
	}
	w.Write(payload)
}

func reviewDeployment(deployment *appsv1.Deployment, ar *v1beta1.AdmissionReview) {
	for _, c := range deployment.Spec.Template.Spec.Containers {
		reviewImages([]string{c.Image}, deployment.Namespace, ar)
	}
	for _, c := range deployment.Spec.Template.Spec.InitContainers {
		reviewImages([]string{c.Image}, deployment.Namespace, ar)
	}
}

func createDeniedResponse(ar *v1beta1.AdmissionReview, message string) {
	ar.Response.Allowed = false
	ar.Response.Result = &metav1.Status{
		Status:  string(constants.FailureStatus),
		Message: message,
	}
}

func reviewImages(images []string, ns string, ar *v1beta1.AdmissionReview) {
	if util.CheckGlobalWhitelist(images) {
		glog.Infof("%s are all whitelisted, returning successful status", images)
		return
	}
	// Validate images in the pod against ImageSecurityPolicies in the same namespace
	isps, err := admissionConfig.fetchImageSecurityPolicies(ns)
	if err != nil {
		errMsg := fmt.Sprintf("error getting image security policies: %v", err)
		glog.Errorf(errMsg)
		createDeniedResponse(ar, errMsg)
		return
	}
	glog.Infof("Got isps %v", isps)
	// get the client we will get vulnz from
	metadataClient, err := admissionConfig.fetchMetadataClient()
	if err != nil {
		errMsg := fmt.Sprintf("error getting metadata client: %v", err)
		glog.Errorf(errMsg)
		createDeniedResponse(ar, errMsg)
		return
	}
	for _, isp := range isps {
		for _, image := range images {
			glog.Infof("Getting vulnz for %s", image)
			violations, err := admissionConfig.validateImageSecurityPolicy(isp, image, metadataClient)
			if err != nil {
				errMsg := fmt.Sprintf("error validating image security policy %v", err)
				glog.Errorf(errMsg)
				createDeniedResponse(ar, errMsg)
				return
			}
			// Check if one of the violations is that the image is not fully qualified
			for _, v := range violations {
				if v.Violation == securitypolicy.UnqualifiedImageViolation {
					errMsg := fmt.Sprintf("%s is not a fully qualified image", image)
					glog.Errorf(errMsg)
					createDeniedResponse(ar, errMsg)
					return
				}
			}
			if len(violations) != 0 {
				defaultViolationStrategy.HandleViolation(image, ns, violations)
				errMsg := fmt.Sprintf("found violations in %s", image)
				glog.Errorf(errMsg)
				createDeniedResponse(ar, errMsg)
				return
			}
		}
	}

}

func reviewPod(pod *v1.Pod, ar *v1beta1.AdmissionReview) {
	// First, check for a breakglass annotation on the pod
	if checkBreakglass(pod) {
		glog.Infof("found breakglass annotation, returning successful status")
		return
	}
	reviewImages(pods.Images(*pod), pod.Namespace, ar)
}

// TODO(aaron-prindle) remove these functions
func unmarshalPod(r *http.Request) (*v1.Pod, v1beta1.AdmissionReview, error) {
	ar := v1beta1.AdmissionReview{}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, ar, err
	}
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, ar, err
	}
	pod := v1.Pod{}
	if err := json.Unmarshal(ar.Request.Object.Raw, &pod); err != nil {
		return nil, ar, err
	}
	return &pod, ar, nil
}

func unmarshalDeployment(r *http.Request) (*appsv1.Deployment, v1beta1.AdmissionReview, error) {
	ar := v1beta1.AdmissionReview{}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, ar, err
	}
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, ar, err
	}
	deployment := appsv1.Deployment{}
	if err := json.Unmarshal(ar.Request.Object.Raw, &deployment); err != nil {
		return nil, ar, err
	}
	return &deployment, ar, nil
}

func checkBreakglass(pod *v1.Pod) bool {
	annotations := pod.GetAnnotations()
	if annotations == nil {
		return false
	}
	_, ok := annotations[kritisconstants.Breakglass]
	return ok
}

// TODO: update this once we have more metadata clients
func metadataClient() (metadata.MetadataFetcher, error) {
	return containeranalysis.NewContainerAnalysisClient()
}

func returnStatus(status constants.Status, message string, w http.ResponseWriter) {
	response := &v1beta1.AdmissionResponse{
		Allowed: (status == constants.SuccessStatus),
		Result: &metav1.Status{
			Status:  string(status),
			Message: message,
		},
	}
	if err := writeHttpResponse(response, w); err != nil {
		glog.Error("error writing response:", err)
	}
}

func writeHttpResponse(response *v1beta1.AdmissionResponse, w http.ResponseWriter) error {
	ar := v1beta1.AdmissionReview{
		Response: response,
	}
	data, err := json.Marshal(ar)
	if err != nil {
		glog.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return nil
	}
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(data)
	return err
}

func isPodRunning(pod *v1.Pod) bool {
	if pod.Status.Phase == v1.PodRunning {
		return true
	}
	return false
}
