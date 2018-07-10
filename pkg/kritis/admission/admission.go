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
	"github.com/grafeas/kritis/pkg/kritis/admission/constants"
	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/kubectl/plugins/resolve"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
	"github.com/grafeas/kritis/pkg/kritis/pods"
	"io/ioutil"
	"k8s.io/api/admission/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"net/http"
)

type config struct {
	retrievePod           func(r *http.Request) (*v1.Pod, error)
	imagesecuritypolicies func(namespace string) ([]kritisv1beta1.ImageSecurityPolicy, error)
	validate              func(isp kritisv1beta1.ImageSecurityPolicy, project, image string, client metadata.MetadataFetcher) ([]metadata.Vulnerability, error)
}

var (
	// For testing
	admissionConfig = config{
		retrievePod:           pod,
		imagesecuritypolicies: securitypolicy.ImageSecurityPolicies,
		validate:              securitypolicy.ValidateImageSecurityPolicy,
	}
)

// This admission controller looks for the breakglass annotation
// If one is not found, it validates against image security policies
// TODO: Check for attestations
func AdmissionReviewHandler(w http.ResponseWriter, r *http.Request) {
	pod, err := admissionConfig.retrievePod(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// First, check for a breakglass annotation on the pod
	if breakglass(pod) {
		returnStatus(constants.SuccessStatus, constants.SuccessMessage, w)
		return
	}
	// Second, get all images in the pod and make sure they are fully qualified
	images := pods.Images(*pod)
	for _, image := range images {
		if !resolve.FullyQualifiedImage(image) {
			returnStatus(constants.FailureStatus, fmt.Sprintf("%s is not a fully qualified image", image), w)
			return
		}
	}
	// Third, validate images in the pod against ImageSecurityPolicies in the same namespace
	isps, err := admissionConfig.imagesecuritypolicies(pod.Namespace)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// get the client we will get vulnz from
	metadataClient, err := metadataClient()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	for _, isp := range isps {
		for _, image := range images {
			violations, err := admissionConfig.validate(isp, "", image, metadataClient)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if len(violations) != 0 {
				//  TODO: Check AttestationAuthorities to see if the image is verified
				log.Printf("found violations in %s: %v\n", image, violations)
				returnStatus(constants.FailureStatus, fmt.Sprintf("found violations in %s", image), w)
				return
			}
		}
	}
	// At this point, we can return a success status
	returnStatus(constants.SuccessStatus, constants.SuccessMessage, w)
}

func pod(r *http.Request) (*v1.Pod, error) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	ar := v1beta1.AdmissionReview{}
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, err
	}
	pod := v1.Pod{}
	if err := json.Unmarshal(ar.Request.Object.Raw, &pod); err != nil {
		return nil, err
	}
	return &pod, nil
}

func breakglass(pod *v1.Pod) bool {
	annotations := pod.GetAnnotations()
	if annotations == nil {
		return false
	}
	_, ok := annotations[constants.BREAKGLASS]
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
		log.Println("error writing response:", err)
	}
}

func writeHttpResponse(response *v1beta1.AdmissionResponse, w http.ResponseWriter) error {
	ar := v1beta1.AdmissionReview{
		Response: response,
	}
	data, err := json.Marshal(ar)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return nil
	}
	if response.Allowed {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
	_, err = w.Write(data)
	return err
}
