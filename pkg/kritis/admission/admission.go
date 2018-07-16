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
	"log"
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
	"github.com/sirupsen/logrus"
	"k8s.io/api/admission/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

type config struct {
	retrievePod                 func(r *http.Request) (*v1.Pod, error)
	retrieveDeployment          func(r *http.Request) (*appsv1.Deployment, error)
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

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
)

func AdmissionReviewHandler(w http.ResponseWriter, r *http.Request) {
	glog.Info("Starting admission review handler: ", version.Commit)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	ar := v1beta1.AdmissionReview{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		payload, err := json.Marshal(&v1beta1.AdmissionResponse{
			UID:     ar.Request.UID,
			Allowed: false,
			Result: &metav1.Status{
				Message: err.Error(),
			},
		})
		if err != nil {
			fmt.Println(err)
		}
		w.Write(payload)
	}

	admitResponse := &v1beta1.AdmissionReview{
		Response: &v1beta1.AdmissionResponse{
			UID:     ar.Request.UID,
			Allowed: true,
			Result:  &metav1.Status{Message: constants.SuccessMessage},
		},
	}

	if ar.Request.Kind.Kind == "Deployment" {
		fmt.Println("handling deployment...")
		deployment := appsv1.Deployment{}
		json.Unmarshal(ar.Request.Object.Raw, &deployment)
		reviewDeployment(&deployment, admitResponse)
	}

	if ar.Request.Kind.Kind == "Pod" {
		fmt.Println("handling pod...")
		pod := v1.Pod{}
		json.Unmarshal(ar.Request.Object.Raw, &pod)
		reviewPod(&pod, admitResponse)
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	payload, err := json.Marshal(admitResponse)
	if err != nil {
		fmt.Println(err)
	}
	w.Write(payload)
}

func reviewDeployment(deployment *appsv1.Deployment, ar *v1beta1.AdmissionReview) {
	for _, c := range deployment.Spec.Template.Spec.Containers {
		log.Println(c.Image)
		reviewImages([]string{c.Image}, deployment.Namespace, ar)
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
		glog.Errorf("error getting image security policies: %v", err)
		ar.Response.Allowed = false
		ar.Response.Result = &metav1.Status{
			Message: "error getting image security policies",
		}
		return
	}
	glog.Infof("Got isps %v", isps)
	// get the client we will get vulnz from
	metadataClient, err := admissionConfig.fetchMetadataClient()
	if err != nil {
		glog.Errorf("error getting metadata client: %v", err)
		ar.Response.Allowed = false
		ar.Response.Result = &metav1.Status{
			Message: fmt.Sprintf("error getting metadata client %v", err),
		}
		return
	}
	for _, isp := range isps {
		for _, image := range images {
			glog.Infof("Getting vulnz for %s", image)
			violations, err := admissionConfig.validateImageSecurityPolicy(isp, image, metadataClient)
			if err != nil {
				ar.Response.Allowed = false
				ar.Response.Result = &metav1.Status{
					Message: fmt.Sprintf("error validating image security policy %v", err),
				}
				return
			}
			// Check if one of the violations is that the image is not fully qualified
			for _, v := range violations {
				if v.Violation == securitypolicy.UnqualifiedImageViolation {
					glog.Infof("%s is not a fully qualified image", image)
					ar.Response.Allowed = false
					ar.Response.Result = &metav1.Status{
						Message: fmt.Sprintf("%s is not a fully qualified image", image),
					}
					return
				}
			}
			if len(violations) != 0 {
				defaultViolationStrategy.HandleViolation(image, ns, violations)
				ar.Response.Allowed = false
				ar.Response.Result = &metav1.Status{
					Message: fmt.Sprintf("found violations in %s", image),
				}
				return
			}
		}
	}

}

func reviewPod(pod *v1.Pod, ar *v1beta1.AdmissionReview) {
	// First, check for a breakglass annotation on the pod
	if checkBreakglass(pod) {
		logrus.Debugf("found breakglass annotation, returning successful status")
		return
	}
	reviewImages(pods.Images(*pod), pod.Namespace, ar)
}

// TODO(aaron-prindle) remove these functions
func unmarshalPod(r *http.Request) (*v1.Pod, error) {
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

func unmarshalDeployment(r *http.Request) (*appsv1.Deployment, error) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	ar := v1beta1.AdmissionReview{}
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, err
	}
	deployment := appsv1.Deployment{}
	if err := json.Unmarshal(ar.Request.Object.Raw, &deployment); err != nil {
		return nil, err
	}
	return &deployment, nil
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
