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
	"net/http"

	"github.com/grafeas/kritis/pkg/kritis/admission/constants"
	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This is very basic admission controller which allows all pods.
func AdmissionReviewHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Add image security policy check
	// 1. Get all Image security Polices
	// 2. Get all pod specs
	// 3. For all pods Get Vulnerabilities for images
	// 4. Validate policy
	// 5. Attest.
	status := &v1beta1.AdmissionResponse{
		Allowed: true,
		Result: &metav1.Status{
			Status:  string(constants.SuccessStatus),
			Message: constants.SuccessMessage,
		},
	}
	WriteHttpResponse(status, w)
}

func WriteHttpResponse(status *v1beta1.AdmissionResponse, w http.ResponseWriter) {
	ar := v1beta1.AdmissionReview{
		Response: status,
	}
	data, err := json.Marshal(ar)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
