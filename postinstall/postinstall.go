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

package main

import (
	"io/ioutil"

	"github.com/sirupsen/logrus"
)

func setNamespace() {
	namespaceFile := "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	contents, err := ioutil.ReadFile(namespaceFile)
	if err != nil {
		logrus.Fatalf("error trying to get namespace from %s: %v", namespaceFile, err)
	}
	logrus.Infof("contents of %s: %s", namespaceFile, contents)
	namespace = string(contents)
}

func getCaBundle() {

}

func createValidationWebhook() {
	webhookSpec := `apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingWebhookConfiguration
metadata:
    name: {{ .Values.serviceName }}
webhooks:
    - name: kritis-validation-hook.grafeas.io
      rules:
        - apiGroups:
            - ""
        apiVersions:
            - v1
        operations:
            - CREATE
            - UPDATE
        resources:
            - pods
    failurePolicy: Fail
    clientConfig:
        caBundle: {{ .Values.caBundle }}
        service:
        name: {{ .Values.serviceName }}
        namespace: {{ .Values.serviceNamespace }}
`
}
