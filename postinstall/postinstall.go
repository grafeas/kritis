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
	"bytes"
	"fmt"
	"os/exec"

	"github.com/grafeas/kritis/pkg/kritis/install"
)

func getCaBundle() {
	certCmd := exec.Command("kubectl", "get", "secret", tlsSecretName, "jsonpath='{.data.tls\\.crt'", "--namespace", namespace)
	output := install.RunCommand(certCmd)
	certificate = string(output)
}

func createValidationWebhook() {
	webhookSpec := `apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingWebhookConfiguration
metadata:
    name: %s
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
        caBundle: %s
    service:
        name: %s
        namespace: %s
`
	webhookSpec = fmt.Sprintf(webhookSpec, webhookName, certificate, serviceName, namespace)
	webhookCmd := exec.Command("kubectl", "apply", "-f", "-")
	webhookCmd.Stdin = bytes.NewReader([]byte(webhookSpec))
	install.RunCommand(webhookCmd)
}
