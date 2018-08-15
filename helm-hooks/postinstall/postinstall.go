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
	"strings"
	"time"

	"github.com/grafeas/kritis/pkg/kritis/install"
	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	"github.com/sirupsen/logrus"
)

func waitForPreinstallPod() {
	client, err := kubernetesutil.GetClientset()
	if err != nil {
		logrus.Fatalf("error getting kubernetes client: %v", err)
	}
	if err := kubernetesutil.WaitForPodComplete(client.CoreV1().Pods(namespace), "kritis-preinstall"); err != nil {
		logrus.Fatalf("preinstall pod didn't complete: %v", err)
	}
}

func waitForTLSSecret() {
	foundSecret := false
	var secretErr error
	for i := 0; i < 20; i++ {
		tlsSecretCmd := exec.Command("kubectl", "get", "secret", tlsSecretName, "--namespace", namespace)
		_, err := tlsSecretCmd.CombinedOutput()
		if err == nil {
			foundSecret = true
			break
		}
		secretErr = err
		time.Sleep(500 * time.Millisecond)
	}
	if !foundSecret {
		logrus.Fatalf("couldn't find csr : %v", secretErr)
	}
}

func getCaBundle() {
	certCmd := exec.Command("kubectl", "get", "secret", tlsSecretName, "-o", "jsonpath='{.data.tls\\.crt}'", "--namespace", namespace)
	output := install.RunCommand(certCmd)
	certificate = string(output)
	certificate = strings.TrimPrefix(certificate, "'")
	certificate = strings.TrimSuffix(certificate, "'")
	logrus.Infof("got cert from secret %s: %s", tlsSecretName, certificate)
}

func createValidationWebhook() {
	webhookSpec := `apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingWebhookConfiguration
metadata:
  name: %s
  labels:
    %s: ""
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
        namespace: %s`

	webhookSpec = fmt.Sprintf(webhookSpec, webhookName, kritisInstallLabel, certificate, serviceName, namespace)
	fmt.Println(webhookSpec)
	webhookCmd := exec.Command("kubectl", "apply", "-f", "-")
	webhookCmd.Stdin = bytes.NewReader([]byte(webhookSpec))
	install.RunCommand(webhookCmd)
}

func createValidationDeploymentWebhook() {
	webhookSpec := `apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingWebhookConfiguration
metadata:
  name: %s
  labels:
    %s: ""
webhooks:
  - name: kritis-validation-hook-deployments.grafeas.io
    rules:
      - apiGroups:
        - "*" # TODO(aaron-prindle) minimize this capture group
        apiVersions:
        - "*" # TODO(aaron-prindle) minimize this capture group
        operations:
          - CREATE
          # - UPDATE # TODO(aaron-prindle) add back update when whitelist and helm do not collide
        resources:
          - deployments
    failurePolicy: Fail
    clientConfig:
      caBundle: %s
      service:
        name: %s
        namespace: %s`
	webhookSpec = fmt.Sprintf(webhookSpec, deploymentWebhookName, kritisInstallLabel, certificate, serviceName, namespace)
	fmt.Println(webhookSpec)
	webhookCmd := exec.Command("kubectl", "apply", "-f", "-")
	webhookCmd.Stdin = bytes.NewReader([]byte(webhookSpec))
	install.RunCommand(webhookCmd)
}
