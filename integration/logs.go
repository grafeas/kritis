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
package integration

import (
	"fmt"
	"os/exec"
	"testing"

	integration_util "github.com/grafeas/kritis/pkg/kritis/integration_util"
	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	"k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getWebhooksInCluster(t *testing.T) string {
	log := ""
	client, err := kubernetesutil.GetClientset()
	if err != nil {
		t.Logf("error getting kubernetes clientset for webhooks in cluster: %v", err)
		return log
	}
	webhooks, err := client.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().List(meta_v1.ListOptions{})
	if err != nil {
		t.Logf("error getting webhooks in cluster: %v", err)
		return log
	}
	for _, webhook := range webhooks.Items {
		log = log + fmt.Sprintf("found webhook %s in cluster \n", webhook.Name)
	}
	return log
}

func getPodLogs(t *testing.T, pod string, ns *v1.Namespace) string {
	cmd := exec.Command("kubectl", "logs", pod, "-n", ns.Name)
	output, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Errorf("%s: %s %v", pod, output, err)
	}
	return string(output)
}

func getKritisLogs(t *testing.T) string {
	cmd := exec.Command("kubectl", "logs", "-l",
		"app=kritis-validation-hook")
	output, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Fatalf("kritis: %s %v", output, err)
	}
	cmd = exec.Command("kubectl", "get", "imagesecuritypolicy")
	output2, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Fatalf("kritis: %s %v", output2, err)
	}
	return string(output[:]) + "\n" + string(output2[:])
}
