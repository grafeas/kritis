// +build integration

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
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"

	integration_util "github.com/grafeas/kritis/pkg/kritis/integration_util"
	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

var gkeZone = flag.String("gke-zone", "us-central1-a", "gke zone")
var gkeClusterName = flag.String("gke-cluster-name", "test-cluster", "name of the integration test cluster")
var gcpProject = flag.String("gcp-project", "kritis-int-test", "the gcp project where the integration test cluster lives")
var remote = flag.Bool("remote", true, "if true, run tests on a remote GKE cluster")

var client kubernetes.Interface

var context *api.Context

func TestMain(m *testing.M) {
	flag.Parse()
	if *remote {
		cmd := exec.Command("gcloud", "container", "clusters", "get-credentials", *gkeClusterName, "--zone", *gkeZone, "--project", *gcpProject)
		if err := integration_util.RunCmd(cmd); err != nil {
			logrus.Fatalf("Error authenticating to GKE cluster stdout: %v", err)
		}
	}

	var err error
	client, err = kubernetesutil.GetClientset()
	if err != nil {
		logrus.Fatalf("Test setup error: getting kubernetes client: %s", err)
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})

	cfg, err := kubeConfig.RawConfig()
	if err != nil {
		logrus.Fatalf("loading kubeconfig: %s", err)
	}

	context = cfg.Contexts[cfg.CurrentContext]

	exitCode := m.Run()

	// Reset default context and namespace
	if err := exec.Command("kubectl", "config", "set-context", context.Cluster, "--namespace", context.Namespace).Run(); err != nil {
		logrus.Warn(err)
	}

	os.Exit(exitCode)
}

func setupNamespace(t *testing.T) (*v1.Namespace, func()) {
	namespaceName := integration_util.RandomID()
	ns, err := client.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      namespaceName,
			Namespace: namespaceName,
		},
	})
	if err != nil {
		t.Fatalf("creating namespace: %s", err)
	}

	kubectlCmd := exec.Command("kubectl", "config", "set-context", context.Cluster, "--namespace", ns.Name)
	if err := integration_util.RunCmd(kubectlCmd); err != nil {
		t.Fatalf("kubectl config set-context --namespace: %v", err)
	}

	os.Setenv("KRITIS_DEPLOY_NAMESPACE", namespaceName)

	return ns, func() {
		client.CoreV1().Namespaces().Delete(ns.Name, &meta_v1.DeleteOptions{})
		os.Setenv("KRITIS_DEPLOY_NAMESPACE", "")
	}
}

var CRDS = []string{
	"attestation-authority-crd.yaml",
	"image-security-policy-crd.yaml",
}

var CRD_EXAMPLES = []string{
	"attestation-authority-example.yaml",
	"image-security-policy-example.yaml",
}

func deleteCRDs() {
	for _, crd := range CRDS {
		crdCmd := exec.Command("kubectl", "delete", "-f",
			crd)
		crdCmd.Dir = "../artifacts/examples"
		integration_util.RunCmdOut(crdCmd)
	}
}

func createCRDs(t *testing.T) {
	for _, crd := range CRDS {
		crdCmd := exec.Command("kubectl", "create", "-f",
			crd)
		crdCmd.Dir = "../artifacts/examples"
		_, err := integration_util.RunCmdOut(crdCmd)
		if err != nil {
			t.Fatalf("testing error: %v", err)
		}
	}
}

func createCRDExamples(t *testing.T) {
	for _, crd := range CRD_EXAMPLES {
		crdCmd := exec.Command("kubectl", "create", "-f",
			crd)
		crdCmd.Dir = "../artifacts/examples"
		_, err := integration_util.RunCmdOut(crdCmd)
		if err != nil {
			t.Fatalf("testing error: %v", err)
		}
	}
}

func TestCRDs(t *testing.T) {
	_, deleteNs := setupNamespace(t)
	defer deleteNs()
	defer deleteCRDs()

	// CRDs themselves are non-namespaced so we have to delete them each run
	deleteCRDs()

	createCRDs(t)

	createCRDExamples(t)
}

func TestKritisHelm(t *testing.T) {
	ns, deleteNs := setupNamespace(t)
	defer deleteNs()

	helmCmd := exec.Command("helm", "certgen", "generate", "./kritis-charts",
		"--namespace", ns.Name)
	helmCmd.Dir = "../"
	_, err := integration_util.RunCmdOut(helmCmd)
	if err != nil {
		t.Fatalf("testing error: %v", err)
	}

	helmCmd = exec.Command("helm", "install", "./kritis-charts",
		"--namespace", ns.Name)
	helmCmd.Dir = "../"
	out, err := integration_util.RunCmdOut(helmCmd)
	if err != nil {
		t.Fatalf("testing error: %v", err)
	}
	// parsing out release name from 'helm init' output
	helmNameString := strings.Split(string(out[:]), "\n")[0]
	kritisRelease := strings.Split(helmNameString, "   ")[1]

	helmCmd = exec.Command("helm", "delete", kritisRelease)
	helmCmd.Dir = "../"
	_, err = integration_util.RunCmdOut(helmCmd)
	if err != nil {
		t.Fatalf("testing error: %v", err)
	}
}
