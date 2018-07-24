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
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	integration_util "github.com/grafeas/kritis/pkg/kritis/integration_util"
	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

var gkeZone = flag.String("gke-zone", "us-central1-a", "gke zone")
var gkeClusterName = flag.String("gke-cluster-name", "test-cluster-2", "name of the integration test cluster")
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
	// TODO(aaron-prindle) add back namespace functionality
	// namespaceName := integration_util.RandomID()

	namespaceName := "default"
	// ns, err := client.CoreV1().Namespaces().Create(&v1.Namespace{
	// 	ObjectMeta: meta_v1.ObjectMeta{
	// 		Name:      namespaceName,
	// 		Namespace: namespaceName,
	// 	},
	// })
	ns, err := client.CoreV1().Namespaces().Get(namespaceName, meta_v1.GetOptions{})
	if err != nil {
		t.Fatalf("creating namespace: %s", err)
	}

	kubectlCmd := exec.Command("kubectl", "config", "set-context", context.Cluster, "--namespace", "default")
	if err := integration_util.RunCmd(kubectlCmd); err != nil {
		t.Fatalf("kubectl config set-context --namespace: %v", err)
	}

	os.Setenv("KRITIS_DEPLOY_NAMESPACE", namespaceName)

	return ns, func() {
		client.CoreV1().Namespaces().Delete("default", &meta_v1.DeleteOptions{})
		os.Setenv("KRITIS_DEPLOY_NAMESPACE", "")
	}
}

var CRDS = []string{
	"attestation-authority-crd.yaml",
	"image-security-policy-crd.yaml",
}

var CRD_EXAMPLES = []string{
	// TODO(aaron-prindle) add back attestation-authority-example.yaml
	// "attestation-authority-example.yaml",
	"image-security-policy-example.yaml",
}

func deleteCRDs() {
	for _, crd := range CRDS {
		crdCmd := exec.Command("kubectl", "delete", "-f",
			crd)
		crdCmd.Dir = "../artifacts"
		integration_util.RunCmdOut(crdCmd)
	}
}

func deleteCRDExamples() {
	for _, crd := range CRDS {
		crdCmd := exec.Command("kubectl", "delete", "-f",
			crd)
		crdCmd.Dir = "../artifacts/integration-examples"
		integration_util.RunCmdOut(crdCmd)
	}
}

func createCRDs(t *testing.T) {
	for _, crd := range CRDS {
		crdCmd := exec.Command("kubectl", "create", "-f",
			crd)
		crdCmd.Dir = "../artifacts"
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
		crdCmd.Dir = "../artifacts/integration-examples"
		_, err := integration_util.RunCmdOut(crdCmd)
		if err != nil {
			t.Fatalf("testing error: %v", err)
		}
	}
}

func initKritis(t *testing.T) func() {
	preinstallCmd := exec.Command("./install/install-kritis.sh", "-p", "-n", "default")
	preinstallCmd.Dir = "../"
	_, err := integration_util.RunCmdOut(preinstallCmd)
	if err != nil {
		t.Fatalf("preinstall err: %v, logs: %s", err, getPreinstallLogs(t))
	}

	helmCmd := exec.Command("kubectl", "get", "secret",
		"tls-webhook-secret", "-o", "jsonpath='{.data.tls\\.crt}'")
	kubeCA, err := integration_util.RunCmdOut(helmCmd)
	if err != nil {
		t.Fatalf("testing error: %v", err)
	}
	helmCmd = exec.Command("helm", "install", "./kritis-charts",
		"--namespace", "default",
		"--set", fmt.Sprintf("caBundle=%s", kubeCA),
		"--set", fmt.Sprintf("image.repository=%s",
			"gcr.io/kritis-int-test/kritis-server"),
		"--set", fmt.Sprintf("=%s", "default"),
	)
	helmCmd.Dir = "../"

	out, err := integration_util.RunCmdOut(helmCmd)
	if err != nil {
		t.Fatalf("testing error: %v", err)
	}
	// parsing out release name from 'helm init' output
	helmNameString := strings.Split(string(out[:]), "\n")[0]
	kritisRelease := strings.Split(helmNameString, "   ")[1]
	return func() {
		// cleanup
		helmCmd = exec.Command("helm", "delete", "--purge", kritisRelease)
		helmCmd.Dir = "../"
		_, err = integration_util.RunCmdOut(helmCmd)
		if err != nil {
			t.Fatalf("testing error: %v", err)
		}
	}
}

func getPreinstallLogs(t *testing.T) string {
	cmd := exec.Command("kubectl", "logs", "kritis-preinstall")
	cmd.Dir = "../"
	output, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Fatalf("kritis preinstall: %s %v", output, err)
	}
	return string(output)
}

func getKritisLogs(t *testing.T) string {
	cmd := exec.Command("kubectl", "logs", "-l",
		"app=kritis-validation-hook")
	cmd.Dir = "../"
	output, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Fatalf("kritis: %s %v", output, err)
	}
	cmd = exec.Command("kubectl", "get", "imagesecuritypolicy")
	cmd.Dir = "../"
	output2, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Fatalf("kritis: %s %v", output2, err)
	}
	return string(output[:]) + "\n" + string(output2[:])
}

func TestKritisPods(t *testing.T) {
	type testObject struct {
		name string
	}

	type testRunCase struct {
		description          string
		dir                  string
		args                 []string
		deployments          []testObject
		pods                 []testObject
		deploymentValidation func(t *testing.T, d *appsv1.Deployment)
		shouldSucceed        bool

		remoteOnly bool
		cleanup    func(t *testing.T)
	}

	var testCases = []testRunCase{
		{
			description: "nginx-no-digest",
			args: []string{"kubectl", "create", "-f",
				"integration/testdata/nginx/nginx-no-digest.yaml"},
			pods: []testObject{
				{
					name: "nginx-no-digest",
				},
			},
			shouldSucceed: false,
			dir:           "../",
			cleanup: func(t *testing.T) {
				cmd := exec.Command("kubectl", "delete", "-f",
					"integration/testdata/nginx/nginx-no-digest.yaml")
				cmd.Dir = "../"
				integration_util.RunCmdOut(cmd)
				// output, err := integration_util.RunCmdOut(cmd)
				// if err != nil {
				// 	t.Fatalf("kritis: %s %v", output, err)
				// }
			},
		},
		{
			description: "nginx-no-digest-whitelist",
			args: []string{"kubectl", "create", "-f",
				"integration/testdata/nginx/nginx-no-digest-whitelist.yaml"},
			pods: []testObject{
				{
					name: "nginx-no-digest-whitelist",
				},
			},
			shouldSucceed: true,
			dir:           "../",
			cleanup: func(t *testing.T) {
				cmd := exec.Command("kubectl", "delete", "-f",
					"integration/testdata/nginx/nginx-no-digest-whitelist.yaml")
				cmd.Dir = "../"
				output, err := integration_util.RunCmdOut(cmd)
				if err != nil {
					t.Fatalf("kritis: %s %v", output, err)
				}
			},
		},
		{
			description: "nginx-digest-whitelist",
			args: []string{"kubectl", "create", "-f",
				"integration/testdata/nginx/nginx-digest-whitelist.yaml"},
			pods: []testObject{
				{
					name: "nginx-digest-whitelist",
				},
			},
			shouldSucceed: true,
			dir:           "../",
			cleanup: func(t *testing.T) {
				cmd := exec.Command("kubectl", "delete", "-f",
					"integration/testdata/nginx/nginx-digest-whitelist.yaml")
				cmd.Dir = "../"
				output, err := integration_util.RunCmdOut(cmd)
				if err != nil {
					t.Fatalf("kritis: %s %v", output, err)
				}
			},
		},
		{
			description: "java-with-vuln",
			args: []string{"kubectl", "create", "-f",
				"integration/testdata/java/java-with-vuln.yaml"},
			pods: []testObject{
				{
					name: "java-with-vuln",
				},
			},
			shouldSucceed: false,
			dir:           "../",
			cleanup: func(t *testing.T) {
				cmd := exec.Command("kubectl", "delete", "-f",
					"integration/testdata/java/java-with-vuln.yaml")
				integration_util.RunCmdOut(cmd)
				// output, err := integration_util.RunCmdOut(cmd)
				// if err != nil {
				// 	t.Fatalf("kritis: %s %v", output, err)
				// }
			},
		},
		{
			description: "nginx-no-digest-breakglass",
			args: []string{"kubectl", "apply", "-f",
				"integration/testdata/nginx/nginx-no-digest-breakglass.yaml"},
			pods: []testObject{
				{
					name: "nginx-no-digest-breakglass",
				},
			},
			shouldSucceed: true,
			dir:           "../",
			cleanup: func(t *testing.T) {
				cmd := exec.Command("kubectl", "delete", "-f",
					"integration/testdata/nginx/nginx-no-digest-breakglass.yaml")
				cmd.Dir = "../"
				output, err := integration_util.RunCmdOut(cmd)
				if err != nil {
					t.Fatalf("kritis: %s %v", output, err)
				}
			},
		},
	}

	// CRDs themselves are non-namespaced so we have to delete them each run
	deleteCRDs()
	deleteCRDExamples()
	// defer deleteCRDExamples()

	deleteKritis := initKritis(t)
	defer deleteKritis()
	if err := kubernetesutil.WaitForDeploymentToStabilize(client, "default",
		"kritis-validation-hook", 2*time.Minute); err != nil {
		t.Fatalf("Timed out waiting for deployment to stabilize")
	}
	createCRDExamples(t)
	time.Sleep(5 * time.Second)
	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			// TODO(aaron-prindle) add back namespaces
			// ns, deleteNs := setupNamespace(t)
			// defer deleteNs()
			defer testCase.cleanup(t)

			cmd := exec.Command(testCase.args[0], testCase.args[1:]...)
			cmd.Dir = testCase.dir
			output, err := integration_util.RunCmdOut(cmd)
			if err != nil {
				if !testCase.shouldSucceed {
					return
				}
				t.Fatalf("kritis: %s %v\n%s", output, err, getKritisLogs(t))

			}
			if !testCase.shouldSucceed {
				t.Fatalf("deployment should have failed but succeeded\n%s",
					getKritisLogs(t))
			}

			for _, p := range testCase.pods {
				if err := kubernetesutil.WaitForPodReady(client.CoreV1().Pods("default"), p.name); err != nil {
					t.Fatalf("Timed out waiting for pod ready\n%s",
						getKritisLogs(t))
				}
			}

			for _, d := range testCase.deployments {
				if err := kubernetesutil.WaitForDeploymentToStabilize(client, "default", d.name, 10*time.Minute); err != nil {
					t.Fatalf("Timed out waiting for deployment to stabilize\n%s",
						getKritisLogs(t))
				}
				if testCase.deploymentValidation != nil {
					deployment, err := client.AppsV1().Deployments("default").Get(d.name, meta_v1.GetOptions{})
					if err != nil {
						t.Fatalf("Could not find deployment: %s %s\n%s", "default", d, getKritisLogs(t))
					}
					testCase.deploymentValidation(t, deployment)
				}
			}
		})
	}
}
