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

	"github.com/grafeas/kritis/cmd/kritis/version"
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
var gkeClusterName = flag.String("gke-cluster-name", "cluster-3", "name of the integration test cluster")
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
	logrus.Infof("Running integration tests in namespace %s", namespaceName)
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

var CRD_EXAMPLES = []string{
	// TODO(aaron-prindle) add back attestation-authority-example.yaml
	// "attestation-authority-example.yaml",
	"image-security-policy-example.yaml",
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

func createGACSecret(t *testing.T, ns *v1.Namespace) {
	crdCmd := exec.Command("gsutil", "cp", "gs://kritis/gac.json", "/tmp")
	crdCmd.Dir = "../"
	_, err := integration_util.RunCmdOut(crdCmd)
	if err != nil {
		t.Fatalf("testing error: %v", err)
	}

	crdCmd = exec.Command("kubectl", "create",
		"secret", "generic", "gac-ca-admin",
		"--from-file=/tmp/gac.json", "--namespace", ns.Name)
	crdCmd.Dir = "../"
	_, err = integration_util.RunCmdOut(crdCmd)
	if err != nil {
		t.Fatalf("testing error: %v", err)
	}
}

func initKritis(t *testing.T, ns *v1.Namespace) func() {
	helmCmd := exec.Command("helm", "install", "./kritis-charts",
		"--namespace", ns.Name,
		"--set", fmt.Sprintf("image.repository=%s",
			"gcr.io/kritis-int-test/kritis-server"),
		"--set", fmt.Sprintf("image.tag=%s",
			version.Commit),
		"--set", fmt.Sprintf("preinstall.pod.image=%s:%s",
			"gcr.io/kritis-int-test/preinstall",
			version.Commit),
		"--set", fmt.Sprintf("postinstall.pod.image=%s:%s",
			"gcr.io/kritis-int-test/postinstall",
			version.Commit),
		"--set", fmt.Sprintf("predelete.pod.image=%s:%s",
			"gcr.io/kritis-int-test/predelete",
			version.Commit),
		"--set", fmt.Sprintf("serviceNamespace=%s", ns.Name),
		"--set", "predelete.deleteCRDs=--delete-crd=false",
		"--set", fmt.Sprintf("csrName=tls-webhook-secret-cert-%s", ns.Name),
		"--set", fmt.Sprintf("tlsSecretName=tls-webhook-secret-%s", ns.Name),
		"--set", fmt.Sprintf("clusterRoleBindingName=kritis-clusterrolebinding-%s", ns.Name),
		"--set", fmt.Sprintf("clusterRoleName=kritis-clusterrole-%s", ns.Name),
	)
	helmCmd.Dir = "../"

	out, err := integration_util.RunCmdOut(helmCmd)
	if err != nil {
		getPreinstallLogs(t)
		getPostinstallLogs(t)
		t.Fatalf("testing error: %v", err)
	}
	// parsing out release name from 'helm init' output
	helmNameString := strings.Split(string(out[:]), "\n")[0]
	kritisRelease := strings.Split(helmNameString, "   ")[1]
	deleteFunc := func() {
		// cleanup
		helmCmd = exec.Command("helm", "delete", "--purge", kritisRelease)
		helmCmd.Dir = "../"
		_, err = integration_util.RunCmdOut(helmCmd)
		if err != nil {
			t.Fatalf("testing error: %v", err)
		}
	}

	client, err := kubernetesutil.GetClientset()
	if err != nil {
		t.Errorf("error getting kubernetes clientset: %v", err)
		return deleteFunc
	}
	// Wait for postinstall pod to finish
	if err := kubernetesutil.WaitForPodComplete(client.CoreV1().Pods(ns.Name), "kritis-postinstall"); err != nil {
		t.Errorf("postinstall pod didn't complete: %v", err)
		return deleteFunc
	}
	// Wait for validation hook pod to start running

	podList, err := client.CoreV1().Pods(ns.Name).List(meta_v1.ListOptions{})
	if err != nil {
		t.Errorf("error getting pods: %v", err)
		getPreinstallLogs(t)
		getPostinstallLogs(t)
		return deleteFunc
	}
	for _, pod := range podList.Items {
		if strings.HasPrefix(pod.Name, "kritis-validation-hook") {
			if err := kubernetesutil.WaitForPodReady(client.CoreV1().Pods(ns.Name), pod.Name); err != nil {
				t.Errorf("%s didn't start running: %v", pod.Name, err)
				return deleteFunc
			}
		}
	}
	return deleteFunc
}

func getPreinstallLogs(t *testing.T) string {
	cmd := exec.Command("kubectl", "logs", "kritis-preinstall")
	cmd.Dir = "../"
	output, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Errorf("kritis preinstall: %s %v", output, err)
	}
	return string(output)
}

func getPostinstallLogs(t *testing.T) string {
	cmd := exec.Command("kubectl", "logs", "kritis-postinstall")
	cmd.Dir = "../"
	output, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Errorf("kritis preinstall: %s %v", output, err)
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
			},
		},
		{
			description: "java-with-vuln-deployment",
			args: []string{"kubectl", "create", "-f",
				"integration/testdata/java/java-with-vuln-deployment.yaml"},
			deployments: []testObject{
				{
					name: "java-with-vuln-deployment",
				},
			},
			shouldSucceed: false,
			dir:           "../",
			cleanup: func(t *testing.T) {
				cmd := exec.Command("kubectl", "delete", "-f",
					"integration/testdata/java/java-with-vuln-deployment.yaml")
				integration_util.RunCmdOut(cmd)
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
		{
			description: "kritis-server-global-whitelist",
			args: []string{"kubectl", "apply", "-f",
				"integration/testdata/kritis-server/kritis-server-global-whitelist.yaml"},
			pods: []testObject{
				{
					name: "kritis-server-global-whitelist",
				},
			},
			shouldSucceed: true,
			dir:           "../",
			cleanup: func(t *testing.T) {
				cmd := exec.Command("kubectl", "delete", "-f",
					"integration/testdata/kritis-server/kritis-server-global-whitelist.yaml")
				cmd.Dir = "../"
				output, err := integration_util.RunCmdOut(cmd)
				if err != nil {
					t.Fatalf("kritis: %s %v", output, err)
				}
			},
		},
		{
			description: "kritis-server-global-whitelist-with-vulnz",
			args: []string{"kubectl", "apply", "-f",
				"integration/testdata/kritis-server/kritis-server-global-whitelist-with-vulnz.yaml"},
			pods: []testObject{
				{
					name: "kritis-server-global-whitelist-with-vulnz",
				},
			},
			shouldSucceed: false,
			dir:           "../",
			cleanup: func(t *testing.T) {
				cmd := exec.Command("kubectl", "delete", "-f",
					"integration/testdata/kritis-server/kritis-server-global-whitelist-with-vulnz.yaml")
				cmd.Dir = "../"
				integration_util.RunCmdOut(cmd)
			},
		},
	}

	ns, deleteNs := setupNamespace(t)
	defer deleteNs()
	createGACSecret(t, ns)
	deleteKritis := initKritis(t, ns)
	defer deleteKritis()
	if err := kubernetesutil.WaitForDeploymentToStabilize(client, ns.Name,
		"kritis-validation-hook", 2*time.Minute); err != nil {
		t.Fatalf("Timed out waiting for deployment to stabilize")
	}
	createCRDExamples(t)
	time.Sleep(10 * time.Second)
	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
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
				if err := kubernetesutil.WaitForPodReady(client.CoreV1().Pods(ns.Name), p.name); err != nil {
					t.Fatalf("Timed out waiting for pod ready\n%s",
						getKritisLogs(t))
				}
			}

			for _, d := range testCase.deployments {
				if err := kubernetesutil.WaitForDeploymentToStabilize(client, ns.Name, d.name, 10*time.Minute); err != nil {
					t.Fatalf("Timed out waiting for deployment to stabilize\n%s",
						getKritisLogs(t))
				}
				if testCase.deploymentValidation != nil {
					deployment, err := client.AppsV1().Deployments(ns.Name).Get(d.name, meta_v1.GetOptions{})
					if err != nil {
						t.Fatalf("Could not find deployment: %s %s\n%s", ns.Name, d, getKritisLogs(t))
					}
					testCase.deploymentValidation(t, deployment)
				}
			}
		})
	}
}
