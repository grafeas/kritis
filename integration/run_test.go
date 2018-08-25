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
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/grafeas/kritis/cmd/kritis/version"
	integration_util "github.com/grafeas/kritis/pkg/kritis/integration_util"
	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

const (
	preinstallPod  = "kritis-preinstall"
	postinstallPod = "kritis-postinstall"
	predeletePod   = "kritis-predelete"
)

var (
	gkeZone        = flag.String("gke-zone", "us-central1-a", "gke zone")
	gkeClusterName = flag.String("gke-cluster-name", "UNSET_CLUSTER_NAME", "name of the integration test cluster")
	gcpProject     = flag.String("gcp-project", "UNSET_GCP_PROJECT", "the gcp project where the integration test cluster lives")
	gacCredentials = flag.String("gac-credentials", "UNSET_CREDENTIALS_PATH", "path to gac.json credentials for --gcp-project")
	deleteWebHooks = flag.Bool("delete-webhooks", true, "delete Kritis webhooks before running tests")
	cleanup        = flag.Bool("cleanup", false, "cleanup allocated resources on exit")
	client         kubernetes.Interface
	context        *api.Context
)

// processTemplate processes a text template and returns the path to it.
func processTemplate(path string) (string, error) {
	in, err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("unable to read %s: %v", path, err)
	}

	tmpl := template.Must(template.New("text").Parse(string(in)))
	vars := struct{ Project string }{*gcpProject}
	tf, err := ioutil.TempFile("", filepath.Base(path))
	if err != nil {
		return "", fmt.Errorf("tempfile: %v", err)
	}
	if err = tmpl.Execute(tf, vars); err != nil {
		return "", fmt.Errorf("unable to process %s: %v", path, err)
	}
	if err = tf.Close(); err != nil {
		return "", fmt.Errorf("close: %v", err)
	}
	return tf.Name(), nil
}

func webhooks() ([]string, error) {
	var names []string
	client, err := kubernetesutil.GetClientset()
	if err != nil {
		return names, fmt.Errorf("GetClientset failed: %v", err)
	}
	hooks, err := client.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().List(meta_v1.ListOptions{})
	if err != nil {
		return names, fmt.Errorf("webhook list failed: %v", err)
	}

	for _, h := range hooks.Items {
		if strings.HasPrefix(h.Name, "kritis-") {
			names = append(names, h.Name)
		}
	}
	return names, nil
}

func TestMain(m *testing.M) {
	flag.Parse()
	wd, err := os.Getwd()
	if err != nil {
		logrus.Fatalf("failed to get wd: %v", err)
	}
	logrus.Infof("TestMain running from %s", wd)

	// Our tests rely on kubectl, so populate the credentials for it.
	cmd := exec.Command("gcloud", "container", "clusters", "get-credentials", *gkeClusterName, "--zone", *gkeZone, "--project", *gcpProject)
	if err := integration_util.RunCmd(cmd); err != nil {
		logrus.Fatalf("Error authenticating to GKE cluster stdout: %v", err)
	}

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

	hooks, err := webhooks()
	if err != nil {
		logrus.Errorf("error retrieving webhooks: %v", err)
	}
	// Delete stray webhooks. They make tests difficult to debug.
	if *deleteWebHooks {
		for _, h := range hooks {
			if err := exec.Command("kubectl", "delete", "ValidatingWebhookConfiguration", string(h)).Run(); err != nil {
				logrus.Errorf("error deleting webhook: %v", err)
			}
		}
	} else {
		if hooks != nil {
			logrus.Warnf("ignoring pre-existing webhooks: %v", hooks)
		}
	}

	logrus.Infof("TestMain complete!")
	os.Exit(exitCode)
}

func setupNamespace() (*v1.Namespace, func(), error) {
	namespaceName := integration_util.RandomID()
	ns, err := client.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      namespaceName,
			Namespace: namespaceName,
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating namespace: %s", err)
	}

	cmd := exec.Command("kubectl", "config", "set-context", context.Cluster, "--namespace", ns.Name)
	if err := integration_util.RunCmd(cmd); err != nil {
		return nil, nil, fmt.Errorf("kubectl config set-context --namespace: %v", err)
	}

	cmd = exec.Command("kubectl", "create", "secret", "generic", "gac-ca-admin",
		fmt.Sprintf("--from-file=%s", *gacCredentials), "--namespace", ns.Name)

	if _, err = integration_util.RunCmdOut(cmd); err != nil {
		return nil, nil, fmt.Errorf("error creating secret %v", err)
	}

	return ns, func() {
		client.CoreV1().Namespaces().Delete(ns.Name, &meta_v1.DeleteOptions{})
	}, nil
}

func install(ns *v1.Namespace) (func(*testing.T), error) {
	helmCmd := exec.Command("helm", "install", "../kritis-charts",
		"--wait",
		"--namespace", ns.Name,
		"--set", fmt.Sprintf("repository=gcr.io/%s/", *gcpProject),
		"--set", fmt.Sprintf("image.tag=%s", version.Commit),
		"--set", fmt.Sprintf("serviceNamespace=%s", ns.Name),
		"--set", "predelete.deleteCRDs=--delete-crd=false",
		"--set", fmt.Sprintf("csrName=tls-webhook-secret-cert-%s", ns.Name),
		"--set", fmt.Sprintf("tlsSecretName=tls-webhook-secret-%s", ns.Name),
		"--set", fmt.Sprintf("clusterRoleBindingName=kritis-clusterrolebinding-%s", ns.Name),
		"--set", fmt.Sprintf("clusterRoleName=kritis-clusterrole-%s", ns.Name),
		"--set", fmt.Sprintf("serviceName=kritis-validation-hook-%s", ns.Name),
		"--set", fmt.Sprintf("serviceNameDeployments=kritis-validation-hook-deployments-%s", ns.Name),
	)
	out, err := integration_util.RunCmdOut(helmCmd)
	if err != nil {
		hooksMsg := ""
		hooks, err := webhooks()
		if err != nil {
			hooksMsg = fmt.Sprintf("ERROR: %v", err)
		} else {
			hooksMsg = strings.Join(hooks, ", ")
		}
		return nil, fmt.Errorf("helm install failed: %v\n\nhooks: %s\n\npreinstall: %s\n\npostinstall: %s", err,
			hooksMsg,
			podLogs(preinstallPod, ns),
			podLogs(postinstallPod, ns))
	}
	// parsing out Kritis release name from 'helm init' out
	helmName := strings.Split(string(out[:]), "\n")[0]
	release := strings.Split(helmName, "   ")[1]

	cleanup := func(t *testing.T) {
		t.Helper()
		helmCmd = exec.Command("helm", "delete", "--purge", release)
		_, err = integration_util.RunCmdOut(helmCmd)
		if err != nil {
			t.Errorf("helm delete failed: %v", err)
			cleanupInstall(ns)
		}
		// make sure kritis-predelete pod completes
		if err := kubernetesutil.WaitForPodComplete(client.CoreV1().Pods(ns.Name), predeletePod); err != nil {
			t.Errorf("predelete pod didn't complete: %v \n %s", err, podLogs(predeletePod, ns))
			cleanupInstall(ns)
		}
	}

	client, err := kubernetesutil.GetClientset()
	if err != nil {
		return cleanup, fmt.Errorf("error getting kubernetes clientset: %v", err)

	}
	// Wait for postinstall pod to finish
	if err := kubernetesutil.WaitForPodComplete(client.CoreV1().Pods(ns.Name), postinstallPod); err != nil {
		return cleanup, fmt.Errorf("postinstall pod didn't complete: %v", err)
	}
	// Wait for validation hook pod to start running

	podList, err := client.CoreV1().Pods(ns.Name).List(meta_v1.ListOptions{})
	if err != nil {
		return cleanup, fmt.Errorf("error getting pods: %v \n %s \n %s", err, podLogs(preinstallPod, ns), podLogs(postinstallPod, ns))
	}

	for _, pod := range podList.Items {
		if strings.HasPrefix(pod.Name, "kritis-validation-hook") {
			if err := kubernetesutil.WaitForPodReady(client.CoreV1().Pods(ns.Name), pod.Name); err != nil {
				return cleanup, fmt.Errorf("%s didn't start running: %v", pod.Name, err)
			}
		}
	}
	if err := kubernetesutil.WaitForDeploymentToStabilize(client, ns.Name,
		fmt.Sprintf("kritis-validation-hook-%s", ns.Name), 2*time.Minute); err != nil {
		return cleanup, fmt.Errorf("Timed out waiting for deployment to stabilize")
	}
	return cleanup, nil
}

func TestKritisISPLogic(t *testing.T) {
	ns, nsCleanup, err := setupNamespace()
	if *cleanup && nsCleanup != nil {
		defer nsCleanup()
	}
	if err != nil {
		t.Fatalf("setupNamespace: %v", err)
	}

	instCleanup, err := install(ns)
	if *cleanup && instCleanup != nil {
		defer instCleanup(t)
	}
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	createCRDExamples(t, ns)
	waitForCRDExamples(t, ns)

	var testCases = []struct {
		template string
		command  string

		deployments    []string
		pods           []string
		replicasets    []string
		attestedImages []string

		shouldSucceed bool
	}{
		{
			template:      "nginx/nginx-no-digest.yaml",
			command:       "create",
			pods:          []string{"nginx-no-digest"},
			shouldSucceed: false,
		},
		{
			template:      "nginx/nginx-no-digest-whitelist.yaml",
			command:       "create",
			pods:          []string{"nginx-no-digest-whitelist"},
			shouldSucceed: true,
		},
		{
			template:      "nginx/nginx-digest-whitelist.yaml",
			command:       "create",
			pods:          []string{"nginx-digest-whitelist"},
			shouldSucceed: true,
		},
		{
			template:      "java/java-with-vulnz.yaml",
			command:       "create",
			pods:          []string{"java-with-vulnz"},
			shouldSucceed: false,
		},
		{
			template:      "java/java-with-vulnz-deployment.yaml",
			command:       "create",
			deployments:   []string{"java-with-vulnz-deployment"},
			shouldSucceed: false,
		},
		{
			template:       "java/java-with-vulnz-replicaset.yaml",
			command:        "create",
			replicasets:    []string{"java-with-vulnz-replicaset"},
			attestedImages: []string{},
			shouldSucceed:  false,
		},
		{
			template:      "nginx/nginx-no-digest-breakglass.yaml",
			command:       "apply",
			pods:          []string{"nginx-no-digest-breakglass"},
			shouldSucceed: true,
		},
		{
			template:      "java/java-with-vulnz-breakglass-deployment.yaml",
			command:       "create",
			deployments:   []string{"java-with-vulnz-breakglass-deployment"},
			shouldSucceed: true,
		},
		{
			template:    "java/java-with-vulnz-breakglass-replicaset.yaml",
			command:     "apply",
			replicasets: []string{"java-with-vulnz-breakglass-replicaset"},
			attestedImages: []string{
				fmt.Sprintf("gcr.io/%s/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8", *gcpProject),
			},
			shouldSucceed: true,
		},
		{
			template:      "kritis-server/kritis-server-global-whitelist.yaml",
			command:       "apply",
			pods:          []string{"kritis-server-global-whitelist"},
			shouldSucceed: true,
		},
		{
			template:      "kritis-server/kritis-server-global-whitelist-with-vulnz.yaml",
			command:       "apply",
			pods:          []string{"kritis-server-global-whitelist-with-vulnz"},
			shouldSucceed: false,
		},
		{
			template:      "vulnz/acceptable-vulnz.yaml",
			command:       "apply",
			pods:          []string{"image-with-acceptable-vulnz"},
			shouldSucceed: true,
		},
		{
			template:      "vulnz/acceptable-vulnz-replicaset.yaml",
			command:       "apply",
			replicasets:   []string{"replicaset-with-acceptable-vulnz"},
			shouldSucceed: true,
			attestedImages: []string{
				fmt.Sprintf("gcr.io/%s/acceptable-vulnz@sha256:2a81797428f5cab4592ac423dc3049050b28ffbaa3dd11000da942320f9979b6", *gcpProject),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.template, func(t *testing.T) {
			path, err := processTemplate(tc.template)
			if err != nil {
				t.Fatalf("failed to process template: %v", err)
			}
			if *cleanup {
				defer cleanupFromTemplate(path)
			}
			cmd := exec.Command("kubectl", tc.command, "-f", path)
			out, err := integration_util.RunCmdOut(cmd)
			if err != nil {
				if !tc.shouldSucceed {
					return
				}
				t.Fatalf("exec failed: %s %v\n%s", out, err, kritisLogs())

			}
			if !tc.shouldSucceed {
				t.Errorf("deployment should have failed but succeeded\n%s", kritisLogs())
			}

			for _, p := range tc.pods {
				if err := kubernetesutil.WaitForPodReady(client.CoreV1().Pods(ns.Name), p); err != nil {
					t.Errorf("timeout waiting for pod %q\n%s\n%s", p, kritisLogs(), out)
				}
			}

			for _, d := range tc.deployments {
				if err := kubernetesutil.WaitForDeploymentToStabilize(client, ns.Name, d, 10*time.Minute); err != nil {
					t.Errorf("timeout waiting for deployment %q\n%s", d, kritisLogs())
				}
			}

			for _, r := range tc.replicasets {
				if err := kubernetesutil.WaitForReplicaSetToStabilize(client, ns.Name, r, 10*time.Minute); err != nil {
					t.Errorf("Timed out waiting for replicasets to stabilize\n%s", kritisLogs())
				}
			}
		})
	}
}

func TestKritisCron(t *testing.T) {
	ns, nsCleanup, err := setupNamespace()
	if *cleanup && nsCleanup != nil {
		defer nsCleanup()
	}
	if err != nil {
		t.Fatalf("setupNamespace: %v", err)
	}

	instCleanup, err := install(ns)
	if *cleanup && instCleanup != nil {
		defer instCleanup(t)
	}
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	createCRDExamples(t, ns)
	waitForCRDExamples(t, ns)

	var testCases = []struct {
		template string
		command  string

		deployments   []string
		pods          []string
		shouldSucceed bool
		shouldLabel   bool
	}{
		{
			template:      "nginx/nginx-no-digest-breakglass.yaml",
			command:       "apply",
			pods:          []string{"nginx-no-digest-breakglass"},
			shouldSucceed: true,
			shouldLabel:   true,
		},
		{
			template:      "testdata/vulnz/acceptable-vulnz.yaml",
			command:       "apply",
			pods:          []string{"image-with-acceptable-vulnz"},
			shouldSucceed: true,
			shouldLabel:   false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.template, func(t *testing.T) {
			path, err := processTemplate(tc.template)
			if err != nil {
				t.Fatalf("failed to process template: %v", err)
			}
			if *cleanup {
				defer cleanupFromTemplate(path)
			}
			cmd := exec.Command("kubectl", tc.command, "-f", path)
			out, err := integration_util.RunCmdOut(cmd)
			if err != nil {
				if !tc.shouldSucceed {
					return
				}
				t.Fatalf("exec failed: %s %v\n%s", out, err, kritisLogs())

			}
			if !tc.shouldSucceed {
				t.Errorf("deployment should have failed but succeeded\n%s", kritisLogs())
			}

			for _, p := range tc.pods {
				if err := kubernetesutil.WaitForPodReady(client.CoreV1().Pods(ns.Name), p); err != nil {
					t.Errorf("timeout waiting for pod %q\n%s\n%s", p, kritisLogs(), out)
				}
			}

			for _, d := range tc.deployments {
				if err := kubernetesutil.WaitForDeploymentToStabilize(client, ns.Name, d, 10*time.Minute); err != nil {
					t.Errorf("timeout waiting for deployment %q\n%s", d, kritisLogs())
				}
			}

			cmd = exec.Command("kubectl", "get", "po")
			pods, err := integration_util.RunCmdOut(cmd)
			if err != nil {
				t.Errorf("kubectl get failed: %s %v", pods, err)
			}
			t.Logf("kubectl get po out: \n %s", pods)

			cmd = exec.Command("kubectl", "get", "po",
				"-l", "label=kritis-validation-hook",
				"-o", "custom-columns=:metadata.name",
				"--no-headers=true")
			hookPod, err := integration_util.RunCmdOut(cmd)
			if err != nil {
				t.Errorf("kubectl get for kritis-validation-hook failed: %s %v", hookPod, err)
			}

			// as kubectl exec opens a tty, out is not monitored
			cmd = exec.Command("kubectl", "exec", strings.TrimSpace(string(hookPod)), "--", "/kritis/kritis-server", "--run-cron")
			if err = cmd.Start(); err != nil {
				t.Errorf("start failed for %s: %v", cmd.Args, err)
			}

			if err = cmd.Wait(); err != nil {
				t.Errorf("wait failed for %s: %v", cmd.Args, err)
			}
			// check labels on pods
			cmd = exec.Command("kubectl", "get", "pods", "-l", "kritis.grafeas.io/invalidImageSecPolicy=invalidImageSecPolicy")
			out, err = integration_util.RunCmdOut(cmd)
			if err != nil {
				t.Errorf("kubectl get pod with cron labels failed: %s %v", out, err)
			}
			if tc.shouldLabel {
				if len(out) < 0 {
					t.Errorf("expected cron to label pod: %s", out)
				}
			} else if len(out) != 0 {
				t.Errorf("expected cron to not label pod: %s", out)
			}
		})
	}
}
