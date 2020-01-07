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
	v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	preinstallPod  = "kritis-preinstall"
	postinstallPod = "kritis-postinstall"
	predeletePod   = "kritis-predelete"
	testDataDir    = "../integration/testdata"
)

var (
	gkeZone        = flag.String("gke-zone", "us-central1-a", "gke zone")
	gkeClusterName = flag.String("gke-cluster-name", "test-cluster-2", "name of the integration test cluster")
	gcpProject     = flag.String("gcp-project", "kritis-int-test", "the gcp project where the integration test cluster lives")
	gacCredentials = flag.String("gac-credentials", "/tmp/gac.json", "path to gac.json credentials for --gcp-project")
	deleteWebHooks = flag.Bool("delete-webhooks", true, "delete Kritis webhooks before running tests")
	cleanup        = flag.Bool("cleanup", true, "cleanup allocated resources on exit")
)

// processTemplate processes a text template and returns the path to it.
func processTemplate(path, ns string) (string, error) {
	in, err := ioutil.ReadFile(filepath.Join(testDataDir, path))
	if err != nil {
		return "", fmt.Errorf("unable to read %s: %v", path, err)
	}

	tmpl := template.Must(template.New("text").Parse(string(in)))
	vars := struct{ Project string }{*gcpProject}
	tf, err := ioutil.TempFile("", fmt.Sprintf("%s.%s.", filepath.Base(path), ns))
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

// cleanupTemplate resources referenced by an expanded text template
func cleanupTemplate(t *testing.T, path, ns string) error {
	if !*cleanup {
		t.Logf("Skipping cleanup of %s because --cleanup=false", path)
		return nil
	}
	t.Logf("Cleaning up after %s ...", path)
	cmd := exec.Command("kubectl", "delete", "-f", path, "--namespace", ns)
	output, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		return fmt.Errorf("kubectl delete failed: %s %v", output, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove failed: %v", err)
	}
	return nil
}

// webhooks returns a list of active webhooks
func webhooks(cs kubernetes.Interface) ([]string, error) {
	var names []string
	hooks, err := cs.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().List(meta_v1.ListOptions{})
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

// testNamespace configures a randomized namespace name, returns cleanup function.
func testNamespace(cs kubernetes.Interface) (*v1.Namespace, func(*testing.T), error) {
	name := integration_util.RandomID()[0:8]
	ns, err := cs.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: name,
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating namespace: %s", err)
	}

	cmd := exec.Command("kubectl", "create", "secret", "generic", "gac-ca-admin",
		fmt.Sprintf("--from-file=%s", *gacCredentials), "--namespace", ns.Name)
	if _, err = integration_util.RunCmdOut(cmd); err != nil {
		return nil, nil, fmt.Errorf("error creating secret %v", err)
	}

	return ns, func(t *testing.T) {
		t.Helper()
		if !*cleanup {
			t.Logf("Skipping deletion of namespace %s because --cleanup=false", ns.Name)
			return
		}

		t.Logf("Deleting namespace %s ...", ns.Name)
		if err := cs.CoreV1().Namespaces().Delete(ns.Name, &meta_v1.DeleteOptions{}); err != nil {
			t.Errorf("namespace deletion failed: %v", err)
		}
	}, nil
}

func installKritis(cs kubernetes.Interface, ns *v1.Namespace) (func(*testing.T), error) {
	cmd := exec.Command("helm", "install", "../kritis-charts",
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
	out, err := integration_util.RunCmdOut(cmd)

	// Install errors are difficult to debug, so spend the effort to generate a great error message.
	if err != nil {
		hooks, err2 := webhooks(cs)
		if err2 != nil {
			hooks = []string{err2.Error()}
		}

		cmd := exec.Command("kubectl", "get", "po", "--namespace", ns.Name)
		podSummary, err3 := integration_util.RunCmdOut(cmd)
		if err3 != nil {
			podSummary = []byte(fmt.Sprintf("kubectl failed: %v", err))
		}

		return nil, fmt.Errorf("helm failure: %v\n\nhooks: %s\n\npreinstall: %s\n\npostinstall: %s\n\npods: %s", err,
			hooks, podLogs(preinstallPod, ns), podLogs(postinstallPod, ns), podSummary)
	}

	// parsing out Kritis release name from 'helm init' out
	helmName := strings.Split(string(out[:]), "\n")[0]
	release := strings.Split(helmName, "   ")[1]

	cleanup := func(t *testing.T) {
		t.Helper()
		if !*cleanup {
			t.Logf("Skipping Kritis deinstall in namespace %s because --cleanup=false", ns.Name)
			return
		}
		t.Logf("Uninstalling Kritis ...")
		cmd = exec.Command("helm", "delete", "--purge", release)
		out, err = integration_util.RunCmdOut(cmd)
		if err != nil {
			t.Errorf("helm delete failed: %v\nout: %s", err, out)
			if err2 := cleanupInstall(ns); err2 != nil {
				t.Errorf("cleanup failed: %v", err2)
			}
			t.Fatalf("Abandoning Kritis deinstall.")
		}

		// If helm delete succeeds, ensure that the kritis-predelete pod completes
		if err := kubernetesutil.WaitForPodComplete(cs.CoreV1().Pods(ns.Name), predeletePod); err != nil {
			t.Errorf("predelete pod didn't complete: %v \n %s", err, podLogs(predeletePod, ns))
			if err2 := cleanupInstall(ns); err2 != nil {
				t.Errorf("cleanup failed: %v", err2)
			}
		}
	}

	// Wait for postinstall pod to finish
	if err := kubernetesutil.WaitForPodComplete(cs.CoreV1().Pods(ns.Name), postinstallPod); err != nil {
		return cleanup, fmt.Errorf("postinstall pod didn't complete: %v", err)
	}

	pods, err := cs.CoreV1().Pods(ns.Name).List(meta_v1.ListOptions{})
	if err != nil {
		return cleanup, fmt.Errorf("error getting pods: %v \n %s \n %s", err, podLogs(preinstallPod, ns), podLogs(postinstallPod, ns))
	}
	// Wait for validation hook pod to start running
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, "kritis-validation-hook") {
			if err := kubernetesutil.WaitForPodReady(cs.CoreV1().Pods(ns.Name), pod.Name); err != nil {
				return cleanup, fmt.Errorf("%s didn't start running: %v", pod.Name, err)
			}
		}
	}
	if err := kubernetesutil.WaitForDeploymentToStabilize(cs, ns.Name,
		fmt.Sprintf("kritis-validation-hook-%s", ns.Name), 2*time.Minute); err != nil {
		return cleanup, fmt.Errorf("Timed out waiting for deployment to stabilize")
	}
	return cleanup, nil
}

func setUpKritisInNS(t *testing.T) (kubernetes.Interface, *v1.Namespace, func(*testing.T)) {
	t.Helper()

	// Otherwise the credentials are stored in an unexpected path within /secret
	if filepath.Base(*gacCredentials) != "gac.json" {
		t.Errorf("--gac-credentials must have a base name of gac.json, not %s", filepath.Base(*gacCredentials))
	}

	cmd := exec.Command("gcloud", "container", "clusters", "get-credentials", *gkeClusterName, "--zone", *gkeZone, "--project", *gcpProject)
	out, err := integration_util.RunCmdOut(cmd)
	if err != nil {
		t.Fatalf("get-credentials: %v - %s\n\nPlease ensure that \"make setup-integration-local\" has been run first", out, err)
	}
	cs, err := kubernetesutil.GetClientset()
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	hooks, err := webhooks(cs)
	if err != nil {
		t.Fatalf("webhooks: %v", err)
	}
	if len(hooks) > 0 {
		// If enabled, delete stray webhooks. They make tests difficult to debug.
		if *deleteWebHooks {
			for _, h := range hooks {
				t.Logf("setup: deleting stray webhook: %s", h)
				if err := exec.Command("kubectl", "delete", "ValidatingWebhookConfiguration", string(h)).Run(); err != nil {
					t.Errorf("error deleting webhook: %v", err)
				}
			}
		} else {
			t.Logf("WARNING: stray webhooks may interfere with your test: %v", hooks)
		}
	}

	ns, nsCleanup, err := testNamespace(cs)
	if err != nil {
		t.Fatalf("testNamespace: %v", err)
	}

	t.Logf("setup: installing kritis with image version %s in namespace %s...", version.Commit, ns.Name)
	instCleanup, err := installKritis(cs, ns)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	return cs, ns, func(t *testing.T) {
		instCleanup(t)
		nsCleanup(t)
	}
}

// Complete setUp for an ISP test. Returns a tearDown function.
func setUpISP(t *testing.T) (kubernetes.Interface, *v1.Namespace, func(t *testing.T)) {
	cs, ns, instInNsCleanup := setUpKritisInNS(t)
	createAttestationAuthority(t, *gcpProject, ns.Name)
	isp, err := processTemplate("image-security-policy/my-isp.yaml", ns.Name)
	if err != nil {
		t.Fatalf("failed to process isp template: %v", err)
	}
	cmd := exec.Command("kubectl", "create", "-f", isp, "-n", ns.Name)
	if out, err := integration_util.RunCmdOut(cmd); err != nil {
		t.Fatalf("testing error: %v\nout: %s", err, out)
	}

	cmd = exec.Command("kubectl", "apply", "-f", "testdata/kritis-server/kritis-config.yaml")
	if out, err := integration_util.RunCmdOut(cmd); err != nil {
		t.Fatalf("testing error: %v\nout: %s", err, out)
	}

	waitForCRDExamples(t, ns, map[string]string{"imagesecuritypolicies.kritis.grafeas.io": "my-isp"})

	return cs, ns, func(t *testing.T) {
		cleanupTemplate(t, isp, ns.Name)
		instInNsCleanup(t)
		t.Logf("tearDown complete, have a wonderful day!")
	}
}

// Complete setUp for a GAP test. Returns a tearDown function.
func setUpGAP(t *testing.T) (kubernetes.Interface, *v1.Namespace, func(t *testing.T)) {
	cs, ns, instInNsCleanup := setUpKritisInNS(t)

	gap, err := processTemplate("generic-attestation-policy/my-gap.yaml", ns.Name)
	if err != nil {
		t.Fatalf("failed to process gap template: %v", err)
	}
	cmd := exec.Command("kubectl", "create", "-f", gap, "-n", ns.Name)
	if out, err := integration_util.RunCmdOut(cmd); err != nil {
		t.Fatalf("testing error: %v\nout: %s", err, out)
	}

	aa, err := processTemplate("generic-attestation-policy/test-attestor-1.yaml", ns.Name)
	if err != nil {
		t.Fatalf("failed to process attestation-authority template: %v", err)
	}
	cmd = exec.Command("kubectl", "create", "-f", aa, "-n", ns.Name)
	if out, err := integration_util.RunCmdOut(cmd); err != nil {
		t.Fatalf("testing error: %v\nout: %s", err, out)
	}

	cmd = exec.Command("kubectl", "apply", "-f", "testdata/kritis-server/kritis-config.yaml")
	if out, err := integration_util.RunCmdOut(cmd); err != nil {
		t.Fatalf("testing error: %v\nout: %s", err, out)
	}

	waitForCRDExamples(t, ns, map[string]string{"genericattestationpolicies.kritis.grafeas.io": "my-gap"})

	return cs, ns, func(t *testing.T) {
		cleanupTemplate(t, gap, ns.Name)
		instInNsCleanup(t)
		t.Logf("tearDown complete, have a wonderful day!")
	}
}

func TestKritisGAPLogic(t *testing.T) {
	cs, ns, tearDown := setUpGAP(t)
	defer tearDown(t)

	var testCases = []struct {
		template string
		pods     []string
		err      string
	}{
		{
			"nginx/nginx-digest.yaml",
			[]string{"nginx-digest"},
			"",
		},
		{
			"java/java-with-digest.yaml",
			[]string{},
			"not attested",
		},
	}

	for _, tc := range testCases {
		path, err := processTemplate(tc.template, ns.Name)
		defer cleanupTemplate(t, path, ns.Name)
		if err != nil {
			t.Fatalf("failed to process template: %v", err)
		}

		cmd := exec.Command("kubectl", "apply", "-f", path, "--namespace", ns.Name)
		t.Logf("Running: %s", cmd.Args)
		out, err := integration_util.RunCmdOut(cmd)

		if err != nil && len(tc.err) == 0 {
			t.Fatalf("failed because error not expected: %v\n\noutput:\n%s\n\nlogs:\n%s\n", err, out, kritisLogs(ns))
		}

		if len(tc.err) > 0 {
			if err == nil {
				t.Fatalf("failed because error was expected")
			}
			if !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("wrong error: %v\n\noutput:\n%s\n\nlogs:\n%s\n", err, out, kritisLogs(ns))
			}
		}

		for _, pod := range tc.pods {
			if err := kubernetesutil.WaitForPodReady(cs.CoreV1().Pods(ns.Name), pod); err != nil {
				t.Errorf("timeout waiting for pod\n%s\n%s", kritisLogs(ns), out)
			}
		}
	}
}

func TestKritisISPLogic(t *testing.T) {
	cs, ns, tearDown := setUpISP(t)
	defer tearDown(t)

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
			shouldSucceed: false,
		},
		{
			template:      "nginx/nginx-no-digest-allowlist.yaml",
			command:       "create",
			pods:          []string{"nginx-no-digest-allowlist"},
			shouldSucceed: true,
		},
		{
			template:      "nginx/nginx-digest-allowlist.yaml",
			command:       "create",
			pods:          []string{"nginx-digest-allowlist"},
			shouldSucceed: true,
		},
		{
			template:      "java/java-with-vulnz.yaml",
			command:       "create",
			shouldSucceed: false,
		},
		{
			template:      "java/java-with-vulnz-deployment.yaml",
			command:       "create",
			shouldSucceed: false,
		},
		{
			template:      "java/java-with-vulnz-replicaset.yaml",
			command:       "create",
			shouldSucceed: false,
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
			template:      "kritis-server/kritis-server-global-allowlist.yaml",
			command:       "apply",
			pods:          []string{"kritis-server-global-allowlist"},
			shouldSucceed: true,
		},
		{
			template:      "kritis-server/kritis-server-global-allowlist-with-vulnz.yaml",
			command:       "apply",
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
			path, err := processTemplate(tc.template, ns.Name)
			defer cleanupTemplate(t, path, ns.Name)
			if err != nil {
				t.Fatalf("failed to process template: %v", err)
			}

			cmd := exec.Command("kubectl", tc.command, "-f", path, "--namespace", ns.Name)
			t.Logf("Running: %s", cmd.Args)
			out, err := integration_util.RunCmdOut(cmd)

			if err != nil {
				if !tc.shouldSucceed {
					return
				}
				t.Fatalf("failed: %v\n\noutput:\n%s\n\nlogs:\n%s\n", err, out, kritisLogs(ns))
			}
			if !tc.shouldSucceed {
				t.Fatalf("deployment should have failed but succeeded\n%s", kritisLogs(ns))
			}

			for _, p := range tc.pods {
				t.Logf("Waiting for pod %s in namespace %s ...", p, ns.Name)
				if err := kubernetesutil.WaitForPodReady(cs.CoreV1().Pods(ns.Name), p); err != nil {
					t.Errorf("timeout waiting for pod %q\n%s\n%s", p, kritisLogs(ns), out)
				}
			}

			for _, d := range tc.deployments {
				t.Logf("Waiting for deployment %s in namespace %s ...", d, ns.Name)
				if err := kubernetesutil.WaitForDeploymentToStabilize(cs, ns.Name, d, 5*time.Minute); err != nil {
					t.Errorf("timeout waiting for deployment %q\n%s", d, kritisLogs(ns))
				}
			}

			for _, r := range tc.replicasets {
				t.Logf("Waiting for replicaset %s in namespace %s ...", r, ns.Name)
				if err := kubernetesutil.WaitForReplicaSetToStabilize(cs, ns.Name, r, 5*time.Minute); err != nil {
					t.Errorf("Timed out waiting for replicasets to stabilize\n%s", kritisLogs(ns))
				}
			}
		})
	}
}

func TestKritisCron(t *testing.T) {
	cs, ns, tearDown := setUpISP(t)
	defer tearDown(t)

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
			template:      "vulnz/acceptable-vulnz.yaml",
			command:       "apply",
			pods:          []string{"image-with-acceptable-vulnz"},
			shouldSucceed: true,
			shouldLabel:   false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.template, func(t *testing.T) {
			path, err := processTemplate(tc.template, ns.Name)
			defer cleanupTemplate(t, path, ns.Name)
			if err != nil {
				t.Fatalf("failed to process template: %v", err)
			}
			cmd := exec.Command("kubectl", tc.command, "-f", path, "--namespace", ns.Name)
			t.Logf("Running: %s", cmd.Args)
			out, err := integration_util.RunCmdOut(cmd)
			if err != nil {
				if !tc.shouldSucceed {
					return
				}
				t.Fatalf("exec failed: %s %v\n%s", out, err, kritisLogs(ns))

			}
			if !tc.shouldSucceed {
				t.Fatalf("deployment should have failed but succeeded\n%s", kritisLogs(ns))
			}

			for _, p := range tc.pods {
				t.Logf("Waiting for pod %s in namespace %s ...", p, ns.Name)
				if err := kubernetesutil.WaitForPodReady(cs.CoreV1().Pods(ns.Name), p); err != nil {
					t.Errorf("timeout waiting for pod %q\n%s\n%s", p, kritisLogs(ns), out)
				}
			}

			for _, d := range tc.deployments {
				t.Logf("Waiting for deployment %s in namespace %s ...", d, ns.Name)
				if err := kubernetesutil.WaitForDeploymentToStabilize(cs, ns.Name, d, 10*time.Minute); err != nil {
					t.Errorf("timeout waiting for deployment %q\n%s", d, kritisLogs(ns))
				}
			}

			cmd = exec.Command("kubectl", "get", "po", "--namespace", ns.Name)
			pods, err := integration_util.RunCmdOut(cmd)
			if err != nil {
				t.Errorf("kubectl get failed: %s %v", pods, err)
			}
			t.Logf("kubectl get po out:\n%s", pods)

			cmd = exec.Command("kubectl", "get", "po",
				"-l", "label=kritis-validation-hook",
				"-o", "custom-columns=:metadata.name",
				"--no-headers=true",
				"--namespace", ns.Name)
			hookPod, err := integration_util.RunCmdOut(cmd)
			if err != nil {
				t.Errorf("kubectl get for kritis-validation-hook failed: %s %v", hookPod, err)
			}

			// as kubectl exec opens a tty, out is not monitored
			cmd = exec.Command("kubectl", "exec", "--namespace", ns.Name,
				strings.TrimSpace(string(hookPod)), "--", "/kritis/kritis-server", "--run-cron")
			if err = cmd.Start(); err != nil {
				t.Errorf("start failed for %s: %v", cmd.Args, err)
			}

			if err = cmd.Wait(); err != nil {
				t.Errorf("wait failed for %s: %v", cmd.Args, err)
			}
			// check labels on pods
			cmd = exec.Command("kubectl", "get", "pods", "-l", "kritis.grafeas.io/invalidImageSecPolicy=invalidImageSecPolicy", "--namespace", ns.Name)
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
