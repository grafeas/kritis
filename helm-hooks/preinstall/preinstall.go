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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/grafeas/kritis/pkg/kritis/install"
	"github.com/sirupsen/logrus"
)

func deleteExistingObjects() {
	csrCmd := exec.Command("kubectl", "get", "csr", csrName, "--namespace", namespace)
	csrCmd.Stderr = os.Stderr
	_, err := csrCmd.Output()
	if err == nil && deleteCSR {
		deleteCSRCmd := exec.Command("kubectl", "delete", "csr", csrName, "--namespace", namespace)
		install.RunCommand(deleteCSRCmd)
	}

	secretCmd := exec.Command("kubectl", "get", "secret", tlsSecretName, "--namespace", namespace)
	secretCmd.Stderr = os.Stderr
	_, err = secretCmd.Output()
	if err == nil {
		deleteSecretCmd := exec.Command("kubectl", "delete", "secret", tlsSecretName, "--namespace", namespace)
		install.RunCommand(deleteSecretCmd)
	}
}

func createCertificates() {
	cert := `{
"hosts": [
    "kritis-validation-hook",
    "kritis-validation-hook.kube-system",
    "kritis-validation-hook.%s",
    "kritis-validation-hook.%s.svc",
    "kritis-validation-hook-deployments",
    "kritis-validation-hook-deployments.kube-system",
    "kritis-validation-hook-deployments.%s",
    "kritis-validation-hook-deployments.%s.svc"

],
"key": {
	"algo": "ecdsa",
	"size": 256
}
}`
	cert = fmt.Sprintf(cert, namespace, namespace, namespace, namespace)
	certCmd := exec.Command("cfssl", "genkey", "-")
	certCmd.Stdin = bytes.NewReader([]byte(cert))
	output := install.RunCommand(certCmd)

	serverCmd := exec.Command("cfssljson", "-bare", "server")
	serverCmd.Stdin = bytes.NewReader(output)
	install.RunCommand(serverCmd)
}

func createCertificateSigningRequest() {
	certificate := retrieveRequestCertificate()
	csr := `apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
    name: %s
spec:
    groups:
    - system:authenticated
    request: %s
    usages:
    - digital signature
    - key encipherment
    - server auth`
	csr = fmt.Sprintf(csr, csrName, certificate)

	kubectlCmd := exec.Command("kubectl", "apply", "-f", "-")
	kubectlCmd.Stdin = bytes.NewReader([]byte(csr))
	fmt.Println(csr)
	install.RunCommand(kubectlCmd)
}

func approveCertificateSigningRequest() {
	approvalCmd := exec.Command("kubectl", "certificate", "approve", csrName)
	install.RunCommand(approvalCmd)
}

func retrieveRequestCertificate() string {
	contents, err := ioutil.ReadFile("server.csr")
	if err != nil {
		logrus.Fatalf("error trying to read contents of server.csr: %v", err)
	}
	// base64 encode the contents
	encodedLen := base64.StdEncoding.EncodedLen(len(contents))
	encoded := make([]byte, encodedLen)
	base64.StdEncoding.Encode(encoded, contents)
	// trim any new lines off the end
	return string(encoded)
}

func createTLSSecret() {
	retrieveCertCmd := exec.Command("kubectl", "get", "csr", csrName, "-o", "jsonpath='{.status.certificate}'", "--namespace", namespace)
	cert := install.RunCommand(retrieveCertCmd)

	certStr := string(cert)
	certStr = strings.TrimPrefix(certStr, "'")
	certStr = strings.TrimSuffix(certStr, "'")
	cert = []byte(certStr)

	decodedLen := base64.StdEncoding.DecodedLen(len(cert))
	decoded := make([]byte, decodedLen)
	_, err := base64.StdEncoding.Decode(decoded, cert)
	if err != nil {
		logrus.Fatalf("couldn't decode cert: %v", err)
	}
	// Save decoded contents to server.crt
	if err := ioutil.WriteFile("server.crt", decoded, 0644); err != nil {
		logrus.Fatalf("unable to copy decoded cert to server.crt: %v", err)
	}
	foundSecret := false
	var secretErr error
	for i := 0; i < 10; i++ {
		tlsSecretCmd := exec.Command("kubectl", "get", "csr", csrName, "--namespace", namespace)
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

	tlsSecretCmd := exec.Command("kubectl", "create", "secret", "tls", tlsSecretName, "--cert=server.crt", "--key=server-key.pem", "--namespace", namespace)
	install.RunCommand(tlsSecretCmd)
}
