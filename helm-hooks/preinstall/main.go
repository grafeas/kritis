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
	"flag"

	"github.com/grafeas/kritis/cmd/kritis/version"
	"github.com/grafeas/kritis/pkg/kritis/install"
	"github.com/sirupsen/logrus"
)

var (
	namespace              = install.RetrieveNamespace()
	csrName                string
	tlsSecretName          string
	createNewCSR           bool
	serviceName            string
	serviceNameDeployments string
	kritisInstallLabel     string
)

func init() {
	flag.StringVar(&csrName, "csr-name", "", "The name of the kritis csr.")
	flag.StringVar(&tlsSecretName, "tls-secret-name", "", "The name of the kritis tls secret.")
	flag.BoolVar(&createNewCSR, "create-new-csr", true, "Set to false in order to only create a new CSR if one is not present.")
	flag.StringVar(&serviceName, "kritis-service-name", "", "The name of the kritis service for pods.")
	flag.StringVar(&serviceNameDeployments, "kritis-service-name-deployments", "", "The name of the kritis service for deployments.")
	flag.StringVar(&kritisInstallLabel, "kritis-install-label", "", "The label to indicate a resource has been created by kritis")
}

func main() {
	flag.Parse()
	logrus.Infof("running preinstall\nversion %s\ncommit: %s",
		version.Version,
		version.Commit,
	)
	// First, delete the CertificateSigningRequest and Secret if they already exist
	deleteExistingObjects()
	if createNewCSR || !csrExists() {
		// Create the certificates
		createCertificates()
		// Create the certificate signing request
		createCertificateSigningRequest()
		// Approve the certificate signing request
		approveCertificateSigningRequest()
	}
	// Create the TLS secret
	createTLSSecret()
	labelTLSSecret()
	installCRDs()
}
