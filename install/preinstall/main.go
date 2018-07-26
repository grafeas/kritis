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

	"github.com/grafeas/kritis/pkg/kritis/install"
)

var (
	namespace     = install.RetrieveNamespace()
	csrName       string
	tlsSecretName string
	deleteCSR     bool
)

func init() {
	flag.StringVar(&csrName, "csr-name", install.CSRName, "The name of the kritis csr.")
	flag.StringVar(&tlsSecretName, "tls-secret-name", install.TlsSecretName, "The name of the kritis tls secret.")
	flag.BoolVar(&deleteCSR, "delete-csr", true, "Delete the csr passed in to csr-name, default tls-webhook-secret-cert")
	flag.Parse()
}

func main() {
	// First, delete the CertificateSigningRequest and Secret if they already exist
	deleteExistingObjects()
	// Create the certificates
	createCertificates()
	// Create the certificate signing request
	createCertificateSigningRequest()
	// Approve the certificate signing request
	approveCertificateSigningRequest()
	// Create the TLS secret
	createTLSSecret()
}
