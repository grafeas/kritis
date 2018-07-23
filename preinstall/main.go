package main

import (
	"flag"
)

var (
	namespace     string
	csrName       string
	tlsSecretName string
)

func init() {
	flag.StringVar(&namespace, "namespace", "default", "The namespace you want to install kritis in.")
	flag.StringVar(&csrName, "csr-name", "tls-webhook-secret-cert", "The name of the kritis csr.")
	flag.StringVar(&tlsSecretName, "tls-secret-name", "tls-webhook-secret", "The name of the kritis tls secret.")
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
