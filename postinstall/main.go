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
	tlsSecretName string
	certificate   string
	webhookName   string
	serviceName   string
)

func init() {
	flag.StringVar(&webhookName, "webhook-name", install.WebhookName, "The name of the validation webhook.")
	flag.StringVar(&serviceName, "service-name", install.ServiceName, "The name of the service for the webhook.")
	flag.StringVar(&tlsSecretName, "tls-secret-name", install.TlsSecretName, "The name of the kritis tls secret.")
	flag.Parse()
}

func main() {
	createValidationWebhook()
}
