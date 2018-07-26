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
	"os"
	"os/exec"

	"github.com/grafeas/kritis/pkg/kritis/install"
	"github.com/sirupsen/logrus"
)

func deleteWebhook() {
	deleteObject("validatingwebhookconfiguration", webhookName)
}

func deleteTLSSecret() {
	deleteObject("secret", tlsSecretName)
}

func deleteCSR() {
	deleteObject("csr", csrName)
}

func deleteObject(object, name string) {
	getCommand := exec.Command("kubectl", "get", object, name, "--namespace", namespace)
	getCommand.Stderr = os.Stderr
	if _, err := getCommand.Output(); err == nil {
		deleteCmd := exec.Command("kubectl", "delete", object, name, "--namespace", namespace)
		install.RunCommand(deleteCmd)
		logrus.Infof("deleted %s %s", object, name)
	}
}
