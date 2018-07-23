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

package secrets

import (
	"encoding/base64"
	"fmt"

	"github.com/grafeas/kritis/pkg/kritis/constants"
	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	"k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	// For testing
	getSecretFunc = getSecret
)

type KSecret struct {
	PublicKey  string
	PrivateKey string
	SecretName string
}

func GetSecret(namespace string, name string) (*KSecret, error) {
	secret, err := getSecretFunc(namespace, name)
	if err != nil {
		return nil, err
	}
	pub, ok := secret.Data[constants.PublicKey]
	if !ok {
		return nil, fmt.Errorf("Invalid Secret %s. Could not find key %s", name, constants.PublicKey)
	}
	priv, ok := secret.Data[constants.PrivateKey]
	if !ok {
		return nil, fmt.Errorf("Invalid Secret %s. Could not find key %s", name, constants.PublicKey)
	}
	return &KSecret{
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
		SecretName: secret.Name,
	}, nil
}

func getSecret(namespace string, name string) (*v1.Secret, error) {
	c, err := kubernetesutil.GetClientset()
	if err != nil {
		return nil, err
	}
	return c.CoreV1().Secrets(namespace).Get(name, meta_v1.GetOptions{})
}
