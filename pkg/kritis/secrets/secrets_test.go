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
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/glog"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var pub, priv = createKeys("good")
var pgpKey, _ = NewPgpKey(priv, "", pub)

var tests = []struct {
	name       string
	secretName string
	shdErr     bool
	expected   *PGPSigningSecret
}{
	{"good", "good-sec", false, &PGPSigningSecret{SecretName: "good-sec", PgpKey: pgpKey}},
	{"bad1", "bad1-sec", true, nil},
	{"bad2", "bad2-sec", true, nil},
	{"notfound", "not-present", true, nil},
}

func TestSecrets(t *testing.T) {
	getSecretFunc = getTestSecret
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := Fetch("test", tc.secretName)
			if !tc.shdErr && err != nil {
				t.Fatalf("expected error: %v but found %v", tc.shdErr, err)
			}
			if !reflect.DeepEqual(tc.expected, actual) {
				t.Fatalf("expected: %v but found %v", tc.expected, actual)
			}
		})
	}
}

var testSecrets = []v1.Secret{
	{
		ObjectMeta: metav1.ObjectMeta{Name: "good-sec"},
		Data: map[string][]byte{
			"private": []byte(priv),
			"public":  []byte(pub),
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{Name: "bad1-sec"},
		Data: map[string][]byte{
			"public": []byte(pub),
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{Name: "bad2-sec"},
		Data: map[string][]byte{
			"private": []byte(priv),
		},
	},
}

func getTestSecret(namespace string, name string) (*v1.Secret, error) {
	for _, sec := range testSecrets {
		if sec.Name == name {
			return &sec, nil
		}
	}
	return nil, fmt.Errorf("Secret %s not found", name)
}

func createKeys(name string) (string, string) {
	// Create a new pair of key
	var key *openpgp.Entity
	key, err := openpgp.NewEntity(name, "test", fmt.Sprintf("%s@grafeas.com", name), nil)
	if err != nil {
		glog.Errorf("Unexpected error: %v", err)
	}
	// Get Pem encoded Public Key
	pub := getKey(key, openpgp.PublicKeyType)
	// Get Pem encoded Private Key
	priv := getKey(key, openpgp.PrivateKeyType)
	return pub, priv
}

func getKey(key *openpgp.Entity, keyType string) string {
	gotWriter := bytes.NewBuffer(nil)
	wr, err := armor.Encode(gotWriter, keyType, nil)
	if err != nil {
		glog.Errorf("Unexpected error: %v", err)
	}
	if keyType == openpgp.PrivateKeyType {
		err := key.SerializePrivate(wr, nil)
		if err != nil {
			glog.Errorf("Unexpected error: %v", err)
		}
	} else {
		err := key.Serialize(wr)
		if err != nil {
			glog.Errorf("Unexpected error: %v", err)
		}
	}
	wr.Close()
	return gotWriter.String()
}
