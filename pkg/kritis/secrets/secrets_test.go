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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var pub, priv = createKeys("good")
var pgpKey, err = NewPgpKey(priv, "", pub)

var pub2, priv2 = passphraseProtectedSecretPublicKey, passphraseProtectedSecretPrivateKey
var goodPassphrase, badPassphrase = passphraseProtectedSecretPassphrase, "bad-passphrase"
var pgpKey2, err2 = NewPgpKey(priv2, goodPassphrase, pub2)

var tests = []struct {
	name       string
	secretName string
	shdErr     bool
	expected   *PGPSigningSecret
}{
	{"good-nopass", "good-sec-nopass", false, &PGPSigningSecret{SecretName: "good-sec-nopass", PgpKey: pgpKey}},
	{"bad1-nopass", "bad-sec-nopass-miss-private-key", true, nil},
	{"bad2-nopass", "bad-sec-nopass-miss-public-key", true, nil},
	{"not-found", "not-found", true, nil},
	{"good-sec-withpass", "good-sec-withpass", false, &PGPSigningSecret{SecretName: "good-sec-withpass", PgpKey: pgpKey2}},
	{"bad-sec-withpass-bad-pass", "bad-sec-withpass-bad-pass", true, nil},
}

func TestSecrets(t *testing.T) {
	if err != nil {
		t.Fatalf("pgp key creation failed %v", err)
	}
	if err2 != nil {
		t.Fatalf("pgp key creation failed %v", err2)
	}
	getSecretFunc = getTestSecret
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := Fetch("test", tc.secretName)
			if !tc.shdErr && err != nil {
				t.Fatalf("expected error: %v but found %v", tc.shdErr, err)
			}
			if !isSecretEqual(tc.expected, actual) {
				t.Fatalf("expected: %v but found %v", tc.expected, actual)
			}
		})
	}
}

// Custom methods to check if two secrets are equal.
// We avoid using reflect.DeepEqual() directly bacause a passphrase-protected
// packet.PrivateKey can contain a function field.
func isSecretEqual(x, y *PGPSigningSecret) bool {
	if (x == nil || y == nil) {
		return x == y
	} else {
		px := x.PgpKey.privateKey
		py := y.PgpKey.privateKey
		return reflect.DeepEqual(x.PgpKey.publicKey, y.PgpKey.publicKey) &&
			reflect.DeepEqual(px.PrivateKey, py.PrivateKey) &&
			reflect.DeepEqual(px.Encrypted, py.Encrypted) &&
			reflect.DeepEqual(px.PublicKey, py.PublicKey)
	}
}

var testSecrets = []v1.Secret{
	// Test secrets with no passphrase
	{
		ObjectMeta: metav1.ObjectMeta{Name: "good-sec-nopass"},
		Data: map[string][]byte{
			"private": []byte(priv),
			"public":  []byte(pub),
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-sec-nopass-miss-private-key"},
		Data: map[string][]byte{
			"public": []byte(pub),
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-sec-nopass-miss-public-key"},
		Data: map[string][]byte{
			"private": []byte(priv),
		},
	},
	// Test secrets with passphrase
	{
		ObjectMeta: metav1.ObjectMeta{Name: "good-sec-withpass"},
		Data: map[string][]byte{
			"private":    []byte(priv2),
			"public":     []byte(pub2),
			"passphrase": []byte(goodPassphrase),
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-sec-withpass-bad-pass"},
		Data: map[string][]byte{
			"private":    []byte(priv2),
			"public":     []byte(pub2),
			"passphrase": []byte(badPassphrase),
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
		glog.Fatalf("entity creation error: %v", err)
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
		glog.Fatalf("armor encode error: %v", err)
	}
	if keyType == openpgp.PrivateKeyType {
		err := key.SerializePrivate(wr, nil)
		if err != nil {
			glog.Errorf("serialization error: %v", err)
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
