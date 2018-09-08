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

package testutil

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func CheckErrorAndDeepEqual(t *testing.T, shouldErr bool, err error, expected, actual interface{}) {
	if err := checkErr(shouldErr, err); err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(expected, actual) {
		// TODO: Print diff instead of full structure http://go/go-test-comments#print-diffs
		t.Errorf("%T differ.\nExpected\n%+v\nActual\n%+v", expected, expected, actual)
		return
	}
}

func CheckError(t *testing.T, shouldErr bool, err error) {
	if err := checkErr(shouldErr, err); err != nil {
		t.Error(err)
	}
}

func checkErr(shouldErr bool, err error) error {
	if err == nil && shouldErr {
		return fmt.Errorf("Expected error, but returned none")
	}
	if err != nil && !shouldErr {
		return fmt.Errorf("Unexpected error: %s", err)
	}
	return nil
}

func CreateKeyPair(t *testing.T, name string) (string, string) {
	// Create a new pair of key
	var key *openpgp.Entity
	key, err := openpgp.NewEntity(name, "test", fmt.Sprintf("%s@grafeas.com", name), nil)
	CheckError(t, false, err)
	// Get Pem encoded Public Key
	pubKey := getKey(key, openpgp.PublicKeyType, t)
	// Get Pem encoded Private Key
	privKey := getKey(key, openpgp.PrivateKeyType, t)
	return pubKey, privKey
}

func getKey(key *openpgp.Entity, keyType string, t *testing.T) string {
	gotWriter := bytes.NewBuffer(nil)
	wr, encodingError := armor.Encode(gotWriter, keyType, nil)
	CheckError(t, false, encodingError)
	if keyType == openpgp.PrivateKeyType {
		CheckError(t, false, key.SerializePrivate(wr, nil))
	} else {
		CheckError(t, false, key.Serialize(wr))
	}
	wr.Close()
	return gotWriter.String()
}

func CreateSecret(t *testing.T, name string) *secrets.PGPSigningSecret {
	pub, priv := CreateKeyPair(t, name)
	return &secrets.PGPSigningSecret{
		PrivateKey: priv,
		PublicKey:  pub,
		SecretName: name,
	}
}

func Base64PublicTestKey(t *testing.T) string {
	b, err := base64.StdEncoding.DecodeString(PublicTestKey)
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}
	return string(b)
}
