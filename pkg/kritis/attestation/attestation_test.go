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

package attestation

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var tcAttestations = []struct {
	name      string
	message   string
	signature string
	hasErr    bool
}{
	{"test-success", "test", "", false},
	{"test-invalid-sig", "test", "", false},
	{"test-incorrect-sig", "test", "", false},
}

func TestAttestations(t *testing.T) {
	for _, tc := range tcAttestations {
		pubKeyBaseEnc, privKeyBaseEnc := createBase64KeyPair(t)
		t.Run(tc.name, func(t *testing.T) {
			sig, err := AttestMessage(pubKeyBaseEnc, privKeyBaseEnc, tc.message)
			testutil.CheckError(t, tc.hasErr, err)
			if tc.signature == "" {
				tc.signature = sig
			}
			err = VerifyImageAttestation(pubKeyBaseEnc, sig)
			testutil.CheckError(t, tc.hasErr, err)
		})
	}
}

func createBase64KeyPair(t *testing.T) (string, string) {
	// Create a new pair of key
	var key *openpgp.Entity
	key, err := openpgp.NewEntity("kritis", "test", "kritis@grafeas.com", nil)
	testutil.CheckError(t, false, err)
	// Get Pem encoded Public Key
	gotWriter := bytes.NewBuffer(nil)
	wr, encodingError := armor.Encode(gotWriter, openpgp.PublicKeyType, nil)
	testutil.CheckError(t, false, encodingError)
	key.Serialize(wr)
	// base64 encoded Public Key
	pubKeyBaseEnc := base64.StdEncoding.EncodeToString(gotWriter.Bytes())

	// Get Pem encoded Private Key
	gotWriter = bytes.NewBuffer(nil)
	wr, encodingError = armor.Encode(gotWriter, openpgp.PrivateKeyType, nil)
	testutil.CheckError(t, false, encodingError)
	key.SerializePrivate(wr, nil)
	// base64 encoded Private Key
	privKeyBaseEnc := base64.StdEncoding.EncodeToString(gotWriter.Bytes())
	return pubKeyBaseEnc, privKeyBaseEnc
}


TestInvalidSig = `

`
