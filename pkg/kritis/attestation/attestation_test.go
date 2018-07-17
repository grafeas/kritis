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
	{"test-invalid-sig", "test", invalidSig, true},
	{"test-incorrect-sig", "test", incorrectSig, true},
}

func TestAttestations(t *testing.T) {
	for _, tc := range tcAttestations {
		publicKey, privateKey := createBase64KeyPair(t)
		t.Run(tc.name, func(t *testing.T) {
			sig, err := AttestMessage(publicKey, privateKey, tc.message)
			if err != nil {
				t.Fatalf("Unexpected error %s", err)
			}
			if tc.signature == "" {
				tc.signature = sig
			}
			err = VerifyImageAttestation(publicKey, tc.signature, tc.message)
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
	pubKeyBaseEnc := getBase64EncodedKey(key, openpgp.PublicKeyType, t)
	// Get Pem encoded Private Key
	privKeyBaseEnc := getBase64EncodedKey(key, openpgp.PrivateKeyType, t)
	return pubKeyBaseEnc, privKeyBaseEnc
}

func getBase64EncodedKey(key *openpgp.Entity, keyType string, t *testing.T) string {
	keyBytes := getKey(key, keyType, t)
	// base64 encoded Key
	return base64.StdEncoding.EncodeToString(keyBytes)
}

func getKey(key *openpgp.Entity, keyType string, t *testing.T) []byte {
	gotWriter := bytes.NewBuffer(nil)
	wr, encodingError := armor.Encode(gotWriter, keyType, nil)
	testutil.CheckError(t, false, encodingError)
	if keyType == openpgp.PrivateKeyType {
		testutil.CheckError(t, false, key.SerializePrivate(wr, nil))
	} else {
		testutil.CheckError(t, false, key.Serialize(wr))
	}
	wr.Close()
	return gotWriter.Bytes()
}

var invalidSig = "invalid sig"

// The PGP signature is incorrect for  message "test"
var incorrectSig = `-----BEGIN PGP SIGNATURE-----

wsBcBAEBCAAQBQJbRuT2CRAkeumEQRqa6QAAqusIAB7rd3ceI2aPFuQWMYfyqrvh
rcs6N4xS3fF157+aCVGs2UFfJgqDL+G5s5u2vnlu72R8xvrVQuKIbyNaFXiougev
YIi/056PA1nw3cTTOI1rXFjxaXxXZoZcWl1oq8D6s9zCYErUCKaAoJTdWzQwo6us
FY/ZfV0YD06pEv+vvMSxJRWKC4sQlnuOR2QxVS0pTlsqgb5WJKvrXqzTL+F+Wiw8
4deXawooZZAN5huDALWL2UBo7QIOuAVhWdtt+NHxHCowvdxzknKakO+4/6fTm19V
hie3zd6sfl5xVuKeU6z19rpjGr6c8ZBrNGzHnXXZzImWHMDXJ5sg3Mu+Sx8G9oM=
=R+zw
-----END PGP SIGNATURE-----`
