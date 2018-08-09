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
	"encoding/base64"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/testutil"
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
		publicKey, privateKey := testutil.CreateKeyPair(t, "test")
		t.Run(tc.name, func(t *testing.T) {
			sig, err := CreateMessageAttestation(publicKey, privateKey, tc.message)
			if err != nil {
				t.Fatalf("Unexpected error %s", err)
			}
			if tc.signature == "" {
				tc.signature = sig
			}
			err = VerifyMessageAttestation(publicKey, tc.signature, tc.message)
			testutil.CheckError(t, tc.hasErr, err)
		})
	}
}

func TestGPGArmorSignIntegration(t *testing.T) {
	b, err := base64.StdEncoding.DecodeString(testutil.PublicTestKey)
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}
	if err := VerifyMessageAttestation(string(b), base64.StdEncoding.EncodeToString([]byte(expectedSig)), "test"); err != nil {
		t.Fatalf("unexpected error %s", err)
	}
}

// Base64 encoded signature.
// Created using echo  test >  test && gpg --armor --sign -u test@kritis.org < test | base64
var expectedSig = `-----BEGIN PGP MESSAGE-----

owEB4gEd/pANAwAKAa6LaZQRYxWjAcsKYgBbY13WdGVzdIkBxAQAAQoALhYhBNKD
pfX19eyqnvGFxa6LaZQRYxWjBQJbY13WEBx0ZXN0QGtyaXRpcy5vcmcACgkQrotp
lBFjFaOHFgwArVh3UFF1EJP87y9dglPjeZyr+Q7cgUm2h6LuUUj9hlThZAIhVKZD
sGOr6mm1050G1JBLE3KJuSBHcgg0NjcId26HxHV4bva1L1QTgLQczlpADZ1LdPYQ
e4y5CCDRt2lwZ0Kq1/Nk2Qz/+379Etj/E0+nH+jV+pWOZsSQbf5I7BDBhtX/insa
zf3IjS4D4vDtg29oyFol8M2Otv1Cx7FJJuS+78Kg/+8caVq6KNwnLkm7RFM1HdV9
wOGFnSUgRs1Amnqvhc6damKj3AUYU7R7MSGvrpT0m4N2ExlaTuR3brT6OQsFLTRy
HdZ7AbFoW1WH8Mt24c0PDjVCnpTwf7YLOlltmZRJ3+bjImPHiE1oTFeu1EJFNd/Y
k8FqtwuKIPTvYPRUD0zlHPgJdkKoO9z56Yt8wTOxlp8+dtDmVJZwDsBT/Nqp5j+W
NkTyozw6wFSDJ/0pMKYKf7jgYyaJyFfM78RV+a5fBbIb9WO+vk72zaYENqNsV86d
/bGUkqbPBGK+
=oQuR
-----END PGP MESSAGE-----`

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
