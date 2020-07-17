/*
Copyright 2020 Google LLC

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

package attestlib

import (
	"crypto/ecdsa"
	"testing"
)

const ec256PrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS0iQ5IlSHswYTbiz
vwR/YeueAakvrLayzcuLVzUPg+ihRANCAASLomGqGvbwvN3ai5f+kUsBXeBcJD26
rqfIemztatGwDuBymNVP0fabJscWxObqe3iaER5NOJg167zqA11PQueQ
-----END PRIVATE KEY-----`

const ec384PrivateKey = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBXs02405f5G7xKHY/l
QprUkVyEVWvNEXe9+xDmOD1pHHpnsTlRfJQo1de0ROuk08ChZANiAATIz2wT8EEq
omyOrPu6hhkR8/0PrY80HSThgHndPFvmvI6vUo6sXS6PJEXPp+iu2GSSYQkL3m+l
kdBOhfd+fYTPSzZVKs5XulL3TQ0ohrMipX4gG5x0wVMoy+CHkxAMBug=
-----END PRIVATE KEY-----`

const ec521PrivateKey = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBWNVxpOzimyMDpF9b
bUp3rPyMCbTaLzi3/7MWHcTO6/OIMeNgOU9ShxSnYAaOa+IPa4HQxsmv1uesijTa
zVKWWOKhgYkDgYYABAH+ih5cBui0i6lcY8fcxHz+0cHx8JPqEg7hWad1JQbux/J4
PsIC6zJmuxzHlr1V07i+dnLGZPxVbjYstLL3J0BHUgE+upGIIPmULuC/P/0xBHiC
Q2XPurJc20OMt1Spsg61RpFAs2Zd5rZQEfrji/TeyI40FH6y72jPiYcfY1IcvCaV
Lg==
-----END PRIVATE KEY-----`

const payload = "good payload"

func TestEcSign(t *testing.T) {
	tcs := []struct {
		name               string
		privateKey         []byte
		signatureAlgorithm SignatureAlgorithm
		expectedError      bool
	}{
		{
			name:               "create ec 256 signature success",
			privateKey:         []byte(ec256PrivateKey),
			signatureAlgorithm: EcdsaP256Sha256,
			expectedError:      false,
		}, {
			name:               "create ec 384 signature success",
			privateKey:         []byte(ec384PrivateKey),
			signatureAlgorithm: EcdsaP384Sha384,
			expectedError:      false,
		}, {
			name:               "create ec 521 signature success",
			privateKey:         []byte(ec521PrivateKey),
			signatureAlgorithm: EcdsaP521Sha512,
			expectedError:      false,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ecKey, err := parsePkixPrivateKeyPem(tc.privateKey)
			if err != nil {
				t.Fatalf("error parsing key %v", err)
			}
			_, err = ecSign(ecKey.(*ecdsa.PrivateKey), []byte(payload), tc.signatureAlgorithm)
			if tc.expectedError {
				if err == nil {
					t.Errorf("ecSign(...) = nil, expected non nil")

				}
			} else {
				if err != nil {
					t.Errorf("ecSign(..) = %v, expected nil", err)
				}
			}

		})
	}
}
