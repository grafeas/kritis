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

package e2etest

import (
	"testing"

	"github.com/grafeas/kritis/pkg/attestlib"
)

const rsa2048PrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDVV/6DeIAscHkY
fPaxMyZWZ6ZUyKjyICAhcOF90mYAkkJQbrW8ftkU4k1bBU+JfYcTiILyq4tPdrZb
mHzU6INjYVd8Pm9kHSXJxc1mhqzKFSULhMWwvTW2CHtbtY3mIEOXDFjXdtyC/v1I
huujP8L6RLX5yq7gZBeYQctgWDzSlBV7uywFpDerEDQcvSF5cl8zRh7jQDDdoLjf
SH3Z/ZrkmBjwkSpFO1iCHdVW6rObcvhC9JaIfN8Hb0FcIHQay0UrjjxpiSTZE8jp
DUuShPs2IKq49UXURidRcqsL4A2hav+XuV0QntXi+mj70QKWddzEDOr+Sep43lZ0
zqI9ifKrAgMBAAECggEAX3wmuYjxNPKSAFfNwbl26y0w0LmOg+/E8bKn+bx1UsQj
UgR66oaLekFfBeH2mz7HegKbOSl2DHbBX3V8SX5Xb99dXIpFKLWy9//D0qNsKnYU
QneGU3gb1gEt1PoJLHo8RhqMmMLmJushSZi5VjNvfLvMBqSkaGHj/Y1VDSXw8v3q
w25PxoudycauNLW0CKLEd2QuPHyjd/krc4R3364PRuIS524V8f+TG3zbXYP+0el3
oPxApXHuMcbwSN+SqyHJecYt5LBVjhJNjilG1p9V4FMzeMnDeYLbi6PLkObtCye5
G8yT2pMIgYztCcbOVrVDPnQ3RqJXuz5r4KHLn9c+QQKBgQD02oHfjSWlLBIOMohh
A1nb3ffsskF6g8aIKz233sGvCrHDyIACzvgwAhV//crp5xuRftyMk0bDpLKFwcvD
Z0BXKgPntq1IRzDyZyKggXEp/XjtPFs6HHFovyX7a1N3/1J20hJJ+gEVEDXAhqxv
88cB+92vFQVbVxotRpuqwEtNaQKBgQDfDkaAeuiX00NXWoymgJRU4hg1vxdcEQ7X
L7JHtUqF510MWsiZBpHfRAV7EN1ZlvGxdBRk2bbTZwV3+4X89SLJLdhS/3fkix1Z
+h/UFm9HZZxcb2UMj/FTuRdQhj1a7h/l6v4KQ2qVCkxwH4Ih5UvLxdmnIcYpbFoB
UhuKGYy48wKBgBucIBTzN5F+fLK5JAO8ev998hzwpM2J2nM0XQtExRZV4GGxVC38
5KOVOJNsLNtfQg6P/ZKkcNBS3AaVKcLo+6pYhIQ2ZyfFT1GmK5NpxTb07BPkQG03
E9q54zCMk6buVYAsg/9vf3u+jjEdfohJNuGUYxUBC8+W7M66LYd9k4AxAoGAemkd
K9lH2DpqlH/u/FlIDiVeX/CU40PBPzq/vjaxxTapi+QufjxqxXpQ/67LqyT5Uwd/
QbFxcibxi10PtTjadEmilDn7FAN8giqQWRZOz4HmA5xmejRsniPPtbNV7JcODmGe
NQe2cECMnmPMSMnLhPL5dY1FcOozotHqpylKXx0CgYBpaBAZeihs5lCZLG9oyeFD
ujesvS5UdBomDgcDmmhd8dtZOIKsgGuEgbcG8NROrG0tE38JgJ2UxL9xVTYrEuy7
TCepA1Coedo2Kx1dnBTyvKBfI/TAsLt+JZ38zymUbvrflMG9c9JlhAtNtxm4MF0B
oujjRhvcxXGmqIt4OSjdQw==
-----END PRIVATE KEY-----`

const rsa2048PubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Vf+g3iALHB5GHz2sTMm
VmemVMio8iAgIXDhfdJmAJJCUG61vH7ZFOJNWwVPiX2HE4iC8quLT3a2W5h81OiD
Y2FXfD5vZB0lycXNZoasyhUlC4TFsL01tgh7W7WN5iBDlwxY13bcgv79SIbroz/C
+kS1+cqu4GQXmEHLYFg80pQVe7ssBaQ3qxA0HL0heXJfM0Ye40Aw3aC430h92f2a
5JgY8JEqRTtYgh3VVuqzm3L4QvSWiHzfB29BXCB0GstFK448aYkk2RPI6Q1LkoT7
NiCquPVF1EYnUXKrC+ANoWr/l7ldEJ7V4vpo+9EClnXcxAzq/knqeN5WdM6iPYny
qwIDAQAB
-----END PUBLIC KEY-----`

const rsa3072PubKey = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA174cl1EgPn1w/4r1OTNy
O5ViVEtjPV1Bl2xXA/4EOcVyvztdwovJriC2sry+gW7WS/YraS6BXTY328daY7u5
OYAHnr/NiF3BoAzbAYMpHU6otMiAlGADrgevESj5XKUp4+XuiYxdOPH7pqgHaZ0+
ZIvp08vH+xXsY1+WqA3TBsKxkCwTmWGUSy/j2Gml6XHgX1SywJGJ9VEI/5wACExX
3NYHx+OXBS5XyjFzIoBxFiuA4g8FRHcTw1uulX98Rt/WTwTjesMeWaB7mOxgK03A
rTOil11+/Wgboow3V93B5pdNMvVjkahYHvkjYkj/HJRuXUKidZANhBWEewpdHDkK
+NXa8BlxcbkzcO2DvXGRu1g0emVInoIEN+/1fz4ab/mTWUGgs9QX+INChlSV3EBz
5I6mXbc3fE4EW2W9KASIPKIpF1HBaF58B//W+XAy7mxhuSfg23/mkf4SI9ZVM82s
rBmJaTmRgKWbZXNaf4yH+RhyGF1CsBN2uLrt667Swxv3AgMBAAE=
-----END PUBLIC KEY-----`

func TestPkixEndToEnd(t *testing.T) {
	tcs := []struct {
		name                string
		privateKey          []byte
		publicKey           []byte
		signatureAlgorithm  attestlib.SignatureAlgorithm
		payload             []byte
		image               string
		expectedCreateError bool
		expectedVerifyError bool
	}{
		{
			name:                "verify attestation success",
			privateKey:          []byte(rsa2048PrivateKey),
			publicKey:           []byte(rsa2048PubKey),
			signatureAlgorithm:  attestlib.RsaSignPkcs12048Sha256,
			payload:             []byte(e2eTestPayload),
			image:               e2eTestImage,
			expectedCreateError: false,
			expectedVerifyError: false,
		}, {
			name:                "verify failed wrong public key",
			privateKey:          []byte(rsa2048PrivateKey),
			publicKey:           []byte(rsa3072PubKey),
			signatureAlgorithm:  attestlib.RsaSignPkcs12048Sha256,
			payload:             []byte(e2eTestPayload),
			image:               e2eTestImage,
			expectedCreateError: false,
			expectedVerifyError: true,
		}, {
			name:                "verify failed image does not match payload",
			privateKey:          []byte(rsa2048PrivateKey),
			publicKey:           []byte(rsa2048PubKey),
			signatureAlgorithm:  attestlib.RsaSignPkcs12048Sha256,
			payload:             []byte(e2eTestPayload),
			image:               wrongTestImage,
			expectedCreateError: false,
			expectedVerifyError: true,
		},
	}
	for _, tc := range tcs {
		signer, err := attestlib.NewPkixSigner(tc.privateKey, tc.signatureAlgorithm, "")
		if err != nil {
			t.Fatalf("Error initializing signer: %v", err)
		}
		att, err := signer.CreateAttestation(tc.payload)
		if tc.expectedCreateError {
			if err == nil {
				t.Fatalf("CreateAttestation(...)=nil, want non-nil")
			}
		} else if err != nil {
			t.Fatalf("CreateAttestation(...)=%v, want nil", err)
		}
		publicKey, err := attestlib.NewPublicKey(attestlib.Pkix, tc.signatureAlgorithm, tc.publicKey, "")
		if err != nil {
			t.Fatalf("Error creating public key: %v", err)
		}
		verifier, err := attestlib.NewVerifier(tc.image, []attestlib.PublicKey{*publicKey})
		if err != nil {
			t.Fatalf("Error initializing verifier: %v", err)
		}
		err = verifier.VerifyAttestation(att)
		if tc.expectedVerifyError && err == nil {
			t.Errorf("VerifyAttestation(...)=nil, want non-nil")
		} else if !tc.expectedVerifyError && err != nil {
			t.Errorf("VerifyAttestation(...)=%v, want nil", err)
		}
	}
}
