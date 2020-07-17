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
	"crypto/rsa"
	"testing"
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

const rsa3072PrivateKey = `-----BEGIN PRIVATE KEY-----
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
iFC0mK345W//6CokZ3In6And
-----END PRIVATE KEY-----
`

const rsa4096PrivateKey = `-----BEGIN PRIVATE KEY-----
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
sO4nyZVNmEYg4tvJVA81UEmK2twOA/Q=
-----END PRIVATE KEY-----`

func TestRsaSign(t *testing.T) {
	tcs := []struct {
		name               string
		privateKey         []byte
		signatureAlgorithm SignatureAlgorithm
		expectedError      bool
	}{
		{
			name:               "create RSA 2048 signature successful",
			privateKey:         []byte(rsa2048PrivateKey),
			signatureAlgorithm: RsaSignPkcs12048Sha256,
			expectedError:      false,
		},
		{
			name:               "create RSA 3072 signature successful",
			privateKey:         []byte(rsa3072PrivateKey),
			signatureAlgorithm: RsaSignPkcs13072Sha256,
			expectedError:      false,
		},
		{
			name:               "create RSA 4096 SHA 256 signature successful",
			privateKey:         []byte(rsa4096PrivateKey),
			signatureAlgorithm: RsaSignPkcs14096Sha256,
			expectedError:      false,
		},
		{
			name:               "create RSA 4096 SHA 512 signature successful",
			privateKey:         []byte(rsa4096PrivateKey),
			signatureAlgorithm: RsaSignPkcs14096Sha512,
			expectedError:      false,
		},
		{
			name:               "create RSA 2048 PSS signature successful",
			privateKey:         []byte(rsa2048PrivateKey),
			signatureAlgorithm: RsaPss2048Sha256,
			expectedError:      false,
		},
		{
			name:               "create RSA 3072 PSS signature successful",
			privateKey:         []byte(rsa3072PrivateKey),
			signatureAlgorithm: RsaPss3072Sha256,
			expectedError:      false,
		},
		{
			name:               "create RSA 4096 SHA 256 PSS signature successful",
			privateKey:         []byte(rsa4096PrivateKey),
			signatureAlgorithm: RsaPss4096Sha256,
			expectedError:      false,
		},
		{
			name:               "create RSA 4096 SHA 512 PSS signature successful",
			privateKey:         []byte(rsa4096PrivateKey),
			signatureAlgorithm: RsaPss4096Sha512,
			expectedError:      false,
		},
		{
			name:               "invalid signature algorithm",
			privateKey:         []byte(rsa2048PrivateKey),
			signatureAlgorithm: EcdsaP256Sha256,
			expectedError:      true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rsaKey, err := parsePkixPrivateKeyPem(tc.privateKey)
			if err != nil {
				t.Fatalf("error parsing key %v", err)
			}
			_, err = rsaSign(rsaKey.(*rsa.PrivateKey), []byte(payload), tc.signatureAlgorithm)
			if tc.expectedError {
				if err == nil {
					t.Errorf("rsaSign(...) = nil, expected non nil")

				}
			} else {
				if err != nil {
					t.Errorf("rsaSign(..) = %v, expected nil", err)
				}
			}
		})
	}
}
