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
	"strings"
	"testing"
)

func TestParsePkixPrivateKeyPem(t *testing.T) {
	tcs := []struct {
		name          string
		privateKey    []byte
		expectedError bool
	}{
		{
			name:          "parse rsa key successful",
			privateKey:    []byte(rsa2048PrivateKey),
			expectedError: false,
		}, {
			name:          "parse ecdsa key successful",
			privateKey:    []byte(ec256PrivateKey),
			expectedError: false,
		}, {
			name:          "invalid key",
			privateKey:    []byte("not a pem"),
			expectedError: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePkixPrivateKeyPem(tc.privateKey)
			if tc.expectedError {
				if err == nil {
					t.Errorf("parsePkixPrivateKeyPem(...) = nil, expected non nil")

				}
			} else {
				if err != nil {
					t.Errorf("parsePkixPrivateKeyPem(..) = %v, expected nil", err)
				}
			}

		})
	}
}

func TestGeneratePKIXPublicKeyIdFromPrivateKey(t *testing.T) {
	tcs := []struct {
		name          string
		privateKey    []byte
		expectedError bool
	}{
		{
			name:          "genrate rsa private key id successful",
			privateKey:    []byte(rsa2048PrivateKey),
			expectedError: false,
		}, {
			name:          "generate ecdsa private key id successful",
			privateKey:    []byte(ec256PrivateKey),
			expectedError: false,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			key, err := parsePkixPrivateKeyPem(tc.privateKey)
			if err != nil {
				t.Fatalf("error parsing key %v", err)
			}
			_, err = generatePkixPublicKeyId(key)
			if tc.expectedError {
				if err == nil {
					t.Errorf("generatePkixPublicKeyId(...) = nil, expected non nil")

				}
			} else {
				if err != nil {
					t.Errorf("generatePkixPublicKeyId(..) = %v, expected nil", err)
				}
			}

		})
	}
}

func TestGeneratePKIXPublicKeyIdFromPublicKey(t *testing.T) {
	tcs := []struct {
		name          string
		publicKey     []byte
		expectedError bool
	}{
		{
			name:          "genrate rsa public key id successful",
			publicKey:     []byte(rsa2048PubKey),
			expectedError: false,
		}, {
			name:          "generate ecdsa public key id successful",
			publicKey:     []byte(ec256PubKey),
			expectedError: false,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			keyId, err := generatePkixPublicKeyId(tc.publicKey)
			if tc.expectedError {
				if err == nil {
					t.Errorf("generatePkixPublicKeyId(...) = nil, expected non nil")

				}
			} else {
				if err != nil {
					t.Errorf("generatePkixPublicKeyId(..) = %v, expected nil", err)
				} else if !strings.HasPrefix(keyId, "ni:///sha-256;") {
					t.Errorf("generatePkixPublicKeyId(..) = %s, expected key id to have prefix ni:///sha-256;", keyId)
				}
			}
		})
	}
}

const rsaPkcs1PrivKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA1Vf+g3iALHB5GHz2sTMmVmemVMio8iAgIXDhfdJmAJJCUG61
vH7ZFOJNWwVPiX2HE4iC8quLT3a2W5h81OiDY2FXfD5vZB0lycXNZoasyhUlC4TF
sL01tgh7W7WN5iBDlwxY13bcgv79SIbroz/C+kS1+cqu4GQXmEHLYFg80pQVe7ss
BaQ3qxA0HL0heXJfM0Ye40Aw3aC430h92f2a5JgY8JEqRTtYgh3VVuqzm3L4QvSW
iHzfB29BXCB0GstFK448aYkk2RPI6Q1LkoT7NiCquPVF1EYnUXKrC+ANoWr/l7ld
EJ7V4vpo+9EClnXcxAzq/knqeN5WdM6iPYnyqwIDAQABAoIBAF98JrmI8TTykgBX
zcG5dustMNC5joPvxPGyp/m8dVLEI1IEeuqGi3pBXwXh9ps+x3oCmzkpdgx2wV91
fEl+V2/fXVyKRSi1svf/w9KjbCp2FEJ3hlN4G9YBLdT6CSx6PEYajJjC5ibrIUmY
uVYzb3y7zAakpGhh4/2NVQ0l8PL96sNuT8aLncnGrjS1tAiixHdkLjx8o3f5K3OE
d9+uD0biEuduFfH/kxt8212D/tHpd6D8QKVx7jHG8EjfkqshyXnGLeSwVY4STY4p
RtafVeBTM3jJw3mC24ujy5Dm7QsnuRvMk9qTCIGM7QnGzla1Qz50N0aiV7s+a+Ch
y5/XPkECgYEA9NqB340lpSwSDjKIYQNZ29337LJBeoPGiCs9t97Brwqxw8iAAs74
MAIVf/3K6ecbkX7cjJNGw6SyhcHLw2dAVyoD57atSEcw8mcioIFxKf147TxbOhxx
aL8l+2tTd/9SdtISSfoBFRA1wIasb/PHAfvdrxUFW1caLUabqsBLTWkCgYEA3w5G
gHrol9NDV1qMpoCUVOIYNb8XXBEO1y+yR7VKheddDFrImQaR30QFexDdWZbxsXQU
ZNm202cFd/uF/PUiyS3YUv935IsdWfof1BZvR2WcXG9lDI/xU7kXUIY9Wu4f5er+
CkNqlQpMcB+CIeVLy8XZpyHGKWxaAVIbihmMuPMCgYAbnCAU8zeRfnyyuSQDvHr/
ffIc8KTNidpzNF0LRMUWVeBhsVQt/OSjlTiTbCzbX0IOj/2SpHDQUtwGlSnC6Puq
WISENmcnxU9RpiuTacU29OwT5EBtNxPaueMwjJOm7lWALIP/b397vo4xHX6ISTbh
lGMVAQvPluzOui2HfZOAMQKBgHppHSvZR9g6apR/7vxZSA4lXl/wlONDwT86v742
scU2qYvkLn48asV6UP+uy6sk+VMHf0GxcXIm8YtdD7U42nRJopQ5+xQDfIIqkFkW
Ts+B5gOcZno0bJ4jz7WzVeyXDg5hnjUHtnBAjJ5jzEjJy4Ty+XWNRXDqM6LR6qcp
Sl8dAoGAaWgQGXoobOZQmSxvaMnhQ7o3rL0uVHQaJg4HA5poXfHbWTiCrIBrhIG3
BvDUTqxtLRN/CYCdlMS/cVU2KxLsu0wnqQNQqHnaNisdXZwU8rygXyP0wLC7fiWd
/M8plG7635TBvXPSZYQLTbcZuDBdAaLo40Yb3MVxpqiLeDko3UM=
-----END RSA PRIVATE KEY-----
`

func TestGenerateIdMatchForKeyPair(t *testing.T) {
	keyId1, err := generatePkixPublicKeyId([]byte(rsa2048PubKey))
	if err != nil {
		t.Fatalf("error generating id from public key, %v", err)
	}
	key, err := parsePkixPrivateKeyPem([]byte(rsaPkcs1PrivKey))
	if err != nil {
		t.Fatalf("error parsing private key, %v", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("error with rsa key")
	}
	keyId2, err := generatePkixPublicKeyId(rsaKey)
	if err != nil {
		t.Fatalf("error generating id from private key, %v", err)
	}

	if keyId1 != keyId2 {
		t.Errorf("key ids dont match. id1 = %s , id2 = %s", keyId1, keyId2)
	}
}
