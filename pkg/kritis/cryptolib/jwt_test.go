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

package cryptolib

import (
	"testing"
)

const goodJwt = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAibXktc2lnbmluZy1rZXkiIH0K.eyAic3ViIjogImNvbnRhaW5lcjpkaWdlc3Q6c2hhMjU2OmZha2UtZGlnZXN0IiwgImF1ZCI6ICIvL2JpbmFyeWF1dGhvcml6YXRpb24uZ29vZ2xlYXBpcy5jb20iLCAiYXR0ZXN0YXRpb25UeXBlIjogIlRCRCIsICJhdHRlc3RhdGlvbiI6ICIiIH0K.cvffj1cTnxvNP70b1iFZUEX6wUhTohNQXIOrT6PJOGV3T+WXfkxJMWw0LaavoW2QSatMJK8HZj/KOSOhu3kzwzLusWZu2xbDjGQNLoUv5JjGTTw5erM4ldMfaA0eAdZfyTt5wHgSTx+maPFN/SOau3xVM4RgB9N7TPRB4xDTNdFZxHX2JZk5uZ6sqAOcAQ9ntxefws61hq32b4lf+QSi0jZllWA3hGgESrETrac6tRzraiqHWgkxRKwQBDCIOyyYlZOc8EjKC3ODQ2shRWSJoN13P1KCteQIwb7B5yaIL5RKP/NYW2f+HVkc3ohDDYAHqLYtUgueNFwbeVvRaf+BxQ"
const jwtWithInvalidHeaderTYP = "eyAgImFsZyI6ICJFUzI1NiIsICJ0eXAiOiAiQkFEVFlQRSIsICJraWQiOiAibXktc2lnbmluZy1rZXkiIH0K.eyAic3ViIjogImNvbnRhaW5lcjpkaWdlc3Q6c2hhMjU2OmZha2UtZGlnZXN0IiwgImF1ZCI6ICIvL2JpbmFyeWF1dGhvcml6YXRpb24uZ29vZ2xlYXBpcy5jb20iLCAiYXR0ZXN0YXRpb25UeXBlIjogIlRCRCIsICJhdHRlc3RhdGlvbiI6ICIiIH0K.cvffj1cTnxvNP70b1iFZUEX6wUhTohNQXIOrT6PJOGV3T+WXfkxJMWw0LaavoW2QSatMJK8HZj/KOSOhu3kzwzLusWZu2xbDjGQNLoUv5JjGTTw5erM4ldMfaA0eAdZfyTt5wHgSTx+maPFN/SOau3xVM4RgB9N7TPRB4xDTNdFZxHX2JZk5uZ6sqAOcAQ9ntxefws61hq32b4lf+QSi0jZllWA3hGgESrETrac6tRzraiqHWgkxRKwQBDCIOyyYlZOc8EjKC3ODQ2shRWSJoN13P1KCteQIwb7B5yaIL5RKP/NYW2f+HVkc3ohDDYAHqLYtUgueNFwbeVvRaf+BxQ"

var goodPubKey = PublicKey{
	KeyType:            Jwt,
	SignatureAlgorithm: EcdsaP256Sha256,
	ID:                 "my-signing-key",
	KeyData:            []byte("some-key"),
}

func TestVerifyJWT(t *testing.T) {
	tcs := []struct {
		name          string
		jwt           []byte
		pubkey        PublicKey
		expectedError bool
	}{
		{
			name:          "valid JWT and Public Key",
			jwt:           []byte(goodJwt),
			pubkey:        goodPubKey,
			expectedError: false,
		}, {
			name:          "invalid JWT length",
			jwt:           []byte("too.many.parts.here"),
			pubkey:        goodPubKey,
			expectedError: true,
		}, {
			name: "PublicKey KeyType does not match ALG in JWT header",
			jwt:  []byte(goodJwt),
			pubkey: PublicKey{
				KeyType:            Jwt,
				SignatureAlgorithm: RsaSignPkcs14096Sha256,
				ID:                 "my-signing-key",
				KeyData:            []byte("some-key"),
			},
			expectedError: true,
		}, {
			name: "PublicKey ID does not match KID in JWT header",
			jwt:  []byte(goodJwt),
			pubkey: PublicKey{
				KeyType:            Jwt,
				SignatureAlgorithm: EcdsaP256Sha256,
				ID:                 "some-key-id",
				KeyData:            []byte("some-key"),
			},
			expectedError: true,
		}, {
			name:          "Invalid TYP field",
			jwt:           []byte(jwtWithInvalidHeaderTYP),
			pubkey:        goodPubKey,
			expectedError: true,
		}, {
			name:          "Invalid Base64Encoding",
			jwt:           []byte("aaaaa.aaaa.aaaa"), // header has 5 a's which should return error from DecodeBase64
			pubkey:        goodPubKey,
			expectedError: true,
		},
	}

	v := jwtVerifierImpl{}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.verifyJwt(tc.jwt, tc.pubkey)
			if tc.expectedError {
				if err == nil {
					t.Fatalf("Passed when failure expected")
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %e", err)
				}

			}
		})
	}
}
