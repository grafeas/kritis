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
	"encoding/base64"
	"testing"
	//   "crypto"
	// 	 "crypto/sha256"
	// 	 "encoding/base64"
	// 	 "crypto/rand"
	// 	 "crypto/rsa"
	// 	 "encoding/pem"
	// 	 "crypto/x509"
	// 	 "fmt"
)

const good_plaintext = "good payload"

// RSA Public Keys
const rsa_2048_pub_key = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Vf+g3iALHB5GHz2sTMm
VmemVMio8iAgIXDhfdJmAJJCUG61vH7ZFOJNWwVPiX2HE4iC8quLT3a2W5h81OiD
Y2FXfD5vZB0lycXNZoasyhUlC4TFsL01tgh7W7WN5iBDlwxY13bcgv79SIbroz/C
+kS1+cqu4GQXmEHLYFg80pQVe7ssBaQ3qxA0HL0heXJfM0Ye40Aw3aC430h92f2a
5JgY8JEqRTtYgh3VVuqzm3L4QvSWiHzfB29BXCB0GstFK448aYkk2RPI6Q1LkoT7
NiCquPVF1EYnUXKrC+ANoWr/l7ldEJ7V4vpo+9EClnXcxAzq/knqeN5WdM6iPYny
qwIDAQAB
-----END PUBLIC KEY-----`
const rsa_4096_pub_key = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAte+CWFUwOwyD/VBaK55o
qxTMOX34Y3evVlCY9iDXwYbi+yDgSgjB4K2sTvyV6ztQEBWzReNX3GG7WkPWkHVB
OIssRgtVUtNnngQkgoOwJWxGf0k1R/NrXRsRMReyuW1zT6iftVhClexf5eBLtmqy
7hXCpy7NNx9486YpF8KJGa1wrV3Ko3R1qHYjGgKd/fjtQ5CcFUZUYgmYQeIkeDO1
DiQOSYS2xnkUTfV2aHIgFUlrxdU2M50He5Z/jSE49/9IXQac599y2m6irVaVT6VM
vY6mxSRGgRx3hkoajVrxd3MglIFLO8/FfrOGwZg9bZFIlgHjUiFPPKbn8bSyldMZ
xNj36t7YC2ZpN6XGzeBnnLfBW1GjGomk3G1eyBUCwRk9nHt9Dsqr/xEauMocHcfA
EfEm8/fwcp5MB8GOZ3l8p9Rs38yoBFzVbj2SeicFoQTnHe4DrtMvBzGyKsiaKszV
5UJAPyqm7zPph/Ck++NRQDmJvkhLXcs7QrUG2TBA7veqaLzrU88jY3RDKSIbNtLA
xBrmQID1ms7TVrCcB6nWrxHJc3FhTP6q/lUL0ziG8fOND9oW6P0YxaXj+1qIxn45
x2j5oDwsx8ig4/V23Yuofvji2j/VYAY/KAkKJOXqfozbmlMNUCpN6HuQ5yakVFgW
XanFz99rw4kZ0z70ziCBp68CAwEAAQ==
-----END PUBLIC KEY-----`

// Signatures created with RSA Keys. Signatures created with rsa.SignPKCS1v15 and rsa.SignPSS methods from crypto/rsa package.
const rsa2048_256_sig = "DDFzpubahBxVPnKdImjEx8qWssgSezVQm7iQt_VaKhi5SuTpNnryIejmBjOvnDG2u94veHvBANwHPTaH7_m6L07N73yVHaOG86BI6z5cVG-jCriLP5acYKosbsSW9rL7ei8IyVR1JEn0LVaIfNjd4LNMQA5fgTIPQ6zqFfqqbFGAKyTFs6qZoz6JVD253-jpSt_2gBPTbav-wubI2ZxMEtsn6OJZbJf08wGjCwdqs_8qM6-N4DaMlkDooQc3qUyeG3PtL0Oc8wv663YNgB0lMwPfFSTiiHWfqlaA5ipWYxR1zabp3edczblEhAzb7t6Eq3LxdbMJV0GsCiFuqur-PA"
const rsa2048_256_pss_sig = "fPdgFVY9OZSDTHqt7a74gFdBokpPuiUntWtPk0W2Bnsbbc2LLAG9qvt-z-WrKQ4IKHjq8Grm-asuePTKvIKRrLETgth2tXNT2yRFplmR3F6rwRbIZrcxEtjWLI2d0n0FVNdjdu7ozlJRWSQV666VP3Sq8BnZE6T5KpoSu4FYgNnE_12Y-DBzSmxcMSuEemO7-LBda0aGU8VxLpa5e0dq614BshF56yYLKIgjeNxBZmvTRSxn6sFdNiSdWed2KWsLAiUgwgcfIEQo4wuAXRia3nlW8ti0lsr3nDPURKdc51-jSCF-Ng9iTETlZeoeT5b2RIPRVPvs4mujrkfYJ_Mphw"
const rsa4096_512_sig = "AAgs8EX5jJ56OcI7V5guArvPbOyLGRyK79_F_1DuubBY-2Q_PdiiTJ2qcfs1TCrVudrJsO-SrUL1sgNpUMl44fcCXHw2SvIecPmdHkkIU6IFtTrBXwie-WUsQqr7kLkhjWejoGdI7bYVzPLT_k_RE8hMDBl1CaQuCMcESVdTqremN2TAax4j4PvbaFYyWDEDM9gGf5ylMzXO6gOw-3HZOrcQ44zNjNhcu6W6xs730TRyGbE9a3q3XyDjNCiikT6U36eds6-m5rDPNMvqin0YJda5ZDOdxge2f9HOu0PHR7WKPtF-65SVHM58c6qzuJHr7jLqG_PkKnBTlwLHZH3G6kZDwl3IepkOkw_esuX-BdzRdS7eFhpr5c20N5VfOYlU_itnEFs850iUkkQ_48vdQC55-hbkYxH9qbYSMbfiVrLxmiI3f5pXmX3MJv1LrHA3XDtBi0dhQpJVYyMfZZmmwZt-oJk-tIzoZb0vBDP5ucCUaiKReiRhCTw07VAH-UY2f5cvRhZ0CW8aZMhkH7JxT1JETov6mRo-kmMsRLKqkTLDjBkrl3YNtRKMQTauCFYCMME4bF4qJxPPBres3LlbAKyNMT0b9V6bpBUrQv247rawl2DEiDUZMDswKN3_kGMfOzW9iCetQYtBRxfkLygocm49UZO3wuNg-deT7Sya7jo"
const rsa4096_512_pss_sig = "f8gSD9u6XkwsqZYEaQtYdha8MwKNtwhtJRdD4YW-hQkTwPZa3dyj7PRulAI_MQWKCANFAVsqh2sHAP7atBpO79Evccqng_XBTsW6VYxMmHE4R3V7_dBKFHPdt3YE66kufrAy5TzYdAtQTikxT2C8SUb6L_KJg4Byavsx1sPbeRLEQBj8a_glBqfgqmr_4i06hfv9c9a1MGye8SSsaxYfURiGeSRs_mTep5CyE0Xze_ByZeoEEZjYsrpaFVzVsvViNHNcrP1GxsBL8GCz1oPcmAUD1P1nRT_X1kYycuodqpX4Pca3OpBp7kGRdXdBm6UugXLYPoHHZd6ks4NXRrTcY9OieE8s3UmQIwG6cJN4o4j8fmZF68iC50_vlA5rGBtxsdRCcmL9Q9LBZKgKH-FRHagrixAm-T3Ahbf-VpRDodgjz01Lwz8cVMfcZJ3SeHPoAvgOO4fGRRTQMpzKmDWNBlx2Nj3WXyIOeJEkg_2kJ7GEt5FspiXPGZsmU1XIJxblCZ_h1dpbQf0ow4l_fmQyAv6q2Gxw0J2I3TmaISsQfwHCpD07FBcp4hLrVrVdRIeRLvhYPcWUaWYn09whhwwpa0s2AJeKEKplbJuJRX322kyfzFsiAAcECWQEc0fz9gNw9aEaWhuUKevS_NpKx7rLZjkFzAYLQKQDme2mbm7OkC8"

// ECDSA Public Keys
const ec256_pub_key = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi6Jhqhr28Lzd2ouX/pFLAV3gXCQ9
uq6nyHps7WrRsA7gcpjVT9H2mybHFsTm6nt4mhEeTTiYNeu86gNdT0LnkA==
-----END PUBLIC KEY-----`
const ec384_pub_key = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEyM9sE/BBKqJsjqz7uoYZEfP9D62PNB0k
4YB53Txb5ryOr1KOrF0ujyRFz6forthkkmEJC95vpZHQToX3fn2Ez0s2VSrOV7pS
900NKIazIqV+IBucdMFTKMvgh5MQDAbo
-----END PUBLIC KEY-----`
const ec521_pub_key = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB/ooeXAbotIupXGPH3MR8/tHB8fCT
6hIO4VmndSUG7sfyeD7CAusyZrscx5a9VdO4vnZyxmT8VW42LLSy9ydAR1IBPrqR
iCD5lC7gvz/9MQR4gkNlz7qyXNtDjLdUqbIOtUaRQLNmXea2UBH644v03siONBR+
su9oz4mHH2NSHLwmlS4=
-----END PUBLIC KEY-----`

// Signatures created with ECDSA Keys. Signatures created with ecdsa.Sign method from crypto/ecdsa package.
const ec256_sig = "MEQCIF3vDDK3-lYuBJLS5YePGYZ1Fih9a1MHkBISa9Yg-32rAiBzNkzKswSiNUHXoTPxBj8XYNrQBZC-jfD2dq-2Ke_zDg"
const ec384_sig = "MGUCMFMH3lMmZrM4qPIegBZxb64fBkfS4jCeZ5XCVw0BYqC27PdTjoTyLaLlBWJvLpS6hAIxAJWsDJLdrhNyVhp9zMLHtFB4J_Q_QrZNh2tflxtVNFwWU3_JDKBr4g7vQFNIfQ880A"
const ec521_sig = "MIGIAkIAofN81k5oSaXMYtoClAYQyVNv2aN1jJtCoIJKeQ0x4bGZAZdpGX8TMdUbiOjfjOedkOE55i94qb4UXzyuvGT0OegCQgC6-8kEXa72KL9upGhzQRzoZOku0EsbyOkwQOHDtj-HZxUG-lGsBhQsc2ABqXoiK07ZmdvMd_t358oVKl_isjEx5w"

const bad_key = "malformed key"

func TestVerifyDetached(t *testing.T) {

	tcs := []struct {
		name          string
		signature     []byte
		pubkey        []byte
		signingAlg    SignatureAlgorithm
		plaintext     []byte
		expectedError bool
	}{
		{
			name:          "good RsaSignPkcs12048Sha256 signature",
			signature:     []byte(rsa2048_256_sig),
			pubkey:        []byte(rsa_2048_pub_key),
			signingAlg:    RsaSignPkcs12048Sha256,
			plaintext:     []byte(good_plaintext),
			expectedError: false,
		},
		{
			name:          "good RsaSignPkcs14096Sha512 signature",
			signature:     []byte(rsa4096_512_sig),
			pubkey:        []byte(rsa_4096_pub_key),
			signingAlg:    RsaSignPkcs14096Sha512,
			plaintext:     []byte(good_plaintext),
			expectedError: false,
		},
		{
			name:          "good RsaPss4096Sha512 signature",
			signature:     []byte(rsa4096_512_pss_sig),
			pubkey:        []byte(rsa_4096_pub_key),
			signingAlg:    RsaPss4096Sha512,
			plaintext:     []byte(good_plaintext),
			expectedError: false,
		},
		{
			name:          "good RsaPss2048Sha256 signature",
			signature:     []byte(rsa2048_256_pss_sig),
			pubkey:        []byte(rsa_2048_pub_key),
			signingAlg:    RsaPss2048Sha256,
			plaintext:     []byte(good_plaintext),
			expectedError: false,
		},
		{
			name:          "good EcdsaP256Sha256 signature",
			signature:     []byte(ec256_sig),
			pubkey:        []byte(ec256_pub_key),
			signingAlg:    EcdsaP256Sha256,
			plaintext:     []byte(good_plaintext),
			expectedError: false,
		},
		{
			name:          "good EcdsaP384Sha384 signature",
			signature:     []byte(ec384_sig),
			pubkey:        []byte(ec384_pub_key),
			signingAlg:    EcdsaP384Sha384,
			plaintext:     []byte(good_plaintext),
			expectedError: false,
		},
		{
			name:          "good EcdsaP521Sha512 signature",
			signature:     []byte(ec521_sig),
			pubkey:        []byte(ec521_pub_key),
			signingAlg:    EcdsaP521Sha512,
			plaintext:     []byte(good_plaintext),
			expectedError: false,
		},
		{
			name:          "bad pub key",
			signature:     []byte(rsa2048_256_sig),
			pubkey:        []byte(bad_key),
			signingAlg:    RsaSignPkcs12048Sha256,
			plaintext:     []byte(good_plaintext),
			expectedError: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			decoded_sig, decodeErr := base64.RawURLEncoding.DecodeString(string(tc.signature))
			if decodeErr != nil {
				t.Errorf("error base64 decoding signature: %e", decodeErr)
			}
			err := verifyDetached(decoded_sig, tc.pubkey, tc.signingAlg, tc.plaintext)
			if tc.expectedError {
				if err == nil {
					t.Errorf("Passed when failure expected")
				}
			} else {
				if err != nil {
					t.Errorf("Undexpected error: %e", err)
				}
			}
		})
	}
}
