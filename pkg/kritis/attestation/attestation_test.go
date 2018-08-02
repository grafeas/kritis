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
		publicKey, privateKey := testutil.CreateBase64KeyPair(t, "test")
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
	testMessage := "test"
	actualSig, err := CreateMessageAttestation(testutil.PublicTestKey, testutil.PrivateTestKey, testMessage)
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}
	if actualSig != expectedSig {
		//t.Fatalf("Signature created using gpg --armor --sign do not match.\nExpected %s \nGot %s", expectedSig, actualSig)
	}
	if err := VerifyMessageAttestation(testutil.PublicTestKey, actualSig, testMessage); err != nil {
		t.Fatalf("unexpected error %s", err)
	}
}

// Base64 encoded signarute.
// Created using gpg --armor --sign -u test@kritis.org < test | base64
var expectedSig = "LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tCgpvd0did012TXdNVzRyanR6aW1DeTZHTEdOZCtUdUpOS2l5dVQ4aXYwaWpQVG81TTA5MVFySlJkbGxtUW1KK1lvCldWVXJaYWFrNXBWa2xsU0MyQ241eWRtcFJicEZxV21wUmFsNXlhbEtWa3JweVVWNm1mbjYyU0FkeGJvRlJmbFoKcWNrbE1HNXhhbEZaYXBGU3JZNVNabTVpZWlxU0VibUplWmxwcWNVbHVpbVo2VUFLYUZCeFJxS1JxWmxWa25HYQpjV3B5Y2xxS2tYbXlwWVdaaWJHaFVXS2FzYm1sbVlHWmVhcDVTcEtSaFlHQmVhS2hxWmxacW1HcWdZbFJzcW1GCm1WRnFhb3B4V3BwaGtsR3lCY2l5a3NvQ2tOTVNTL0p6TTVNVmt2UHpTaEl6ODFLTEZJRCt5MHNzS1MxS1ZhcXQKNWVwa1BNTEN3TWpGb0NlbXlIS3BlZW5YcjEvZnJKcjNzZlVvTEdSWW1VQmhJU0JUQW5TZUE4US9ldmxGNlF4YwpuQUl3SlJmdWMvOFZxOWUzMmRYUHNmZjNqRVc1dDJLYjdBcmtPSFVuSldTdG5QZzAraXpQOWZtYlZuU1g4blM5Cm1YQTM1SVpSZzhLeUtSZVZWWS9mUFdIL1lzL1NNTlk5RDF2TThqWUVoTmJlbEF4N2FXR3k0SER3MHJ0ZW5xeUMKaG05c29uc01yT2YwM3Z0bGtOZXdSWFBIM0EwZnI1NmVzQzNZdVlGeitZYnNLYjg2N3o1UUQxWHo5LzUyNFpOKwo2dVBqQzFuV0hud1F4QlFXbVBoMWUrdGF0MjcrdmJOZnQ1eWQ3Rmk5N2NEakh1YzlISXNlUGVsYnRtaUc4Wk5OCmRYdWw5UmFhRkQ2ck81WEMzOGJyZTNTTlMwN09rVmpabnhjYS84NE1Menc3MVdIdFJ1K3ZwcDI1RzliLzRIUTQKeVBaZFMxRWtSbVdlNXZYSm4zNVZab3V2anJuRXdWSmQwQ1h3MmEvcXlmeTlzN2VJRmdwVVRVNHlyalg1djNIMwpzZktHSzc0Yy9kK0x1bFFqMy95N2V5U1AvWXVRcUxpTThqR1c1enQyZGUrWmZkdXRPTVAwK1dYTGlhZVgzazkxCjJHclpkVEl5cmtzd3grTmRXV1hETnpIM1MweTdYM0ltU1U0cW1SVmVvK2Q4ZFoydFVXdjhEdmZuaXlWTGxlNnYKT3l4VG1yYy9WdlpkaGswQVF5Mno2VDZtcGpVRlh6LzFtNnpudjk0TkFBPT0KPXRCeDMKLS0tLS1FTkQgUEdQIE1FU1NBR0UtLS0tLQo="

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
