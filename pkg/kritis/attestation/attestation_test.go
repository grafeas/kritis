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
	_ "golang.org/x/crypto/ripemd160"
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

// // The PGP signature for using keys and command
// //
// var realSig = `-----BEGIN PGP MESSAGE-----

// owGbwMvMwMU466P5nCK9E9yMa+SSuHNTi4sT01P1SipKon2ZrpekFpfoQsW4OhlP
// sDAwcjEYiSmy6B7etKVkxzeDJU8deGEGsDKBtIjIgDWlF6Q7ZBdllmQW6yXn5zJw
// cQrAlH224mGYplYTt/TV3TUmvGwqV++Y930OmaO1y+H2ohpro+aXicdfivWfzLZy
// ZtnCJ31Voe7WPwvTtdwd+qEreZaxie3euZ41Inbx0cf/hU+aPVh6LJHhhqphLWec
// jWB77KXaM5+Z8ic2TnXQiC1+zVTy4XTi8VUxqh7pee1LNlyyW3G/UuCcxcyHO7bN
// WrAn5Z50oUj5Ri+Zj28kW9Nj5plpTv8rr2PTyugeWf5J/N3da1UKPLOvH5s7bwH3
// cq93MpU2rIu2vWDtYra5t2DNCdGIf7p2rBtVV3q671VddWeN8LuWs2GHk2LvKbv4
// f5hw4GVBTkxlXMHlxpPrT1QtDvNZsmfLLR0Oicpej4Zd944b72iOW+7te+OsoMiN
// H/c7RbPncuiJrCrl7rloXVldduy9WPnWJT86mVhbltowaZz1nF+xas0FE+nvIu7e
// Jm8+XV9qxmnTyJdad/ne/0CNWPl1uae1UpZX6uxK5tbv9WFnfuwUIhzlMesHT1vV
// eU6lrqt1kWYW6yZsX3Lg0VnJz7u4vebW/110uwIA
// =Bk7p
// -----END PGP MESSAGE-----`

// // Create from gpg --armor --export-secret-key <keyID> | base64
// var realPrivateKey = `LS0tLS1CRUdJTiBQR1AgUFJJVkFURSBLRVkgQkxPQ0stLS0tLQoKbFFHVkJGdE5BZE1CREFEQ0Ux
// YW1CY1V0Vk52VkdzdTdvcFBONUlMVmxSbXcwcmNGQ1hvekZibVJXTDgyNVFOdAplb01jTlhESVcw
// Nkl4UXYxbWxEajh3bkY2QlBFVmYvbGF4ei9EZVlXQW9GT0RBVmtyUE5kSEZVZkxpaStvQ3lGCkJZ
// VW5BSVIzTG5Ca3E3UnRCbkJOUEo3anZyTi9qN0xxaGJVVWplNEJSZGRTWHVtdm82ZXRjQnFrbGRH
// WTVBRzEKaXZWSkh0NlN6WnhQaW52ekJoMzJOYUxaUmZwWC8rTXBMdEFxR3IxajhMcy9rNGZVYkdH
// SGhNbFU5SzdKLzM1SwpYc1NKT0VsNjJJNWs3QXdlTHo0OFR5Q3RsaWJLMmNXbHluOU05N3FGcXNj
// dWFObkYrTVRrbFJCN1lBaWc0REF6Ck5uc0ZKODExaHFqd2dENDMwRGtDWkVZRGlwWHRUUmZhOHlY
// QlU0WWN6VW90RXI3RDNpREZraWk2bERkRmNkSXMKRWZtQjIvUUVpaXBBVURDOURWM0FyNTVtOHpO
// UVpxZ2UzY29hY2pKeDZmVHFXUVcwNXJqQ0dFZzNaenNwQlQrNwp0Zll1WjJMZFNzbmhXYmNJTjl0
// Sm8vMHovOFlXMWNReFU4Rms5cStsRUp2eUYwcGZvWTgwNTcwLzIvWEpIdGJFCjFhMkxObXZtYVVy
// MUxHOEFFUUVBQWY4QVpRQkhUbFVCdEJOMFpYTjBMV2R3WjBCcmNtbDBhWE11WTI5dGlRSFUKQkJN
// QkNnQStGaUVFTGNPeXRIUzQ5akNrNVVBTm12RTNuSEl1eUFzRkFsdE5BZE1DR3dNRkNRUENad0FG
// Q3drSQpCd0lHRlFvSkNBc0NCQllDQXdFQ0hnRUNGNEFBQ2drUW12RTNuSEl1eUF1ZGVBdi9WbmpC
// dGNVVTVPNGJtTEZzCnN4bGUzZkU5UlVmb01MbklCUTIvRDhrYk94WGhRbmV4azFsWVdkTU5PZUhr
// WkJ4TkJINzlva2x6ejF6Qkw2MVEKZmRzdnJHRnFrRzlOQnZtdS9RZEdTL3ArZXdBcWpxK0R5dlhX
// UzBWWDZRVVJyeTFKaDE5a2dhV1BncDFuRjNhdwppZTJ0QVc5NlZJcW11d1lETFUzVnlOM0QwQVBZ
// TW96UXcwaG1JaXpXQjZTaElHNnpvVjRKcE5YbUE1Q3JlT1c5CnpsOXJMK2VuZFdmQVc5NStBaFRP
// QUJ4VVFmYzFCOHhzOTJYVXZxTU1RaUN3QnFHSFF3dHh5bWoyV000bkh5QlYKZGRGYkYrQnJ3SlVn
// eWYveU9tMkhNVE1DYXJPNGZBRzArSm1QbHBzemxoWHJYVDVBdmpDbVhCeDR6NkUzYTVwVgoyOTFt
// bGptQjdhbkpwQ0ZGTXFUVWE1c2Q2N1hyd0t2dXlrbXFGbFVCbGtlUTZ5MVF1QWdEdkZ6U0cyMG9y
// MFJECjQ2R3RBMFNpVnZQeVplYWY5L3hlaTk3dkFQNWRBTGdCY0JpOGJycWEySkE5c1gvandRaUhr
// eVRBTlhRMGdvenkKbGFyNFpFTFhBUG12bVRiRng2NzJFb042bGx2RG1SS25NaGRWZkY0d3doZU92
// dTFvblFXR0JGdE5BZE1CREFETgpSejREVW03VVNpZjQxTmU0L0ZkSTdkUFNHbmU1ZHBBb0lKb0Fw
// Mjd3RUp1eFpYV1lMTWlZNkpLb2s1M0xRLzdECmlCMmtZTkM3NHZoOU9yWHFWbVZPTXBKT3VHVWVa
// V1IrZS91b2lta0F4NWVMZTV2d3lJUU05VFExRm5WeS9YeTcKK3lvbVN4TkRTZkt6YStMczFPVHJn
// d0llTVZqc1o3Z3NTQm9jUUVPS3c0bzQ2SFY5dnpRdUtBRVpJaE0vWW0vNwpTeDUzZW1YWkpDaUNQ
// L0dyZDQ5V1lxZy9VQ252RzMvZUlYeFRxTVRJdGwzYTdpdk5QakxZeTJmajVubTBTM2FHCjJzdHZE
// Yy80cW9EZ2lYVUV4Znp0T2YyZ2RyVXczbmU2cjlnVXYzVmFOQlAwOFFhMVVHK2krVmlqUmUySkVT
// T0QKMmYzMm5vQzE5SGc0TVpkcTUxODhTYTBTTGw0WFc5cGovbGRqcnVrZjhDcmJpZTR4OHYxL2NI
// bXlnTUF5OG85KwpxVzB6RjVNaEZaSHRxUjQ5NHNtSTJWOXRQdnBmcm1GaUhIeDNDQ0lQS1c4SXZ2
// NUdWTWRaSnBuMy83eVV2Y3p3CkdkSmphVVp6S1RRWUc5RjlXTi8xTm1lYWY0cWpGYXFKanNqWlVG
// RUx6RTVCb3lpL01PS3VqMDAzKysxQUNZMEEKRVFFQUFmNEhBd0lqQURkZ01UKzAyZjhJSDgrbGE3
// K25LbkVOZUd4ZFFhTGg3S3NwMWZaNjJmTFdIZStKUHY4aAptNGpUWGRHNzZ0YktlclZ5eWxlam53
// TFNIL1YyNm9xclZHWTFWejZQMis0SWZqcGRZOUJLNDROWHk0dlhuaDNrCjBRM3VTWVV4QkxLWDEz
// cE5zaWJGNTIrREcwSVBHcTA1SnlaU0VUSVlaNVNYSlNYMmJENHEwdjR2d3VxcjZBT3kKemxXajZ2
// Y1M3NERFRENvZTljZTlGdDdXUytRZ0pzd3dhSENrMnFrOW9wZ2xIcFBXY3dSdkN5RmVqYWdtTTd1
// bgpOeWtpVko5VGp2RTJqWjNHYlAzZ255TjFhREREbURvRi9CSlUvNmI5QndxQXBYajNRL1RjWUY5
// TkV3RWJ2THB6ClBPWmNWNmwvYmloRTVmc3pOczRqdVNKU2Z1eEhtRVc2Y3o0UW9pU0NRNmYrR055
// MXpTRFVvTkFBYkZaN2oycngKUjZnMzBQdFFaMGx1NGRlSzVxODJ2dmw3M2hSdTRTTlFCR2FYYjY3
// bXNRSkdXVEU5OGlIY0RrU09GWS9vTlNmawo5dDRGZlpxVGZxUEo5bEZJclVXM1oydXVnZzhmb2Zq
// VGljZnZLM3M0N1FGYThtSHdxZnNrbFBRMlhzUHRjUUpnCkNRSGIrNk41V0ljdWp1cUkxSi9pL2RQ
// YjJDNlhwSzFOOXBzQUFKd3IyOTNuSVk0T1laVmFyZE04Q1J2aFJhM2kKWVF0K0FLYldNam5nQTJt
// WFRRZG92d1M1NGJnS2c1YWZqUHZxUnBseDl4ZGNPTWJPV3pFRlRXcXhVUXVRYWtzcAprT1pQcWlO
// UkEzVHl0L05NdWFWVXJWWDVvazlQYW5rWkFTbHB4b29acERLZXcwMi9PK0RqcnIzaXViTzl1aDNy
// CkkraUxHekxKeVVXN0k4d2pJbnlmdzUxNWJXbHVaSEVMalJyL1g3SVhuWEtzZzNiVVN0L2dZdDI5
// ZUhmcmM1VHQKekVWNDFzNCtkZjdScDlRbXNQS3R6Y2NoOVJLWEF3Mk11RG9OMHFHdnB5WVArTStq
// bHdHdjNUbFZKZS9sRm9ycgpPTjhOUElzeDh4S2NKZFZBMHg3WHQ5bVYvM0FiRElBVWFZWmhRNXEx
// OFlNYTI1SmtJWWtyck9aMHBYNjlqRktLClBuQ2V3dzlOcE9iMzFIbDB2MXFqUEVkemNMSExLcW41
// cFdGWTlGL1AwS3VKMXNRamU4cnZmYkYyUTFBVjJ6TFoKMXJHM09QZk1yU2hrY3cwRnNYT2hOMkE1
// V3hKNmpkcnV2OFlvYnl6VjBPNDViSWROeDRURWJIVUVGUU5nOGZOYQpHNlZSYlBQdkh2cXhFalhy
// MlY2VjBWNi9OaEsvK3pmYnlpTjJnOVZXYkJIWDhSUnhrc2owR0ZvQmV1ekt3YUhQCitJeXlGbXd1
// aU5zZTdzTHhGbVdya2xCUlBFV2ttS0lhdkZSRjRiYkRvOHA5Tis5bzNubkhnd1hYZytYaWprdW8K
// TXpsVXRITUdLeW52LzVreUhzN3hUYmhzOUV4K21TYkZSelNEL1FDZ0VXTHJ2K3JubXBBOGMwcC92
// cWVtaWtFZwpnRlgrV1EyY1hiMHZXcnhWaWppL1JZdmJjcHFFQ1BnZmtnM1U3S2hhcU5UWkpSajA0
// RjIxbFdnS0hjazF3NDlRCmtrcEZTbkhsTUFIaWt2a3FjNDd3azNvekppUndWSGRFLzhSeDVNcWRa
// cHVjbmwwUTJxeTdlSUNrVkEvNiswc04KUjRsYnB0NDdNWVY5bGRSSHFva0J0Z1FZQVFvQUlCWWhC
// QzNEc3JSMHVQWXdwT1ZBRFpyeE41eHlMc2dMQlFKYgpUUUhUQWhzTUFBb0pFSnJ4TjV4eUxzZ0xH
// WWdML2lVSUtIV1g5ZEFYYzdNNDZoUk92dVJCSjAvRk0rQ1QxZVZOCm5CNmdCS1NpSkxFeHNocEJ0
// NW9iaUhQakhEU3M3ZnlzdnZOL21PTnlqN29acXZnaU12aFFrWXo0WEVsR3JlZXYKYkRqMjdQMjEx
// TGpkLzJPQ3NtWUxXYktNSys0RFRIdU03TWhRbXBKS3Z2VWNsUmhwMnd6b3RwTG5jZitZQ0FlaQpN
// Z0NZMXh1NkpLbi9Mb2hDTG5nejdocVIya0JJSHR2eXd2VTk0cys4SjJNSTRsMlJkdVd0clhieWE1
// LzgyRUpmClBvYTBVZjJnbEE2R1BNeUJDaHZmUXM2c0xZam0reHNwUFJPVjNQak54Wm5yTVlwZFVl
// a3pUVFFYYTNxN0twNzgKMHlyd3U3WTFhNUovZGxmWmYyWkJjdGJubkxyeHlSWkNPQVo0K0wwOEs0
// ZGN6ZS81UVZ3TnROQTg1NW01ekFIcwpqVS82VXVSR3YrSlhVZytOWG1hek0vT0RzbTJxbVMrOTZv
// L3lMcVRGYkRTcGhjQi9PSEkyMkNMTU84ZGpyc25YCk5qTGcvMndTWnBDKzBhVjgyUTdBUGtpSENn
// Z1JCYzRCRURJbHVvcXVuWTFkcS9RUGFXOGZiR2NlUHl0WVpBSGwKVDVvT1NRcTk4YzNrYi9rNGpZ
// dm5MVDVGaFlJTnVnPT0KPTVydlEKLS0tLS1FTkQgUEdQIFBSSVZBVEUgS0VZIEJMT0NLLS0tLS0K`

// // Created from gpg --armor --export  <keyID> | base64
// var realPublicKey = `LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCgptUUdOQkZ0TkFkTUJEQURDRTFh
// bUJjVXRWTnZWR3N1N29wUE41SUxWbFJtdzByY0ZDWG96RmJtUldMODI1UU50CmVvTWNOWERJVzA2
// SXhRdjFtbERqOHduRjZCUEVWZi9sYXh6L0RlWVdBb0ZPREFWa3JQTmRIRlVmTGlpK29DeUYKQllV
// bkFJUjNMbkJrcTdSdEJuQk5QSjdqdnJOL2o3THFoYlVVamU0QlJkZFNYdW12bzZldGNCcWtsZEdZ
// NUFHMQppdlZKSHQ2U3paeFBpbnZ6QmgzMk5hTFpSZnBYLytNcEx0QXFHcjFqOExzL2s0ZlViR0dI
// aE1sVTlLN0ovMzVLClhzU0pPRWw2Mkk1azdBd2VMejQ4VHlDdGxpYksyY1dseW45TTk3cUZxc2N1
// YU5uRitNVGtsUkI3WUFpZzREQXoKTm5zRko4MTFocWp3Z0Q0MzBEa0NaRVlEaXBYdFRSZmE4eVhC
// VTRZY3pVb3RFcjdEM2lERmtpaTZsRGRGY2RJcwpFZm1CMi9RRWlpcEFVREM5RFYzQXI1NW04ek5R
// WnFnZTNjb2Fjakp4NmZUcVdRVzA1cmpDR0VnM1p6c3BCVCs3CnRmWXVaMkxkU3NuaFdiY0lOOXRK
// by8wei84WVcxY1F4VThGazlxK2xFSnZ5RjBwZm9ZODA1NzAvMi9YSkh0YkUKMWEyTE5tdm1hVXIx
// TEc4QUVRRUFBYlFUZEdWemRDMW5jR2RBYTNKcGRHbHpMbU52YllrQjFBUVRBUW9BUGhZaApCQzNE
// c3JSMHVQWXdwT1ZBRFpyeE41eHlMc2dMQlFKYlRRSFRBaHNEQlFrRHdtY0FCUXNKQ0FjQ0JoVUtD
// UWdMCkFnUVdBZ01CQWg0QkFoZUFBQW9KRUpyeE41eHlMc2dMblhnTC8xWjR3YlhGRk9UdUc1aXhi
// TE1aWHQzeFBVVkgKNkRDNXlBVU52dy9KR3pzVjRVSjNzWk5aV0ZuVERUbmg1R1FjVFFSKy9hSkpj
// ODljd1MrdFVIM2JMNnhoYXBCdgpUUWI1cnYwSFJrdjZmbnNBS282dmc4cjExa3RGVitrRkVhOHRT
// WWRmWklHbGo0S2RaeGQyc0ludHJRRnZlbFNLCnByc0dBeTFOMWNqZHc5QUQyREtNME1OSVppSXMx
// Z2Vrb1NCdXM2RmVDYVRWNWdPUXEzamx2YzVmYXkvbnAzVm4Kd0Z2ZWZnSVV6Z0FjVkVIM05RZk1i
// UGRsMUw2akRFSWdzQWFoaDBNTGNjcG85bGpPSng4Z1ZYWFJXeGZnYThDVgpJTW4vOGpwdGh6RXpB
// bXF6dUh3QnRQaVpqNWFiTTVZVjYxMCtRTDR3cGx3Y2VNK2hOMnVhVmR2ZFpwWTVnZTJwCnlhUWhS
// VEtrMUd1YkhldTE2OENyN3NwSnFoWlZBWlpIa09zdFVMZ0lBN3hjMGh0dEtLOUVRK09oclFORW9s
// YnoKOG1YbW4vZjhYb3ZlN3dEK1hRQzRBWEFZdkc2Nm10aVFQYkYvNDhFSWg1TWt3RFYwTklLTThw
// V3ErR1JDMXdENQpyNWsyeGNldTloS0RlcFpidzVrU3B6SVhWWHhlTU1JWGpyN3RhTGtCalFSYlRR
// SFRBUXdBelVjK0ExSnUxRW9uCitOVFh1UHhYU08zVDBocDN1WGFRS0NDYUFLZHU4QkNic1dWMW1D
// ekltT2lTcUpPZHkwUCt3NGdkcEdEUXUrTDQKZlRxMTZsWmxUaktTVHJobEhtVmtmbnY3cUlwcEFN
// ZVhpM3ViOE1pRURQVTBOUloxY3YxOHUvc3FKa3NUUTBueQpzMnZpN05UazY0TUNIakZZN0dlNExF
// Z2FIRUJEaXNPS09PaDFmYjgwTGlnQkdTSVRQMkp2KzBzZWQzcGwyU1FvCmdqL3hxM2VQVm1Lb1Ax
// QXA3eHQvM2lGOFU2akV5TFpkMnU0cnpUNHkyTXRuNCtaNXRFdDJodHJMYnczUCtLcUEKNElsMUJN
// WDg3VG45b0hhMU1ONTN1cS9ZRkw5MVdqUVQ5UEVHdFZCdm92bFlvMFh0aVJFamc5bjk5cDZBdGZS
// NApPREdYYXVkZlBFbXRFaTVlRjF2YVkvNVhZNjdwSC9BcTI0bnVNZkw5ZjNCNXNvREFNdktQZnFs
// dE14ZVRJUldSCjdha2VQZUxKaU5sZmJUNzZYNjVoWWh4OGR3Z2lEeWx2Q0w3K1JsVEhXU2FaOS8r
// OGxMM004Qm5TWTJsR2N5azAKR0J2UmZWamY5VFpubW4rS294V3FpWTdJMlZCUkM4eE9RYU1vdnpE
// aXJvOU5OL3Z0UUFtTkFCRUJBQUdKQWJZRQpHQUVLQUNBV0lRUXR3N0swZExqMk1LVGxRQTJhOFRl
// Y2NpN0lDd1VDVzAwQjB3SWJEQUFLQ1JDYThUZWNjaTdJCkN4bUlDLzRsQ0NoMWwvWFFGM096T09v
// VVRyN2tRU2RQeFRQZ2s5WGxUWndlb0FTa29pU3hNYklhUWJlYUc0aHoKNHh3MHJPMzhyTDd6ZjVq
// amNvKzZHYXI0SWpMNFVKR00rRnhKUnEzbnIydzQ5dXo5dGRTNDNmOWpnckptQzFteQpqQ3Z1QTB4
// N2pPeklVSnFTU3I3MUhKVVlhZHNNNkxhUzUzSC9tQWdIb2pJQW1OY2J1aVNwL3k2SVFpNTRNKzRh
// CmtkcEFTQjdiOHNMMVBlTFB2Q2RqQ09KZGtYYmxyYTEyOG11Zi9OaENYejZHdEZIOW9KUU9oanpN
// Z1FvYjMwTE8KckMySTV2c2JLVDBUbGR6NHpjV1o2ekdLWFZIcE0wMDBGMnQ2dXlxZS9OTXE4THUy
// Tld1U2YzWlgyWDltUVhMVwo1NXk2OGNrV1FqZ0dlUGk5UEN1SFhNM3YrVUZjRGJUUVBPZVp1Y3dC
// N0kxUCtsTGtSci9pVjFJUGpWNW1zelB6Cmc3SnRxcGt2dmVxUDhpNmt4V3cwcVlYQWZ6aHlOdGdp
// ekR2SFk2N0oxell5NFA5c0VtYVF2dEdsZk5rT3dENUkKaHdvSUVRWE9BUkF5SmJxS3JwMk5YYXYw
// RDJsdkgyeG5IajhyV0dRQjVVK2FEa2tLdmZITjVHLzVPSTJMNXkwKwpSWVdDRGJvPQo9dHhqeQot
// LS0tLUVORCBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCg==`
