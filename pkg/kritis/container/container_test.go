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
package container

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
)

var (
	goodImage = "gcr.io/kritis-project/kritis-server@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8"
)

func Test_ContainerSigCreation(t *testing.T) {
	var tests = []struct {
		name         string
		imageName    string
		imageDigest  string
		concatString string
		shouldErr    bool
	}{
		{
			name:         "GoodImage",
			imageName:    "gcr.io/kritis-project/kritis-server",
			imageDigest:  "sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8",
			concatString: "@",
			shouldErr:    false,
		},
		{
			name:         "BadImage",
			imageName:    "gcr.io/kritis-project/kritis-server",
			imageDigest:  "tag",
			concatString: ":",
			shouldErr:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := strings.Join([]string{test.imageName, test.imageDigest}, test.concatString)
			actual, err := NewAtomicContainerSig(image, nil)
			expected := AtomicContainerSig{
				Critical: &Critical{
					Identity: &Identity{
						DockerRef: test.imageName,
					},
					Image: &Image{
						DockerDigest: test.imageDigest,
					},
					Type: "atomic container signature",
				},
			}
			testutil.CheckError(t, test.shouldErr, err)
			if !test.shouldErr && !reflect.DeepEqual(actual.Critical, expected.Critical) {
				t.Errorf("\nExpected\n%+v\nActual\n%+v", expected.Critical, actual.Critical)
			}
		})
	}
}

func TestCreateAttestationSignature(t *testing.T) {
	container, err := NewAtomicContainerSig(goodImage, map[string]string{})
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	secret := testutil.CreateSecret(t, "test")
	tests := []struct {
		name          string
		signingSecret *secrets.PGPSigningSecret
		shouldErr     bool
	}{
		{
			name:          "Good secret",
			shouldErr:     false,
			signingSecret: secret,
		},
		{
			name:          "bad secret",
			shouldErr:     false,
			signingSecret: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := container.CreateAttestationSignature(secret)
			testutil.CheckError(t, test.shouldErr, err)
		})
	}
}

func TestValidateAttestationSignature(t *testing.T) {
	secret := testutil.CreateSecret(t, "test")
	container, err := NewAtomicContainerSig(goodImage, map[string]string{})
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	inputSig, err := container.CreateAttestationSignature(secret)
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}

	tests := []struct {
		name      string
		shouldErr bool
		publickey string
	}{
		{
			name:      "verify using same public key",
			shouldErr: false,
			publickey: secret.PublicKey,
		},
		{
			name:      "verify using another public key",
			shouldErr: true,
			publickey: testutil.PublicTestKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verificationErr := container.VerifyAttestationSignature(test.publickey, inputSig)
			testutil.CheckError(t, test.shouldErr, verificationErr)
		})
	}
}

func TestGPGArmorSignVerifyIntegration(t *testing.T) {
	goodImage = "gcr.io/pso-sec-train-default/mynginx@sha256:958123f8ad595b4ec16757566c1f83aa5e64fe02625e4a7f8cc61254abac28d5"
	container, err := NewAtomicContainerSig(goodImage, map[string]string{})
	fmt.Println(container.JSON())
	secret := &secrets.PGPSigningSecret{
		PrivateKey: privateKey,
		PublicKey:  pubKey,
		SecretName: "demo-testing",
	}
	sig, err := container.CreateAttestationSignature(secret)
	fmt.Println(sig)

	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	if err := container.VerifyAttestationSignature(pubKey, sig); err != nil {
		t.Fatalf("unexpected error %s", err)
	}
}

// Base64 encoded signarute.
// Created using gpg --armor --sign -u test@kritis.org <atomic_host_json_representation.txt> | base64
var expectedSig = "LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tCgpvd0did012TXdNVzRyanR6aW1DeTZHTEcwd2Uwa3hpaWszMU9WaXNsRjJXV1pDWW41aWhaVlN0bHBxVG1sV1NXClZJTFlLZm5KMmFsRnVrV3BhYWxGcVhuSnFVcFdTdW5KUlhxWitmclpJQjNGdWdWRitWbXB5U1V3Ym5GcVVWbHEKa1ZLdGpsSm1ibUo2S3BJUnVZbDVtV21weFNXNktabnBRQXBvVUhGR29wR3BtVldTY1pweGFuSnlXb3FSZWJLbApoWm1Kc2FGUllwcXh1YVdaZ1psNXFubEtrcEdGZ1lGNW9xR3BtVm1xWWFxQmlWR3lxWVdaVVdwcWluRmFtbUdTClViSUZ5TEtTeWdLUTB4Skw4bk16a3hXUzgvTktFalB6VW9zVWlqUFQ4eEpMU290U2xXcHJPeG1Qc0RBd2NqSG8KaVNteVhHcGUrdlhyMXplcjVuMXNQUW9MRGxZbVVGQUl5SlFBWGVjQThZNWVmbEU2QXhlbkFFekppK2ZjL3dNeQpDOFVQOFM5WnZzQjVXdmczNVNYNlMrWFNXdlAxanEvYUovek9Za2VkaHVHUm9BdWVwL25rY3Zaa0JQWHN0RlppCmMzcnNwZDl3NktDN2tHOXY3NTc0WSsxWHN2bVAvTGtjWFNYOXNxRnc3ZG5mRXlkVSt5NHhmdi9sUzkycFMzOFcKdjJPNmZWQTEzWFhCNnFlZE1YS3JGMmpvdXUrZWwzMm5ZTEhsdS9BS3FmUyt2d2NtQ1BleHJqK1JkM1A5Vm9HNApLY21yVkp1ZWxpek9uelhWYVpXT1VzQnBqdVJYejN4Vys0bE5YckZ0WWNTVGpoVlI4cE1NNDNXRStlZVUzWCtYCjZSRzR1ZTNNZlptYmxpZmJUM1JYaUY2YyttSnk1Zy96TkFrZHRoMGZRb0k5RnBWL3NWazgvVVRHQmVZSmYrMlkKSTdOa3BwMzRPdW5CaXFpM2RYYWR5NXdNMWVyYWx1ZThPY0ZhVmhJUlZMS3QyS3B2YzJIRys1MC9lVk5aQ2dKZQo3VkxvVzVZcG0vMVg3ZTZKTUNPRFZRL1dxTXlJWWxsbTV6L3pZNmlVWDVVVzc2eWdxdGRUNWxuZGJCS3QzQ041Cm4ySGRoTjJucXo0K3VoRzdVbStWVkdUMXlRS3puOHV1K0hCZnZhdDNMVkh2MDlFVFF1MUMxNXFtWnZheXVWMWkKMWxMeE9jVDBiLzNYTjIyZjdrNFg4MWI3cmdZQQo9ZU9GVwotLS0tLUVORCBQR1AgTUVTU0FHRS0tLS0tCg=="
var privateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQOYBFuQP8IBCAC8YGxLmNjQr3zS1bUxXmYhSiG27BXasTtTdv1L7e9qgyPfXTbl
bDtmRvZHVAWC62LaESBGpXhiNDAOBxqhKTL4fuY4iI0iARnSR9ut1rezVtqVcSNp
A02n+S2LO3i+aA01H1iCPKPvYaznhdFUDnqsNGoW0Lx/cO95foSSZhAQdZqXjkgy
7EIsXclrGpHOLPpAow8eNen671z/0Aa/JOqyKTuML5lxtSk1hZPXdFDo7ICMKpiY
hwQgFSsmMgVPSuS0Q8l54m4IS3JWkw4t2la37kmufZrWQTTqVdWJKNUFrKhzJI0Z
kZJ9iK9bfd3pqTpVty0vNG5S3R9lYhoJ4Uw3ABEBAAEAB/wKzaLYUQs6KJ5Jfx0V
mDrWNOirE24LbTegSUYsiRg+bQftIuznimX7rx0nqQ9p2zL/m5TUyF+XjjOlUk36
KSE1tB1i553kcdi3wQw9s380h0og4OytdJWLCRTOE9qQXOpI/iO20GB8dYcTfg6r
ueraHmVpKo5s5p6tQo660KSiNOs40eeRLRPvuj3LuM1e4CMwAJIzH0hrgR83y+G+
GzznJ3uj6TPSDyQcaD7JladrpCdgp1CZejuADkZaaC6Qio/xcefbFjlnf3aFa/Mz
ePBXEQgDB0n/Jby7F99ojWkavkGvONB/epW8Yg5b1itb+n1yaGxWYRJCqOhhwrf1
S3LpBADZv2pUKXZDijkEvGHJHaldBfmWKIYsml6rK2jSI/i2FmffJXZXh+a8P+wD
9ji+5fDY0xVkzg52qKWOI2dPBLX6GvGrAFh8LbWpJpmvriMmvsR1jcYb5U39JnYu
UK2S10W/wzLfxyXptcGlkToq2ZnkcZH/95NVa/SqxulAbNruOQQA3XggqFMdTggP
wQp/Fie1xkqVKUoLczepMy4zz+cnO5AvGpP1/3OzyDn+jy0dH7L655djYMJXysgy
y5Zazje0udR8kQpFoPSUN89Bsi4bh5C40zRHUC+70RjwVzGdTdFndXFZVDYLz4nX
8prsrDUW1Tvqr37Yzbluf2dCniaEDe8EALsOXPlpob3myW6v7F6eisVWVELObrds
AV1jiEnw3kij40xBAPQRiqO2Xcv57wzYdVZFHUant9Tx363cHpNI5HZg5/iGDY91
1fh+pyp/IN5bg7jicaiqfSrZhGVF1T2gVrMGOdiDTBqy/GCZGd6urNydVTcWmc4U
1ELtVNegsqd8QSO0LSJEZW1vIEF0dGVzdG9yIiA8ImJyYWRnZWVzYW1hbkBsb25p
bWJ1cy5jb20iPokBTgQTAQgAOBYhBISe2sQ9HxgEdsaG2pfIcvTkSQo2BQJbkD/C
AhsvBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEJfIcvTkSQo2qFQH/ibRySV7
uMZyM6VRbhiwl5ziwkbVhhh2RpAelNez0WSw/c6oU+M6MNxU8O/VEEfq6jnc1iFN
zP4PEXjjyENrRCILdEN+hzBRx5KD7GqcjwnnX5JtJT9m5ROA3+j7cAA0cN2kgYGl
TyS+1ePeyvq0j6okTLCIb9hUXdg/nnZsR/a1LiglS/wDbIEfhMqIM46J2xrtonos
Zg5vvLzJYf44EF7LZ7uC5pwspOznrq+3Dq9CmC4wO5LtnlKmMZikoS0H4XFVbvc1
mT21Lmtxhep86qZBvhnHNf5+FMXp/t1IXRErItno0EbJ3a9seaFep2Hk9FfpksKe
8U/4OT7eaOlZvyU=
=sJcY
-----END PGP PRIVATE KEY BLOCK-----`
var pubKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFuQP8IBCAC8YGxLmNjQr3zS1bUxXmYhSiG27BXasTtTdv1L7e9qgyPfXTbl
bDtmRvZHVAWC62LaESBGpXhiNDAOBxqhKTL4fuY4iI0iARnSR9ut1rezVtqVcSNp
A02n+S2LO3i+aA01H1iCPKPvYaznhdFUDnqsNGoW0Lx/cO95foSSZhAQdZqXjkgy
7EIsXclrGpHOLPpAow8eNen671z/0Aa/JOqyKTuML5lxtSk1hZPXdFDo7ICMKpiY
hwQgFSsmMgVPSuS0Q8l54m4IS3JWkw4t2la37kmufZrWQTTqVdWJKNUFrKhzJI0Z
kZJ9iK9bfd3pqTpVty0vNG5S3R9lYhoJ4Uw3ABEBAAG0LSJEZW1vIEF0dGVzdG9y
IiA8ImJyYWRnZWVzYW1hbkBsb25pbWJ1cy5jb20iPokBTgQTAQgAOBYhBISe2sQ9
HxgEdsaG2pfIcvTkSQo2BQJbkD/CAhsvBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheA
AAoJEJfIcvTkSQo2qFQH/ibRySV7uMZyM6VRbhiwl5ziwkbVhhh2RpAelNez0WSw
/c6oU+M6MNxU8O/VEEfq6jnc1iFNzP4PEXjjyENrRCILdEN+hzBRx5KD7Gqcjwnn
X5JtJT9m5ROA3+j7cAA0cN2kgYGlTyS+1ePeyvq0j6okTLCIb9hUXdg/nnZsR/a1
LiglS/wDbIEfhMqIM46J2xrtonosZg5vvLzJYf44EF7LZ7uC5pwspOznrq+3Dq9C
mC4wO5LtnlKmMZikoS0H4XFVbvc1mT21Lmtxhep86qZBvhnHNf5+FMXp/t1IXREr
Itno0EbJ3a9seaFep2Hk9FfpksKe8U/4OT7eaOlZvyU=
=r759
-----END PGP PUBLIC KEY BLOCK-----`
