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
package util

import (
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
)

func TestCreateAttestationSignature(t *testing.T) {
	var tests = []struct {
		name      string
		image     string
		shouldErr bool
	}{
		{
			name:      "GoodImage",
			image:     "gcr.io/kritis-project/kritis-server@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8",
			shouldErr: false,
		},
		{
			name:      "BadImage",
			image:     "gcr.io/kritis-project/kritis-server:tag",
			shouldErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pub, priv := testutil.CreateBase64KeyPair(t)
			secret := secrets.PgpSigningSecret{
				PrivateKey: priv,
				PublicKey:  pub,
				SecretName: "test",
			}
			_, err := CreateAttestationSignature(test.image, &secret)
			testutil.CheckError(t, test.shouldErr, err)
		})
	}
}
