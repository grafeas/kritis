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

package signer

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/grafeas/kritis/pkg/attestlib"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type DigestAlgorithm string

const (
	SHA256 DigestAlgorithm = "SHA256"
	SHA384 DigestAlgorithm = "SHA384"
	SHA512 DigestAlgorithm = "SHA512"
)

type kmsSigner struct {
	keyName   string
	digestAlg DigestAlgorithm
	client    *kms.KeyManagementClient
}

func NewCloudKmsSigner(keyName string, digestAlg DigestAlgorithm) (attestlib.Signer, error) {
	// Create the client.
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	out := kmsSigner{
		keyName:   keyName,
		digestAlg: digestAlg,
		client:    client,
	}
	return out, nil
}

func (s kmsSigner) CreateAttestation(payload []byte) (*attestlib.Attestation, error) {
	var digest hash.Hash
	switch s.digestAlg {
	case SHA256:
		digest = sha256.New()
	case SHA384:
		digest = sha512.New384()
	case SHA512:
		digest = sha512.New()
	default:
		return nil, fmt.Errorf("Unsupported digest algorithm %v", s.digestAlg)
	}
	if _, err := digest.Write(payload); err != nil {
		return nil, err
	}
	var d kmspb.Digest
	switch s.digestAlg {
	case SHA256:
		d.Digest = &kmspb.Digest_Sha256{
			Sha256: digest.Sum(nil),
		}
	case SHA384:
		d.Digest = &kmspb.Digest_Sha384{
			Sha384: digest.Sum(nil),
		}
	case SHA512:
		d.Digest = &kmspb.Digest_Sha512{
			Sha512: digest.Sum(nil),
		}
	default:
		return nil, fmt.Errorf("Unsupported digest algorithm %v", s.digestAlg)
	}
	req := &kmspb.AsymmetricSignRequest{
		Name:   s.keyName,
		Digest: &d,
	}

	// Call the API.
	ctx := context.Background()
	result, err := s.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, err
	}
	att := attestlib.Attestation{
		PublicKeyID:       fmt.Sprintf("//cloudkms.googleapis.com/v1/%s", s.keyName),
		Signature:         result.Signature,
		SerializedPayload: payload,
	}
	return &att, nil
}
