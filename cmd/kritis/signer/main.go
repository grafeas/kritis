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

package main

import (
	"encoding/base64"
	"flag"
	"os"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/vulnzsigningpolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/signer"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	yaml "k8s.io/apimachinery/pkg/util/yaml"
)

type SignerMode string

const (
	CheckAndSign  SignerMode = "check-and-sign"
	CheckOnly     SignerMode = "check-only"
	BypassAndSign SignerMode = "bypass-and-sign"
)

func main() {
	var image, pri_key_path, passphrase, pub_key_path, policy_path, mode string

	flag.StringVar(&mode, "mode", "", "mode of operation, check-and-sign|check-only|bypass-and-sign")
	flag.StringVar(&image, "image", "", "image url, e.g., gcr.io/foo/bar@sha256:abcd")
	flag.StringVar(&pri_key_path, "private_key", "", "signer private key path, e.g., /dev/shm/key.pgp")
	flag.StringVar(&passphrase, "passphrase", "", "passphrase for private key, if any")
	flag.StringVar(&pub_key_path, "public_key", "", "public key path, e.g., /dev/shm/key.pub")
	flag.StringVar(&policy_path, "policy", "", "vulnerability signing policy file path, e.g., /tmp/vulnz_signing_policy.yaml")
	flag.Parse()

	switch SignerMode(mode) {
	case CheckAndSign, BypassAndSign:
		glog.Infof("Signer mode: %s.", mode)
	case CheckOnly:
		glog.Fatalf("Mode %s note supported yet.", mode)
	default:
		glog.Fatalf("Unrecognized mode %s.", mode)
	}

	signerKey, err := ioutil.ReadFile(pri_key_path)
	if err != nil {
		glog.Fatalf("Fail to read signer key: %v", err)
	}

	// Parse the vulnz signing policy
	policy := v1beta1.VulnzSigningPolicy{}
	policyFile, err := os.Open(policy_path)
	if err != nil {
		glog.Fatalf("Fail to load vulnz signing policy: %v", err)
	}
	defer policyFile.Close()
	// err = json.Unmarshal(policyFile, &policy)
	if err := yaml.NewYAMLToJSONDecoder(policyFile).Decode(&policy); err != nil {
		glog.Fatalf("Fail to parse policy file: %v", err)
	} else {
		glog.Infof("Policy noteReference: %v\n", policy.Spec.NoteReference)
		glog.Infof("Policy req: %v\n", policy.Spec.PackageVulnerabilityRequirements)
	}

	pubKey, err := ioutil.ReadFile(pub_key_path)
	if err != nil {
		glog.Fatalf("Fail to read public key: %v", err)
	}

	// Create pgp key
	pgpKey, err := secrets.NewPgpKey(string(signerKey), passphrase, string(pubKey))
	if err != nil {
		glog.Fatalf("Creating pgp key from files fail: %v\nprivate key:\n%s\npublic key:\n%s\n", err, string(signerKey), string(pubKey))
	}
	// Create AA
	// Create an AttestaionAuthority to help create noteOcurrences.
	// This is quite hacky.
	// TODO: refactor out the authority code
	authority := v1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{Name: "signing-aa"},
		Spec: v1beta1.AttestationAuthoritySpec{
			NoteReference: policy.Spec.NoteReference,
			PublicKeys: []v1beta1.PublicKey{
				{
					KeyType:                  "PGP",
					AsciiArmoredPgpPublicKey: base64.StdEncoding.EncodeToString([]byte(pubKey)),
				},
			},
		},
	}

	client, err := containeranalysis.NewCache()
	if err != nil {
		glog.Fatalf("Could not initialize the client %v", err)
	}

	r := signer.New(client, &signer.Config{
		Validate:  vulnzsigningpolicy.ValidateVulnzSigningPolicy,
		PgpKey:    pgpKey,
		Authority: authority,
		Project:   policy.Spec.Project,
	})

	if image == "" {
		glog.Fatalf("Image url is empty: %s", image)
	}

	if SignerMode(mode) == BypassAndSign {
		r.SignImage(image)
		return
	}

	if SignerMode(mode) == CheckAndSign {
		// Read the vulnz scanning events
		vulnz, err := client.Vulnerabilities(image)
		if err != nil {
			glog.Fatalf("Found err %s", err)
		}
		if vulnz == nil {
			glog.Fatalf("Expected some vulnerabilities. Nil found")
		}

		imageVulnz := signer.ImageVulnerabilities{
			ImageRef:        image,
			Vulnerabilities: vulnz,
		}

		if err := r.ValidateAndSign(imageVulnz, policy); err != nil {
			glog.Fatalf("Error creating signature: %v", err)
		}
		return
	}
}
