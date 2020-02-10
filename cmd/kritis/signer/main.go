package main

import (
	"flag"
	"fmt"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/vulnzsigningpolicy"
	containeranalysis "github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/signer"
	"google.golang.org/api/option"
	"io/ioutil"

	"github.com/golang/glog"
	"gopkg.in/yaml.v2"
)

func main() {
	var image, json_key_path, s_key_path, policy_path string

	flag.StringVar(&image, "image url", "", "image url, e.g., gcr.io/foo/bar@sha256:abcd")
	flag.StringVar(&json_key_path, "json credentials file path", "", "json credentials file path, e.g., ./key.json")
	flag.StringVar(&s_key_path, "signer private key path", "", "signer private key path, e.g., /dev/shm/key.pgp")
	flag.StringVar(&policy_path, "vulnerability signing policy file path", "", "vulnerability signing policy file path, e.g., /tmp/vulnz_signing_policy.yaml")
	flag.Parse()

	glog.Infof("image: %s, json_path: %s, s_key: %s, policy: %s", image, json_key_path, s_key_path, policy_path)

	signerKey, err := ioutil.ReadFile(s_key_path)
	if err != nil {
		glog.Fatalf("Fail to read signer key: %v", err)
	}

	policyFile, err := ioutil.ReadFile(policy_path)
	if err != nil {
		glog.Fatalf("Fail to read vulnz signing policy: %v", err)
	}

	// Parse the vulnz signing policy
	var policy v1beta1.VulnzSigningPolicy

	err = yaml.Unmarshal(policyFile, &policy)
	if err != nil {
		glog.Fatalf("Fail to parse policy file: %v", err)
	}

	// Read the vulnz scanning events
	if image == "" {
		glog.Fatalf("Image url is empty: %s", image)
	}

	d, err := containeranalysis.New(option.WithCredentialsFile(json_key_path))
	if err != nil {
		glog.Fatalf("Could not initialize the client %v", err)
	}
	vulnz, err := d.Vulnerabilities(image)
	if err != nil {
		glog.Fatalf("Found err %s", err)
	}
	if vulnz == nil {
		glog.Fatalf("Expected some vulnerabilities. Nil found")
	}

	fmt.Printf("policy %v\n", policy)
	fmt.Printf("signer_key %v\n", signerKey)


	// Run the signer
	client, err := containeranalysis.NewCache()
	if err != nil {
		glog.Fatalf("Error getting Container Analysis client: %v", err)
	}

	// Create pgp key
	pgpKey, err := secrets.NewPgpKey(string(priv), string(phrase), string(pub))

	r := signer.New(client, &signer.Config{
		Secret:   secrets.Fetch,
		Validate: vulnzsigningpolicy.ValidateVulnzSigningPolicy,
	})
	imageVulnz := signer.ImageVulnerabilities{
		ImageRef:        image,
		Vulnerabilities: vulnz,
	}

	if err := r.ValidateAndSign(imageVulnz, policy, pgpKey); err != nil {
		glog.Fatalf("Error creating signature: %v", err)
	}
}
