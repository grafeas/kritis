package main

import (
	"flag"
	"fmt"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	containeranalysis "github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
	"io/ioutil"

	"github.com/golang/glog"
	"gopkg.in/yaml.v2"
)

func main() {
	var image, s_key_path, policy_path string

	flag.StringVar(&image, "image url", "", "image url, e.g., gcr.io/foo/bar@sha256:abcd")
	flag.StringVar(&s_key_path, "signer private key path", "", "signer private key path, e.g., /dev/shm/key.pgp")
	flag.StringVar(&policy_path, "vulnerability signing policy file path", "", "vulnerability signing policy file path, e.g., /tmp/vulnz_signing_policy.yaml")
	flag.Parse()

	glog.Infof("image: %s, s_key: %s, policy: %s", image, s_key_path, policy_path)

	signerKey, err := ioutil.ReadFile(s_key_path)
	if err != nil {
		glog.Fatalf("Fail to read signer key: %s", err)
	}

	policyFile, err := ioutil.ReadFile(policy_path)
	if err != nil {
		glog.Fatalf("Fail to read vulnz signing policy: %s", err)
	}

	// Parse the vulnz signing policy
	var vsp v1beta1.VulnzSigningPolicy

	err = yaml.Unmarshal(policyFile, &vsp)
	if err != nil {
		glog.Fatalf("Fail to parse policy file: %s", err)
	}

	// Read the vulnz scanning events
	if image == "" {
		glog.Fatalf("Image url is empty: %s", image)
	}

	d, err := containeranalysis.New()
	if err != nil {
		glog.Fatalf("Could not initialize the client %s", err)
	}
	vuln, err := d.Vulnerabilities("gcr.io/kritis-int-test/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a")
	if err != nil {
		glog.Fatalf("Found err %s", err)
	}
	if vuln == nil {
		glog.Fatalf("Expected some vulnerabilities. Nil found")
	}

	fmt.Printf("policy %v\n", vsp)
	fmt.Printf("signer_key %v\n", signerKey)


	// Run the signer
}
