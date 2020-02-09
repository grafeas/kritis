package main

import (
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/golang/glog"
)

func main() {
	var image, s_key_path, policy_path string

	flag.StringVar(&image, "image url", "", "image url, e.g., gcr.io/foo/bar@sha256:abcd")
	flag.StringVar(&s_key_path, "signer private key path", "", "signer private key path, e.g., /dev/shm/key.pgp")
	flag.StringVar(&policy_path, "vulnerability signing policy file path", "", "vulnerability signing policy file path, e.g., /tmp/vulnz_signing_policy.yaml")
	flag.Parse()

	glog.Infof("image: %s, s_key: %s, policy: %s", image, s_key_path, policy_path)

	signer_key, err := ioutil.ReadFile(s_key_path)
	if err != nil {
		glog.Fatalf("Fail to read signer key: %s", err)
	}

	policy, err := ioutil.ReadFile(policy_path)
	if err != nil {
		glog.Fatalf("Fail to read vulnz signing policy: %s", err)
	}

	if image == "" {
		glog.Fatalf("Image url is empty: %s", image)
	}

	fmt.Printf("policy %v\n", policy)
	fmt.Printf("signer_key %v\n", signer_key)
}
