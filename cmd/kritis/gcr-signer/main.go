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
	ca "cloud.google.com/go/containeranalysis/apiv1beta1"
	"flag"
	"fmt"
	"github.com/docker/distribution/reference"
	"github.com/grafeas/kritis/pkg/kritis/crd/vulnzsigningpolicy"
	"k8s.io/apimachinery/pkg/util/yaml"
	"os"
	"strconv"
	"time"

	"context"
	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/attestlib"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
	"github.com/grafeas/kritis/pkg/kritis/signer"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"strings"
)

var (
	vulnzTimeout       time.Duration
	policy             *v1beta1.VulnzSigningPolicy
	attestationProject string
	overwrite          bool
	noteName           string
	kmsKeyName         string
	kmsDigestAlg       string

	// global
	client     *containeranalysis.Client
	grafeas    *ca.GrafeasV1Beta1Client
	noteSigner attestlib.Signer
)

func isFlagPassed(name string) bool {
	found := false
	flag.CommandLine.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func getFlagValue(name string) string {
	result := ""
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if f.Name == name {
			result = f.Value.String()
		}
	})
	return result
}

func ParsePolicy(policyDocument string) (*v1beta1.VulnzSigningPolicy, error) {
	policy := v1beta1.VulnzSigningPolicy{}
	if err := yaml.NewYAMLToJSONDecoder(strings.NewReader(policyDocument)).Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy, %s", err)
	}
	return &policy, nil
}

func ReadPolicyFile(path string) (*v1beta1.VulnzSigningPolicy, error) {
	policy := v1beta1.VulnzSigningPolicy{}
	policyFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy file '%s', %s", path, err)
	}
	defer policyFile.Close()
	if err := yaml.NewYAMLToJSONDecoder(policyFile).Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy from '%s', %s", path, err)
	} else {
		glog.Infof("Policy req: %v\n", policy.Spec.ImageVulnerabilityRequirements)
	}

	return &policy, nil
}

func exitOnBadFlags(err string) {
	flag.CommandLine.PrintDefaults()
	fmt.Fprintf(flag.CommandLine.Output(), "%s\n", err)
	os.Exit(1)
}

// returns nil when the image reference uses the digest format
func IsImageReferenceWithDigest(image string) error {
	ref, err := reference.ParseAnyReference(image)
	if err != nil {
		return fmt.Errorf("failed to parse container image reference %s, %s", image, err)
	}

	if _, ok := ref.(reference.Digested); !ok {
		return fmt.Errorf("image reference should have digest")
	}
	return nil
}

// checks whether the image passes the policy on security vulnerabilities.
// returns a list of violations if err == nill
func DoCheck(image string) ([]string, error) {
	var result []string
	err := IsImageReferenceWithDigest(image)
	if err != nil {
		return nil, err
	}

	err = client.WaitForVulnzAnalysis(image, vulnzTimeout)
	if err != nil {
		return nil, fmt.Errorf("Error waiting for vulnerability analysis %v", err)
	}

	vulnerabilities, err := client.Vulnerabilities(image)
	if err != nil {
		return nil, fmt.Errorf("failed to read discovered vulnerabilities. %s", err)
	}

	if vulnerabilities == nil {
		return nil, fmt.Errorf("no vulnerabilities found")
	}

	violations, err := vulnzsigningpolicy.ValidateVulnzSigningPolicy(*policy, image, vulnerabilities)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate image against policy %s, %s", policy.Name, err)
	}

	if violations != nil && len(violations) != 0 {
		result = make([]string, len(violations))
		for i, v := range violations {
			result[i] = string(v.Reason())
		}
	}
	return result, nil
}

// sign the `image`
func DoSign(image string) error {
	project := attestationProject
	if project == "" {
		project = util.GetProjectFromContainerImage(image)
		glog.Infof("Using image project as attestation project: %s\n", project)
	} else {
		glog.Infof("Using specified attestation project: %s\n", project)
	}

	noteSigner := signer.New(client, noteSigner, noteName, project, overwrite)
	return noteSigner.SignImage(image)
}

func main() {
	var err error
	var timeout string
	var policyPath string
	var policyDocument string

	flag.StringVar(&policyPath, "policy", "", "vulnerability signing policy file path, e.g., /tmp/vulnz_signing_policy.yaml")
	flag.StringVar(&timeout, "vulnz_timeout", "5m", "timeout for polling image vulnerability , e.g., 600s, 5m")
	flag.StringVar(&noteName, "note_name", "", "note name that created attestations are attached to, in the form of projects/[PROVIDER_ID]/notes/[NOTE_ID]")
	flag.StringVar(&attestationProject, "attestation_project", "", "project id for GCP project that stores attestation, use image project if set to empty")
	flag.BoolVar(&overwrite, "overwrite", false, "overwrite attestation if already existed")
	flag.StringVar(&kmsKeyName, "kms_key_name", "", "kms key name, in the format of in the format projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*")
	flag.StringVar(&kmsDigestAlg, "kms_digest_alg", "", "kms digest algorithm, must be one of SHA256|SHA384|SHA512, and the same as specified by the key version's algorithm")
	flag.Parse()

	if isFlagPassed("policy") {
		policyPath = getFlagValue("policy")
	} else {
		policyPath = os.Getenv("ATTESTATION_POLICY_PATH")
	}

	if policyPath == "" {
		policyDocument = os.Getenv("ATTESTATION_POLICY")
	}

	if policyPath == "" && policyDocument == "" {
		exitOnBadFlags("no policy path or document is specified")
	}

	if policyPath != "" {
		policy, err = ReadPolicyFile(policyPath)
		if err != nil {
			glog.Fatal(err)
		}
	} else {
		policy, err = ParsePolicy(policyDocument)
		if err != nil {
			glog.Fatal(err)
		}
	}

	if noteName == "" {
		noteName = os.Getenv("ATTESTATION_NOTE_NAME")
	}

	if noteName == "" {
		exitOnBadFlags("No note name was specified")
	}

	err = util.CheckNoteName(noteName)
	if err != nil {
		exitOnBadFlags(err.Error())
	}

	if attestationProject == "" {
		attestationProject = os.Getenv("ATTESTATION_PROJECT")
	}

	if !isFlagPassed("overwrite") && os.Getenv("ATTESTATION_OVERWRITE") != "" {
		overwrite, err = strconv.ParseBool(os.Getenv("ATTESTATION_OVERWRITE"))
		if err != nil {
			glog.Fatalf("failed to parse boolean from  ATTESTATION_OVERWRITE, %s", err)
		}
	}

	if kmsKeyName == "" {
		kmsKeyName = os.Getenv("ATTESTATION_KMS_KEY")
	}

	if kmsDigestAlg == "" {
		kmsDigestAlg = os.Getenv("ATTESTATION_DIGEST_ALGORITHM")
	}

	if kmsKeyName == "" || kmsDigestAlg == "" {
		exitOnBadFlags("both kms key name and kms key digest are required")
	}

	vulnzTimeout, err = time.ParseDuration(timeout)
	if err != nil {
		exitOnBadFlags(fmt.Sprintf("Fail to parse timeout, %s", err))
	}

	noteSigner, err = signer.NewCloudKmsSigner(kmsKeyName, signer.DigestAlgorithm(kmsDigestAlg))
	if err != nil {
		exitOnBadFlags(fmt.Sprintf("Creating kms signer failed, %s", err))
	}

	client, err = containeranalysis.New()
	if err != nil {
		glog.Fatalf("Could not initialize the container analysis client, %s", err)
	}

	grafeas, err = ca.NewGrafeasV1Beta1Client(context.Background())
	if err != nil {
		glog.Fatalf("Could not initialize the grafeas client, %s", err)
	}

	Serve()
}
