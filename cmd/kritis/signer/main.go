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
	"io/ioutil"
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

type SignerMode string

const (
	Server        SignerMode = "server"
	CheckAndSign  SignerMode = "check-and-sign"
	CheckOnly     SignerMode = "check-only"
	BypassAndSign SignerMode = "bypass-and-sign"
)

var (
	// input flags
	mode               string
	image              string
	vulnzTimeout       time.Duration
	policy             *v1beta1.VulnzSigningPolicy
	attestationProject string
	overwrite          bool
	noteName           string
	// input flags: pgp key flags
	pgpPriKeyPath string
	pgpPassphrase string
	// pkix key flags
	pkixPriKeyPath string
	pkixAlg        string

	// input flags: kms flags
	kmsKeyName   string
	kmsDigestAlg string

	// helper global variables
	modeFlags   *flag.FlagSet
	modeExample string

	client     *containeranalysis.Client
	grafeas    *ca.GrafeasV1Beta1Client
	noteSigner attestlib.Signer
)

func init() {
	// need to add all flags to avoid "flag not provided error"
	addBasicFlags(flag.CommandLine)
	addCheckFlags(flag.CommandLine)
	addSignFlags(flag.CommandLine)
}

func addBasicFlags(fs *flag.FlagSet) {
	fs.StringVar(&mode, "mode", "check-and-sign", "(required) mode of operation, check-and-sign|check-only|bypass-and-sign")
	fs.StringVar(&image, "image", "", "(required) image url, e.g., gcr.io/foo/bar@sha256:abcd")
}

func addCheckFlags(fs *flag.FlagSet) {
	fs.String("policy", "", "(required for check) vulnerability signing policy file path, e.g., /tmp/vulnz_signing_policy.yaml")
	fs.String("vulnz_timeout", "5m", "timeout for polling image vulnerability , e.g., 600s, 5m")
}

func addSignFlags(fs *flag.FlagSet) {
	fs.StringVar(&noteName, "note_name", "", "(required for sign) note name that created attestations are attached to, in the form of projects/[PROVIDER_ID]/notes/[NOTE_ID]")
	fs.StringVar(&attestationProject, "attestation_project", "", "project id for GCP project that stores attestation, use image project if set to empty")
	fs.BoolVar(&overwrite, "overwrite", false, "overwrite attestation if already existed")
	fs.StringVar(&kmsKeyName, "kms_key_name", "", "kms key name, in the format of in the format projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*")
	fs.StringVar(&kmsDigestAlg, "kms_digest_alg", "", "kms digest algorithm, must be one of SHA256|SHA384|SHA512, and the same as specified by the key version's algorithm")
	fs.StringVar(&pgpPriKeyPath, "pgp_private_key", "", "pgp private signing key path, e.g., /dev/shm/key.pgp")
	fs.StringVar(&pgpPassphrase, "pgp_passphrase", "", "passphrase for pgp private key, if any")
	fs.StringVar(&pkixPriKeyPath, "pkix_private_key", "", "pkix private signing key path, e.g., /dev/shm/key.pem")
	fs.StringVar(&pkixAlg, "pkix_alg", "", "pkix signature algorithm, e.g., ecdsa-p256-sha256")
}

func isFlagPassed(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func getFlagValue(fs *flag.FlagSet, name string) string {
	result := ""
	fs.VisitAll(func(f *flag.Flag) {
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

func initialize(fs *flag.FlagSet, signerMode SignerMode) {
	var err error
	var policyPath string
	var policyDocument string

	if isFlagPassed(fs, "policy") {
		policyPath = getFlagValue(fs, "policy")
	} else {
		policyPath = os.Getenv("ATTESTATION_POLICY_PATH")
	}

	if policyPath == "" {
		policyDocument = os.Getenv("ATTESTATION_POLICY")
	}

	if policyPath == "" && policyDocument == "" {
		exitOnBadFlags(SignerMode(mode), "no policy path or document is specified")
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

	if signerMode != CheckOnly {
		if noteName == "" {
			noteName = os.Getenv("ATTESTATION_NOTE_NAME")
		}

		if noteName == "" {
			exitOnBadFlags(SignerMode(mode), "No note name was specified")
		}

		err = util.CheckNoteName(noteName)
		if err != nil {
			exitOnBadFlags(SignerMode(mode), fmt.Sprintf("note name '%s' is invalid %s", noteName, err))
		}

		if attestationProject == "" {
			attestationProject = os.Getenv("ATTESTATION_PROJECT")
		}

		if !isFlagPassed(fs, "overwrite") && os.Getenv("ATTESTATION_OVERWRITE") != "" {
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

		initializeSigner()
	}

	timeout := getFlagValue(fs, "vulnz_timeout")
	vulnzTimeout, err = time.ParseDuration(timeout)
	if err != nil {
		exitOnBadFlags(SignerMode(mode), fmt.Sprintf("Fail to parse timeout %v", err))
	}

	client, err = containeranalysis.New()
	if err != nil {
		glog.Fatalf("Could not initialize the container analysis client, %s", err)
	}

	grafeas, err = ca.NewGrafeasV1Beta1Client(context.Background())
	if err != nil {
		glog.Fatalf("Could not initialize the grafeas client, %s", err)
	}
}

// parseSignerMode creates mode-specific flagset and analyze actions (check, sign) for given mode
func parseSignerMode(mode SignerMode) (doCheck bool, doSign bool, err error) {
	modeFlags, doCheck, doSign, err = flag.NewFlagSet("", flag.ExitOnError), false, false, nil
	addBasicFlags(modeFlags)
	switch mode {
	case Server:
		addCheckFlags(modeFlags)
		addSignFlags(modeFlags)
		doCheck, doSign = true, true
		modeExample = `	./signer \
	  -mode=server \
	  -vulnz_timeout=10s \
	  -policy=policy.yaml \
	  -note_name=projects/$NOTE_PROJECT/notes/$NOTE_ID \
	  -kms_key_name=projects/$KMS_PROJECT/locations/$KMS_KEYLOCATION/keyRings/$KMS_KEYRING/cryptoKeys/$KMS_KEYNAME/cryptoKeyVersions/$KMS_KEYVERSION \
	  -kms_digest_alg=SHA512`
	case CheckAndSign:
		addCheckFlags(modeFlags)
		addSignFlags(modeFlags)
		doCheck, doSign = true, true
		modeExample = `	./signer \
	-mode=check-and-sign \
	-image=gcr.io/my-image-repo/image-1@sha256:123 \
	-policy=policy.yaml \
	-note_name=projects/$NOTE_PROJECT/notes/$NOTE_ID \
	-kms_key_name=projects/$KMS_PROJECT/locations/$KMS_KEYLOCATION/keyRings/$KMS_KEYRING/cryptoKeys/$KMS_KEYNAME/cryptoKeyVersions/$KMS_KEYVERSION \
	-kms_digest_alg=SHA512`
	case BypassAndSign:
		addSignFlags(modeFlags)
		doSign = true
		modeExample = `	./signer \
	-mode=bypass-and-sign \
	-image=gcr.io/my-image-repo/image-1@sha256:123 \
	-note_name=projects/$NOTE_PROJECT/notes/$NOTE_ID \
	-kms_key_name=projects/$KMS_PROJECT/locations/$KMS_KEYLOCATION/keyRings/$KMS_KEYRING/cryptoKeys/$KMS_KEYNAME/cryptoKeyVersions/$KMS_KEYVERSION \
	-kms_digest_alg=SHA512`
	case CheckOnly:
		addCheckFlags(modeFlags)
		doCheck = true
		modeExample = `	./signer \
	-mode=check-only \
	-image=gcr.io/my-image-repo/image-1@sha256:123 \
	-policy=policy.yaml`
	default:
		return false, false, fmt.Errorf("unrecognized mode %s, must be one of check-and-sign|check-only|bypass-and-sign", mode)
	}
	flag.Parse()

	initialize(flag.CommandLine, mode)

	return doCheck, doSign, err
}

func exitOnBadFlags(mode SignerMode, err string) {
	fmt.Fprintf(modeFlags.Output(), "Usage of signer's %s mode:\n", mode)
	modeFlags.PrintDefaults()
	fmt.Fprintf(modeFlags.Output(), "Example (%s mode):\n %s\n", mode, modeExample)
	fmt.Fprintf(modeFlags.Output(), "Bad flags for mode %s: %v. \n", mode, err)
	os.Exit(1)
}

func initializeSigner() {
	var err error
	if kmsKeyName == "" && pgpPriKeyPath == "" && pkixPriKeyPath == "" {
		exitOnBadFlags(SignerMode(mode), "Neither kms_key_name, pgp_private_key, or pkix_private_key is specified")
	}
	if kmsKeyName != "" {
		glog.Infof("Using kms key %s for signing.", kmsKeyName)
		if kmsDigestAlg == "" {
			glog.Fatalf("kms_digest_alg is unspecified, must be one of SHA256|SHA384|SHA512, and the same as specified by the key version's algorithm")
		}
		noteSigner, err = signer.NewCloudKmsSigner(kmsKeyName, signer.DigestAlgorithm(kmsDigestAlg))
		if err != nil {
			glog.Fatalf("Creating kms signer failed: %v\n", err)
		}
	} else if pgpPriKeyPath != "" {
		glog.Infof("Using pgp key for signing.")
		signerKey, err := ioutil.ReadFile(pgpPriKeyPath)
		if err != nil {
			glog.Fatalf("Fail to read signer key: %v\n", err)
		}
		// Create a cryptolib signer
		noteSigner, err = attestlib.NewPgpSigner(signerKey, pgpPassphrase)
		if err != nil {
			glog.Fatalf("Creating pgp signer failed: %v\n", err)
		}
	} else {
		glog.Infof("Using pkix key for signing.")
		signerKey, err := ioutil.ReadFile(pkixPriKeyPath)
		if err != nil {
			glog.Fatalf("Fail to read signer key: %v\n", err)
		}
		sAlg := attestlib.ParseSignatureAlgorithm(pkixAlg)
		if sAlg == attestlib.UnknownSigningAlgorithm {
			glog.Fatalf("Empty or unknown PKIX signature algorithm: %s\n", pkixAlg)
		}
		noteSigner, err = attestlib.NewPkixSigner(signerKey, sAlg, "")
		if err != nil {
			glog.Fatalf("Creating pkix signer failed: %v\n", err)
		}
	}
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
	flag.Parse()
	glog.Infof("Signer mode: %s.", mode)

	doCheck, doSign, err := parseSignerMode(SignerMode(mode))
	if err != nil {
		glog.Fatalf("Parse mode err %v.", err)
	}

	if SignerMode(mode) == Server {
		Serve()
		return
	}

	// Check image url is non-empty
	if image == "" {
		exitOnBadFlags(SignerMode(mode), "image url is empty")
	}

	if doCheck {
		violations, err := DoCheck(image)
		if err != nil {
			glog.Fatalf("Found err %s", err)
		}

		if violations != nil && len(violations) != 0 {
			glog.Errorf("Image %q does not pass VulnzSigningPolicy %q:", image, policy.Name)
			glog.Errorf("Found %d violations in image %s:", len(violations), image)
			for _, v := range violations {
				glog.Error(v)
			}
			os.Exit(1)
		}
		glog.Infof("Image %q passes VulnzSigningPolicy %s.", image, policy.Name)
	}

	if doSign {
		err = DoSign(image)
		if err != nil {
			glog.Fatalf("Signing image failed: %v", err)
		}
	}
}
