# Kritis Signing Helper

Kritis signing helper (or, the signer tool) is a command-line tool that can be run locally or in
CI environment to check policy conformance for images and create attestations (signing).
The created attestations can be used for Kritis and Binary Authorization deployment enforcement. 

Currently, the tool supports vulnerability-based policy check, 
uses [Google Vulnerability Scanning](https://cloud.google.com/container-registry/docs/vulnerability-scanning) as vulnerability source,
and creates attestation in
[Google Container Analysis](https://cloud.google.com/container-registry/docs/container-analysis).
Support for other type of checks (e.g., base-image check), other vulnerability sources and attestation storage are underway.

This doc provides:
- a general overview;
- a step by step tutorial for the signer tool;
- links to other resources, e.g., CI integration of the signer tool with Google Cloud Build.

## Overview

## Signer Modes

The tool can be run in three different modes:
- **check-and-sign**: default mode, checks policy conformance for a image, and conditionally creates attestation for the image if check passes.
- **check-only**: only checks policy conformance and outputs results, but does not create any attestation.
- **bypass-and-sign**: bypasses any check and creates attestation for a image.

| mode            | checking? | signing? |
|-----------------|-----------|----------|
| check-and-sign  | ✓         | ✓        |
| check-only      | ✓         |          |
| bypass-and-sign |           | ✓        |

Users can specify the mode with `-mode` flag.

### Checking

The signer tool can check an image's metadata against rules in a user-provided policy. The tool now supports vulnerability-based policy check
and will add more checks in the future.

#### Vulnerability Source

During the checking process, the signer tool will fetch vulnerability results for the image from a source. 
The tool now supports [Google Vulnerability Scanning](https://cloud.google.com/container-registry/docs/vulnerability-scanning) as a vulnerability source.
If enabled, any image a user pushes to Google Container Registry, or gcr.io, will be automatically scanned for vulnerability. 

#### Vulnerability Signing Policy

A vulnerability signing policy yaml file can be specified via `-policy` flag, and controls requirements 
for an image to pass vulnerability-based checks.

#### Vulnerability Signing Policy Spec

| Field     | Default (if applicable)   | Description |
|-----------|---------------------------|-------------|
|packageVulnerabilityPolicy.maximumFixableSeverity| CRITICAL | Tolerance level for vulnerabilities found in the container image.|
|packageVulnerabilityPolicy.maximumUnfixableSeverity |  ALLOW_ALL | The tolerance level for vulnerabilities found that have no fix available.|
|imageVulnerabilityRequirements.allowlistCVEs |  | List of CVEs which will be ignored, has to be full note name.|

Example policy:

```
apiVersion: kritis.grafeas.io/v1beta1
kind: VulnzSigningPolicy
metadata:
  name: my-vsp
spec:
  imageVulnerabilityRequirements:
    maximumFixableSeverity: MEDIUM
    maximumUnfixableSeverity: MEDIUM
    allowlistCVEs:
      - projects/goog-vulnz/notes/CVE-2020-10543
      - projects/goog-vulnz/notes/CVE-2020-10878
      - projects/goog-vulnz/notes/CVE-2020-14155
```

Here are the valid values for severity levels.

| Value       | Outcome |
|-------------|----------- |
| BLOCK_ALL | Block all vulnerabilities except listed in allowlist. |
| LOW | Allow Containers with Low  vulnerabilities. |
| MEDIUM | Allow Containers with Low and Medium vulnerabilities. |
| HIGH  | Allow Containers with Low, Medium & High vulnerabilities. |
| CRITICAL  | Allow Containers with all known vulnerability levels (LOW to CRITICAL). |
| ALLOW_ALL | Allow all vulnerabilities, including vulnerability with unknown severity levels. |

### Signing

Signing is the process of creating and storing an attestation for an image.
To create an attestation, a private signing key is needed. The signer tool now
supports three types of signing methods: PGP keys, PKIX keys, or signing via [Cloud KMS] (https://cloud.google.com/kms).

## Tutorial


## Useful links

