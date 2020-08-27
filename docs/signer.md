# Kritis Signer

Kritis Signer is a command-line tool that creates attestations. These attestations can be used for Kritis and Binary Authorization deployment enforcement.

The tool can create attestations directly or conditionally, checking policy conformance based on Vulnerability scanning results from Google Cloud Container Analysis.

It can be run either locally or as part of a continuous integration (CI) pipeline.

Currently, the tool supports vulnerability-based policy check, 
using [vulnerability scanning](https://cloud.google.com/container-registry/docs/vulnerability-scanning), a feature of [Google Container Analysis](https://cloud.google.com/container-registry/docs/container-analysis) that returns a list of vulnerabilities associated with a container image. Kritis Signer then creates an attestation and stores it in Google Container Analysis data store.
Support for other type of checks (e.g., base-image check), other vulnerability sources and attestation storage are underway.

This doc provides:
- a general overview;
- a step by step tutorial describing how to use the signer tool.

## Overview

### Signer Modes

The tool can be run in three different modes:
- **check-and-sign**: default mode, checks policy conformance for a image, and conditionally creates attestation for the image if check passes. Currently, only vulnerability policy is supported. 
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

By default, the signing helper will also upload the attestation occurrence to [Google Container Analysis](https://cloud.google.com/container-registry/docs/container-analysis),
and the uploaded attestation can be used by both Binary Authorization and Kritis for enforcement-time decisions.

#### Supported key types

The tool currently supports three types of keys:

- PGP keys using `-pgp_private_key` and optionally `-pgp_passphrase`  if the key is passphrase protected.
- PKIX keys using `-pkix_private_key` and `-pkix_alg`. Supported PKIX algorithms match those [supported by Binary Authorization](https://cloud.google.com/sdk/gcloud/reference/container/binauthz/attestors/public-keys/add#--pkix-public-key-algorithm).
- Cloud KMS using with `-kms_key_name` and `-kms_digest_alg`. 

## Tutorial

The tutorial will walk through how to run the signing helper tool in a local environment.

1. Build the tool.

    ```shell
    go build -o ./signer ./cmd/kritis/signer
    ```

2. Enable GCP services.

    The signing tool needs to access a number of Google Cloud Platform (GCP) services.
First we need to pick a GCP project and enable those services within the project.

    1. Set the default GCP project used by `gcloud`.

        ```shell
        export PROJECT_ID=[PROJECT ID]
        ```

    2. Set the default GCP project used by `gcloud`.

        ```shell
        gcloud config set project ${PROJECT_ID}
        ```

    3. Run `gcloud` to enable services within a project.

        ```shell
        gcloud services enable \
          cloudbuild.googleapis.com \
          containerregistry.googleapis.com \
          containeranalysis.googleapis.com \
          containerscanning.googleapis.com \
          cloudkms.googleapis.com # If using Cloud KMS
        ```

3. Setting up GCP credentials.

    1. Create a service account within the GCP project.

        ```shell
        export SA_NAME=[Service Account Name]
        gcloud iam service-accounts create ${SA_NAME}
        ```

    2. Add permissions to the created service account.

        ```shell
        # permission to create note
        gcloud projects add-iam-policy-binding $PROJECT_ID \
          --member serviceAccount:${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
          --role roles/containeranalysis.notes.editor

        # permission to view vulnerability and attestation occurrences
        gcloud projects add-iam-policy-binding $PROJECT_ID \
          --member serviceAccount:${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
          --role roles/containeranalysis.notes.occurrences.viewer

        # permission to upload attestation occurrences
        gcloud projects add-iam-policy-binding $PROJECT_ID \
          --member serviceAccount:${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
          --role roles/containeranalysis.occurrences.editor

        # (if using Cloud KMS) permission to cloud KMS signing service
        gcloud projects add-iam-policy-binding $PROJECT_ID \
          --member serviceAccount:${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
          --role roles/cloudkms.signer
        ```

    3. Create json credentials for the service account.

        ```shell
        gcloud iam service-accounts keys create ./sa.json  --iam-account ${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com
        ```

        The json credentials are saved in `sa.json`.

    4. Setting GAC environment variable.

        ```shell
        export GOOGLE_APPLICATION_CREDENTIALS="$PWD/sa.json"
        ```

        Now the signer tool will automatically pick up the credentials via the environment variable.

4. Creating a signing key. 

    A private signing key is required to create attestations for an image. 
Here, we use Cloud KMS as an example. The tool also supports PGP and PKIX keys.

    Run the following commands to create a key ring and an asymmetric signing key, and note down the KMS key name.

    ```shell
    gcloud kms keyrings create my-key-ring-1 \
        --location global

    gcloud --project=$PROJECT_ID kms keys create my-signing-key-1 \
        --keyring my-key-ring-1 \
        --location global \
        --purpose "asymmetric-signing" \
        --default-algorithm "rsa-sign-pkcs1-2048-sha256"
    ```

    Note down the digest algorithm “SHA256” and key name.

    ```shell
    export KMS_DIGEST_ALG=SHA256
    export KMS_KEY_NAME=projects/$PROJECT_ID/locations/global/keyRings/my-key-ring-1/cryptoKeys/my-signing-key-1/cryptoKeyVersions/1
    ```

5. Pick a note name.

    All attestations need to be attached to a note. The signer tool will automatically create a note for a given name. It can also reuse an existing note.

    ```shell
    export NOTE_ID=my-signer-note
    export NOTE_NAME=projects/${PROJECT_ID}/notes/${NOTE_ID}
    ```

6. Create vulnerability signing policy.

    An example policy is in the samples.

    ```shell
    cat samples/signer/policy.yaml

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

7. Run signer on a built image (pass example).

    1. Build and push an example good image.

        ```shell
        docker build -t gcr.io/$PROJECT_ID/signer-test:good -f samples/signer/Dockerfile.good .
        docker push gcr.io/$PROJECT_ID/signer-test:good
        ```

    2. Note down the image digest url.

        ```shell
        export GOOD_IMG_URL=$(docker image inspect gcr.io/$PROJECT_ID/signer-test:good --format '{{index .RepoDigests 0}}')
        ```

    3. Run the signer.

        ```shell
        ./signer \
          -v=10 \
          -alsologtostderr \
          -image=$GOOD_IMG_URL \
          -policy=samples/signer/policy.yaml \
          -kms_key_name=$KMS_KEY_NAME \
          -kms_digest_alg=$KMS_DIGEST_ALG \
          -note_name=$NOTE_NAME
        ```

        The signer should output that the image "passes VulnzSigningPolicy my-vsp" and that an attestation is created and uploaded.

    4. (optional) Run the tool in other modes.

        The signer can also run in other modes to only perform policy check (`check-only`) or create attestation (`bypass-and-sign`):

        ```shell
        ./signer \
          -mode=check-only \
          -v=10 \
          -alsologtostderr \
          -image=$GOOD_IMG_URL \
          -policy=samples/signer/policy.yaml \
        ```

        ```shell
        ./signer \
          -mode=bypass-and-sign \
          -v=10 \
          -alsologtostderr \
          -image=$GOOD_IMG_URL \
          -kms_key_name=$KMS_KEY_NAME \
          -kms_digest_alg=$KMS_DIGEST_ALG \
          -note_name=$NOTE_NAME
        ```

8. Run signer on a built image (fail example).

    1. Build and push an example good image.

        ```shell
        docker build -t gcr.io/$PROJECT_ID/signer-test:bad -f samples/signer/Dockerfile.bad .
        docker push gcr.io/$PROJECT_ID/signer-test:bad
        ```

    2. Note down the image digest url.

        ```shell
        export BAD_IMG_URL=$(docker image inspect gcr.io/$PROJECT_ID/signer-test:bad --format '{{index .RepoDigests 0}}')
        ```

    3. Run the signer.

        ```shell
        ./signer \
          -v=10 \
          -alsologtostderr \
          -image=$BAD_IMG_URL \
          -policy=samples/signer/policy.yaml \
          -kms_key_name=$KMS_KEY_NAME \
          -kms_digest_alg=$KMS_DIGEST_ALG \
          -note_name=$NOTE_NAME
        ```

        The signer should print out that the image "does not pass VulnzSigningPolicy my-vsp".

    4. (optional) Run the tool in other modes.

        The signer can also run in other modes to only perform policy check (`check-only`) or create attestation (`bypass-and-sign`):

        ```shell
        ./signer \
          -mode=check-only \
          -v=10 \
          -alsologtostderr \
          -image=$BAD_IMG_URL \
          -policy=samples/signer/policy.yaml \
        ```

        ```shell
        ./signer \
          -mode=bypass-and-sign \
          -v=10 \
          -alsologtostderr \
          -image=$BAD_IMG_URL \
          -kms_key_name=$KMS_KEY_NAME \
          -kms_digest_alg=$KMS_DIGEST_ALG \
          -note_name=$NOTE_NAME
        ```

        With `bypass-and-sign` mode, an attestation will also be created for the bad image.

