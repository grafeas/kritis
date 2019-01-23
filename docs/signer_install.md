# Kritis Signer

The Kritis Signer is a collection of services to create attestations based on
CI/CD pipeline events (e.g., builds or vulnerability scan events).  These
attestations can then be used by implementations of Kritis enforcement or by
Binary Authorization to control deployments to GKE.

The current implementation covers [Cloud
Build](https://cloud.google.com/cloud-build/docs/) and [Container
Analysis](https://cloud.google.com/container-analysis/api/reference/rest/).

# Prerequisites for GCP based setup

This guide assumes various components are already set up:

*   [Container Registry](https://cloud.google.com/container-registry/) to store
    the images attested to.
*   Container build (e.g., using [Cloud
    Build](https://cloud.google.com/cloud-build/docs/).  This guide only covers
    attestations for Cloud Build for build based attestations, but other build
    platforms will be added in the future.
*   [Container
    Analysis](https://cloud.google.com/container-analysis/api/reference/rest/)
    to do vulnerability scans.  This is optional if no enforcement based on
    vulnerability scans is needed.

This documents assumes the project running the build and the project used for
creating attestations are distinct:

*   `$BUILDER_PROJECT_ID` is the project running the builds / storing the image
    in GCR.  
*   `$SIGNER_PROJECT_ID` is the project id running the GKE cluster executing the
    signing process.
*   `SIGNER_ACCOUNT_EMAIL` is a service account to use by the signer to access
    GCP resource (e.g.,
    `kritis-signer@${SIGNER_PROJECT_ID}.iam.gserviceaccount.com`).



## Builder Project Setup

### Container Analysis Setup

The builder project must have [Container
Analysis](https://cloud.google.com/container-analysis/api/reference/rest/) enabled
to allow storing the attestations.  Container analysis will also store build
details created by Cloud Build.

```shell
# Enable Container Analysis
gcloud --project=${BUILDER_PROJECT_ID} services enable containeranalysis.googleapis.com

# Allow the signer to create occurrences
gcloud projects add-iam-policy-binding ${BUILDER_PROJECT_ID} --member=serviceAccount:${SIGNER_ACCOUNT_EMAIL} --role=roles/containeranalysis.occurrences.editor

# Allow the signer to read Notes (for BUILD_DETAILS)
gcloud  projects add-iam-policy-binding ${BUILDER_PROJECT_ID} --member=serviceAccount:${SIGNER_ACCOUNT_EMAIL} --role=roles/containeranalysis.notes.viewer
```

### PubSub Setup

The signer uses PubSub to retrieve information about builds.  This requires the
appropriate topics and subscriptions to be created and set up to allow
`${SIGNER_ACCOUNT_EMAIL}` access.

```shell
gcloud --project=${BUILDER_PROJECT_ID} pubsub topics create cloud-builds
gcloud --project=${BUILDER_PROJECT_ID} pubsub subscriptions \
  create build-signer --topic=cloud-builds
gcloud --project=${BUILDER_PROJECT_ID} beta pubsub subscriptions \
  add-iam-policy-binding build-signer \
  --member=serviceAccount:${SIGNER_ACCOUNT_EMAIL} \
  --role=roles/pubsub.subscriber
gcloud --project=${BUILDER_PROJECT_ID} beta pubsub subscriptions \
  add-iam-policy-binding build-signer \
  --member=serviceAccount:${SIGNER_ACCOUNT_EMAIL} \
  --role=roles/pubsub.viewer
```

## Signer Project Setup

### Container Analysis Setup

[Container
Analysis](https://cloud.ogle.com/container-analysis/api/reference/rest/) enabled
to allow storing the Note objects in Container Analysis that anchor the
attestations.

```shell
gcloud --project=${SIGNER_PROJECT_ID} services \
  enable containeranalysis.googleapis.com

# Allow the service account to create Notes and attach attestations to them.
gcloud projects add-iam-policy-binding ${SIGNER_PROJECT_ID} \
  --member=serviceAccount:${SIGNER_ACCOUNT_EMAIL} \
  --role=roles/containeranalysis.notes.editor
gcloud projects add-iam-policy-binding ${SIGNER_PROJECT_ID} \
  --member=serviceAccount:${SIGNER_ACCOUNT_EMAIL} \
  --role=roles/containeranalysis.notes.attacher
```

## GKE Cluster Setup

The GKE cluster should be started with the service account enabled so that the
signer process can access the resources.


### CRDs and Roles

Policies and other data for the signer are stored as CRDs and secrets in the
Kubernetes cluster.  These examples are simplified, please ensure to carefully
review the policies to ensure they are properly ACLed.

```shell
# Create the CRDs
kubectl create -f ./artifacts/attestation-authority-crd.yaml 
kubectl create -f ./artifacts/build-policy-crd.yaml

# Set up the access permissions for the CRDs
kubectl create clusterrolebinding cluster-admin-binding \
  --clusterrole=cluster-admin --user=$YOUR_GCP_USER_ID
kubectl create -f ./artifacts/examples/kritis-role-example.yaml
kubectl create -f ./artifacts/examples/kritis-rolebinding-example.yaml

# Create example policies
kubectl create -f ./artifacts/examples/attestation-authority-example.yaml
kubectl create -f ./artifacts/examples/build-policy-example.yaml
```

### PGP Key

Kritis uses Kubernetes secrets to store the PGP keys to create the attestations.
Please ensure the secret is properly protected by ACLs.

```shell
kubectl create secret generic kritis-authority-key \
  --from-file=public=${PUB_KEY_FILE} --from-file=private=${PRIV_KEY_FILE} --from-literal=passphrase=<PASSPHRASE>
```

## Signer Execution

The signer will connect to the pubsub, listen to build events and create
attestations for all attestation authorities that are connected to a matching
policy.

```shell
kubectl create -f artifacts/examples/kritis-gcb-signer-deployment.yaml
```

