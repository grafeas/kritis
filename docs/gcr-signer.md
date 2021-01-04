# GCR Kritis Signer

GCR Kritis Signer is a service which creates attestations based on software vulnerabilities identified by the [Google Container Analysis](https://cloud.google.com/container-registry/docs/container-analysis)  after [scanning]((https://cloud.google.com/container-registry/docs/vulnerability-scanning) of container images stored in [Google Container Registry](https://cloud.google.com/container-registry).

The signer will attest whether the image conforms to the [signer policy](signer.md#vulnerability-signing-policy) you defined.

#### Supported key types

The GCR signer only supports the Google Cloud KMS key.

### Environment variables
The GCR Kritis signer follows the 12-factor application principles. It is configured
 via command options or one of the following environment variables:

| name                         | equivalent option  | description                                 | required |
| ---------------------------- | ----------------  | ------------------------------------------- | -------- |
| ATTESTATION\_NOTE\_NAME        | -note\_name        | name of the note to attest                  | yes |
| ATTESTATION\_KMS\_KEY          | -kms\_key\_name          | KMS key version to use to sign              | yes |
| ATTESTATION\_DIGEST\_ALGORITHM | -kms\_digest\_alg | digest algorithm used                       | yes |
| ATTESTATION\_PROJECT          | -attestation\_project          | GCP project to store attestation            | no, default it uses the image project |
| ATTESTATION\_OVERWRITE        | -overwrite        |overwrite existing attestations              | no, default false |
| ATTESTATION\_POLICY           | NA               | vulnerability policy document   | yes, if -policy is missing |

The command line option takes precedence over the corresponding environment variable.

### API specification
When running the signer in server mode, the following operations are available:

| path            | description               |
| --------------- | --------------------------|
| /check-only     | checks the specified image against the policy |
| /check-and-sign | checks and signs if the image passes the policy |
| /event          | if the event indicates the completion of a vulnerability scan, checks and signs the image |

Checkout the complete [open API specification](../cmd/kritis/gcr-signer/api-specification.yaml):

### sample check calls
/check-only and /check-and-sign accept the following request message:

```json
{
   "image": "gcr.io/project/alpine@sha256:f86657a463e3de9e5176e4774640c76399b2480634af97f45354f1553e372cc9",
}
```

If the image passes the policy the response message will be:
```json
{
    "image": "gcr.io/project/alpine@sha256:f86657a463e3de9e5176e4774640c76399b2480634af97f45354f1553e372cc9",
    "status": "ok"
}
```
If it does not pass the policy, the message will be.
```json
{
  "status": "failed",
  "image": "gcr.io/speeltuin-mvanholsteijn/a27@sha256:f86657a463e3de9e5176e4774640c76399b2480634af97f45354f1553e372cc9",
  "violations": [
    "found unfixable CVE projects/goog-vulnz/notes/CVE-2018-18344 in gcr.io/project/alpine@sha256:f86657a463e3de9e5176e4774640c76399b2480634af97f45354f1553e372cc9, which has severity MEDIUM exceeding max unfixable severity LOW",
    "found unfixable CVE projects/goog-vulnz/notes/CVE-2020-1751 in gcr.io/project/alpine@sha256:f86657a463e3de9e5176e4774640c76399b2480634af97f45354f1553e372cc9, which has severity MEDIUM exceeding max unfixable severity LOW",
  ]
}
```
### sample pub/sub event notification
/event accepts a normal pubsub event message:

```json
{
  "subscription": "vulnerability-attestor-container-analysis-occurrences",
  "message": {
    "data": "eyJuYW1lIjoicHJvamVjdHMvcHJvamVjdC9vY2N1cnJlbmNlcy9mNjJmMWU1MC1lMGUyLTQ3ZWYtOTI1ZC1iZDc5OTA1YWI4MmQiLCJraW5kIjoiRElTQ09WRVJZIiwibm90aWZpY2F0aW9uVGltZSI6IjIwMjAtMTEtMDZUMTU6MDM6NTAuNTMxMDgyWiJ9",
    "id": "1681150847368976"
  }
}
```

where the data will be provided by the container analysis service:
```json
{
  "name": "projects/project/occurrences/f62f1e50-e0e2-47ef-925d-bd79905ab82d",
  "kind": "DISCOVERY",
  "notificationTime": "2020-11-06T15:03:50.531082Z"
}
```

##  Installation

To install the kritis gcr signer:

1. Enable GCP services.

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
          run.googleapis.com \
          binaryauthorization.googleapis.com \
          cloudbuild.googleapis.com \
          containerregistry.googleapis.com \
          containeranalysis.googleapis.com \
          containerscanning.googleapis.com \
          cloudkms.googleapis.com # If using Cloud KMS
        ```

1. Build the grc signer container image.

    ```shell
   gcloud builds submit --config deploy/gcr-kritis-signer/cloudbuild.yaml .
    ```

1. Enable Google Cloud service accounts and Cloud IAM roles.

    1. Create a service account within the GCP project.

        ```shell
        export SA_NAME=vulnerability-policy-attestor
        gcloud iam service-accounts create ${SA_NAME}
        ```

    2. Add roles to the created service account.

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

1. Creating a signing key.

    To create attestations for an image, the signer requires a private signing key. Run the following commands
    to create a keyring and an asymmetric signing key, and save the KMS key name.

    ```shell
    gcloud kms keyrings create vulnerability-policy-attestors \
        --location global

    gcloud --project=$PROJECT_ID kms keys create passed-vulnerability-policy \
        --keyring vulnerability-policy-attestors \
        --location global \
        --purpose "asymmetric-signing" \
        --default-algorithm "rsa-sign-pkcs1-2048-sha256"
    ```

    Note down the digest algorithm “SHA256” and key name.

    ```shell
    export KMS_DIGEST_ALG=SHA256
    export KMS_KEY_NAME=projects/$PROJECT_ID/locations/global/keyRings/vulnerability-policy-attestors/cryptoKeys/passed-vulnerability-policy/cryptoKeyVersions/1
    ```

1. Create the attestor

    Create the attestor for the note by adding its public key.

    ```shell
    export NOTE_ID=passed-vulnerability-policy
    export NOTE_NAME=projects/${PROJECT_ID}/notes/${NOTE_ID}

    gcloud container binauthz attestors \
      create vulnerability-policy \
           --attestation-authority-note passed-vulnerability-policy \
           --attestation-authority-note-project $PROJECT_ID

    gcloud container binauthz attestors public-keys add \
      --attestor vulnerability-policy \
      --keyversion-location global \
      --keyversion-keyring vulnerability-policy-attestors \
      --keyversion-key passed-vulnerability-policy \
      --keyversion 1 \
      --project $PROJECT_ID
    ```

1. Create vulnerability signing policy.

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

1. Run the kritis gcr signer as a service

    1. Create the kritis-signer Cloud Run service:

        ```shell
             gcloud run deploy gcr-kritis-signer \
              --image  gcr.io/${PROJECT_ID}/gcr-kritis-signer:latest \
              --service-account ${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
              --set-env-vars "ATTESTATION_POLICY=$(cat samples/signer/policy.yaml)" \
              --timeout 2m \
              --allow-unauthenticated \
              --args="-vulnz_timeout=20s,-note_name=$NOTE_NAME,-kms_key_name=$KMS_KEY_NAME,-kms_digest_alg=$KMS_DIGEST_ALG"

            KRITIS_URL=$(gcloud run services describe gcr-kritis-signer --format 'value(status.url)')
       ```
       Note that this service can now be invoked by unauthenticated users. We recommend to secure this for a production deployment.

     2. subscribe to the container analysis occurrence notifications:

        ```shell
            gcloud pubsub subscriptions create gcr-kritis-signer \
                --topic container-analysis-occurrences-v1 \
                --push-endpoint $KRITIS_URL/event
        ```

Now the signer will automatically sign images after the vulnerability scan completes.

## examples

1. Run signer on a built image (pass example).

    1. Build and push an example good image.

        ```shell
        docker build -t gcr.io/$PROJECT_ID/signer-test:good -f samples/signer/Dockerfile.good samples/signer
        docker push gcr.io/$PROJECT_ID/signer-test:good
        ```


    2. Note down the image digest url.

        ```shell
        export GOOD_IMG_URL=$(docker image inspect gcr.io/$PROJECT_ID/signer-test:good --format '{{index .RepoDigests 0}}')
        ```

    3. wait until you see the attestation appear

         ```shell
         gcloud container binauthz attestations list \
             --artifact-url $GOOD_IMG_URL  \
             --attestor vulnerability-policy
         ```

     3. you can also request a manual check by calling the service:

        ```shell
        curl -d @- $KRITIS_URL/check-only <<!
        {"image": "$GOOD_IMG_URL"}
        !
        ```

     4. or request a check-and-sign:

        ```shell
        curl -d @- $KRITIS_URL/check-and-sign <<!
        {"image": "$GOOD_IMG_URL"}
        !
        ```

1. Run signer on a built image (fail example).

    1. Build and push an example good image.

        ```shell
        docker build -t gcr.io/$PROJECT_ID/signer-test:bad -f samples/signer/Dockerfile.bad samples/signer
        docker push gcr.io/$PROJECT_ID/signer-test:bad
        ```

    2. Get the image digest url.

        ```shell
        export BAD_IMG_URL=$(docker image inspect gcr.io/$PROJECT_ID/signer-test:bad --format '{{index .RepoDigests 0}}')
        ```

        in this case, no attestation will appear.

         ```shell
         gcloud container binauthz attestations list \
             --artifact-url $BAD_IMG_URL  \
             --attestor vulnerability-policy
         ```

     3. you can request a manual check to see the errors:

        ```shell
        curl -d @- $KRITIS_URL/check-only <<!
        {"image": "$BAD_IMG_URL"}
        !
        ```

     4. attempt to request a manual check-and-sign, will fail too:

        ```shell
        curl -d @- $KRITIS_URL/check-and-sign <<!
        {"image": "$BAD_IMG_URL"}
        !
        ```
