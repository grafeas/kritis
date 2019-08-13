# Kritis Tutorial

## Before you begin

[Install Kritis](install.md) to your cluster.

## Pod Deployment using ImageSecurityPolicy

1. Define an ImageSecurityPolicy.

    Kritis relies on a user-defined *ImageSecurityPolicy* (ISP) to determine whether a pod meets the criteria for deployment. Create an ISP that restricts Kubernetes from deploying a HIGH severity vulnerability, unless it is within a set of allowlisted [CVEs](https://cve.mitre.org/):

    ```shell
    cat <<EOF | kubectl apply -f - \

    apiVersion: kritis.grafeas.io/v1beta1
    kind: ImageSecurityPolicy
    metadata:
      name: my-isp
      namespace: default
    spec:
      packageVulnerabilityRequirements:
        maximumSeverity: MEDIUM
        allowlistCVEs:
          - providers/goog-vulnz/notes/CVE-2017-1000081
    EOF
    ```

1. Set up an AttestationAuthority.

    Kritis relies on user-defined AttestationAuthorities to attest images to be admitted.
    Once an image is attested, it will always be (re-)admitted in the future.

    1. Create a public and private key pair. You'll be prompted to create a
       passphrase. Make sure to save it to the `PHRASE` environment variable.

        Generate new key with `gpg` and extract its fingerprint.
        ```shell
        GPG_OUTPUT="$(gpg --quick-generate-key --yes attestor@example.com)"
        KEY_FINGERPRINT="$(echo $GPG_OUTPUT | sed -n 's/.*\([A-Z0-9]\{40\}\).*/\1/p')"
        ```
        Check that the 40-digit fingerprint is correctly extracted.
        ```
        echo $KEY_FINGERPRINT
        ```
        Export the key.
        ```
        gpg --armor --export $KEY_FINGERPRINT gpg.pub
        gpg --armor --export-secret-keys $KEY_FINGERPRINT > gpg.priv
        PHRASE=<passphrase you chose>
        ```

        If you use Ubuntu on GCP and got hung in above, then see
        [these instructions](https://delightlylinux.wordpress.com/2015/07/01/is-gpg-hanging-when-generating-a-key/)
        to make sure you got enough entropy.

    1. Set the base64 encoded value of the public key for the secret you just created. On Mac OS X:

        ```shell
        PUBLIC_KEY=`base64 gpg.pub`
        ```

        On Linux:

        ```shell
        PUBLIC_KEY=`base64 gpg.pub -w 0`
        ```

    1. Create a k8s secret using the exported public and private keys and the
       passphrase:

        ```shell
        kubectl create secret generic my-attestor --from-file=public=gpg.pub --from-file=private=gpg.priv --from-literal=passphrase=${PHRASE}
        ```

    1. Create an attestation authority:

        ```shell
        cat <<EOF | kubectl apply -f - \

        apiVersion: kritis.grafeas.io/v1beta1
        kind: AttestationAuthority
        metadata:
            name: my-attestor
            namespace: default
        spec:
            noteReference: v1beta1/projects/$PROJECT
            privateKeySecretName: my-attestor
            publicKeyData: $PUBLIC_KEY
        EOF
        ```

        This `AttestationAuthority` will create [Attestation Note](https://github.com/grafeas/grafeas#definition-of-terms) in project specified in `$PROJECT` variable and attest valid images using the secret `my-attestor` which we created.

1. Copy a vulnerable image.

    The [Container Analysis API](https://cloud.google.com/container-analysis/api/reference/rest/)
    only reveals vulnerability information for images owned by your project.
    This makes a copy of a sample vulnerable image into your container registry:

    ```shell
    gcloud container images add-tag \
      gcr.io/kritis-tutorial/java-with-vulnz:latest \
      gcr.io/$PROJECT/java-with-vulnz:latest
    ```

    It will take a moment to scan the image, but once this command outputs a long list of vulnerabilities, you are ready to proceed:

    ```shell
    gcloud alpha container images describe --show-package-vulnerability \
      gcr.io/$PROJECT/java-with-vulnz:latest
    ```

    For more information about copying images, see
    [Google Cloud: Pushing and Pulling Images](https://cloud.google.com/container-registry/docs/pushing-and-pulling).

1. Deploy a pod containing the vulnerable image:

    ```shell
    cat <<EOF | kubectl apply -f - \

    apiVersion: v1
    kind: Pod
    metadata:
      name: java-with-vulnz
      labels: {
        "kritis.grafeas.io/tutorial":""
      }
    spec:
      containers:
      - name: java-with-vulnz
        image: gcr.io/$PROJECT/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a
        ports:
        - containerPort: 80
    EOF
    ```

    The following error will appear:

    ```shell
    "kritis-validation-hook.grafeas.io" denied the request: found violations in gcr.io/$PROJECT/java-with-vulnz@sha256:<hash>
    ```

    Learn more by inspecting the *kritis-validation-hook* logs:

    ```shell
    kubectl logs -l app=kritis-validation-hook
    ```

    Example:

    ```shell
    kubectl get pods
    NAME                                      READY     STATUS    RESTARTS   AGE
    kritis-validation-hook-56d9d7d4f5-54mqt   1/1       Running   0          3m
    ```

    ```shell
    kubectl logs -f kritis-validation-hook-56d9d7d4f5-54mqt
    ...
    found CVE projects/goog-vulnz/notes/CVE-2013-7445 in gcr.io/$PROJECT/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a
    which has fixes available
    found CVE projects/goog-vulnz/notes/CVE-2015-8985 in gcr.io/$PROJECT/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a
    which has fixes available
    ```

1. Deploying an image by tag name:

    ```shell
    cat <<EOF > resolve.yaml

    apiVersion: v1
    kind: Pod
    metadata:
      name: java-with-vulnz-tagged
      labels: {
        "kritis.grafeas.io/tutorial":""
      }
    spec:
      containers:
      - name: java-with-vulnz-tagged
        image: gcr.io/$PROJECT/java-with-vulnz:latest
        ports:
        - containerPort: 80
    EOF
    ```

    Apply the YAML:

    ```shell
    kubectl apply -f resolve.yaml
    ```

    Unless the tag is specifically in the allowlist, the following error will be displayed:

    ```shell
    admission webhook "kritis-validation-hook.grafeas.io" denied the request: gcr.io/kritis-doc-test/java-with-vulnz:latest is not a fully qualified image
    ```

    Instead, to deploy images by a tag name, use the `resolve-tags` plugin:

    TODO(tstromberg): Document how to solve UNAUTHORIZED errors here.

    ```shell
    kubectl plugin resolve-tags -f resolve.yaml --apply true
    ```

1. Add an image to allowlist:

    ```shell
    cat <<EOF | kubectl apply -f - \

    apiVersion: kritis.grafeas.io/v1beta1
    kind: ImageSecurityPolicy
    metadata:
      name: my-isp
      namespace: default
    spec:
      imageAllowlist:
        - gcr.io/$PROJECT/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a
      packageVulnerabilityRequirements:
        maximumSeverity: MEDIUM
        allowlistCVEs:
          - providers/goog-vulnz/notes/CVE-2017-1000081
    EOF
    ```

1. Deploy the `java-with-vulnz` pod with the allowlist in place:

    ```shell
    cat <<EOF | kubectl apply -f - \

    apiVersion: v1
    kind: Pod
    metadata:
      name: java-with-vulnz-allowlist
      labels: {
        "kritis.grafeas.io/tutorial":""
      }
    spec:
      containers:
      - name: java-with-vulnz-allowlist
        image: gcr.io/$PROJECT/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a
        ports:
        - containerPort: 80
    EOF
    ```

1. Force deployment with a breakglass annotation.

    Rather than adding an image to allowlist, you can also force a deployment
    that normally fails validation, by adding a *breakglass* annotation to the pod spec:

    ```shell
    cat <<EOF | kubectl apply -f - \

    apiVersion: v1
    kind: Pod
    metadata:
      name: java-with-vulnz-breakglass
      labels: {
        "kritis.grafeas.io/tutorial":""
      }
      annotations: {
        "kritis.grafeas.io/breakglass": "true"
      }
    spec:
      containers:
      - name: java-with-vulnz-breakglass
        image: gcr.io/$PROJECT/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a
        ports:
        - containerPort: 80
    EOF
    ```

    The annotation can also be provided for a deployment:

    ```shell
    cat <<EOF | kubectl apply -f - \

    apiVersion: apps/v1beta1
    kind: Deployment
    metadata:
      name: java-with-vulnz-breakglass-deployment
      labels: {
        "kritis.grafeas.io/tutorial":""
      }
      annotations: {
        "kritis.grafeas.io/breakglass": "true"
      }
    spec:
      replicas: 2
      template:
        metadata:
          labels:
            app: java-with-vulnz
        spec:
          containers:
          - name: java-with-vulnz
            image: gcr.io/$PROJECT/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a
            ports:
            - containerPort: 80
    EOF
    ```

### Kritis Background Cron

Kritis also runs a hourly cron in background to continuously validate and reconcile policies. Images can go out of policy while running.

This cron uses the same policies as the webhook, and will audit via adding a label `kritis.grafeas.io/invalidImageSecPolicy` and an annotation `kritis.grafeas.io/invalidImageSecPolicy` with reason.

To run the cron in foreground:

```shell
POD_ID=$(kubectl get po -l label=kritis-validation-hook -o custom-columns=:metadata.name --no-headers=true)
kubectl exec $POD_ID -- /kritis/kritis-server --run-cron
```

The output is similar to this:

```shell
I0810 23:46:10.353516      23 cron.go:103] Checking po java-with-vulnz
I0810 23:46:10.354142      23 review.go:68] Validating against ImageSecurityPolicy my-isp
I0810 23:46:10.354395      23 review.go:70] Check if gcr.io/tejaldesai-personal/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a as valid Attestations.
I0810 23:46:10.881752      23 strategy.go:98] Adding label attested and annotation Previously attested.
I0810 23:46:10.997035      23 review.go:77] Getting vulnz for gcr.io/tejaldesai-personal/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a
I0810 23:46:12.743845      23 strategy.go:81] Adding label invalidImageSecPolicy and annotation found 3 CVEs
E0810 23:46:12.882533      23 cron.go:105] found violations in gcr.io/tejaldesai-personal/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a
...
```

To view the pods with `kritis.grafeas.io/invalidImageSecPolicy` label:

```shell
 kubectl get po  -l kritis.grafeas.io/invalidImageSecPolicy=invalidImageSecPolicy --show-labels
```

The output is similar to this:

```shell
NAME               READY     STATUS             RESTARTS   AGE       LABELS
java-with-vulnz     0/1       Completed          10         29m       kritis.grafeas.io/attestation=attested,kritis.grafeas.io/invalidImageSecPolicy=invalidImageSecPolicy
kritis-predelete   0/1       Completed          0          34m       kritis.grafeas.io/attestation=notAttested,kritis.grafeas.io/invalidImageSecPolicy=invalidImageSecPolicy
```

That brings us to the end of the tutorial!

## Cleanup

You can delete all pods and deployments created in this tutorial by running:

```
kubectl delete pods,deployments --selector=kritis.grafeas.io/tutorial
```

To delete the image you pushed to your project run:

```
gcloud container images delete gcr.io/$PROJECT/java-with-vulnz:latest
```

You can uninstall kritis by following these [instructions](install.md#Uninstalling-Kritis).
