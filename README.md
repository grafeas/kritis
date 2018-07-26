# Kritis

Kritis (“judge” in Greek), provides full software supply chain security for Kubernetes applications,
allowing devOps teams to enforce deploy-time image security policies using metadata and attestations stored in [Grafeas](https://github.com/grafeas/grafeas).

You can read the [Kritis whitepaper](https://github.com/Grafeas/Grafeas/blob/master/case-studies/binary-authorization.md) for more details.

Note: Currently kritis doesn't use grafeas and pulls vulnerability informtation via the [Container Analysis API](https://cloud.google.com/container-analysis/api/reference/rest/).

## Installing Kritis

Instructions for installing kritis on your cluster via helm can be found [here](https://github.com/grafeas/kritis/blob/master/kritis-charts/README.md).

Installing Kritis, creates a number of resources in your cluster. Mentioned below are important ones.

| Resource Name | Resource Kind | Description |
|---------------|---------------|----------------|
| kritis-validation-hook| ValidatingWebhookConfiguration | This is Kubernetes [Validating Admission Webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers) which enforces the policies. |
| imagesecuritypolicies.kritis.grafeas.io | crd | This CRD defines the image security policy kind ImageSecurityPolicy.|
| attestationauthorities.kritis.grafeas.io | crd | The CRD defines the attestation authority policy kind AttestationAuthority.|
| tls-webhook-secret | secret | Secret required for ValidatingWebhookConfiguration|


## Description of Resources.
### kritis-validation-hook
The validating admission Webhook runs a https service and a background cron job.
The webhook, runs when pods and deployments are created or updated in your cluster.
To view webhook, run
```
kubectl describe ValidatingWebhookConfiguration kritis-validation-hook
```
The cron job runs hourly to continuously validate and reconcile policies. It adds labels and annotations to pods out of policy.

### ImageSecurityPolicy CRD
ImageSecurityPolicy is Custom Resource Definition which enforce policies.
The ImageSecurityPolicy are Namespace Scoped meaning, it will only be verified against pods in the same namespace.
You can deploy multiple ImageSecurityPolicies in different namespaces, ideally one per namespace.

To view the image security policy run,
```
kubectl describe crd imagesecuritypolicies.kritis.grafeas.io

# To list all Image Security Policies.
kubectl get ImageSecurityPolicy --all-namespaces
NAMESPACE             NAME      AGE
example-namespace     my-isp    22h
qa                    qa-isp    11h
```

A sample is shown here,
```yaml
apiVersion: kritis.github.com/v1beta1
kind: ImageSecurityPolicy
metadata:
    name: my-isp
    namespace: example-namespace
spec:
  imageWhitelist:
  - gcr.io/my-project/whitelist-image@sha256:<DIGEST>
  packageVulnerabilityPolicy:
    maximumSeverity: MEDIUM
    onlyFixesNotAvailable: YES
    whitelistCVEs:
      providers/goog-vulnz/notes/CVE-2017-1000082
      providers/goog-vulnz/notes/CVE-2017-1000082
```
Image Security Policy Spec description:
| Field | Default  (if applicable)   | Description |
|-----------|-------------|-------------|
|imageWhitelist | | List of images that are whitelisted and are not inspected by Admission Controller.|
|packageVulnerabilityPolicy.whitelistCVEs |  | List of CVEs which will be ignored.|
|packageVulnerabilityPolicy.maximumSeverity| CRITICAL|Defines the tolerance level for vulnerability found in the container image.|
|packageVulnerabilityPolicy.onlyFixesNotAvailable|  true |when set to "true" only allow packages with vulnerabilities that have fixes out.|

Here are the valid values for Policy Specs.

|<td rowspan=1>Field | Value       | Outcome |
|----------- |-------------|----------- |
|<td rowspan=5>packageVulnerabilityPolicy.maximumSeverity | LOW | Only allow containers with Low Vulnz. |
|                          | MEDIUM | Allow Containers with Low and Medium Vulnz. |
|                                           | HIGH  | Allow Containers with Low, Medium & High Vulnz. |
|                                           | CRITICAL |  Allow Containers with all Vulnz |
|                                           | BLOCKALL | Block any Vulnz except listed in whitelist. |
|<td rowspan=2>packageVulnerabilityPolicy.onlyFixesNotAvailable | true | Only all containers with vulnz not fixed |
|                                      | false  | All containers with vulnz fixed or not fixed.|


### AttestationAuthority CRD
The webhook will attest valid images once they pass the validity check. This is important because re-deployments can occur from scaling events,rescheduling, termination, etc. Attested images are always admitted in custer.
This allows users to manually deploy a container with an older image which was validated in past.

To view the attesation authority CRD run,
```
kubectl describe crd attestationauthorities.kritis.grafeas.io

# List all attestation authorities.
kubectl get AttestationAuthority --all-namespaces
NAMESPACE             NAME             AGE
qa                    qa-attestator    11h
```

Here is an example of AttestionAuthority.
```yaml
apiVersion: kritis.github.com/v1beta1
kind: AttestationAuthority
metadata:
    name: qa-attestator
    namespace: qa
spec:
    noteReference: v1alpha1/projects/image-attestor
    privateKeySecretName: foo
    publicKeyData: ...
```
Where “image-attestor” is the project for creating AttestationAuthority Notes.
In order to create notes, the service account `gac-ca-admin` must have containeranalysis.notes.attacher role on this project.
The Kubernetes secret "foo" must have data fields "private" and "public" which contain the gpg private and public key respectively.

To create a gpg public, private key pair run,
```
$gpg --quick-generate-key --yes kritis.attestor@example.com

$gpg --armor --export kritis.attestor@example.com > gpg.pub

$gpg --list-keys kritis.attestor@example.com
pub   rsa3072 2018-06-14 [SC] [expires: 2020-06-13]
      C8C9D53FAE035A650B6B12D3BFF4AC9F1EED759C
uid           [ultimate] kritis.attestor@example.com
sub   rsa3072 2018-06-14 [E]

$gpg --export-secret-keys --armor C8C9D53FAE035A650B6B12D3BFF4AC9F1EED759C > gpg.priv
```

Now create a secret using the exported public and private keys
```
kubectl create secret foo --from-file=public=gpg.pub --from-file=private=gpg.priv
```
The publicKeyData is the base encoded PEM public key.
```
cat gpg.pub | base64
```

## Kritis Tutorial

### 1. Setting up an ImageSecurityPolicy

Kritis relies on user defined `ImageSecurityPolicies` to determine whether a pod should be admitted or denied at deploy time.

First, you will need to create an `ImageSecurityPolicy`.
```shell
cat <<EOF | kubectl apply -f - \

apiVersion: kritis.grafeas.io/v1beta1
kind: ImageSecurityPolicy
metadata:
  name: my-isp
  namespace: default
spec:
  imageWhitelist:
  - gcr.io/kritis-int-test/nginx-digest-whitelist:latest
  - gcr.io/kritis-int-test/nginx-digest-whitelist@sha256:56e0af16f4a9d2401d3f55bc8d214d519f070b5317512c87568603f315a8be72
  packageVulnerabilityRequirements:
    maximumSeverity: HIGH
    onlyFixesNotAvailable: true
    whitelistCVEs:
      - providers/goog-vulnz/notes/CVE-2017-1000082
      - providers/goog-vulnz/notes/CVE-2017-1000081
EOF
```

The `ImageSecurityPolicy` should be configured:
```shell
imagesecuritypolicy.kritis.grafeas.io/my-isp configured
```
This `ImageSecurityPolicy` specifies two `nginx` images that are whitelisted and should always be allowed entry.
It sets the maximum CVE severity allowed in any image to `HIGH`, and whitelists two CVEs which should be ignored during validation.
It also sets `onlyFixesNotAvailable: true`, meaning that images that contain CVEs with fixes available should be denied.

### 2. Deploying An Image With Vulnerabilities
Now that we have kritis installed and an `ImageSecurityPolicy` to validate against, we can go ahead and start deploying some images!

First, let's try to deploy a java image:
```shell
cat <<EOF | kubectl apply -f - \

apiVersion: v1
kind: Pod
metadata:
  name: java-with-vuln
spec:
  containers:
  - name: java-with-vuln
    image: gcr.io/kritis-int-test/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
    ports:
    - containerPort: 80
EOF
```

You should see an error:
```shell
Error from server: error when creating "integration/testdata/java/java-with-vuln.yaml ": admission webhook
"kritis-validation-hook.grafeas.io" denied the request: found violations in
gcr.io/kritis-int-test/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
```

Kritis denied this pod deployment because violations not allowed by the `ImageSecurityPolicy` were found in the image.

### 3. Checking Kritis Logs

We can learn more about why a deployment failed by looking at logs for the kritis validation hook pod.
```
$ kubectl get pods
NAME                                      READY     STATUS    RESTARTS   AGE
kritis-validation-hook-56d9d7d4f5-54mqt   1/1       Running   0          3m
$ kubectl logs -f kritis-validation-hook-56d9d7d4f5-54mqt
    ...
    found CVE projects/goog-vulnz/notes/CVE-2013-7445 in gcr.io/kritis-int-test/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
        which has fixes available
    found CVE projects/goog-vulnz/notes/CVE-2015-8985 in gcr.io/kritis-int-test/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
        which has fixes available

```
The logs show that this image contains CVEs with fixes available.
Since our `ImageSecurityPolicy` was configured to deny such images, our request to deploy this pod was denied.

### 4. Force Deployment With a Breakglass Annotation
Say we want to force deploy this image even though it doesn't pass validation checks.

We can add a breakglass annotation to the pod spec which instructs kritis to always allow the pod:

```shell
cat <<EOF | kubectl apply -f - \

apiVersion: v1
kind: Pod
metadata:
  name: java-with-vuln
  annotations: {
    "kritis.grafeas.io/breakglass": "true"
  }
spec:
  containers:
  - name: java-with-vuln
    image: gcr.io/kritis-int-test/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
    ports:
    - containerPort: 80
EOF
```

The pod should be created:
```shell
pod/java-with-vuln created
```
### 5. Deploying a Tagged Image
Kritis expects all images it inspects to be fully qualified with a digest, since it can't retrieve vulnerability information for tagged images.

We can try to deploy a tagged image:
```shell
cat <<EOF | kubectl apply -f - \

apiVersion: v1
kind: Pod
metadata:
  name: nginx-no-digest
spec:
  containers:
  - name: nginx-no-digest
    image: gcr.io/kritis-int-test/nginx-no-digest:latest
    ports:
    - containerPort: 80
EOF
```
which should result in an error:
```shell
"kritis-validation-hook.grafeas.io" denied the request: gcr.io/kritis-int-test/nginx-no-digest:latest
    is not a fully qualified image
```

### 6. Deploying a Tagged Whitelisted Image

To deploy a tagged image, you can add that image to the `imageWhitelist` in your `ImageSecurityPolicy`.

We can try to deploy a tagged whitelisted image:
```shell
cat <<EOF | kubectl apply -f - \

apiVersion: v1
kind: Pod
metadata:
  name: nginx-no-digest-whitelist
spec:
  containers:
  - name: nginx-no-digest-whitelist
    image: gcr.io/kritis-int-test/nginx-digest-whitelist:latest
    ports:
    - containerPort: 80
EOF
```

The pod should be created:
```shell
pod/nginx-no-digest-whitelist created
```

That brings us to the end of the tutorial!

## Qualifying Images with Resolve-Tags
When deploying pods, images must be fully qualified with digests.
This is necessary because tags are mutable, and kritis may not get the correct vulnerability information for a tagged image.

We provide [resolve-tags](https://github.com/grafeas/kritis/blob/master/cmd/kritis/kubectl/plugins/resolve/README.md), which can be run as a kubectl plugin or as a standalone binary to resolve all images from tags to digests in Kubernetes yamls.

