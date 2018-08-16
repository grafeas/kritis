# Usage

## resolve-tags plugin

See the [resolve-tags plug-in guide](https://github.com/grafeas/kritis/blob/master/cmd/kritis/kubectl/plugins/resolve/README.md)

## Resource Reference

Installing Kritis, creates a number of resources in your cluster. Mentioned below are important ones.

| Resource Name | Resource Kind | Description |
|---------------|---------------|----------------|
| kritis-validation-hook| ValidatingWebhookConfiguration | This is Kubernetes [Validating Admission Webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers) which enforces the policies. |
| imagesecuritypolicies.kritis.grafeas.io | crd | This CRD defines the image security policy kind ImageSecurityPolicy.|
| attestationauthorities.kritis.grafeas.io | crd | The CRD defines the attestation authority policy kind AttestationAuthority.|
| tls-webhook-secret | secret | Secret required for ValidatingWebhookConfiguration|

### kritis-validation-hook

The validating admission Webhook runs a https service and a background cron job.
The webhook, runs when pods and deployments are created or updated in your cluster.
To view webhook, run

```shell
kubectl describe ValidatingWebhookConfiguration kritis-validation-hook
```

The cron job runs hourly to continuously validate and reconcile policies. It adds labels and annotations to pods out of policy.

### ImageSecurityPolicy CRD

ImageSecurityPolicy is Custom Resource Definition which enforce policies.
The ImageSecurityPolicy are Namespace Scoped meaning, it will only be verified against pods in the same namespace.
You can deploy multiple ImageSecurityPolicies in different namespaces, ideally one per namespace.

To view the image security policy run,

```shell
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
    whitelistCVEs:
      providers/goog-vulnz/notes/CVE-2017-1000082
      providers/goog-vulnz/notes/CVE-2017-1000082
```

Image Security Policy Spec description:

| Field     | Default (if applicable)   | Description |
|-----------|---------------------------|-------------|
|imageWhitelist | | List of images that are whitelisted and are not inspected by Admission Controller.|
|packageVulnerabilityPolicy.whitelistCVEs |  | List of CVEs which will be ignored.|
|packageVulnerabilityPolicy.maximumSeverity| ALLOW_ALL | Tolerance level for vulnerabilities found in the container image.|
|packageVulnerabilityPolicy.maximumFixUnavailableSeverity |  ALLOW_ALL | The tolerance level for vulnerabilities found that have no fix available.|

Here are the valid values for Policy Specs.

|<td rowspan=1>Field | Value       | Outcome |
|----------- |-------------|----------- |
|<td rowspan=5>packageVulnerabilityPolicy.maximumSeverity | LOW | Only allow containers with low vulnerabilities. |
|                          | MEDIUM | Allow Containers with Low and Medium vulnerabilities. |
|                                           | HIGH  | Allow Containers with Low, Medium & High vulnerabilities. |
|                                           | ALLOW_ALL | Allow all vulnerabilities.  |
|                                           | BLOCK_ALL | Block all vulnerabilities except listed in whitelist. |
|<td rowspan=5>packageVulnerabilityPolicy.maximumFixUnavailableSeverity | LOW | Only allow containers with low unpatchable vulnerabilities. |
|                          | MEDIUM | Allow Containers with Low and Medium unpatchable vulnerabilities. |
|                                           | HIGH  | Allow Containers with Low, Medium & High  unpatchaable vulnerabilities. |
|                                           | ALLOW_ALL | Allow all unpatchable vulnerabilities.  |
|                                           | BLOCK_ALL | Block all unpatchable vulnerabilities except listed in whitelist. |

### AttestationAuthority CRD

The webhook will attest valid images once they pass the validity check. This is important because re-deployments can occur from scaling events,rescheduling, termination, etc. Attested images are always admitted in custer.
This allows users to manually deploy a container with an older image which was validated in past.

To view the attesation authority CRD run,

```shell
kubectl describe crd attestationauthorities.kritis.grafeas.io
```

List all attestation authorities:

```shell
kubectl get AttestationAuthority --all-namespaces
NAMESPACE             NAME             AGE
qa                    qa-attestator    11h
```

example AttestionAuthority:

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

In order to create notes, the service account `gac-ca-admin` must have `containeranalysis.notes.attacher role` on this project.

The Kubernetes secret `foo` must have data fields `private` and `public` which contain the gpg private and public key respectively.

`publicKeyData` is the base encoded PEM public key for the gpg secret.
