# Resource Reference

Installing Kritis, creates a number of resources in your cluster. Here are the most important ones:

| Resource Name | Resource Kind | Description |
|---------------|---------------|----------------|
| kritis-validation-hook| ValidatingWebhookConfiguration | This is Kubernetes [Validating Admission Webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers) which enforces the policies. |
| genericattestationpolicies.kritis.grafeas.io | crd | This CRD defines the generic attestation policy kind GenericAttestationPolicy.|
| imagesecuritypolicies.kritis.grafeas.io | crd | This CRD defines the image security policy kind ImageSecurityPolicy.|
| attestationauthorities.kritis.grafeas.io | crd | The CRD defines the attestation authority policy kind AttestationAuthority.|
| tls-webhook-secret | secret | Secret required for ValidatingWebhookConfiguration|

## kritis-validation-hook

The validating admission Webhook runs a https service and a background cron job.
The webhook, runs when pods and deployments are created or updated in your cluster.
To view webhook, run

```shell
kubectl describe ValidatingWebhookConfiguration kritis-validation-hook
```

The cron job validates and reconcile policies on an hourly basis, and adds labels and annotations to pods out of policy. You may force it to run via:

```shell
kubectl exec -l label=kritis-validation-hook -- /kritis/kritis-server --run-cron
```

To view the list of pods it has annotated:

```shell
kubetl get pods -l kritis.grafeas.io/invalidImageSecPolicy=invalidImageSecPolicy
```

## GenericAttestationPolicy CRD

GenericAttestationPolicy (GAP) is a Custom Resource Definition which enforces policies based on pre-existing attestations.
The policy expects any one attestation authority to be satisfied before allowing the container image to be admitted.
As opposed to [ISPs](#imagesecuritypolicy-crd) the GAP does not create new attestations.
The general use case for GAPs are to have a policy that enforces attestations that have come from your CI pipeline, or other places in your release pipeline.

The policy is scoped to the Kubernetes namespace, so the policies can be different per namespace.

Example policy:

```yaml
apiVersion: kritis.grafeas.io/v1beta1
kind: GenericAttestationPolicy
metadata:
  name: my-gap
  namespace: default
spec:
  attestationAuthorityNames:
  - kritis-authority
```

To view the CRD:

```shell
kubectl describe crd genericattestationpolicies.kritis.grafeas.io
```

To list all Generic Attestation Policies.

```shell
kubectl get GenericAttestationPolicy --all-namespaces
```

Example output:

```shell
NAMESPACE             NAME      AGE
gap-namespace         my-gap    2d
qa                    qa-gap    1h
```

To view the active Generic Attestation Policy:

```shell
kubectl describe GenericAttestationPolicy my-gap
```

Generic Attestation Policy Spec description:

| Field     | Default (if applicable)   | Description |
|-----------|---------------------------|-------------|
| attestationAuthorityNames | | List of [Attestation Authorities](#attestationauthority-crd) for which one of is required to be satisfied before the Admission Controller will admit the pod.|

## ImageSecurityPolicy CRD

ImageSecurityPolicy (ISP) is Custom Resource Definition which enforces policies.
The ImageSecurityPolicy are Namespace Scoped meaning, it will only be verified against pods in the same namespace.
You can deploy multiple ImageSecurityPolicies in different namespaces, ideally one per namespace.

Example policy:

```yaml
apiVersion: kritis.github.com/v1beta1
kind: ImageSecurityPolicy
metadata:
    name: my-isp
    namespace: example-namespace
spec:
  imageAllowlist:
  - gcr.io/my-project/allowlist-image@sha256:<DIGEST>
  packageVulnerabilityPolicy:
    maximumSeverity: MEDIUM
    allowlistCVEs:
      - providers/goog-vulnz/notes/CVE-2017-1000082
      - providers/goog-vulnz/notes/CVE-2017-1000081
```

To view the CRD:

```shell
kubectl describe crd imagesecuritypolicies.kritis.grafeas.io
```

To list all Image Security Policies.

```shell
kubectl get ImageSecurityPolicy --all-namespaces
```

Example output:

```shell
NAMESPACE             NAME      AGE
example-namespace     my-isp    22h
qa                    qa-isp    11h
```

To view the active ImageSecurityPolicy:

```shell
kubectl describe ImageSecurityPolicy my-isp
```

Image Security Policy Spec description:

| Field     | Default (if applicable)   | Description |
|-----------|---------------------------|-------------|
|imageAllowlist | | List of images that are allowlisted and are not inspected by Admission Controller.|
|packageVulnerabilityPolicy.allowlistCVEs |  | List of CVEs which will be ignored.|
|packageVulnerabilityPolicy.maximumSeverity| ALLOW_ALL | Tolerance level for vulnerabilities found in the container image.|
|packageVulnerabilityPolicy.maximumFixUnavailableSeverity |  ALLOW_ALL | The tolerance level for vulnerabilities found that have no fix available.|

Here are the valid values for Policy Specs.

|Field | Value       | Outcome |
|----------- |-------------|----------- |
|packageVulnerabilityPolicy.maximumSeverity | LOW | Only allow containers with low vulnerabilities. |
|                          | MEDIUM | Allow Containers with Low and Medium vulnerabilities. |
|                                           | HIGH  | Allow Containers with Low, Medium & High vulnerabilities. |
|                                           | ALLOW_ALL | Allow all vulnerabilities.  |
|                                           | BLOCK_ALL | Block all vulnerabilities except listed in allowlist. |
|packageVulnerabilityPolicy.maximumFixUnavailableSeverity | LOW | Only allow containers with low unpatchable vulnerabilities. |
|                          | MEDIUM | Allow Containers with Low and Medium unpatchable vulnerabilities. |
|                                           | HIGH  | Allow Containers with Low, Medium & High  unpatchable vulnerabilities. |
|                                           | ALLOW_ALL | Allow all unpatchable vulnerabilities.  |
|                                           | BLOCK_ALL | Block all unpatchable vulnerabilities except listed in allowlist. |

## AttestationAuthority CRD

The webhook will attest valid images once they pass the validity check. This is important because re-deployments can occur from scaling events,rescheduling, termination, etc. Attested images are always admitted in custer.
This allows users to manually deploy a container with an older image which was validated in past.

To view the attesation authority CRD run,

```shell
kubectl describe crd attestationauthorities.kritis.grafeas.io
```

To list all attestation authorities:

```shell
kubectl get AttestationAuthority --all-namespaces
```

Here is example output:

```shell
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
    noteReference: projects/image-attestor/notes/qa-note
    privateKeySecretName: foo
    publicKeyData: ...
```

Where “image-attestor” is the project for creating AttestationAuthority Notes.

In order to create notes, the service account `gac-ca-admin` must have `containeranalysis.notes.attacher role` on this project.

The Kubernetes secret `foo` must have data fields `private` and `public` which contain the gpg private and public key respectively.

`publicKeyData` is the base encoded PEM public key for the gpg secret.
