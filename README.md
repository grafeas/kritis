# Kritis

Kritis (“judge” in Greek), provides full software supply chain security for Kubernetes applications,
allowing devOps teams to enforce deploy-time image security policies using metadata and attestations stored in [Grafeas](https://github.com/grafeas/grafeas).

You can read the [Kritis whitepaper](https://github.com/Grafeas/Grafeas/blob/master/case-studies/binary-authorization.md) for more details.

Note: Currently kritis doesn't use grafeas and pulls vulnerability informtation via the [Container Analysis API](https://cloud.google.com/container-analysis/api/reference/rest/).

## Installing Kritis

Instructions for installing kritis on your cluster via helm can be found [here](https://github.com/grafeas/kritis/blob/master/kritis-charts/README.md).

## Kritis Tutorial

### Setting up an ImageSecurityPolicy

Kritis relies on user defined `ImageSecurityPolicies` to determine whether a pod should be admitted or denied at deploy time.
First, create the `ImageSecurityPolicy` CRD (custom resource definition).

```
$ kubectl create -f artifacts/image-security-policy-crd.yaml
    customresourcedefinition.apiextensions.k8s.io "imagesecuritypolicies.kritis.grafeas.io" created
```

The user then needs to specify an `ImageSecurityPolicy`. 
A sample is shown here:
```yaml
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
```
| Field         | Possible Values           | Details  |
| ------------- | ------------- | ----- |
| imageWhitelist  | | A list of images that are whitelisted and should always be allowed. |
| maximumSeverity | LOW/MEDIUM/HIGH/CRITICAL/BLOCKALL |   The maximum CVE severity allowed in an image. An image with CVEs exceeding this limit will result in the pod being denied. `BLOCKALL` will block an image with any CVEs that aren't whitelisted.|
| onlyFixesNotAvailable | true/false | When set to true, any images that contain CVEs with fixes available will be denied. |
| whitelistCVEs |     | Ignore these CVEs when deciding whether to allow or deny a pod. |

Create your image security policy:
```
$ kubectl create -f image-security-policy.yaml 
    imagesecuritypolicy.kritis.grafeas.io "my-isp" created
```

### Fully Qualified Images
When deploying pods, images must be fully qualified with digests.
This is necessary because tags are mutable, and kritis may not get the correct vulnerability information for a tagged image.

We provide [resolve-tags](https://github.com/grafeas/kritis/blob/master/cmd/kritis/kubectl/plugins/resolve/README.md), which can be run as a kubectl plugin or as a standalone binary to resolve all images from tags to digests in Kubernetes yamls.

If you need to deploy tagged images, you can add them to the `imageWhitelist` in your image security policy.

### Breakglass Annotation
To deploy a pod without any validation checks, you can add a breakglass annotation to your pod.
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-no-digest-breakglass
  annotations: {
    "kritis.grafeas.io/breakglass": "true"
  }
spec:
  containers:
  - name: nginx-no-digest-breakglass
    image: gcr.io/kritis-int-test/nginx-no-digest-breakglass:latest
    ports:
    - containerPort: 80
```

### Deploying Pods
Now, when you deploy pods kritis will validate them against all `ImageSecurityPolicies` found in the same namespace.
We can deploy a pod with a whitelisted image, which will be allowed:

```
$ kubectl create -f integration/testdata/nginx/nginx-digest-whitelist.yaml 
    pod "nginx-digest-whitelist" created
```

We can deploy an unqualified image, which is whitelisted:
```
$ kubectl create -f integration/testdata/nginx/nginx-no-digest-whitelist.yaml 
    pod "nginx-no-digest-whitelist" created
```

We can deploy any pod with the breakglass annotation:
```
$ kubectl create -f integration/testdata/nginx/nginx-no-digest-breakglass.yaml 
    pod "nginx-no-digest-breakglass" created
```

However, an unqualified image that isn't whitelisted will be denied:
```
$ kubectl create -f integration/testdata/nginx/nginx-no-digest.yaml
    Error from server: error when creating "integration/testdata/nginx/nginx-no-digest.yaml": admission webhook 
    "kritis-validation-hook.grafeas.io" denied the request: gcr.io/kritis-int-test/nginx-no-digest:latest is not a fully 
    qualified image
```

An image with violation that exceed the max severity defined in the image security policy will also be denied:
```
kubectl create -f integration/testdata/java/java-with-vuln.yaml 
    Error from server: error when creating "integration/testdata/java/java-with-vuln.yaml ": admission webhook 
    "kritis-validation-hook.grafeas.io" denied the request: found violations in 
    gcr.io/kritis-int-test/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
```

To get more information about why a request was denied, you can look at the logs for the kritis webhook pod:
```
$ kubectl get pods
NAME                                      READY     STATUS    RESTARTS   AGE
kritis-validation-hook-56d9d7d4f5-54mqt   1/1       Running   0          3m
$ kubectl logs -f kritis-validation-hook-56d9d7d4f5-54mqt
    ...
```
