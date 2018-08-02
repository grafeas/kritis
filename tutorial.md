## Kritis Tutorial

First, run through the [installation guide](install.md).

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