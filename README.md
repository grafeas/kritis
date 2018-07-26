# Kritis

Kritis (“judge” in Greek), provides full software supply chain security for Kubernetes applications,
allowing devOps teams to enforce deploy-time image security policies using metadata and attestations stored in [Grafeas](https://github.com/grafeas/grafeas).

You can read the [Kritis whitepaper](https://github.com/Grafeas/Grafeas/blob/master/case-studies/binary-authorization.md) for more details.

Note: Currently kritis doesn't use grafeas and pulls vulnerability informtation via the [Container Analysis API](https://cloud.google.com/container-analysis/api/reference/rest/).

## Installing Kritis

Instructions for installing kritis on your cluster via helm can be found [here](https://github.com/grafeas/kritis/blob/master/kritis-charts/README.md).

## Kritis Tutorial

### 1. Setting up an ImageSecurityPolicy

Kritis relies on user defined `ImageSecurityPolicies` to determine whether a pod should be admitted or denied at deploy time.

<<<<<<< HEAD
First, you will need to create an `ImageSecurityPolicy`. 
```shell
cat <<EOF | kubectl apply -f - \

=======
First, you will need to specify an `ImageSecurityPolicy`.
A sample is shown here:
```yaml
>>>>>>> WIP: TODO add tests
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
<<<<<<< HEAD
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
=======
$ kubectl create -f image-security-policy.yaml
    imagesecuritypolicy.kritis.grafeas.io "my-isp" created
>>>>>>> WIP: TODO add tests
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

<<<<<<< HEAD
The pod should be created:
```shell
pod/java-with-vuln created
=======
### Deploying Pods
Now, when you deploy pods kritis will validate them against all `ImageSecurityPolicies` found in the same namespace.
We can deploy a pod with a whitelisted image, which will be allowed:

```
$ kubectl create -f integration/testdata/nginx/nginx-digest-whitelist.yaml
    pod "nginx-digest-whitelist" created
>>>>>>> WIP: TODO add tests
```
### 5. Deploying a Tagged Image
Kritis expects all images it inspects to be fully qualified with a digest, since it can't retrieve vulnerability information for tagged images.

<<<<<<< HEAD
We can try to deploy a tagged image:
```shell
cat <<EOF | kubectl apply -f - \
=======
We can deploy an unqualified image, which is whitelisted:
```
$ kubectl create -f integration/testdata/nginx/nginx-no-digest-whitelist.yaml
    pod "nginx-no-digest-whitelist" created
```
>>>>>>> WIP: TODO add tests

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
<<<<<<< HEAD
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
=======
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
>>>>>>> WIP: TODO add tests

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

<<<<<<< HEAD
That brings us to the end of the tutorial!

## Qualifying Images with Resolve-Tags
When deploying pods, images must be fully qualified with digests.
This is necessary because tags are mutable, and kritis may not get the correct vulnerability information for a tagged image.

We provide [resolve-tags](https://github.com/grafeas/kritis/blob/master/cmd/kritis/kubectl/plugins/resolve/README.md), which can be run as a kubectl plugin or as a standalone binary to resolve all images from tags to digests in Kubernetes yamls.

=======
### Kritis Cron Job.
Kritis also runs an hourly cron job to continuously validate and reconcile policies. Images can go out of policy while running.
This job will use the same policies as the webhook, and will audit/alert via adding a label `kritis.grafeas.io/invalidImageSecPolicy` and
an annotation `kritis.grafeas.io/invalidImageSecPolicy` with reason.

You can run the cron job in foreground by running the `kritis-server --run-cron` in the kritis-validation-hook pod.

To find the pod name for kritis-validation-hook run,
```
kubectl get pods
NAME                                      READY     STATUS    RESTARTS   AGE
kritis-validation-hook-7958b4b954-xmjwf   1/1       Running   0          2h
```

Grab the pod name and run `kritis-server --run-cron`
```
kubectl exec kritis-validation-hook-<YOUR-POD-ID> -- /kritis/kritis-server --run-cron
I0725 22:18:13.871483      22 cron.go:123] Got isps [{{ImageSecurityPolicy kritis.grafeas.io/v1beta1} {my-isp  default /apis/kritis.grafeas.io/v1beta1/namespaces/default/imagesecuritypolicies/my-isp d4bb6020-9057-11e8-8aed-42010a800166 4873590 0 2018-07-25 22:12:34 +0000 UTC <nil> <nil> map[] map[] [] nil [] } {[gcr.io/my/image] {HIGH true [providers/goog-vulnz/notes/CVE-2017-1000082 providers/goog-vulnz/notes/CVE-2017-1000081]}}}]
I0725 22:18:13.939068      22 cron.go:100] Checking po nginx-no-digest-breakglass-6ccfbbdbbb-dfkdk
I0725 22:18:13.957239      22 strategy.go:67] Adding label invalidImageSecPolicy and annotation gcr.io/kritis-int-test/nginx-no-digest-breakglass:latest is not a fully qualified image
```

You can verify the label and annotation by running describe on the pod.
```
kubectl describe pod nginx-no-digest-breakglass
Name:         nginx-no-digest-breakglass
Namespace:    default
Node:         gke-k0-default-pool-8320c004-dwhk/10.128.0.3
Start Time:   Wed, 25 Jul 2018 17:10:33 -0700
Labels:       kritis.grafeas.io/invalidImageSecPolicy=invalidImageSecPolicy
Annotations:  kritis.grafeas.io/breakglass=true
              kritis.grafeas.io/invalidImageSecPolicy=gcr.io/kritis-int-test/nginx-no-digest-breakglass:latest is not a fully qualified image
```
>>>>>>> WIP: TODO add tests
