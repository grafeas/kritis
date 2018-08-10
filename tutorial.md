# Kritis Tutorial

## Before you begin

First **[Install Kritis](install.md)** to your cluster.

Configure gcloud to use the correct project. You may use `gcloud projects list` to see a list of them.

```shell
gcloud config set project <project ID>
```

For convenience, save the project ID as an environment variable:

```shell
PROJECT=<project ID assigned to you>
```

### 1. Defining an ImageSecurityPolicy

Kritis relies on a user-defined *ImageSecurityPolicy* (ISP) to determine whether a pod meets the criteria for deployment. Create an ISP that restricts Kubernetes from deploying a HIGH severity vulnerability, unless it is within a set of white-listed [CVEs]:

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
    whitelistCVEs:
      - providers/goog-vulnz/notes/CVE-2017-1000081
EOF
```

### 2. Copy a vulnerable image

The [Container Analysis API](https://cloud.google.com/container-analysis/api/reference/rest/) only reveals vulnerability information for images owned by your project. This makes a copy of a sample vulnerable image into your container registry:

```shell
gcloud container images add-tag \
  gcr.io/kritis-tutorial/java-with-vuln:latest \
  gcr.io/$PROJECT/java-with-vuln:latest
```

It will take a moment to scan the image, but once this command outputs a long list of vulnerabilities, you are ready to proceed:

```shell
gcloud alpha container images describe --show-package-vulnerability \
  gcr.io/$PROJECT/java-with-vuln:latest
```

For more information about copying images, see [Google Cloud: Pushing and Pulling Images](https://cloud.google.com/container-registry/docs/pushing-and-pulling).

### 3. Deploy a vulnerable image

Deploy a pod containing our vulnerable image:

```shell
cat <<EOF | kubectl apply -f - \

apiVersion: v1
kind: Pod
metadata:
  name: java-with-vuln
spec:
  containers:
  - name: java-with-vuln
    image: gcr.io/$PROJECT/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
    ports:
    - containerPort: 80
EOF
```

The following error will appear:

```shell
"kritis-validation-hook.grafeas.io" denied the request: found violations in gcr.io/$PROJECT/java-with-vuln@sha256:<hash>
```

Learn more by inspecting the *kritis-validation-hook* logs:

```shell
kubectl logs -l app=kritis-validation-hook
```

Example output:

```shell
NAME                                      READY     STATUS    RESTARTS   AGE
kritis-validation-hook-56d9d7d4f5-54mqt   1/1       Running   0          3m
$ kubectl logs -f kritis-validation-hook-56d9d7d4f5-54mqt
    ...
    found CVE projects/goog-vulnz/notes/CVE-2013-7445 in gcr.io/$PROJECT/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
        which has fixes available
    found CVE projects/goog-vulnz/notes/CVE-2015-8985 in gcr.io/$PROJECT/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
        which has fixes available
```

### 4. Deploying an image by tag name

Create an example YAML which uses the `latest` image tag:

```shell
cat <<EOF > resolve.yaml

apiVersion: v1
kind: Pod
metadata:
  name: java-with-vuln-tagged
spec:
  containers:
  - name: java-with-vuln-tagged
    image: gcr.io/$PROJECT/java-with-vuln:latest
    ports:
    - containerPort: 80
EOF
```

Apply the YAML:

```shell
kubectl apply -f resolve.yaml
```

Unless the tag is specifically whitelisted, the following error will be displayed:

```shell
admission webhook "kritis-validation-hook.grafeas.io" denied the request: gcr.io/kritis-doc-test/java-with-vuln:latest is not a fully qualified image
```

Instead, to deploy images by a tag name, use the `resolve-tags` plugin:

```shell
# TODO(tstromberg): Document how to solve UNAUTHORIZED errors here.
kubectl plugin resolve-tags -f resolve.yaml --apply true
```

### 5. Whitelist an image

To whitelist an image, specify a path containing a tag (such as `latest`), or sha256:

```shell
cat <<EOF | kubectl apply -f - \

apiVersion: kritis.grafeas.io/v1beta1
kind: ImageSecurityPolicy
metadata:
  name: my-isp
  namespace: default
spec:
  imageWhitelist:
    - gcr.io/$PROJECT/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
  packageVulnerabilityRequirements:
    maximumSeverity: MEDIUM
    whitelistCVEs:
      - providers/goog-vulnz/notes/CVE-2017-1000081
EOF
```

Then deploy the java-with-vuln pod with the whitelist in place:

```shell
cat <<EOF | kubectl apply -f - \

apiVersion: v1
kind: Pod
metadata:
  name: java-with-vuln-whitelist
spec:
  containers:
  - name: java-with-vuln-whitelist
    image: gcr.io/$PROJECT/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
    ports:
    - containerPort: 80
EOF
```

### 6. Force deployment with a breakglass annotation

Rather than white-listing an image, you can also force a deployment  that normally fails validation, by adding a *breakglass* annotation to the pod spec:

```shell
cat <<EOF | kubectl apply -f - \

apiVersion: v1
kind: Pod
metadata:
  name: java-with-vuln-breakglass
  annotations: {
    "kritis.grafeas.io/breakglass": "true"
  }
spec:
  containers:
  - name: java-with-vuln-breakglass
    image: gcr.io/$PROJECT/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
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
  name: java-with-vuln-breakglass-deployment
  annotations: {
    "kritis.grafeas.io/breakglass": "true"
  }
spec:
  replicas: 2
  template:
    metadata:
      annotations:
        kritis.grafeas.io/breakglass: "true"
      labels:
        app: java-with-vuln
    spec:
      containers:
      - name: java-with-vuln
        image: gcr.io/$PROJECT/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
        ports:
        - containerPort: 80
EOF
```

That brings us to the end of the tutorial!

You can uninstall kritis by following these [instructions](install.md#Uninstalling-Kritis).
