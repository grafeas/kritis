## Before You Begin

This tutorial has the following requirements:

- Kritis (see [Kritis Installation guide](install.md)).
- Google Cloud SDK

Configure gcloud for your intended project before continuing. If you do not recall the name, use `gcloud projects list`:

```shell
gcloud config set project <project ID>
```

For convenience, save the project ID as an environment variable:

```shell
PROJECT=<project ID assigned to you>
```
### 1. Defining the ImageSecurityPolicy

Kritis relies on a user-defined *ImageSecurityPolicy* (ISP) to determine whether a pod meets a specific criteria for deployment. Begin by creating an ImageSecurityPolicy that restricts one from deploying a HIGH severity vulnerability,  unless they are are within our set of white-listed [CVEs](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures), or contained within a set of white-listed images.

```shell
cat <<EOF | kubectl apply -f - \

apiVersion: kritis.grafeas.io/v1beta1
kind: ImageSecurityPolicy
metadata:
  name: my-isp
  namespace: default
spec:
  imageWhitelist:
  - gcr.io/$PROJECT/nginx-digest-whitelist:latest
  - gcr.io/$PROJECT/nginx-digest-whitelist@sha256:56e0af16f4a9d2401d3f55bc8d214d519f070b5317512c87568603f315a8be72
  packageVulnerabilityRequirements:
    maximumSeverity: MEDIUM
    whitelistCVEs:
      - providers/goog-vulnz/notes/CVE-2017-1000082
      - providers/goog-vulnz/notes/CVE-2017-1000081
EOF
```

### 2. Upload a vulnerable image

The [Container Analysis API](https://cloud.google.com/container-analysis/api/reference/rest/) only reveals vulnerability information for images owned by your project. This makes a copy of a sample vulnerable image into your container registry:

```shell
% gcloud container images add-tag \
  gcr.io/kritis-tutorial/nginx-digest-whitelist:latest \
  gcr.io/$PROJECT/nginx-digest-whitelist:latest
```
For more information about copying images, see [Google Cloud: Pushing and Pulling Images](https://cloud.google.com/container-registry/docs/pushing-and-pulling).

### 3. Deploy a vulnerable pod

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
"kritis-validation-hook.grafeas.io" denied the request: found violations in
gcr.io/$PROJECT/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
```

Be amazed!


### 3. Checking logs

Learn why the deployment failed by examining the logs for the *kritis-validation-hook* pod.
```
kubectl get pods
```

The output will show which CVE's caused the failure:

```
NAME                                      READY     STATUS    RESTARTS   AGE
kritis-validation-hook-56d9d7d4f5-54mqt   1/1       Running   0          3m
$ kubectl logs -f kritis-validation-hook-56d9d7d4f5-54mqt
    ...
    found CVE projects/goog-vulnz/notes/CVE-2013-7445 in gcr.io/$PROJECT/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
        which has fixes available
    found CVE projects/goog-vulnz/notes/CVE-2015-8985 in gcr.io/$PROJECT/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
        which has fixes available

```

### 4. Force Deployment With a Breakglass Annotation

To force the deployment of an image that normally fails validation, add a *breakglass* annotation to the pod spec.

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
    image: gcr.io/$PROJECT/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8
    ports:
    - containerPort: 80
EOF
```

Here is an example for a deployment:
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

### 5. Deploying a tagged image
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
    image: gcr.io/$PROJECT/nginx-no-digest:latest
    ports:
    - containerPort: 80
EOF
```
which should result in an error:
```shell
"kritis-validation-hook.grafeas.io" denied the request: gcr.io/$PROJECT/nginx-no-digest:latest
    is not a fully qualified image
```

### 6. Deploying a whitelisted Image

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
    image: gcr.io/$PROJECT/nginx-digest-whitelist:latest
    ports:
    - containerPort: 80
EOF
```
That brings us to the end of the tutorial!
