# Installing Kritis

## Requirements

The only currently supported backend for vulnerability data is the [Google Cloud Container Analysis API](https://cloud.google.com/container-registry/docs/container-analysis). You will need access to it, along with:

- [Google Cloud](https://cloud.google.com) account with [billing enabled](https://console.cloud.google.com/billing)
- [Google Cloud SDK](https://cloud.google.com/sdk/docs/) (gcloud)
- [Kubernetes](https://kubernetes.io/) 1.9.2+
- [GnuPG](https://gnupg.org/download/)

## Step #1: Create a Google Cloud Project

Follow the prompts at [Google Cloud Console: New Project](https://console.cloud.google.com/projectcreate).

For convenience, save the project ID as an environment variable:

```shell
PROJECT=<project ID assigned to you>
```

Configure `gcloud` to use the correct project.

```shell
gcloud config set project $PROJECT
```

If you do not know your project ID, you may use:

```shell
gcloud projects list
```

## Step #2: Enable the requisite API's for your Google Cloud Project

NOTE: Your account must be whitelisted to enable the Container Analysis API. To do so, join the  [Container Analysis Users Group](https://groups.google.com/forum/#!forum/containeranalysis-users). It may take 1-5 business days to approve the request.

Once approved, enable the necessary API's:

Enable the Container Analysis API:

```shell
gcloud services enable containeranalysis.googleapis.com
```

Enable the Kubernetes API:

```shell
gcloud services enable container.googleapis.com
```

Enable the Container Registry API:

```shell
gcloud services enable containerregistry.googleapis.com
```

Wait for the above API's to be fully enabled, then enable vulnerability scanning:

- [Enable vulnerability scanning](https://console.cloud.google.com/gcr/settings)

For more documentation, see [Container Analysis Overview](https://cloud.google.com/container-registry/docs/container-analysis).

## Step #3: Create a cluster

kritis requires a cluster running Kubernetes v1.9.2 or newer. You may create one named `kritis-test` by executing:

```shell
gcloud components update
gcloud config set project $PROJECT
gcloud config set compute/zone us-central1-a
gcloud container clusters create kritis-test --num-nodes=2
```

After creating your cluster, you need to get authentication credentials to interact with the cluster. This command will also configure  `kubectl` for your newly created cluster:

```shell
gcloud container clusters get-credentials kritis-test
```

For more documentation, see [Kubernetes Engine: Creating a Cluster](https://cloud.google.com/kubernetes-engine/docs/how-to/creating-a-cluster).

## Step #4: Create service account & configure roles

This creates a service account named `kritis-ca-admin`:

```shell
gcloud iam service-accounts create kritis-ca-admin \
  --display-name "Kritis Service Account"
```

Which must be bound to the appropriate roles:

```shell
gcloud projects add-iam-policy-binding $PROJECT \
  --member=serviceAccount:kritis-ca-admin@${PROJECT}.iam.gserviceaccount.com \
  --role=roles/containeranalysis.notes.viewer

gcloud projects add-iam-policy-binding $PROJECT \
  --member=serviceAccount:kritis-ca-admin@${PROJECT}.iam.gserviceaccount.com \
  --role=roles/containeranalysis.notes.editor

gcloud projects add-iam-policy-binding $PROJECT \
  --member=serviceAccount:kritis-ca-admin@${PROJECT}.iam.gserviceaccount.com \
  --role=roles/containeranalysis.occurrences.viewer

gcloud projects add-iam-policy-binding $PROJECT \
  --member=serviceAccount:kritis-ca-admin@${PROJECT}.iam.gserviceaccount.com \
  --role=roles/containeranalysis.occurrences.editor
```

## Step #5: Upload the Service Account Key

Download the service key from Google Cloud:

```shell
gcloud iam service-accounts keys create gac.json \
  --iam-account kritis-ca-admin@${PROJECT}.iam.gserviceaccount.com
```

Then upload the service key to your Kubernetes cluster:

```shell
kubectl create secret generic gac-ca-admin --from-file=gac.json
```

## Step #6: Install and Configure Helm

Install [helm](https://docs.helm.sh/using_helm/), and execute the following to create an account for helm in your cluster:

```shell
kubectl create serviceaccount --namespace kube-system tiller

kubectl create clusterrolebinding tiller-cluster-rule \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:tiller
```

Then deploy helm:

```shell
helm init --wait --service-account tiller
```

## Installing Kritis to your cluster

Install the `resolve-tags` kubectl plugin and binary:

## Mac OS X

```shell
curl -LO https://storage.googleapis.com/resolve-tags/latest/resolve-tags-darwin-amd64.tar.gz && \
  RESOLVE_TAGS_DIR=$HOME/.kube/plugins/resolve && \
  mkdir -p $RESOLVE_TAGS_DIR && tar -C $RESOLVE_TAGS_DIR -xzf resolve-tags-darwin-amd64.tar.gz && \
  mv $RESOLVE_TAGS_DIR/resolve-tags-darwin-amd64 $RESOLVE_TAGS_DIR/resolve-tags && \
  sudo cp $RESOLVE_TAGS_DIR/resolve-tags /usr/local/bin/
```

## Linux

```shell
curl -LO https://storage.googleapis.com/resolve-tags/latest/resolve-tags-linux-amd64.tar.gz && \
  RESOLVE_TAGS_DIR=$HOME/.kube/plugins/resolve && \
  mkdir -p $RESOLVE_TAGS_DIR && tar -C $RESOLVE_TAGS_DIR -xzf resolve-tags-linux-amd64.tar.gz && \
  mv $RESOLVE_TAGS_DIR/resolve-tags-linux-amd64 $RESOLVE_TAGS_DIR/resolve-tags && \
  sudo cp $RESOLVE_TAGS_DIR/resolve-tags /usr/local/bin/
```

For more information, please see the resolve-tags [documentation](cmd/kritis/kubectl/plugins/resolve/README.md).

Install kritis to your cluster:

```shell
helm install https://storage.googleapis.com/kritis-charts/repository/kritis-charts-0.1.0.tgz
```

You may use the --set flag, to override the installation defaults:

|  Value                | Default      | Description  |
|-----------------------|--------------|--------------|
| serviceNamespace      | default      | namespace to install kritis within |
| gacSecret.name        | gac-ca-admin | name of the secret created above with container analysis permissions |

The kritis installation will create 3 pods:

- `kritis-preinstall` creates a `CertificateSigningRequest` and TLS Secret for the webhook
- `kritis-postinstall` creates the `ValidatingWebhookConfiguration`
- `kritis-validation-hook-xxx` serves the webhook

The deployment status may be viewed using:

```shell
kubectl get pods
```

Sample output:

```shell
NAME                                      READY     STATUS             RESTARTS   AGE
kritis-postinstall                        0/1       Completed          0          2m
kritis-preinstall                         0/1       Completed          0          2m
kritis-validation-hook-7c84c48f47-lsjpg   1/1       Running            0          2m
```

The installation is complete once:

- `kritis-preinstall` and `kritis-postinstall` have status `Completed`
- `kritis-validation-hook-xxx` is `Running`

## Tutorial

Once installed, follow our [tutorial](docs/tutorial.md) to learn how to test and manage Kritis.

## Uninstalling Kritis

Find the name of your helm release to delete:

```shell
helm ls
```

example:

```shell
NAME          REVISION  UPDATED                   STATUS    CHART         NAMESPACE
loopy-numbat    1       Fri Jul 27 14:25:44 2018  DEPLOYED  kritis-0.1.0  default
```

Then delete the name of the release:

```shell
helm delete <name>
```

This command will also kick off the `kritis-predelete` pod, which deletes the CertificateSigningRequest, TLS Secret, and Webhooks created during installation. You may view the status using:

```shell
kubectl get pods kritis-predelete
```

And the logs using:

```shell
kubectl logs kritis-predelete
```

Most resources created by kritis will be deleted from your cluster once this Pod has reached `Completed` status.

To delete the remaining resources run:

```
kubectl delete pods,serviceaccount,clusterrolebinding --selector kritis.grafeas.io/install --namespace <your namespace>
```

NOTE: This will not delete the container analysis secret created above.

## Troubleshooting

### Logs

If you're unable to install or delete kritis, looking at logs for the following pods could provide more information:

- `kritis-validation-hook-xxx`
- `kritis-preinstall` (during installation)
- `kritis-postinstall` (during installation)
- `kritis-predelete` (during deletion)

You can view their status using:

```shell
kubectl get pods
```

### Deleting Kritis Manually

If you're unable to delete kritis via `helm delete <DEPLOYMENT NAME>`, you can manually delete all kritis resources with the following commands:

```shell
kubectl delete all,validatingwebhookconfiguration,serviceaccount,secret,csr,crd \
  --selector kritis.grafeas.io/install \
  --namespace <your namespace>
```

You should then be able to delete the helm deployment with 

```shell
helm delete [deployment name] --no-hooks
```
