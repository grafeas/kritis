# Installing Kritis

## Step #1: Create a Google Cloud Project

At the moment, the only API implementation is within Google Cloud, so you will need to follow the prompts at [Google Cloud Console: New Project](https://console.cloud.google.com/projectcreate). For more details, read [Google Cloud: Creating and Managing Projects](https://cloud.google.com/resource-manager/docs/creating-managing-projects).

For convenience, you may your project ID as an environment variable:

```shell
PROJECT=<project ID assigned to you>
```

If you have forgotten your project ID, you may use:

```shell
gcloud projects list
```

## Step #2: Enable Billing on your Google Cloud Project

Ensure that your new project has a billing account associated to it, otherwise the requisite API's will fail to enable: https://console.cloud.google.com/billing

## Step #3: Enable the requisite API's for your Google Cloud Project

NOTE: You will need to get your Google Account whitelisted to use the Container Analysis API. Join the [Container Analysis Users Group](https://groups.google.com/forum/#!forum/containeranalysis-users) to be whitelisted. It will take 1-5 business days to approve the request. Once approved, you will need to visit following links to enable the necessary API's:

*  [Enable the Container Analysis API](https://console.cloud.google.com/flows/enableapi?apiid=containeranalysis.googleapis.com&redirect=https://cloud.google.com/container-registry/docs/get-image-vulnerabilities)
* [Enable the Kubernetes API](https://console.cloud.google.com/projectselector/kubernetes)
* [Enable vulnerability scanning](https://console.cloud.google.com/gcr/settings)

For more documentation, see [Container Analysis Overview](https://cloud.google.com/container-registry/docs/container-analysis). 

## Step #4: Create a cluster

You may skip this step if you already have a cluster configured.

```shell
gcloud components update
gcloud config set project $PROJECT
gcloud config set compute/zone us-central1-a
gcloud container clusters create kritis-test --num-nodes=2
```
After creating your cluster, you need to get authentication credentials to interact with the cluster. This command configures `kubectl` to use the cluster you created:

```shell
gcloud container clusters get-credentials kritis-test
```

For more documentation, see [Kubernetes Engine: Creating a Cluster](https://cloud.google.com/kubernetes-engine/docs/how-to/creating-a-cluster).

## Step #5: Create service account & configure roles

Create a service account named `kritis-ca-admin`, and download the key for it:

```shell
gcloud iam service-accounts create kritis-ca-admin \
  --display-name "Kritis Service Account"
```

And lastly, bind the service account to the appropriate roles:

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

## Step #6: Upload the Service Account Key

Download the service key from Google Cloud:

```shell
gcloud iam service-accounts keys create gac.json \
  --iam-account kritis-ca-admin@${PROJECT}.iam.gserviceaccount.com
```

Upload the service key to Kubernetes:

```shell
kubectl create secret generic gac-ca-admin --from-file=gac.json
```

## Step #7: Install and Configure Helm

kritis requires [helm](https://docs.helm.sh/using_helm/) to be installed. 

Once installed, execute the following to give Helm permission to your cluster:

```
kubectl create serviceaccount --namespace kube-system tiller

kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller

kubectl patch deploy --namespace kube-system tiller-deploy -p '{"spec":{"template":{"spec":{"serviceAccount":"tiller"}}}}'
```

Then execute the following to deploy it into your cluster:

```shell
helm init --wait
```


## Installing Kritis

Install kritis via helm:

```
helm install ./kritis-charts/
```

Using the --set flag, you can set custom installion values:

|  Value                | Default      | Description  |   
|-----------------------|--------------|--------------|
| serviceNamespace      | default      | The namespace to install kritis in |   
| gacSecret.name        | gac-ca-admin | The name of the secret created above with container analysis permissions | 

Installation will create 3 Pods:

- `kritis-preinstall` creates a `CertificateSigningRequest` and TLS Secret for the webhook.
- `kritis-postinstall` creates the `ValidatingWebhookConfiguration`.
- `kritis-validation-hook-xxx` operates the webhook

You may view the status of the Pod deployment using:

```shell
kubectl get pods
```

Sample output:

```
NAME                                      READY     STATUS             RESTARTS   AGE
kritis-postinstall                        0/1       Completed          0          2m
kritis-preinstall                         0/1       Completed          0          2m
kritis-validation-hook-7c84c48f47-lsjpg   1/1       Running            0          2m
```
Once `kritis-preinstall` and `kritis-postinstall` have status `Completed`, and `kritis-validation-hook-xxxx` is `Running`, kritis is installed in your cluster.

## Tutorial

Once installed, follow our [tutorial](tutorial.md) to learn how to test and manage Kritis.

## Uninstalling Kritis

Find the name of your helm release to delete:

```shell
helm ls
```

example: 

```
NAME        	REVISION	UPDATED                 	STATUS  	CHART         NAMESPACE
loopy-numbat	1       	Fri Jul 27 14:25:44 2018	DEPLOYED	kritis-0.1.0  default  
```

Then delete the name of the release:

```shell
helm delete <name>
```

This command will also kick off the `kritis-predelete` pod, which deletes the CertificateSigningRequest, TLS Secret, and Webhooks created during installation. You may view the status using:

```
kubectl get pods kritis-predelete
```

And the logs using:

```
kubectl logs kritis-predelete
```

Kritis will be deleted from your cluster once this Pod has reached `Completed` status.

NOTE: This will not delete the `ServiceAccount` or `ClusterRoleBinding` created during preinstall, or the container analysis secret created above.

# Troubleshooting

## Logs
If you're unable to install or delete kritis, looking at logs for the following pods could provide more information:
* kritis-validation-hook-xxx
* kritis-preinstall (during installation)
* kritis-postinstall (during installation)
* kritis-predelete (during deletion)

You can view their status using:

```
kubectl get pods
```

## Deleting Kritis Manually

If you're unable to delete kritis via `helm delete <DEPLOYMENT NAME>`, you can manually delete kritis `validatingwebhookconfiguration` with the following commands:

```shell
kubectl delete validatingwebhookconfiguration kritis-validation-hook --namespace <YOUR NAMESPACE>

kubectl delete validatingwebhookconfiguration kritis-validation-hook-deployments --namespace <YOUR NAMESPACE>
```

`helm delete` should work at this point.
