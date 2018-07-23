# kritis

## Setting up Kritis

### Creating a Kubernetes Cluster

To run the kritis admission webhook, you will need access to a version 1.9.2+ Kubernetes cluster.
You can create one by running
```
gcloud container clusters create <CLUSTER NAME> \
--cluster-version 1.9.7-gke.3 \
--zone us-central1-a \
--num-nodes 1
```

### Enabling the Container Analysis API

You will need to enable the Container Analysis API and enable Vulnerability Scanning in your Google Cloud Console project.
Instructions can be found in the `Before you Begin` section of the [Getting Image Vulnerabilities](https://cloud.google.com/container-registry/docs/get-image-vulnerabilities#before_you_begin) docs.
kritis can only inspect images hosted in projects that have both of these enabled, and have already been scanned for vulnerabilities.

### Creating a Container Analysis Secret
You will need to create a Kubernetes secret, which will provide kritis with the auth required to get vulnerability information for images. You can create the secret through the Google Cloud Console or on the command line with gcloud.

#### Creating Container Analysis Secret via Google Cloud Console
To create the secret:
1. Create a service account with `Container Analysis Notes Viewer`, `Container Analysis Notes Editor`, `Container Analysis Occurrences Viewer`, and `Container Analysis Occurrences Editor` permissions in the Google Cloud Console project that hosts the images kritis will be inspecting
2. Download a JSON key for the service account
3. Rename the key to `gac.json`
4. Create a Kubernetes secret by running:
```
kubectl create secret generic gac-secret --from-file=<path to kritis.json>
```

#### Creating Container Analysis Secret via Command Line
1. First create the service account
```
gcloud iam service-accounts create ACCOUNT_NAME --display-name DISPLAY_NAME
```
This should create a service account ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com.
The project id can be found from `gcloud config list project`.

2. Create a key for the service account
```
gcloud iam service-accounts keys create ~/kritis.json --iam-account=ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com
```

3. Create a kubernetes secret for the service account
```
kubectl create secret generic <SECRET NAME> --from-file=~/kritis.json
```

3. Create policy bindings for the necessary roles:

```
export MEMBER=serviceAccount:ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com
gcloud projects add-iam-policy-binding PROJECT_ID--member=$MEMBER --role=roles/containeranalysis.notes.viewer

gcloud projects add-iam-policy-binding PROJECT_ID--member=$MEMBER --role=roles/containeranalysis.occurrences.viewer

gcloud projects add-iam-policy-binding PROJECT_ID--member=$MEMBER --role=roles/containeranalysis.notes.editor

gcloud projects add-iam-policy-binding PROJECT_ID--member=$MEMBER --role=roles/containeranalysis.occurrences.viewer
```

### Installing Helm
You will need [helm](https://docs.helm.sh/using_helm/) installed to install kritis.

### GKE Helm Service Account
If you installed helm on GKE with `helm init` you will need to configure helm permissions to create deployments via RBAC rules. To setup a helm service account with correct permissions on GKE, run the following (NOTE: this has to run after helm init):
```
kubectl create serviceaccount --namespace kube-system tiller
kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
kubectl patch deploy --namespace kube-system tiller-deploy -p '{"spec":{"template":{"spec":{"serviceAccount":"tiller"}}}}'
```

## Installing Kritis
1. To install kritis via helm, we need to first generate TLS certs.
   To do that,
   1. First download the helm plugin to generate certs from [here](https://github.com/SUSE/helm-certgen/releases)
   2. Unzip the tar and then install the plugin.
      ```
      tar -xvf certgen-CLIENT_PLATFORM-amd64-CERTGEN_VERSION.tgz --directory ~/certgen/
      helm plugin install ~/certgen/
      ```
2. Now run the install script.
   This should create TLS certs, deploy kritis in given namespace.

   The secret name is the Container Analysis Secret you created above.

   ```
    ./install/install-kritis.sh -n <your namespace | DEFAUT=default>

    NAME:   whimsical-cricket
    LAST DEPLOYED: Wed Jul 18 15:41:50 2018
    NAMESPACE: default
    STATUS: DEPLOYED

    RESOURCES:
    ==> v1beta1/ValidatingWebhookConfiguration
    NAME                    AGE
    kritis-validation-hook  0s

    ==> v1/Pod(related)
    NAME                                     READY  STATUS             RESTARTS  AGE
    kritis-validation-hook-85dbc5c8c8-n4tr5  0/1    ContainerCreating  0         0s

    ==> v1/Service
    NAME                    TYPE       CLUSTER-IP     EXTERNAL-IP  PORT(S)  AGE
    kritis-validation-hook  ClusterIP  10.63.244.219  <none>       443/TCP  1s

    ==> v1beta2/Deployment
    NAME                    DESIRED  CURRENT  UP-TO-DATE  AVAILABLE  AGE
    kritis-validation-hook  1        1        1           0          0s

    ==> v1beta1/ClusterRoleBinding
    NAME                       AGE
    kritis-clusterrolebinding  0s

    ==> v1/ClusterRole
    NAME                AGE
    kritis-clusterrole  0s
    ```
    Helm will create a cluster role and cluster role binding, which gives the kritis deployment access to the ImageSecurityPolicy CRD.
3. You can delete all the deployments using the release name.
   ```
   helm delete whimsical-cricket
   ```
   Note: This does not delete the secrets.
