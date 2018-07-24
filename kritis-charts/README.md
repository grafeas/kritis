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
kubectl create secret generic gac-ca-admin --from-file=<path to kritis.json>
```

#### Creating Container Analysis Secret via Command Line
1. First create the service account
```
gcloud iam service-accounts create ACC_NAME --display-name DISPLAY_NAME
```
This should create a service account ACC_NAME@PROJECT_ID.iam.gserviceaccount.com.
The project id can be found from `gcloud config list project`.

2. Create a key for the service account
```
gcloud iam service-accounts keys create ~/gac.json --iam-account=ACC_NAME@PROJECT_ID.iam.gserviceaccount.com
```

3. Create a kubernetes secret for the service account
```
kubectl create secret generic <SECRET NAME> --from-file=~/gac.json
```

3. Create policy bindings for the necessary roles:

```
gcloud projects add-iam-policy-binding PROJECT_ID--member=serviceAccount:ACC_NAME@PROJECT_ID.iam.gserviceaccount.com --role=roles/containeranalysis.notes.viewer

gcloud projects add-iam-policy-binding PROJECT_ID--member=serviceAccount:ACC_NAME@PROJECT_ID.iam.gserviceaccount.com --role=roles/containeranalysis.occurrences.viewer

gcloud projects add-iam-policy-binding PROJECT_ID--member=serviceAccount:ACC_NAME@PROJECT_ID.iam.gserviceaccount.com --role=roles/containeranalysis.notes.editor

gcloud projects add-iam-policy-binding PROJECT_ID--member=serviceAccount:ACC_NAME@PROJECT_ID.iam.gserviceaccount.com --role=roles/containeranalysis.occurrences.viewer
```

### Installing Helm
You will need [helm](https://docs.helm.sh/using_helm/) installed to install kritis.

After installing helm, run
```
helm init
```
to install helm into your cluster.

You may also need to run these commands to give helm permissions in your cluster:
```
kubectl create serviceaccount --namespace kube-system tiller
kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
kubectl patch deploy --namespace kube-system tiller-deploy -p '{"spec":{"template":{"spec":{"serviceAccount":"tiller"}}}}'
```

## Installing Kritis
Now run the install script.
This will create the necessary TLS certs and deploy kritis into the given namespace.
```
./install/install-kritis.sh
```

### Optional Flags
|  Flag | Default      | Description  |   
|-------|--------------|--------------|
| -n    | default      | The namespace to install kritis in |   
| -s    | gac-ca-admin | The name of the secret created above with container analysis permissions |  

```shell
$ ./install/install-kritis.sh
+ NAMESPACE=default
+ GAC_SECRET=gac-ca-admin
+ PREINSTALL_FILE=preinstall/preinstall.yaml
+ CERTIFICATE=
+ TLS_SECRET=tls-webhook-secret
+ CHARTS_DIR=kritis-charts/
+ getopts n:s opt
+ kritis::preinstall
+ kubectl apply -f preinstall/preinstall.yaml --namespace default
serviceaccount "kritis-preinstall-serviceaccount" created
clusterrolebinding.rbac.authorization.k8s.io "kritis-preinstall-clusterrolebinding" created
pod "preinstall-kritis" created
+ kritis::get_certificate
++ kubectl get secret tls-webhook-secret -o 'jsonpath={.data.tls\.crt}' --namespace default
    ...
+ kritis::install_helm
    ...
+ helm install kritis-charts/ --namespace default --set serviceNamespace=default --set 
    ...
NAME:   piquant-seagull
LAST DEPLOYED: Tue Jul 24 13:03:24 2018
NAMESPACE: default
STATUS: DEPLOYED

RESOURCES:
==> v1beta1/ClusterRoleBinding
NAME                       AGE
kritis-clusterrolebinding  0s

==> v1/ClusterRole
NAME                AGE
kritis-clusterrole  0s

==> v1beta1/ValidatingWebhookConfiguration
kritis-validation-hook  0s

==> v1/Pod(related)
NAME                                     READY  STATUS             RESTARTS  AGE
kritis-validation-hook-59f47c77b8-7qb4b  0/1    ContainerCreating  0         0s

==> v1beta1/CustomResourceDefinition
NAME                                      AGE
attestationauthorities.kritis.grafeas.io  0s
imagesecuritypolicies.kritis.grafeas.io   0s

==> v1/Service
NAME                    TYPE       CLUSTER-IP     EXTERNAL-IP  PORT(S)  AGE
kritis-validation-hook  ClusterIP  10.63.249.175  <none>       443/TCP  0s

==> v1beta2/Deployment
NAME                    DESIRED  CURRENT  UP-TO-DATE  AVAILABLE  AGE
kritis-validation-hook  1        1        1           0          0s


+ kritis::delete_preinstall
+ kubectl delete -f preinstall/preinstall.yaml --namespace default
serviceaccount "kritis-preinstall-serviceaccount" deleted
clusterrolebinding.rbac.authorization.k8s.io "kritis-preinstall-clusterrolebinding" deleted
pod "preinstall-kritis" deleted
```

## Deleting Kritis

You can delete kritis by deleting the helm deployment:
```shell
$ helm ls
NAME           	REVISION	UPDATED                 	STATUS  	CHART       	NAMESPACE
piquant-seagull	1       	Tue Jul 24 13:03:24 2018	DEPLOYED	kritis-0.1.0	default  
$ helm delete piquant-seagull
release "piquant-seagull" deleted

```
Note: This will not delete the CertificateSigningRequest or TLS secret created during preinstall, or the container analysis secret created above.
