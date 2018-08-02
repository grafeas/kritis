# kritis

## Setting up Kritis
In order to setup Kritis, let define some variables.
```
PROJECT_ID=<your project id>
CLUSTER_NAME=<your cluster>
gcloud config set project $PROJECT_ID
```
### Creating a Kubernetes Cluster

To run the kritis admission webhook, you will need access to a version 1.9.2+ Kubernetes cluster.
You can create one by running

```
gcloud container clusters create $CLUSTER_NAME \
--cluster-version 1.9.7-gke.3 \
--zone us-central1-a \
--num-nodes 6
```
Now, add run command to add kubectl config to connect to this cluster.
```
gcloud container clusters get-credentials $CLUSTER_NAME -zone us-central1-a --project $PROJECT_ID
```

### Enabling the Container Analysis API

You will need to enable the Container Analysis API and enable Vulnerability Scanning in your Google Cloud Console project.
Instructions can be found in the `Before you Begin` section of the [Getting Image Vulnerabilities](https://cloud.google.com/container-registry/docs/get-image-vulnerabilities#before_you_begin) docs.
kritis can only inspect images hosted in projects that have both of these enabled, and have already been scanned for vulnerabilities.

### Creating a Container Analysis Secret
You will need to create a Kubernetes secret, which will provide kritis with the auth required to get vulnerability information for images.
You can create the secret through the Google Cloud Console or on the command line with gcloud.

#### Creating Container Analysis Secret via Command Line
Before you start, please make sure you are running as a user with permissions to create service accounts.

First, lets define variables for your serviceaccount and glcoud project.
```
ACC_NAME=kritis-ca-admin
ACC_DISP_NAME="Kritis Service Account"
```

1. First create the service account
```
gcloud iam service-accounts create $ACC_NAME --display-name "$ACC_DISP_NAME"
```
This should create a service account $ACC_NAME@$PROJECT_ID.iam.gserviceaccount.com.

2. Create a key for the service account
```
gcloud iam service-accounts keys create ~/gac.json --iam-account=$ACC_NAME@$PROJECT_ID.iam.gserviceaccount.com
```

3. Create policy bindings for the necessary roles:

```
gcloud projects add-iam-policy-binding $PROJECT_ID --member=serviceAccount:$ACC_NAME@$PROJECT_ID.iam.gserviceaccount.com --role=roles/containeranalysis.notes.viewer

gcloud projects add-iam-policy-binding $PROJECT_ID --member=serviceAccount:$ACC_NAME@$PROJECT_ID.iam.gserviceaccount.com --role=roles/containeranalysis.occurrences.viewer

gcloud projects add-iam-policy-binding $PROJECT_ID --member=serviceAccount:$ACC_NAME@$PROJECT_ID.iam.gserviceaccount.com --role=roles/containeranalysis.notes.editor

gcloud projects add-iam-policy-binding $PROJECT_ID --member=serviceAccount:$ACC_NAME@$PROJECT_ID.iam.gserviceaccount.com --role=roles/containeranalysis.occurrences.viewer
```

#### Creating Container Analysis Secret via Google Cloud Console
To create the secret:
1. Create a service account with `Container Analysis Notes Viewer`, `Container Analysis Notes Editor`, `Container Analysis Occurrences Viewer`, and `Container Analysis Occurrences Editor` permissions in the Google Cloud Console project that hosts the images kritis will be inspecting
2. Download a JSON key for the service account
3. Rename the key to `gac.json`

Now, you can create a kubernetes secret by running this command.
Create a Kubernetes secret by running:
```
kubectl create secret generic gac-ca-admin --from-file=`ls ~/gac.json`
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
You can install kritis via helm:

```
$ helm install ./kritis-charts/

NAME:   innocent-parrot
LAST DEPLOYED: Fri Jul 27 13:53:55 2018
NAMESPACE: default
STATUS: DEPLOYED

RESOURCES:
==> v1beta1/CustomResourceDefinition
NAME                                      AGE
attestationauthorities.kritis.grafeas.io  1s
imagesecuritypolicies.kritis.grafeas.io   1s

==> v1/Service
NAME                    TYPE       CLUSTER-IP    EXTERNAL-IP  PORT(S)  AGE
kritis-validation-hook  ClusterIP  10.63.247.40  <none>       443/TCP  1s

==> v1beta2/Deployment
NAME                    DESIRED  CURRENT  UP-TO-DATE  AVAILABLE  AGE
kritis-validation-hook  1        1        1           0          1s

==> v1beta1/ClusterRoleBinding
NAME                       AGE
kritis-clusterrolebinding  1s

==> v1/ClusterRole
NAME                AGE
kritis-clusterrole  1s

==> v1beta1/ValidatingWebhookConfiguration
kritis-validation-hook-deployments  1s

==> v1/Pod(related)
NAME                                     READY  STATUS             RESTARTS  AGE
kritis-validation-hook-5b86964479-tdm24  0/1    ContainerCreating  0         1s
```

Installation will also create two pods, called `kritis-preinstall` and `kritis-postinstall`.
```
$ kubectl get pods
NAME                                      READY     STATUS              RESTARTS   AGE
kritis-postinstall                        1/1       Running             0          5s
kritis-preinstall                         0/1       ContainerCreating   0          5s
kritis-validation-hook-7c84c48f47-lsjpg   0/1       ContainerCreating   0          5s
```

`kritis-preinstall` creates a `CertificateSigningRequest` and a TLS Secret for the webhook.

`kritis-postinstall` creates the `ValidatingWebhookConfiguration`.

```
$ kubectl get pods
NAME                                      READY     STATUS             RESTARTS   AGE
kritis-postinstall                        0/1       Completed          0          2m
kritis-preinstall                         0/1       Completed          0          2m
kritis-validation-hook-7c84c48f47-lsjpg   1/1       Running            0          2m
```
Once `kritis-preinstall` and `kritis-postinstall` have status `Completed`, and `kritis-validation-hook-xxxx` is `Running`, kritis is installed in your cluster.

### Optional Flags
Using the --set flag, you can set custom values when installing kritis:

|  Value                | Default      | Description  |   
|-----------------------|--------------|--------------|
| serviceNamespace      | default      | The namespace to install kritis in |   
| gacSecret.name        | gac-ca-admin | The name of the secret created above with container analysis permissions | 

For example, to install kritis in the namespace `test`, you could run:
```
helm install ./kritis-charts --set serviceNamespace=test
```

## Tutorial

Once you have installed Kritis, you may want to follow our [tutorial](tutorial.md) to learn how your can manage and test your Kritis configuration.

## Uninstalling Kritis

You can delete kritis by deleting the helm deployment:
```shell
$ helm ls
NAME        	REVISION	UPDATED                 	STATUS  	CHART         NAMESPACE
loopy-numbat	1       	Fri Jul 27 14:25:44 2018	DEPLOYED	kritis-0.1.0  default  
$ helm delete loopy-numbat
release "loopy-numbat" deleted
```

This command will also kick off the `kritis-predelete` pod, which deletes the CertificateSigningRequest, TLS Secret, and Webhooks created during installation.

```
$ kubectl get pods kritis-predelete
NAME                 READY     STATUS             RESTARTS   AGE
kritis-predelete     0/1       Completed          0          13s

$ kubectl logs kritis-predelete
level=info msg="contents of /var/run/secrets/kubernetes.io/serviceaccount/namespace: default"
level=info msg="[kubectl delete validatingwebhookconfiguration kritis-validation-hook --namespace default]"
level=info msg="validatingwebhookconfiguration.admissionregistration.k8s.io \"kritis-validation-hook\" deleted\n"
level=info msg="deleted validatingwebhookconfiguration kritis-validation-hook"
level=info msg="[kubectl delete secret tls-webhook-secret --namespace default]"
level=info msg="secret \"tls-webhook-secret\" deleted\n"
level=info msg="deleted secret tls-webhook-secret"
level=info msg="[kubectl delete csr tls-webhook-secret-cert --namespace default]"
level=info msg="certificatesigningrequest.certificates.k8s.io \"tls-webhook-secret-cert\" deleted\n"
level=info msg="deleted csr tls-webhook-secret-cert"
```

Kritis will be deleted from your cluster once this pod has reached `Completed` status.

Note: This will not delete the `ServiceAccount` or `ClusterRoleBinding` created during preinstall, or the container analysis secret created above.

# Troubleshooting

## Logs
If you're unable to install or delete kritis, looking at logs for the following pods could provide more information:
* kritis-validation-hook-xxx
* kritis-preinstall (during installation)
* kritis-postinstall (during installation)
* kritis-predelete (during deletion)

```
$ kubectl get pods
NAME                                      READY     STATUS             RESTARTS   AGE
kritis-postinstall                        0/1       Completed          0          2m
kritis-preinstall                         0/1       Completed          0          2m
kritis-validation-hook-7c84c48f47-lsjpg   1/1       Running            0          2m

$ kubectl logs kritis-postinstall
   ...
```

## Deleting Kritis
If you're unable to delete kritis via `helm delete [DEPLOYMENT NAME]`, you can manually delete kritis `validatingwebhookconfiguration` with the following commands:

```shell
$ kubectl delete validatingwebhookconfiguration kritis-validation-hook --namespace [YOUR NAMESPACE]

$ kubectl delete validatingwebhookconfiguration kritis-validation-hook-deployments --namespace [YOUR NAMESPACE]
```

`helm delete` should work at this point.
