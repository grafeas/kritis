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
kritis can only inspect images hosted in projects that have both of these enabled.

### Creating a Container Analysis Secret
You will need to create a Kubernetes secret, which will provide kritis with the auth required to get vulnerability information for images.
To create the secret:
1. Create a service account with `Container Analysis Admin` permissions in the Google Cloud Console project that hosts the images kritis will be inspecting
2. Download a JSON key for the service account
3. Rename the key to `kritis.json`
4. Create a Kubernetes secret by running:
```
kubectl create secret generic <SECRET NAME> --from-file=<path to kritis.json>
```

## Installing Kritis
1. To install kritis via helm, we need to first generate TLS certs.
   To do that,
   1. First download the helm plugin to generate certs from [here](https://github.com/SUSE/helm-certgen/releases)
   2. Unzip the tar and then install the plugin.
      ```
      tar -xvf certgen-linux-amd64-1-0-0-1501794790-f3b21c90.tgz --directory ~/certgen/
      helm plugin install ~/certgen/
      ```
   3. Finally generate the Cert using the plugin.
      ```
       helm certgen generate ./kritis-charts --namespace <your namespace>
      ```
2. Once the certs are created, you will see secret `tls-webhook-secret` created in your cluster.
   ```
   $ kubectl get secrets --namespace=default
   NAME                  TYPE                                  DATA      AGE
   tls-webhook-secret    Opaque                                2         11m
   ```
   You can examine the secret by running
   ```
   $  kubectl get secret tls-webhook-secret --output=yaml
   ```
3. Now run, `helm install` to install the kritis-server.
   
   You will pass in the certificate from `tls-webhook-secret` to caBundle and the name of the secret with container analysis permissions created above.
   
   Note: Please install in the same namespace that you created the secret using the `certgen` plugin.
   ```
   $ helm install ./kritis-charts --namespace <your namesapce> \
        --set caBundle=$(kubectl get secret tls-webhook-secret -o jsonpath='{.data.cert}') \
        --set secret.name=<your secret name>
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
4. You can delete all the deployments using the release name.
   ```
   helm delete whimsical-cricket
   ```
   Note: This does not delete the secrets.
