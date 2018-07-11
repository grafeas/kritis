# kritis

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
   Note: Please install in the same namespace that you created the secret using the `certgen` plugin.
   ```
   $ helm install ./kritis-charts --namespace <your namesapce>
   NAME:   lovely-chimp
   LAST DEPLOYED: Wed Jul 11 13:29:28 2018
   NAMESPACE: test
   STATUS: DEPLOYED

   RESOURCES:
   ==> v1/Service
   NAME                    TYPE       CLUSTER-IP     EXTERNAL-IP  PORT(S)  AGE
   kritis-validation-hook  ClusterIP  10.31.250.149  <none>       80/TCP   1s

   ==> v1beta2/Deployment
   NAME                    DESIRED  CURRENT  UP-TO-DATE  AVAILABLE  AGE
   kritis-validation-hook  1        1        1           0          1s

   ==> v1/Pod(related)
   NAME                                     READY  STATUS             RESTARTS  AGE
   kritis-validation-hook-595fdcdf74-cw5sj  0/1    ContainerCreating  0         1s
   ```
4. You can delete all the deployments using the release name.
   ```
   helm delete lovely-chimp
   ```
   Note: This does not delete the secrets.
