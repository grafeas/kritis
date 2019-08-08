# Kritis with Standalone Grafeas

## Before you begin

Make sure you have the following installed:

* [Kubernetes](https://kubernetes.io/) v1.9.2+
* [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
* [helm](https://helm.sh/)
* [openssl](https://www.openssl.org/)
* [GnuPG](https://gnupg.org/download/)
* [Google Cloud](https://cloud.google.com) account with [billing enabled](https://console.cloud.google.com/billing)
* [Google Cloud SDK](https://cloud.google.com/sdk/docs/) (gcloud)

Note: you will be charged for running on GCP. See [Free
Tier](https://cloud.google.com/free) for information on how to try out GCP.
Contributions of the examples running on other k8s engines are welcome!

## Installation Steps

NOTE: The steps described in this section will install Grafeas and Kritis charts to the `default` k8s namespace.

1. Check out your fork of the Kritis repository by following [these
   instructions](../../DEVELOPMENT.md#checkout-your-fork). Then, navigate to the
   standalone folder:

    ```shell
    cd ${GOPATH}/src/github.com/grafeas/kritis/docs/standalone
    ```

1. Set up GCP project where Kubernetes Engine API is enabled. You'll need to create a new project by following the prompts at [Google Cloud Console: New Project](https://console.cloud.google.com/projectcreate).
    For convenience, save the project ID as an environment variable and set up
    the GKE cluster.

    ```shell
    PROJECT=<project ID assigned to you>
    gcloud config set project $PROJECT
    gcloud components update
    gcloud config set compute/zone us-central1-a
    gcloud container clusters create kritis-test --num-nodes=2
    gcloud container clusters get-credentials kritis-test
    ```

    For more documentation, see [Kubernetes Engine: Creating a Cluster](https://cloud.google.com/kubernetes-engine/docs/how-to/creating-a-cluster).

1. Upload the Service Account Key:


    ```shell
    gcloud iam service-accounts keys create gac.json \
      --iam-account kritis-ca-admin@${PROJECT}.iam.gserviceaccount.com
    kubectl create secret generic gac-ca-admin --from-file=gac.json
    ```

1. Set up Helm:

    ```shell
    ./setup_helm.sh
    ```

1. Install Grafeas to the cluster with the following script. The script will
   also generate TLS certificates that the Grafeas server uses.

   WARNING: Make sure to set `Common Name` to `grafeas-server` when prompted
   during the certificate creation.

    ```shell
    ./setup_grafeas.sh
    ```

    You can ensure that Grafeas is running:

    ```shell
    kubectl get pods
    NAME                              READY   STATUS      RESTARTS   AGE
    grafeas-server-64b74cf696-6vb4b   1/1     Running     0          16s
    ```

1. Install Kritis to your cluster:

    ```shell
    ./setup_kritis.sh
    ```

    You can ensure that Kritis is running:

    ```shell
    kubectl get pods
    NAME                                      READY   STATUS      RESTARTS   AGE
    kritis-postinstall                        0/1     Completed   0          3m
    kritis-predelete                          0/1     Completed   0          18h
    kritis-preinstall                         0/1     Completed   0          3m
    kritis-validation-hook-576dbb55c6-752nq   1/1     Running     0          3m
    ```

## User Journeys

1. No policies are defined, so a pod is admitted by default, due to the
   admit-all fallback policy:

    ```shell
    kubectl apply -f pod.yaml
    ```

    You should get `pod/java created` in response.

1. `GenericAttestationPolicy` is set, but no attestation exists for the pod in
   Grafeas.

   NOTE: The script below assumes Linux platform, but you can modify it to run
   on MacOS X as described
   [here](../tutorial.md#2-setting-up-an-attestationauthority).

   ```shell
   ./no_attestation.sh
   ```

   You will get `Error from server: error when creating "pod.yaml": admission
   webhook "kritis-validation-hook.grafeas.io" denied the request: image
   gcr.io/kritis-tutorial/java-with-vulnz@sha256:<hash> is not attested` in response.

   You can check the reason the pod creation was rejected by looking at the
   Kritis logs:

    ```shell
    kubectl logs -l app=kritis-validation-hook
    ```

    You'll find `No attestations found for image
    gcr.io/kritis-tutorial/java-with-vulnz@sha256:<hash>.` message in the logs.

1. Create a valid attestation and ensure this pod is now admitted.

    To get the external IP address of the Grafeas server, run:

    ```shell
    kubectl get svc
    NAME                     TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)         AGE
    grafeas-server           LoadBalancer   10.31.248.62    35.232.9.51   443:31212/TCP   11m
    ...
    ```

    Create an entry in your local `/etc/hosts`, to map `EXTERNAL-IP` to the
    service name:

    ```shell
    35.232.9.51 grafeas-server
    ```

    Run the sample client:

    ```shell
    go run create_attestation.go
    ```

    You should get `pod/java created` in response and see the following in
    `kubectl logs -l app=kritis-validation-hook`:

    ```shell
    admission.go:124] handling pod java in...
    admission.go:245] Reviewing images for &Pod{ObjectMeta:k8s_io_apimachinery_pkg_apis_meta_v1.ObjectMeta{Name:java,GenerateName:,Namespace:default,SelfLink:,UID:98a55b42-b87e-11e9-bd23-42010a80011e,ResourceVersion:,Generation:0,CreationTimestamp:2019-08-06 19:15:47 +0000 UTC,DeletionTimestamp:<nil>,DeletionGracePeriodSeconds:nil,Labels:map[string]string{},Annotations:map[string]string{kubectl.kubernetes.io/last-applied-configuration: {"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{},"name":"java","namespace":"default"},"spec":{"containers":[{"image":"gcr.io/kritis-tutorial/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a","name":"java","ports":[{"containerPort":80}]}]}}
      ...
      admission.go:264] Found 1 Generic Attestation Policies
      review.go:72] Check if gcr.io/kritis-tutorial/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a has valid Attestations.
      ...
      strategy.go:51] Image gcr.io/kritis-tutorial/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a has one or more valid attestation(s)
      ...
    ```

## Cleanup

To delete the Kritis and Grafeas, run:

```shell
./cleanup.sh
```

The first command in the script will delete Kritis helm chart and kick off the `kritis-predelete` pod, which deletes the CertificateSigningRequest, TLS Secret, and Webhooks created during installation. You may view the status using:

```shell
kubectl get pods kritis-predelete
```

And the logs using:

```shell
kubectl logs kritis-predelete
```

Most resources created by Kritis will be deleted from your cluster once this Pod has reached `Completed` status. The second command in the script will delete the remaining resources.

The last command in the script will delete the Grafeas helm chart.
