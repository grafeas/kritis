# Kritis with Standalone Grafeas

## Before you begin

Make sure you have the following installed:

* [Kubernetes](https://kubernetes.io/)
* [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
* [helm](https://helm.sh/)
* [openssl](https://www.openssl.org/)
* [GnuPG](https://gnupg.org/download/)

## Installation Steps

NOTE: The steps described in this section will install Grafeas and Kritis charts to the `default` k8s namespace.

1. Check out your fork of the Kritis repository by following [these
   instructions](../../DEVELOPMENT.md#checkout-your-fork). Then, navigate to the
   standalone folder:

    ```shell
    cd ${GOPATH}/src/github.com/grafeas/kritis/docs/standalone
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

   NOTE: Make sure to set `gpg` passphrase to the same value as the argument you
   pass to the script, e.g. `passphrase` in this example.

   NOTE: The script below assumes Linux platform, but you can modify it to run
   on MacOS X as described
   [here](../tutorial.md#2-setting-up-an-attestationauthority).

   ```shell
   ./no_attestation.sh passphrase
   ```

   You will get `Error from server: error when creating "pod.yaml": admission
   webhook "kritis-validation-hook.grafeas.io" denied the request: image
   gcr.io/kritis-tutorial/java-with-vulnz:latest is not attested` in response.

   You can check the reason the pod creation was rejected by looking at the
   Kritis logs:

    ```shell
    kubectl logs -l app=kritis-validation-hook
    ```

    You'll find `No attestations found for image
    gcr.io/kritis-tutorial/java-with-vulnz:latest.` message in the logs.

1. Create a valid attestation and ensure this pod is now admitted.

    TODO: add example here.

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
