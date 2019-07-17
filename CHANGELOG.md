This is the changelog of Kritis releases

v0.1.0:
  * Kritis supports two policies for pod admission:
    * `ImageSecurityPolicy` which allows users to secure their clusters by specifying the vulnerability threshold for containers above which they cannot be deployed;
    * `GenericAttestationPolicy` which allows users to only deploy pods for
      which they explicitly stored an attestation.
  * Kritis has the allow-all fallback policy if neither of the policies is
    specified.
  * Kritis uses Grafeas API to get vulnerability and attestation information via:
    * standalone Grafeas server running locally in k8s cluster;
    * Container Analysis API on GCP.
  * Kritis has an ability to continuously monitor the pods in the cluster and add labels and annotation to the pods out of policy.

