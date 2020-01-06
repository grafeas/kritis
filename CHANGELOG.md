This is the changelog of Kritis releases

v0.2.0:
  * Added support for separating image and Attestor into different GCP projects.
  * Improvements for highly available Kritis:
    * `namespaceSelector` to allowlist critical namespaces, e.g. `kube-system`,
      in the event Kritis is unavailable.
  * No-op refactoring to use two new interfaces to work with attestations:
    * `ValidatedAttestation` -- a trusted, verified attestion.
    * `ValidatingTransport` -- allows caller to obtain `ValidatedAttestation`
      for a given image.
  * Added clarifications for guarantees in `ListNoteOccurrences` when retrieving
    attestations.
  * Cleanup:
    * removed API version from NoteReference.
    * s/Occurence/Occurrence where applicable.

v0.1.1:
  * Fixed memory leak due to unused connections

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

