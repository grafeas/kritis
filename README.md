# Kritis

Kritis (“judge” in Greek), provides full software supply chain security for Kubernetes applications,
allowing devOps teams to enforce deploy-time image security policies using metadata and attestations stored in [Grafeas](https://github.com/grafeas/grafeas).

You can read the [Kritis whitepaper](https://github.com/Grafeas/Grafeas/blob/master/case-studies/binary-authorization.md) for more details.

Note: Currently kritis doesn't use grafeas and pulls vulnerability informtation via the [Container Analysis API](https://cloud.google.com/container-analysis/api/reference/rest/)

## Installing Kritis

Instructions for installing kritis on your cluster via helm can be found [here](https://github.com/grafeas/kritis/blob/master/kritis-charts/README.md)

## Kritis Tutorial

### Setting up an ImageSecurityPolicy

Kritis relies on user defined `ImageSecurityPolicies` to determine whether a pod should be admitted or denied at deploy time.
First, create the `ImageSecurityPolicy` CRD (custom resource definition).

`kubectl create -f artifacts/image-security-policy-crd.yaml`

The user then needs to specify an `ImageSecurityPolicy`. 
A sample is shown here:
```yaml
apiVersion: kritis.grafeas.io/v1beta1
kind: ImageSecurityPolicy
metadata:
  name: my-isp
  namespace: default
spec:
  imageWhitelist: 
  - gcr.io/my/image
  packageVulnerabilityRequirements:
    maximumSeverity: HIGH
    onlyFixesNotAvailable: true
    whitelistCVEs:
      - providers/goog-vulnz/notes/CVE-2017-1000082
      - providers/goog-vulnz/notes/CVE-2017-1000081
```
| Field         | Possible Values           | Details  |
| ------------- | ------------- | ----- |
| imageWhitelist  | | A list of images that are whitelisted and should always be allowed. |
| maximumSeverity | LOW|MEDIUM|HIGH|CRITICAL|BLOCKALL |   The maximum CVE severity allowed in an image. An image with CVEs exceeding this limit will result in the pod being denied. `BLOCKALL` will block an image with any CVEs that aren't whitelisted.|
| onlyFixesNotAvailable | true/false | When set to true, any images that contain CVEs with fixes available will be denied. |
| whitelistCVEs |     | Ignore these CVEs when deciding whether to allow or deny a pod. |

