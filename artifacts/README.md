# Kritis Custom Resource Definitions

## ImageSecurityPolicy

Kritis relies on a user defined `ImageSecurityPolicy` to determine whether a pod should be admitted or denied at deploy time.

A sample is shown here:
```yaml
apiVersion: kritis.grafeas.io/v1beta1
kind: ImageSecurityPolicy
metadata:
  name: my-isp
  namespace: default
spec:
  imageWhitelist: 
  - gcr.io/kritis-int-test/nginx-digest-whitelist:latest
  - gcr.io/kritis-int-test/nginx-digest-whitelist@sha256:digest
  packageVulnerabilityRequirements:
    maximumSeverity: HIGH
    onlyFixesNotAvailable: true
    whitelistCVEs:
      - providers/goog-vulnz/notes/CVE-2017-1000082
      - providers/goog-vulnz/notes/CVE-2017-1000081
```


| Field                     | Default | Possible Values                  | Details  |
| -----------------------   | ------- |---------------------------       | -------- |
| imageWhitelist            |         |                                  | A list of images that are whitelisted and should always be allowed. |
| maximumSeverity           |         |LOW/MEDIUM/HIGH/CRITICAL/BLOCKALL | The maximum CVE severity allowed in an image. An image with CVEs exceeding this limit will result in the pod being denied. `BLOCKALL` will block an image with any CVEs that aren't whitelisted.|
| onlyFixesNotAvailable     | false   | true/false                       | When set to true, any images that contain CVEs with fixes available will be denied. |
| whitelistCVEs             |         |                                  | Ignore these CVEs when deciding whether to allow or deny a pod. |
