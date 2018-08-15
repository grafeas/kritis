# Kritis

Kritis (“judge” in Greek), provides software supply chain security for Kubernetes applications,
allowing DevOps teams to enforce deploy-time image security policies using metadata and attestations stored in [Grafeas](https://github.com/grafeas/grafeas).

Here is an example  policy which may be set with Kritis,  to prevent the deployment of Kubernetes pod containing a critical vulnerability unless specifically whitelisted:


```yaml
imageWhitelist:
- gcr.io/my-project/whitelist-image@sha256:<DIGEST>
packageVulnerabilityPolicy:
  maximumSeverity: HIGH
  whitelistCVEs:
    providers/goog-vulnz/notes/CVE-2017-1000082
    providers/goog-vulnz/notes/CVE-2017-1000082
```

For more details, read the [Kritis whitepaper](https://github.com/Grafeas/Grafeas/blob/master/case-studies/binary-authorization.md).

NOTE: Kritis currently requires access to the [Google Cloud Container Analysis API](https://cloud.google.com/container-analysis/api/reference/rest/)

## Documentation

* [Installation](install.md)
* [Tutorial](tutorial.md)
* [Resources reference](resources.md)
* [resolve-tags plug-in guide](https://github.com/grafeas/kritis/blob/master/cmd/kritis/kubectl/plugins/resolve/README.md)
