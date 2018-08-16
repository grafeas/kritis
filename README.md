# Kritis

Kritis (“judge” in Greek), is an open-source solution for securing your software supply chain for Kubernetes applications. Kritis enforces deploy-time security policies using the [Google Cloud Container Analysis API](https://cloud.google.com/container-analysis/api/reference/rest/), and in a subsequent release, [Grafeas](https://github.com/grafeas/grafeas).

Here is an example Kritis policy, to prevent the deployment of Pod with a critical vulnerability unless it has been whitelisted:

```yaml
imageWhitelist:
- gcr.io/my-project/whitelist-image@sha256:<DIGEST>
packageVulnerabilityPolicy:
  maximumSeverity: HIGH
  whitelistCVEs:
    providers/goog-vulnz/notes/CVE-2017-1000082
    providers/goog-vulnz/notes/CVE-2017-1000082
```

## Getting Started

* Learn the concepts in the [Kritis whitepaper](https://github.com/Grafeas/Grafeas/blob/master/case-studies/binary-authorization.md)
* Get Kritis running with the [Installation guide](install.md)
* Try the [Tutorial](tutorial.md) to learn how to block vulnerabilities
* Learn the configuration details in the [Usage guide](usage.md)

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for details on how you can contribute.

See [DEVELOPMENT](DEVELOPMENT.md) for details on the  development and testing workflow.

## License

Kritis is under the Apache 2.0 license. See the [LICENSE](LICENSE.md) file for details.