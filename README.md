# Kritis

[![GoDoc Widget]][GoDoc]
[![BuildStatus Widget]][BuildStatus Result]
[![GoReport Widget]][GoReport Status]

[GoDoc]: https://godoc.org/github.com/grafeas/kritis
[GoDoc Widget]: https://godoc.org/github.com/grafeas/kritis?status.svg

[BuildStatus Result]: https://travis-ci.org/grafeas/kritis
[BuildStatus Widget]: https://travis-ci.org/grafeas/kritis.svg?branch=master

[GoReport Status]: https://goreportcard.com/report/github.com/grafeas/kritis
[GoReport Widget]: https://goreportcard.com/badge/github.com/grafeas/kritis


![Kritis logo](logo/logo-128.png)

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

In addition to the enforcement this project also contains *signers* that can be
used to create [Grafeas](https://github.com/grafeas/grafeas) Attestation
Occurrences to be used in other enforcement systems like [Binary
Authorization](https://cloud.google.com/binary-authorization/).  For details see
[Kritis Signer](docs/signer_install.md).

## Getting Started

* Learn the concepts in the [Kritis whitepaper](docs/binary-authorization.md)
* Get Kritis running with the [Installation guide](docs/install.md)
* Try the [Tutorial](docs/tutorial.md) to learn how to block vulnerabilities
* Read the [Resource Reference](docs/resources.md) to configure and interact with Kritis resources
* Resolve image tags to hashes using the [resolve-tags plug-in](https://github.com/grafeas/kritis/blob/master/cmd/kritis/kubectl/plugins/resolve/README.md)

## Support

If you have questions, reach out to us on
[kritis-users](https://groups.google.com/forum/#!forum/kritis-users). For
questions about contributing, please see the [section](#contributing) below.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for details on how you can contribute.

See [DEVELOPMENT](DEVELOPMENT.md) for details on the  development and testing workflow.

## License

Kritis is under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.
