# Kritis Versioning Explained: API vs Server

Kritis uses a mix of [Kubernetes API](https://kubernetes.io/docs/concepts/overview/kubernetes-api/#api-versioning) and [semantic](https://semver.org/) versioning. This document clarifies the rationale behind this mix in versioning approaches.

## API

Kritis follows Kubernetes versioning scheme, to be consistent with the approach
used by the larger Kubernetes community.

## Server

Kritis server uses semantic versioning. The server currently supports v1beta1
version of the Kritis API. This approach allows us to communicate to the open
source community the production readiness of Kritis, as well as differentiate
between bug fixes, minor and major feature releases.
