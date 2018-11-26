# Development

This doc explains the development workflow so you can get started [contributing](CONTRIBUTING.md) to Kritis!

## Getting started

First you will need to setup your GitHub account and create a fork:

1. Create [a GitHub account](https://github.com/join)
1. Setup [GitHub access via
   SSH](https://help.github.com/articles/connecting-to-github-with-ssh/)
1. [Create and checkout a repo fork](#checkout-your-fork)

Once you have those, you can iterate on kritis:

1. [Run your instance of kritis](docs/install.md#Installing-Kritis-to-your-cluster)
1. [Run kritis tests](#testing-kritis)

When you're ready, you can [create a PR](#creating-a-pr)!

## Checkout your fork

The Go tools require that you clone the repository to the `src/github.com/GoogleContainerTools/kritis` directory
in your [`GOPATH`](https://github.com/golang/go/wiki/SettingGOPATH).

To check out this repository:

1. Create your own [fork of this
  repo](https://help.github.com/articles/fork-a-repo/)
2. Clone it to your machine:

  ```shell
  mkdir -p ${GOPATH}/src/github.com/grafeas
  cd ${GOPATH}/src/github.com/grafeas
  git clone git@github.com:${YOUR_GITHUB_USERNAME}/kritis.git
  cd kritis
  git remote add upstream git@github.com:grafeas/kritis.git
  git remote set-url --push upstream no_push
  ```

_Adding the `upstream` remote sets you up nicely for regularly [syncing your
fork](https://help.github.com/articles/syncing-a-fork/)._

## Testing kritis

kritis has both [unit tests](#unit-tests) and [integration tests](#integration-tests).

### Unit Tests

The unit tests live with the code they test and can be run with:

```shell
make test
```

:warning: These tests will not run correctly unless you have [checked out your fork into your `$GOPATH`](#checkout-your-fork).

### Integration tests

On a GCP project where Kritis has already been installed, this will prepare a new cluster named `kritis-integration-test`:

```shell
make -e GCP_PROJECT=<project id> setup-integration-local
```

As you develop, you can build new test images and run the integration test on demand:

```shell
make -e GCP_PROJECT=<project id> integration-local
```

## Creating a PR

When you have changes you would like to propose to kritis, you will need to:

1. Ensure the commit message(s) describe what issue you are fixing and how you are fixing it
   (include references to [issue numbers](https://help.github.com/articles/closing-issues-using-keywords/)
   if appropriate)
1. [Create a pull request](https://help.github.com/articles/creating-a-pull-request-from-a-fork/)

### Reviews

Each PR must be reviewed by a maintainer. This maintainer will add the `kokoro:run` label
to a PR to kick of [the integration tests](#integration-tests), which must pass for the PR
to be submitted.
