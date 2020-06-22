# Steps to Release Kritis

We're following [semantic versioning](https://semver.org/) approach to releases in Kritis.

## Create a release tracking issue

Use the [release tracking](https://github.com/grafeas/kritis/issues/new?template=feature_request.md)
template to create a release tracking issue. If any problems come up during the release process, please use
this issue to note them. Also use this issue to track the progress of the release process.

## Create a Release PR
Associate the PR to the tracking issue.  Modify the Kritis version values for the containers in these locations:

* [Makefile](Makefile#L19)
* [Chart.yaml](kritis-charts/Chart.yaml#L5)
* [values.yaml](kritis-charts/values.yaml#L8)

Assemble all the meaningful changes since the last release into the [CHANGELOG.md](CHANGELOG.md) file.
See [this PR](https://github.com/grafeas/kritis/pull/244) for an example.

## Merge Release PR
Verify that the integration test suite has passed for the release PR, then merge the PR.

## Tag the release

Make sure your fork of the repository is updated. Assuming `git remote` shows the `origin` (the fork) and `upstream` (the main repository), do:

```
git pull origin master
git pull upstream master
git tag -am "kritis-vX.Y.Z release" vX.Y.Z
git push upstream --tags
```

NOTE: the last command will not work if you set `git remote set-url --push upstream no_push` as described in [DEVELOPMENT.md](DEVELOPMENT.md). You will need to re-enable the `push` for this to work, so proceed with caution.

Once the tag is pushed upstream, the CloudBuild will run, creating the new versions of the kritis containers and a new helm chart.

## See the release in Github
You can find the releases in Github, e.g. [v0.1.0](https://github.com/grafeas/kritis/releases/tag/v0.1.0).
