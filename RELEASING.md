# Steps to Release kritis

## Create a Release PR
Modify the kritis version values for the containers in these locations:
[Makefile](https://github.com/grafeas/kritis/blob/master/Makefile#L19)
[Chart.yaml](https://github.com/grafeas/kritis/blob/master/kritis-charts/Chart.yaml#L5)
Update all tags to be equal to the version here, find-replace :OLD_VERSION, :NEW_VERSION:
[values.yaml](https://github.com/grafeas/kritis/blob/master/kritis-charts/values.yaml)

Assemble all the meaningful changes since the last release into the CHANGELOG.md file.
See [this PR](https://github.com/grafeas/kritis/pull/1) for an example.

## Merge Release PR
Verify that the integration test suite has passed for the release PR, then merge the PR

## Tag the release
git pull checkout master
git pull upstream master
git tag -am "kritis-vX.Y.Z ftl release" kritis-vX.Y.Z
git push upstream --tags

## Cloudbuild kritis release build triggers
Once the tag is pushed upstream, a the Cloudbuild job [here](https://github.com/grafeas/kritis/pull/1) will run, creating the new versions of the kritis containers and creating a new helm chart

## Create a Release in Github
Create a new release based on your tag, like [this one](https://github.com/grafeas/kritis/releases/tag/v0.1.0).

Upload the files, and calculated checksums.
