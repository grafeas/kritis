#!/bin/bash

PROJECT_ROOT=$(dirname "${BASH_SOURCE}")/..

# Register function to be called on EXIT to remove generated binary.
function cleanup {
  ls "${PROJECT_ROOT}/cmd/kritis"
}
trap cleanup EXIT

pushd "${PROJECT_ROOT}"
cp -v _output/bin/kritis-server cmd/kritis
docker build -t gcr.io/kritis/kritis-server:latest kritis
popd
