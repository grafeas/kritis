#!/bin/bash

# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -e: if command fails, script exits
# -u: treat unset variables as an error and immediately exit
# -f: disable filename expansion
# -x: debug mode
set -euf -x

source "${KOKORO_GFILE_DIR}/common.sh"

# Get everything into GOPATH
sudo mkdir -p "${GOPATH}/src/github.com/grafeas/kritis/"
CWD=`pwd`
sudo cp -ar "${CWD}/github/kritis/." "${GOPATH}/src/github.com/grafeas/kritis"

pushd "${GOPATH}/src/github.com/grafeas/kritis"

echo "Check format"
./hack/check-fmt.sh

echo "Copying kritis int test creds..."
mkdir -p "${HOME}/tmp/"
cp "${KOKORO_ROOT}/src/keystore/72508_kritis_int_test" "${HOME}/tmp/gac.json"


echo "Running unit and integration tests..."
go test -cover -v -timeout 60s -tags=integration \
  `go list ./... \ | grep -v vendor | grep -v kritis/integration`

GO_TEST_EXIT_CODE="${PIPESTATUS[0]}"
if [[ "${GO_TEST_EXIT_CODE}" -ne 0 ]]; then
    exit "${GO_TEST_EXIT_CODE}"
fi

REGISTRY=gcr.io/YOUR_TEST_PROJECT make build-push-image
REGISTRY=gcr.io/YOUR_TEST_PROJECT make integration-in-docker

popd
