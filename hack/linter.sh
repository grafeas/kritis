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

set -eu -o pipefail

readonly GO_BIN="${GOPATH:=$HOME/go}/bin"
readonly DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
readonly VERSION="v1.11.2"
readonly LINTER="golangci-lint-${VERSION}"

if ! [ -x "${GO_BIN}/${LINTER}" ]; then
	${DIR}/install_golint.sh -b "${GO_BIN}" "${VERSION}"
  mv "${GO_BIN}/golangci-lint" "${GO_BIN}/${LINTER}"
fi

# TODO(tstromberg): enable golint, deadcode, megacheck once code base is ready.
"${GO_BIN}/${LINTER}" run \
	--no-config \
	--exclude-use-default \
	--enable goconst \
	--enable gofmt \
	--enable goimports \
	--enable golint \
	--enable interfacer \
	--enable misspell \
	--enable unconvert \
	--enable unparam \
	--disable deadcode \
	--disable megacheck
