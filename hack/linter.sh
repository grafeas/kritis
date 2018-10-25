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

set -eux -o pipefail

readonly go_bin="${GOPATH:=$HOME/go}/bin"
readonly release="v2.0.11"
readonly cmd="gometalinter-${release}"
readonly cmd_path="${go_bin}/${cmd}"
readonly pwd="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if ! [[ -x "${cmd_path}" ]]; then
  ${pwd}/install_golint.sh -b "${go_bin}" "${release}"
  mv "${go_bin}/gometalinter" "${cmd_path}"
fi

# unparam should be enabled once source code issues are addressed.
"${cmd_path}" \
  -s vendor \
  -s versioned \
  --exclude vendor/ \
  --no-config \
  --deadline 300s \
  --aggregate \
  --sort=path \
  --enable gofmt \
  --enable goimports \
  --enable misspell \
  --enable unconvert \
  --disable deadcode \
  --disable gosec \
  --disable gotype \
  --disable gocyclo \
  --disable megacheck \
  --disable unparam \
  ./...
