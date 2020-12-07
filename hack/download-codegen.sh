#!/bin/sh

# Copyright 2020 Google LLC
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

set -o errexit
set -o nounset
set -o pipefail

CODEGEN_VERSION="kubernetes-1.10.0"

wget "https://github.com/kubernetes/code-generator/archive/${CODEGEN_VERSION}.tar.gz"
echo "67bfc9d104fac00a76bc9aec1fb3b1af1d731987d021f49c72d9fa2d5ed5748e ${CODEGEN_VERSION}.tar.gz" | sha256sum -c
mkdir -p $GOPATH/src/k8s.io && tar xvzf "${CODEGEN_VERSION}.tar.gz" -C $GOPATH/src/k8s.io 
mv "${GOPATH}/src/k8s.io/code-generator-${CODEGEN_VERSION}" $GOPATH/src/k8s.io/code-generator
cd "${GOPATH}/src/k8s.io/code-generator"
go install ./cmd/{defaulter-gen,client-gen,lister-gen,informer-gen,deepcopy-gen}
sed -i.bak '/^go install/s//#&/' "${GOPATH}/src/k8s.io/code-generator/generate-groups.sh"
