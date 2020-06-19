#!/bin/bash

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

# Signer integration testing script
set -ex

# set note id
export NOTE_ID=kritis-attestor-note
# create policy.yaml
cat policy_template.yaml \
| sed -e "s?<ATTESTATION_PROJECT>?${PROJECT_ID}?g" \
| sed -e "s?<NOTE_PROJECT>?${PROJECT_ID}?g" \
| sed -e "s?<NOTE_ID>?${NOTE_ID}?g" \
> policy.yaml

# install jq
# TODO: bake jq into a custom image
apt-get install -y -q jq
# Helper function for encoding url
urlencode() {
    # urlencode <string>
    local LC_COLLATE=C

    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf "$c" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done
}

export -f urlencode

#### TEST 1: bypass-and-sign mode ####
./tests/test-bypass-and-sign.sh

exit

#### TEST 2: check-and-sign mode, good case ####
./tests/test-check-and-sign-good.sh

#### TEST 3: check-and-sign mode, bad case ####
./tests/test-check-and-sign-bad.sh
