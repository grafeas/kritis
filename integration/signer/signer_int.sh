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

set +x
ACCESS_TOKEN=$(gcloud --project ${PROJECT_ID} auth print-access-token)
# TODO: debugging, remove before merge
exit

#### TEST 1: bypass-and-sign mode ####
./tests/test-bypass-and-sign.sh



#### TEST 2: check-and-sign mode, good case ####
./tests/test-check-and-sign-good.sh

#### TEST 3: check-and-sign mode, bad case ####
./tests/test-check-and-sign-bad.sh