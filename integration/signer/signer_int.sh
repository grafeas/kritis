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
NOTE_ID=kritis-attestor-note
export NOTE_NAME=projects/${PROJECT_ID}/notes/${NOTE_ID}
export KMS_KEYRING=signer-int-test-keyring
export KMS_KEYNAME=signer-int-test-asymmetric-sign-key
export KMS_KEYLOCATION=global
export KMS_KEYVERSION=1
export KMS_PROJECT=$PROJECT_ID
export KMS_DIGESTALG=SHA512
export NOTE_NAME=projects/${PROJECT_ID}/notes/${NOTE_ID}

# create policy.yaml
cp policy_template.yaml policy.yaml

# install jq
# TODO: bake jq into a custom image
apt-get install -y -q jq
# Helper functions
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

delete_image() {
    ARG=$?
    set +ex
    IMG_TO_DELETE=$1
    echo "Delete image if uploaded."
    gcloud container images delete $IMG_TO_DELETE --force-delete-tags \
      --quiet
    exit $ARG
}

delete_occ() {
    ARG=$?
    set +ex
    IMG_DIGEST_URL_TO_DELETE=$1
    echo "Delete occurrence if created."
    if [ -n "$IMG_DIGEST_URL_TO_DELETE" ]; then
          ACCESS_TOKEN=$(gcloud --project ${PROJECT_ID} auth print-access-token)
          ENCODED_RESOURCE_URL=$(urlencode https://$IMG_DIGEST_URL_TO_DELETE)
          _OCCURRENCES_TO_CLEANUP=$(curl -X GET \
                 -H "Content-Type: application/json" \
                 -H "Authorization: Bearer ${ACCESS_TOKEN}"  \
                 https://containeranalysis.googleapis.com/v1/projects/${PROJECT_ID}/occurrences?filter=kind%3D%22ATTESTATION%22%20AND%20resourceUrl%3D%22${ENCODED_RESOURCE_URL}%22)
      if [ "$(echo ${_OCCURRENCES_TO_CLEANUP} | jq length)" -gt 0 ]; then
        _OCC_NAMES=$(echo ${_OCCURRENCES_TO_CLEANUP} | jq '.occurrences | .[] | .name' | tr -d '"')
        for _OCC_NAME in ${_OCC_NAMES}; do
          echo "Delete occurrence ${_OCC_NAME}."
          curl -X DELETE \
              -H "Content-Type: application/json" \
              -H "Authorization: Bearer ${ACCESS_TOKEN}"  \
              -H "x-goog-user-project: ${PROJECT_ID}" \
              "https://containeranalysis.googleapis.com/v1/${_OCC_NAME}"
        done
      fi
    fi
    exit $ARG
}

export -f urlencode
export -f delete_image
export -f delete_occ

# run tests
tmp_file=$(mktemp /tmp/file.XXX)
for script in ./tests/*.sh; do
   bash $script > ${script}.out 2>&1 &
   PID="$!"
   echo "$PID:$script" >> $tmp_file
   PID_LIST+="$PID "
done

# process test results
set +e
RESULT=0
SUMMARY=""
for PID in ${PID_LIST[@]};do
   wait $PID
   exit_status=$?
   if [ $exit_status -ne 0 ] ; then
     RESULT=1
   fi
   script_name=`egrep PID $tmp_file | awk -F ":" '{print $2}'`
   SUMMARY+="$script_name exit status: $exit_status\n"
done

for log in ./tests/*.out; do
   cat $log
done

printf $SUMMARY

exit $RESULT
