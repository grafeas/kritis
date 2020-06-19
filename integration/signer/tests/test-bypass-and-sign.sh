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

echo ""
echo ""

set -eux

GOOD_IMAGE_URL=gcr.io/$PROJECT_ID/signer-int-good-image:$BUILD_ID
docker build --no-cache -t $GOOD_IMAGE_URL -f ./Dockerfile.good .
clean_up () {
    set +ex
    ARG=$?
    echo "Delete image if uploaded."
    gcloud container images delete $GOOD_IMAGE_URL --force-delete-tags \
      --quiet
    echo "Delete occurrence if created."
    if [ -n "$GOOD_IMG_DIGEST_URL" ]; then
          ACCESS_TOKEN=$(gcloud --project ${PROJECT_ID} auth print-access-token)
          ENCODED_RESOURCE_URL=$(urlencode https://$GOOD_IMG_DIGEST_URL)
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
              "https://containeranalysis.googleapis.com/v1beta1/${_OCC_NAME}"
        done
      fi
    fi
    exit $ARG
}
trap clean_up EXIT

# push good image
docker push $GOOD_IMAGE_URL
# get image url with digest format
GOOD_IMG_DIGEST_URL=$(docker image inspect $GOOD_IMAGE_URL --format '{{index .RepoDigests 0}}')


# sign good image in bypass mode
./signer -v 10 \
-alsologtostderr \
-mode=bypass-and-sign \
-image=${GOOD_IMG_DIGEST_URL} \
-public_key=public.key \
-private_key=private.key \
-policy=policy.yaml

echo ""
echo ""
