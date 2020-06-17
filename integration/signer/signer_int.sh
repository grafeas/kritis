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
# create policy.yaml
cat policy_template.yaml \
| sed -e "s?<ATTESTATION_PROJECT>?${PROJECT_ID}?g" \
| sed -e "s?<NOTE_PROJECT>?${PROJECT_ID}?g" \
| sed -e "s?<NOTE_ID>?${NOTE_ID}?g" \
> policy.yaml

#### TEST 1: bypass-and-sign mode ####
# build a "good" example image
TEST1_GOOD_IMAGE_URL=gcr.io/$PROJECT_ID/signer-int-good-image:$BUILD_ID
docker build -t $TEST1_GOOD_IMAGE_URL -f ./Dockerfile.good .
delete_test1_good_image () {
    ARG=$?
    echo "Delete good image."
    gcloud container images delete $TEST1_GOOD_IMAGE_URL --force-delete-tags \
      --quiet
    exit $ARG
}
trap delete_test1_good_image EXIT

# push good image
docker push $TEST1_GOOD_IMAGE_URL
# get image url with digest format
TEST1_GOOD_IMG_DIGEST_URL=$(docker image inspect $TEST1_GOOD_IMAGE_URL --format '{{index .RepoDigests 0}}')

# sign good image
./signer -v 10 \
-alsologtostderr \
-mode=bypass-and-sign \
-image=${TEST1_GOOD_IMG_DIGEST_URL} \
-public_key=public.key \
-private_key=private.key \
-policy=policy.yaml


# exit early, skipping tests with policy check for now.
# TODO: enable tests after #527 is merged.
exit 0


#### TEST 2: check-and-sign mode, good case ####
# build a "good" example image
GOOD_IMAGE_URL=gcr.io/$PROJECT_ID/signer-int-good-image:$BUILD_ID
docker build -t $GOOD_IMAGE_URL -f ./Dockerfile.good .
delete_good_image () {
    ARG=$?
    echo "Delete good image."
    gcloud container images delete $GOOD_IMAGE_URL --force-delete-tags \
      --quiet
    exit $ARG
}
trap delete_good_image EXIT

# push good image
docker push $GOOD_IMAGE_URL
# get image url with digest format
GOOD_IMG_DIGEST_URL=$(docker image inspect $GOOD_IMAGE_URL --format '{{index .RepoDigests 0}}')

# sign good image
./signer -v 10 \
-alsologtostderr \
-image=${GOOD_IMG_DIGEST_URL} \
-public_key=public.key \
-private_key=private.key \
-policy=policy.yaml


#### TEST 3: check-and-sign mode, bad case ####
# build a "bad" example image
BAD_IMAGE_URL=gcr.io/$PROJECT_ID/signer-int-bad-image:$BUILD_ID
docker build -t $BAD_IMAGE_URL -f ./Dockerfile.bad .
delete_bad_image () {
    ARG=$?
    echo "Delete bad image."
    gcloud container images delete $BAD_IMAGE_URL --force-delete-tags \
      --quiet
    exit $ARG
}
trap delete_bad_image EXIT

# push bad image
docker push $BAD_IMAGE_URL
# get image url with digest format
BAD_IMG_DIGEST_URL=$(docker image inspect $BAD_IMAGE_URL --format '{{index .RepoDigests 0}}')

signing_bad_image_failed=false
./signer -v 10 \
-alsologtostderr \
-image=${BAD_IMG_DIGEST_URL} \
-public_key=public.key \
-private_key=private.key \
-policy=policy.yaml || singing_bad_image_failed=true


if [ "$signing_bad_image_failed" = true ] ; then
	echo "Signing failed for bad image as expected."
    exit 0
else
	echo "Error: signing should fail for bad image, but succeeded."
    exit 1
fi
