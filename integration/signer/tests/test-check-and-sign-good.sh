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

set -ex

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

