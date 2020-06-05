# Signer integration testing script
set -ex

# prepare policy file
export NOTE_ID=kritis-attestor-note
# create policy.yaml
cat policy_template.yaml \
| sed -e "s?<ATTESTATION_PROJECT>?${PROJECT_ID}?g" \
| sed -e "s?<NOTE_PROJECT>?${PROJECT_ID}?g" \
| sed -e "s?<NOTE_ID>?${NOTE_ID}?g" \
> policy.yaml

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

./signer -v 10 \
-alsologtostderr \
-image=${BAD_IMG_DIGEST_URL} \
-public_key=public.key \
-private_key=private.key \
-policy=policy.yaml || exit 0
