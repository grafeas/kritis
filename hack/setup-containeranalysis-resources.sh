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

cleanup () {
  echo "Deleting Occurrences and Notes"

  _OCCURRENCES_TO_CLEANUP=$(curl -X GET \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}"  \
      -H "x-goog-user-project: ${PROJECT_ID}" \
      "https://containeranalysis.googleapis.com/v1beta1/projects/${PROJECT_ID}/notes/${NOTE_ID}/occurrences")
  if [ "$(echo ${_OCCURRENCES_TO_CLEANUP} | jq length)" -gt 0 ]; then
    _OCC_NAMES=$(echo ${_OCCURRENCES_TO_CLEANUP} | jq '.occurrences | .[] | .name' | tr -d '"')
    for _OCC_NAME in ${_OCC_NAMES}; do
      curl -X DELETE \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer ${ACCESS_TOKEN}"  \
          -H "x-goog-user-project: ${PROJECT_ID}" \
          "https://containeranalysis.googleapis.com/v1beta1/${_OCC_NAME}"
    done
  fi

  curl -X DELETE \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}"  \
      -H "x-goog-user-project: ${PROJECT_ID}" \
      "https://containeranalysis.googleapis.com/v1beta1/projects/${PROJECT_ID}/notes/${NOTE_ID}"
}

usage() {
  cat <<EOF
usage: ${0} [--project project_id]
EOF
}

set -e

while [[ $# -gt 0 ]]; do
    case ${1} in
        --project)
            PROJECT_ID="$2"
            shift
            ;;
        *)
            usage
            ;;
    esac
    shift
done

if [ -z "${PROJECT_ID}" ]; then
  echo "--project must be set"
  exit 1
fi

TMPDIR=$(mktemp -d)
echo Created tempdir ${TMPDIR}
ACCESS_TOKEN=$(gcloud --project ${PROJECT_ID} auth print-access-token)
NOTE_ID=test-attestor-1
NOTE_URI=projects/${PROJECT_ID}/notes/${NOTE_ID}
IMAGE_PATH=gcr.io/${PROJECT_ID}/nginx-digest-whitelist
IMAGE_DIGEST=sha256:56e0af16f4a9d2401d3f55bc8d214d519f070b5317512c87568603f315a8be72
IMAGE_TO_ATTEST="https://${IMAGE_PATH}@${IMAGE_DIGEST}"
ATTESTOR_NAME=test-attestor-1
ATTESTOR_EMAIL=test-attestor-1@example.com
ATTESTOR_1_SECRET_KEY_PATH=integration/testdata/keys/attestor-1-secret-key.pgp
ATTESTOR_2_SECRET_KEY_PATH=integration/testdata/keys/attestor-2-secret-key.pgp

cleanup

cat > ${TMPDIR}/note_payload.json << EOM
{
  "name": "${NOTE_URI}",
  "attestationAuthority": {
    "hint": {
      "human_readable_name": "note 1"
    }
  }
}
EOM

curl -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}"  \
    -H "x-goog-user-project: ${PROJECT_ID}" \
    --data-binary @${TMPDIR}/note_payload.json  \
    "https://containeranalysis.googleapis.com/v1beta1/projects/${PROJECT_ID}/notes/?noteId=${NOTE_ID}"

gpg --homedir=${TMPDIR} --import "${ATTESTOR_1_SECRET_KEY_PATH}"
gpg --homedir=${TMPDIR} --import "${ATTESTOR_2_SECRET_KEY_PATH}"

# To generate new keys suitable for tests, you can use this as a starting point:
#gpg --homedir=${TMPDIR} --batch --gen-key <(
#  cat <<- EOF
#    Key-Type: RSA
#    Key-Length: 2048
#    Name-Real: "${ATTESTOR_NAME}"
#    Name-Email: "${ATTESTOR_EMAIL}"
#    %no-protection
#    %no-ask-passphrase
#    %commit
#EOF
#)

PUBLIC_KEY_FINGERPRINT=$(gpg --homedir=${TMPDIR} --with-colons --list-keys ${ATTESTOR_EMAIL} | grep '^fpr'  | cut --delimiter=: -f 10 - )
PUBLIC_KEY=$(gpg --homedir=${TMPDIR} --armor --export ${ATTESTOR_EMAIL})

cat > ${TMPDIR}/generated_payload.json << EOM
{
  "critical": {
    "identity": {
      "docker-reference": "${IMAGE_PATH}"
    },
    "image": {
      "docker-manifest-digest": "${IMAGE_DIGEST}"
    },
    "type": "Google cloud binauthz container signature"
  }
}
EOM

gpg \
    --homedir=${TMPDIR} \
    --local-user "test-attestor-1@example.com" \
    --armor \
    --output ${TMPDIR}/generated_signature.pgp \
    --sign ${TMPDIR}/generated_payload.json


# TODO get key id programatically
cat > ${TMPDIR}/attestation.json << EOM
{
  "resource": {
    "uri": "${IMAGE_TO_ATTEST}"
  },
  "note_name": "${NOTE_URI}",
  "attestation": {
     "attestation": {
        "pgpSignedAttestation": {
          "signature": "$(base64 --wrap=0 ${TMPDIR}/generated_signature.pgp)",
          "pgpKeyId": "EDEEBA8C1643F102542055B1B77522D28FA683D6"
        }
     }
  }
}
EOM

curl -X POST \
    -H "Content-Type: application/json" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    --data-binary @${TMPDIR}/attestation.json \
    "https://containeranalysis.googleapis.com/v1beta1/projects/${PROJECT_ID}/occurrences/"

