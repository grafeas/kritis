#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

environment () {
  # Set values that will be overwritten if env.sh exists
  export BINAUTHZ_PROJECT=$(gcloud config get-value project)
  export BINAUTHZ_PROJECTNUM=$(gcloud projects list --filter="${BINAUTHZ_PROJECTNUM}" --format="value(PROJECT_NUMBER)")
  export BINAUTHZ_ZONE=us-central1a

  [[ -f "$DIR/env.sh" ]]; && echo "Importing environment from $DIR/env.sh..." && . $DIR/env.sh
  echo "Writing $DIR/env.sh..."
  cat > $DIR/env.sh << EOF
export BINAUTHZ_PROJECT=${BINAUTHZ_PROJECT}
export BINAUTHZ_ZONE=${BINAUTHZ_ZONE}
EOF
}

binauthz_project_setup () {
  echo "Setting up project for Binary Authorization Sample..."
  set -x
  gcloud config set project ${BINAUTHZ_PROJECT}
  echo

  echo "Enabling apis..."
  gcloud services enable compute.googleapis.com
  gcloud services enable cloudbuild.googleapis.com
  glcoud services enable container.googleapis.com
  gcloud services enable containerregistry.googleapis.com
  gcloud services enable containeranalysis.googleapis.com
  gcloud services enable binaryauthorization.googleapis.com
  echo

  echo "Setting up service accounts and permissions.."
  gcloud ${BINAUTHZ_PROJECTNUM}@cloudbuild.gserviceaccount.com
  gcloud project add-iam-policy-binding ${BINAUTHZ_PROJECT} \
    --member ${BINAUTHZ_PROJECTNUM}@cloudbuild.gserviceaccount.com \
    --role container.developer

  gcloud iam service-accounts create kritis-signer \
    --description "For creating attestations" \
    --display-name "kritis-signer"
  gcloud project add-iam-policy-binding ${BINAUTHZ_PROJECT} \
    --member kritis-signer@${BINAUTHZ_PROJECT}.iam.gserviceaccount.com \
    --role roles/containeranalysis.ServiceAgent
  gcloud project add-iam-policy-binding ${BINAUTHZ_PROJECT} \
    --member kritis-signer@${BINAUTHZ_PROJECT}.iam.gserviceaccount.com \
    --role roles/containeranalysis.notes.editor

  gcloud iam service-accounts keys create ${DIR}/kritis-service-account.json \
  --iam-account kritis-signer@${BINAUTHZ_PROJECT}.iam.gserviceaccount.com
  
  echo "Configuring docker to Container Registry authentication.."
  gcloud auth configure-docker
  echo

  echo "Creating target deployment cluster.."
  gcloud container clusters create \
    --enable-binauthz \
    --zone ${BINAUTHZ_ZONE} \
    binauthz-sample
  echo

  echo "Building custom python cloud builder.."
  docker build -t gcr.io/${BINAUTHZ_PROJECT}/python-builder:latest -f ./Dockerfile.python-builder .
  docker push gcr.io/${BINAUTHZ_PROJECT}/python-builder:latest
  echo


  echo "Building custom kritis signer cloud builder.."
  $(cd ../../; make signer-image)
  KRITIS_DIGEST=$(docker images gcr.io/${BINAUTHZ_PROJECT}/kritis-signer | grep gcr.io | head -1 | awk -e ' { print $2 } ')
  docker tag gcr.io/${BINAUTHZ_PROJECT}/kritis-signer:$KRITIS_DIGEST gcr.io/${BINAUTHZ_PROJECT}/kritis-signer:latest
  docker push gcr.io/${BINAUTHZ_PROJECT}/kritis-signer:latest
  echo

  echo "Generating keys.  When asked, please provide an empty passphrase.."
  GPG_OUTPUT="$(gpg --quick-generate-key --yes attestor@example.com)"
  KEY_FINGERPRINT="$(echo $GPG_OUTPUT | sed -n 's/.*\([A-Z0-9]\{40\}\).*/\1/p')"
  gpg --armor --export $KEY_FINGERPRINT > $DIR/gpg.pub
  gpg --armor --export-secret-keys $KEY_FINGERPRINT > $DIR/gpg.priv

  set +x
}

#Main
echo "Setting up the environment..."
environment
binauthz_project_setup

