#!/bin/bash

# This script provides a one-button setup of an entire pipeline to demonstrate
# binary authorization signing and enforcement:
# - local environment
# - binauthz project setup
# After running this script, a user can check for vulnerabilities against an allowlist with a
# single command line, as follows:
# gcloud builds submit --config=cloudbuild-good.yaml

environment () {
  if [ "${GOPATH}" == "" ]; then
    echo "You must have golang installed and $GOPATH set to the top of your go src tree to compile this code."
    exit 1
  fi
  
  # Set values that will be overwritten if env.sh exists
  echo "Setting up the environment..."
  export DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
  export TOPDIR="$( cd "$( dirname "${BASH_SOURCE[0]}")/../.." >/dev/null 2>&1 && pwd )"
  export GODIR=$( echo "${GOPATH//:/$'\n'}" | head -1)/src/github.com/grafeas/kritis
  
  # When we build the signer-image below, the script needs this tree to
  # live in a proper $GOPATH.  We'll build a link tree to serve
  if [ ! -d "${GODIR}" ]; then
    mkdir -p $(dirname ${GODIR})
    cp -rl ${TOPDIR} ${GODIR}
  fi
  
  export BINAUTHZ_PROJECT=$(gcloud config get-value project)
  export BINAUTHZ_PROJECTNUM=$(gcloud projects list --filter="${BINAUTHZ_PROJECT}" --format="value(PROJECT_NUMBER)")
  export BINAUTHZ_ZONE=us-central1-a
  
  [[ -f "${DIR}/env.sh" ]] && echo "Importing environment from ${DIR}/env.sh..." && . ${DIR}/env.sh
  echo "Writing ${DIR}/env.sh..."
  cat > ${DIR}/env.sh << EOF
export BINAUTHZ_PROJECT=${BINAUTHZ_PROJECT}
export BINAUTHZ_PROJECTNUM=${BINAUTHZ_PROJECTNUM}
export BINAUTHZ_ZONE=${BINAUTHZ_ZONE}
EOF
}

binauthz_project_setup () {
  set +x; echo "Setting up project for Binary Authorization Sample..."
  set -x
  gcloud config set project ${BINAUTHZ_PROJECT}
  set +x; echo; set -x

  set +x; echo "Enabling apis..."; set -x
  gcloud services enable cloudbuild.googleapis.com
  gcloud services enable containerregistry.googleapis.com
  gcloud services enable containeranalysis.googleapis.com
  gcloud services enable containerscanning.googleapis.com
  set +x; echo; set -x

  set +x; echo "Setting up service accounts and permissions.."; set -x
  gcloud projects add-iam-policy-binding ${BINAUTHZ_PROJECT} \
    --member serviceAccount:${BINAUTHZ_PROJECTNUM}@cloudbuild.gserviceaccount.com \
    --role roles/containeranalysis.notes.occurrences.viewer

  set +x; echo "Configuring docker to Container Registry authentication.."; set -x
  gcloud auth configure-docker
  set +x; echo


  set +x; echo "Building custom kritis signer cloud builder.."; set -x
  cd ${GODIR}
  gcloud builds submit . --config deploy/kritis-signer/cloudbuild.yaml
  set +x; echo
}

#Main
environment
binauthz_project_setup

