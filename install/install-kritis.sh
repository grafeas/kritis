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

set -ex

# Command line Args Default
NAMESPACE="default"
GAC_SECRET="gac-secret"

# Global variables.
CERT_FILE="kritis-charts/certs.yaml"
CERT_TEMPLATE_FILE="kritis-charts/certs.yaml.template"
CERTIFICATE=""
TLS_SECRET="tls-webhook-secret"
CHARTS_DIR="kritis-charts/"

while getopts "n:s" opt; do
  case $opt in
    n) NAMESPACE="$OPTARG"
    ;;
    s) GAC_SECRET="$OPTARG"
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
    ;;
  esac
done

# creates a cert
function kritis::create_cert {
    # First Substitute $NAMESPACE in kritis-charts/cert.yaml
    cat $CERT_TEMPLATE_FILE | sed "s/NAMESPACE/$NAMESPACE/g" > $CERT_FILE
    CMD="helm certgen generate $CHARTS_DIR --namespace $NAMESPACE"
    $CMD
}

# gets the  certifacate value
function kritis::get_certificate {
  CERTIFICATE=$(kubectl get secret $TLS_SECRET -o jsonpath='{.data.cert}' --namespace $NAMESPACE)
  if [[ "$CERTIFICATE" == "null" ]]; then
    echo "Could not find certificate $CERTIFICATE"
    exit 1
  fi
}

# install kritis charts
function kritis::install_helm {
  CMD="helm install $CHARTS_DIR --namespace $NAMESPACE \
  --set serviceNamespace=$NAMESPACE --set caBundle=$CERTIFICATE --set gacSecret.name=$GAC_SECRET"
  $CMD
}


kritis::create_cert
kritis::get_certificate
kritis::install_helm
