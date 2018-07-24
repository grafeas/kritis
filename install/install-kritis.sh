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
GAC_SECRET="gac-ca-admin"

# Global variables.
PREINSTALL_FILE="preinstall/preinstall.yaml"
CERTIFICATE=""
TLS_SECRET="tls-webhook-secret"
CHARTS_DIR="kritis-charts/"
PREINSTALL_ONLY=""

while getopts "n:sp" opt; do
  case $opt in
    n) NAMESPACE="$OPTARG"
    ;;
    s) GAC_SECRET="$OPTARG"
    ;;
    p) PREINSTALL_ONLY="true"
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
    ;;
  esac
done

function kritis::preinstall {
  kubectl apply -f $PREINSTALL_FILE --namespace $NAMESPACE
}

# gets the  certifacate value
function kritis::get_certificate {
  CERTIFICATE=$(kubectl get secret $TLS_SECRET -o jsonpath='{.data.tls\.crt}' --namespace $NAMESPACE)
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

function kritis::delete_preinstall {
  kubectl delete -f $PREINSTALL_FILE --namespace $NAMESPACE
}

kritis::preinstall
if "$PREINSTALL_ONLY" -eq "true" ; then
  exit 0
fi
kritis::get_certificate
kritis::install_helm
kritis::delete_preinstall
