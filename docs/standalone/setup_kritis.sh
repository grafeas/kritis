#!/bin/bash

# Copyright 2019 Google LLC
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
set -e

# Create KritisConfig CRD in the k8s cluster and set it.
kubectl apply -f ../../artifacts/kritis-config-crd.yaml
cat <<EOF | kubectl apply -f - \

apiVersion: kritis.grafeas.io/v1beta1
kind: KritisConfig
metadata:
  name: kritis-config
spec:
  metadataBackend: grafeas
  cronInterval: 1h
  serverAddr: :443
  grafeas:
    addr: grafeas-server:443
EOF

# Create the client key and CSR.
openssl genrsa -out kritis.key 2048
openssl req -subj "/CN=grafeas-server" -new -key kritis.key -out kritis.csr

# Create self-signed client certificate
openssl x509 -req -days 365 -in kritis.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out kritis.crt

# Delete the client CSR, as it's no longer needed
rm kritis.csr

# Install Kritis helm chart
helm install --name kritis https://storage.googleapis.com/kritis-charts/repository/kritis-charts-0.1.0.tgz --set certificates.ca="$(cat ca.crt)" --set certificates.cert="$(cat kritis.crt)" --set certificates.key="$(cat kritis.key)"
