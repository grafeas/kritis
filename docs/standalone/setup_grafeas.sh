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

# Generate Certificate Authority
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

# Create the server key and CSR.
# The parameter in -subj specifies Common Name, which is the only required field
# in CSR, and should correspond to NAME in
# $ kubectl get svc
openssl genrsa -out grafeas.key 2048
openssl req -subj "/CN=grafeas-server" -new -key grafeas.key -out grafeas.csr

# Create self-signed server certificate
openssl x509 -req -days 365 -in grafeas.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out grafeas.crt

# Delete the server CSR, as it's no longer needed
rm grafeas.csr

# Install Grafeas helm chart
helm install --name grafeas https://storage.googleapis.com/grafeas-charts/repository/grafeas-charts-0.1.0.tgz --set certificates.ca="$(cat ca.crt)" --set certificates.cert="$(cat grafeas.crt)" --set "certificates.key=$(cat grafeas.key)" --set service.type="LoadBalancer"
