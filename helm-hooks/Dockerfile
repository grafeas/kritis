# Copyright 2018 Google, Inc. All rights reserved.
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

FROM golang:1.12
WORKDIR /go/src/github.com/grafeas/kritis
COPY . .
ARG stage
RUN make ${stage} 


FROM golang:1.12
RUN go get -u github.com/cloudflare/cfssl/cmd/...

ENV KUBECTL_VERSION v1.16.4
RUN curl -Lo /usr/local/bin/kubectl https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl  && \
    chmod +x /usr/local/bin/kubectl

COPY --from=0 /go/src/github.com/grafeas/kritis/out/${stage}  /${stage}

# Copy artifacts to the image.
COPY --from=0 /go/src/github.com/grafeas/kritis/artifacts /artifacts
