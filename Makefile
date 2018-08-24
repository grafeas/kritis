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

PWD = $(shell pwd)
GOOS ?= $(shell go env GOOS)
GOARCH = amd64
BUILD_DIR ?= ./out
COMMIT ?= $(shell git rev-parse HEAD)
VERSION ?= v0.1.0
IMAGE_TAG ?= $(COMMIT)

# Used for integration testing. example:
# "make -e GCP_PROJECT=kritis-int integration-local"
GCP_PROJECT ?= PLEASE_SET_GCP_PROJECT_ENV
GCP_ZONE ?= us-central1-a
TEST_CLUSTER ?= kritis-integration-test

%.exe: %
	mv $< $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

GITHUB_ORG := github.com/grafeas
GITHUB_PROJECT := kritis
REPOPATH ?= $(GITHUB_ORG)/$(GITHUB_PROJECT)
RESOLVE_TAGS_PROJECT := resolve-tags

SUPPORTED_PLATFORMS := linux-$(GOARCH) darwin-$(GOARCH) windows-$(GOARCH).exe
RESOLVE_TAGS_PATH = cmd/kritis/kubectl/plugins/resolve
RESOLVE_TAGS_PACKAGE = $(REPOPATH)/$(RESOLVE_TAGS_PATH)
RESOLVE_TAGS_KUBECTL_DIR = ~/.kube/plugins/resolve-tags

GAC_CREDENTIALS_PATH ?= .integration_test_gac_$(GCP_PROJECT).json

.PHONY: test
test: cross
	./hack/check-fmt.sh
	./hack/boilerplate.sh
	./hack/verify-codegen.sh
	./hack/dep.sh
	./hack/test.sh
	./hack/linter.sh

GO_FILES := $(shell find . -type f -name '*.go' -not -path "./vendor/*")
GO_LD_RESOLVE_FLAGS :=""
GO_BUILD_TAGS := ""

.PRECIOUS: $(foreach platform, $(SUPPORTED_PLATFORMS), $(BUILD_DIR)/$(GITHUB_PROJECT)-$(platform))

$(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT): $(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)-$(GOOS)-$(GOARCH)
	cp $(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)-$(GOOS)-$(GOARCH) $@

.PHONY: cross
cross: $(foreach platform, $(SUPPORTED_PLATFORMS), $(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)-$(platform))

$(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)-%-$(GOARCH): $(GO_FILES) $(BUILD_DIR)
	GOOS=$* GOARCH=$(GOARCH) CGO_ENABLED=0 go build -ldflags $(GO_LD_RESOLVE_FLAGS) -tags $(GO_BUILD_TAGS) -o $@ $(RESOLVE_TAGS_PACKAGE)

.PHONY: cross-tar
cross-tar: $(foreach platform, $(SUPPORTED_PLATFORMS), $(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)-$(platform).tar.gz)

$(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)-%.tar.gz: cross
	tar -czf $@ -C $(RESOLVE_TAGS_PATH) plugin.yaml -C $(PWD)/out/ resolve-tags-$*

.PHONY: install-plugin
install-plugin: $BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)
	mkdir -p $(RESOLVE_TAGS_KUBECTL_DIR)
	cp $(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT) $(RESOLVE_TAGS_KUBECTL_DIR)
	cp cmd/kritis/kubectl/plugins/resolve/plugin.yaml $(RESOLVE_TAGS_KUBECTL_DIR)

GO_LDFLAGS := -extldflags "-static"
GO_LDFLAGS += -X github.com/grafeas/kritis/cmd/kritis/version.Commit=$(COMMIT)
GO_LDFLAGS += -X github.com/grafeas/kritis/cmd/kritis/version.Version=$(VERSION)
GO_LDFLAGS += -w -s # Drop debugging symbols.

REGISTRY?=gcr.io/kritis-project
TEST_REGISTRY?=gcr.io/$(GCP_PROJECT)
SERVICE_PACKAGE = $(REPOPATH)/cmd/kritis/admission
GCB_SIGNER_PACKAGE = $(REPOPATH)/cmd/kritis/gcbsigner


out/kritis-server: $(GO_FILES)
	GOARCH=$(GOARCH) GOOS=linux CGO_ENABLED=0 go build -ldflags "$(GO_LDFLAGS)" -o $@ $(SERVICE_PACKAGE)

out/gcb-signer: $(GO_FILES)
	GOARCH=$(GOARCH) GOOS=linux CGO_ENABLED=0 go build -ldflags "$(GO_LDFLAGS)" -o $@ $(GCB_SIGNER_PACKAGE)

.PHONY: build-image
build-image: out/kritis-server
	docker build -t $(REGISTRY)/kritis-server:$(IMAGE_TAG) -f deploy/Dockerfile .

# build-test-image locally builds images for use in integration testing.
.PHONY: build-test-image
build-test-image: out/kritis-server
	docker build -t $(TEST_REGISTRY)/kritis-server:$(IMAGE_TAG) -f deploy/Dockerfile .

HELM_HOOKS = preinstall postinstall predelete

$(HELM_HOOKS): $(GO_FILES)
	GOARCH=$(GOARCH) GOOS=linux CGO_ENABLED=0 go build -ldflags "$(GO_LDFLAGS)" -o out/$@ $(REPOPATH)/helm-hooks/$@

.PHONY: %-image
%-image: $(HELM_HOOKS)
	docker build -t $(REGISTRY)/$*:$(IMAGE_TAG) -f helm-hooks/Dockerfile . --build-arg stage=$*

.PHONY: %-test-image
%-test-image: $(HELM_HOOKS)
	docker build -t $(TEST_REGISTRY)/$*:$(IMAGE_TAG) -f helm-hooks/Dockerfile . --build-arg stage=$*

.PHONY: helm-release-image
helm-release-image:
	docker build -t $(REGISTRY)/helm-release:$(IMAGE_TAG) -f helm-release/Dockerfile .

.PHONY: helm-install-from-head
helm-install-from-head:
	helm install --set repository=$(TEST_REGISTRY)/ --set image.tag=$(COMMIT) ./kritis-charts

clean:
	rm -rf $(BUILD_DIR)
.PHONY: integration
integration: cross
	go test -ldflags "$(GO_LDFLAGS)" -v -tags integration $(REPOPATH)/integration -timeout 5m -- --remote=true

# Steps to create a new test cluster on an GCP project that has already had a Kritis setup.
.PHONY: setup-integration-local
setup-integration-local:
	gcloud --project=$(GCP_PROJECT) container clusters describe $(TEST_CLUSTER) >/dev/null \
		|| gcloud --project=$(GCP_PROJECT) container clusters create $(TEST_CLUSTER) \
		--num-nodes=2 --zone=$(GCP_ZONE)
	gcloud --project=$(GCP_PROJECT) container clusters get-credentials $(TEST_CLUSTER)
	test -s $(GAC_CREDENTIALS_PATH) \
		|| gcloud --project=$(GCP_PROJECT) iam service-accounts keys \
		create $(GAC_CREDENTIALS_PATH) --iam-account kritis-ca-admin@${GCP_PROJECT}.iam.gserviceaccount.com
	kubectl create serviceaccount --namespace kube-system tiller
	kubectl create clusterrolebinding tiller-cluster-rule \
		  --clusterrole=cluster-admin \
		    --serviceaccount=kube-system:tiller
	helm init --wait --service-account tiller
	gcloud -q container images add-tag \
		gcr.io/kritis-tutorial/acceptable-vulnz@sha256:2a81797428f5cab4592ac423dc3049050b28ffbaa3dd11000da942320f9979b6 \
		gcr.io/$(GCP_PROJECT)/acceptable-vulnz:latest
	gcloud -q container images add-tag \
		gcr.io/kritis-tutorial/java-with-vulnz@sha256:358687cfd3ec8e1dfeb2bf51b5110e4e16f6df71f64fba01986f720b2fcba68a \
		gcr.io/$(GCP_PROJECT)/java-with-vulnz:latest
	gcloud -q container images add-tag \
		gcr.io/kritis-tutorial/nginx-digest-whitelist:latest \
		gcr.io/$(GCP_PROJECT)/nginx-digest-whitelist:latest
	gcloud -q container images add-tag \
		gcr.io/kritis-tutorial/nginx-no-digest-breakglass:latest \
		gcr.io/$(GCP_PROJECT)/nginx-no-digest-breakglass:latest
	gcloud -q container images add-tag \
		gcr.io/kritis-tutorial/nginx-no-digest:latest \
		gcr.io/$(GCP_PROJECT)/nginx-no-digest:latest



# integration-local requires that "setup-integration-local" has been run at least once.
.PHONY: integration-local
integration-local:
	echo "Test cluster: $(TEST_CLUSTER) Test project: $(GCP_PROJECT)"
	go test -ldflags "$(GO_LDFLAGS)" -v -tags integration \
		$(REPOPATH)/integration \
		-run TestKritisISPLogic \
		-timeout 5m \
		-gac-credentials=$(GAC_CREDENTIALS_PATH) \
		-gcp-project=$(GCP_PROJECT) \
		-gke-cluster-name=$(TEST_CLUSTER)

.PHONY: build-push-image
build-push-image: build-image preinstall-image postinstall-image predelete-image
	docker push $(REGISTRY)/kritis-server:$(IMAGE_TAG)
	docker push $(REGISTRY)/preinstall:$(IMAGE_TAG)
	docker push $(REGISTRY)/postinstall:$(IMAGE_TAG)
	docker push $(REGISTRY)/predelete:$(IMAGE_TAG)

.PHONY: build-push-test-image
build-push-test-image: build-test-image preinstall-test-image postinstall-test-image predelete-test-image
	docker push $(TEST_REGISTRY)/kritis-server:$(IMAGE_TAG)
	docker push $(TEST_REGISTRY)/preinstall:$(IMAGE_TAG)
	docker push $(TEST_REGISTRY)/postinstall:$(IMAGE_TAG)
	docker push $(TEST_REGISTRY)/predelete:$(IMAGE_TAG)

.PHONY: integration-in-docker
integration-in-docker: build-push-image
	docker build \
		-f deploy/$(GCP_PROJECT)/Dockerfile \
		--target integration \
		-t $(REGISTRY)/kritis-integration:$(IMAGE_TAG) .
	docker run \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(HOME)/tmp:/tmp \
		-v $(HOME)/.config/gcloud:/root/.config/gcloud \
		-v $(GOOGLE_APPLICATION_CREDENTIALS):$(GOOGLE_APPLICATION_CREDENTIALS) \
		-e REMOTE_INTEGRATION=true \
		-e DOCKER_CONFIG=/root/.docker \
		-e GOOGLE_APPLICATION_CREDENTIALS=$(GOOGLE_APPLICATION_CREDENTIALS) \
		$(REGISTRY)/kritis-integration:$(IMAGE_TAG)

.PHONY: gcb-signer-image
gcb-signer-image: out/gcb-signer-image
	docker build -t $(REGISTRY)/kritis-gcb-signer:$(IMAGE_TAG) -f deploy/kritis-gcb-signer/Dockerfile .

.PHONY: gcb-signer-push-image
gcb-signer-push-image: gcb-signer-image
	docker push $(REGISTRY)/kritis-gcb-signer:$(IMAGE_TAG)

