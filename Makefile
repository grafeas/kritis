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

GOOS ?= $(shell go env GOOS)
GOARCH = amd64
BUILD_DIR ?= ./out
COMMIT ?= $(shell git rev-parse HEAD)
VERSION ?= v0.0.1

GCP_TEST_PROJECT ?= kritis-int-test

%.exe: %
	mv $< $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

ORG := github.com/grafeas
PROJECT := kritis
RESOLVE_TAGS_PROJECT := resolve-tags
REPOPATH ?= $(ORG)/$(PROJECT)

SUPPORTED_PLATFORMS := linux-$(GOARCH) darwin-$(GOARCH) windows-$(GOARCH).exe
RESOLVE_TAGS_PACKAGE = $(REPOPATH)/cmd/kritis/kubectl/plugins/resolve
RESOLVE_TAGS_KUBECTL_DIR = ~/.kube/plugins/resolve-tags


.PHONY: test
test: cross
	./hack/check-fmt.sh
	./hack/boilerplate.sh
	./hack/verify-codegen.sh
	./hack/dep.sh
	./hack/test.sh

GO_FILES := $(shell find . -type f -name '*.go' -not -path "./vendor/*")
GO_LD_RESOLVE_FLAGS :=""
GO_BUILD_TAGS := ""

.PRECIOUS: $(foreach platform, $(SUPPORTED_PLATFORMS), $(BUILD_DIR)/$(PROJECT)-$(platform))

$(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT): $(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)-$(GOOS)-$(GOARCH)
	cp $(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)-$(GOOS)-$(GOARCH) $@

.PHONY: cross
cross: $(foreach platform, $(SUPPORTED_PLATFORMS), $(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)-$(platform))

$(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)-%-$(GOARCH): $(GO_FILES) $(BUILD_DIR)
	GOOS=$* GOARCH=$(GOARCH) CGO_ENABLED=0 go build -ldflags $(GO_LD_RESOLVE_FLAGS) -tags $(GO_BUILD_TAGS) -o $@ $(RESOLVE_TAGS_PACKAGE)

.PHONY: install-plugin
install-plugin: $(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT)
	mkdir -p $(RESOLVE_TAGS_KUBECTL_DIR)
	cp $(BUILD_DIR)/$(RESOLVE_TAGS_PROJECT) $(RESOLVE_TAGS_KUBECTL_DIR)
	cp cmd/kritis/kubectl/plugins/resolve/plugin.yaml $(RESOLVE_TAGS_KUBECTL_DIR)

GO_LDFLAGS := -extldflags "-static"
GO_LDFLAGS += -X github.com/grafeas/kritis/cmd/kritis/version.Commit=$(COMMIT)
GO_LDFLAGS += -X github.com/grafeas/kritis/cmd/kritis/version.Version=$(VERSION)
GO_LDFLAGS += -w -s # Drop debugging symbols.

REGISTRY?=gcr.io/kritis-project
REPOPATH ?= $(ORG)/$(PROJECT)
SERVICE_PACKAGE = $(REPOPATH)/cmd/kritis/admission
KRITIS_PROJECT = $(REPOPATH)/kritis

out/kritis-server: $(GO_FILES)
	GOARCH=$(GOARCH) GOOS=linux CGO_ENABLED=0 go build -ldflags "$(GO_LDFLAGS)" -o $@ $(SERVICE_PACKAGE)

.PHONY: build-image
build-image: out/kritis-server
	docker build -t $(REGISTRY)/kritis-server:$(VERSION) -f deploy/Dockerfile .

out/preinstall: $(GO_FILES)
	GOARCH=$(GOARCH) GOOS=linux CGO_ENABLED=0 go build -ldflags "$(GO_LDFLAGS)" -o $@ $(REPOPATH)/helm-hooks/preinstall

.PHONY: preinstall-image
preinstall-image:  out/preinstall
	docker build -t $(REGISTRY)/preinstall:$(VERSION) -f helm-hooks/Dockerfile . --build-arg stage=preinstall

out/postinstall: $(GO_FILES)
	GOARCH=$(GOARCH) GOOS=linux CGO_ENABLED=0 go build -ldflags "$(GO_LDFLAGS)" -o $@ $(REPOPATH)/helm-hooks/postinstall

.PHONY: postinstall-image
postinstall-image:  out/postinstall
	docker build -t $(REGISTRY)/postinstall:$(VERSION) -f helm-hooks/Dockerfile . --build-arg stage=postinstall

out/predelete: $(GO_FILES)
	GOARCH=$(GOARCH) GOOS=linux CGO_ENABLED=0 go build -o $@ $(REPOPATH)/helm-hooks/predelete

.PHONY: predelete-image
predelete-image:  out/predelete
	docker build -t $(REGISTRY)/predelete:$(VERSION) -f helm-hooks/Dockerfile . --build-arg stage=predelete

.PHONY: helm-release-image
helm-release-image:
	docker build -t $(REGISTRY)/helm-release:$(VERSION) -f helm-release/Dockerfile .

clean:
	rm -rf $(BUILD_DIR)
.PHONY: integration
integration: cross
	go test -v -tags integration $(REPOPATH)/integration -timeout 10m -- --remote=true

.PHONY: build-push-image-version
build-push-image-version: out/kritis-server out/preinstall out/postinstall out/predelete
	docker build \
		-f deploy/kritis-int-test/Dockerfile \
		--target integration \
		-t $(REGISTRY)/kritis-integration:$(VERSION) .
	docker build \
		-f helm-hooks/Dockerfile \
		-t $(REGISTRY)/preinstall:$(VERSION) . \
		--build-arg stage=preinstall
	docker build \
		-f helm-hooks/Dockerfile \
		-t $(REGISTRY)/postinstall:$(VERSION) . \
		--build-arg stage=postinstall
	docker build \
		-f helm-hooks/Dockerfile \
		-t $(REGISTRY)/predelete:$(VERSION) . \
		--build-arg stage=predelete
	docker push $(REGISTRY)/kritis-integration:$(VERSION)
	docker push $(REGISTRY)/preinstall:$(VERSION)
	docker push $(REGISTRY)/postinstall:$(VERSION)
	docker push $(REGISTRY)/predelete:$(VERSION)

.PHONY: build-push-image-commit
build-push-image-commit: out/kritis-server out/preinstall out/postinstall out/predelete
	docker build \
		-f deploy/kritis-int-test/Dockerfile \
		--target integration \
		-t $(REGISTRY)/kritis-integration:$(COMMIT) .
	docker build \
		-f helm-hooks/Dockerfile \
		-t $(REGISTRY)/preinstall:$(COMMIT) . \
		--build-arg stage=preinstall
	docker build \
		-f helm-hooks/Dockerfile \
		-t $(REGISTRY)/postinstall:$(COMMIT) . \
		--build-arg stage=postinstall
	docker build \
		-f helm-hooks/Dockerfile \
		-t $(REGISTRY)/predelete:$(COMMIT) . \
		--build-arg stage=predelete
	docker push $(REGISTRY)/kritis-integration:$(COMMIT)
	docker push $(REGISTRY)/preinstall:$(COMMIT)
	docker push $(REGISTRY)/postinstall:$(COMMIT)
	docker push $(REGISTRY)/predelete:$(COMMIT)

.PHONY: integration-in-docker
integration-in-docker: build-push-image-commit
	docker run \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(HOME)/.config/gcloud:/root/.config/gcloud \
		-v $(GOOGLE_APPLICATION_CREDENTIALS):$(GOOGLE_APPLICATION_CREDENTIALS) \
		-e REMOTE_INTEGRATION=true \
		-e DOCKER_CONFIG=/root/.docker \
		-e GOOGLE_APPLICATION_CREDENTIALS=$(GOOGLE_APPLICATION_CREDENTIALS) \
		$(REGISTRY)/kritis-integration:$(COMMIT)
