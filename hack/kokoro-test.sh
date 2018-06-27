#!/bin/bash
set -ex

source "$KOKORO_GFILE_DIR/common.sh"

pushd github/kritis

echo "Check format"
./hack/check-fmt.sh

echo "Running unit and integration tests..."
go test -cover -v -timeout 60s -tags=integration `go list ./...  | grep -v vendor`
GO_TEST_EXIT_CODE=${PIPESTATUS[0]}
popd

exit $GO_TEST_EXIT_CODE
