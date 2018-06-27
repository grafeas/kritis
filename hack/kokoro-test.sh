#!/bin/bash
set -ex

source "$KOKORO_GFILE_DIR/common.sh"

echo "Running unit tests..."
# Run the tests.
./hack/test.sh


echo "Running integration tests..."
go test -cover -v -timeout 60s `go list ./integration_tests/...`
GO_TEST_EXIT_CODE=${PIPESTATUS[0]}
exit $GO_TEST_EXIT_CODE
