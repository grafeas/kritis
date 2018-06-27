#!/bin/bash
set -ex

echo "Running go tests..."
go test -cover -v -timeout 60s `go list ./...  | grep -v vendor`
GO_TEST_EXIT_CODE=${PIPESTATUS[0]}
exit $GO_TEST_EXIT_CODE
