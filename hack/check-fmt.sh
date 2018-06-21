#!/bin/bash
set -e

echo "Checking gofmt..."
files=$(find . -name "*.go" | grep -v vendor/ | xargs gofmt -l -s)
if [[ $files ]]; then
    echo "Gofmt errors in files: $files"
    exit 1
fi
