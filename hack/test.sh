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

if [ ! -x "$(command -v gotestsum)" ] && [ ! -x $GOPATH/bin/gotestsum ]; then
    echo "gotestsum not found, try installing it..."
    go get -u gotest.tools/gotestsum
fi

set -ex

pkgs2test=`go list ./...  | grep -v vendor`

echo "Running go tests..."
if [ -x "$(command -v gotestsum)" ]; then
    timeout 60 gotestsum -- -cover -timeout 60s $pkgs2test
elif [ -x $GOPATH/bin/gotestsum ]; then
    timeout 60 $GOPATH/bin/gotestsum -- -cover -timeout 60s $pkgs2test
else
    echo "gotestsum not installed, defaulting to regular test output."
    go test -cover -v -timeout 60s $pkgs2test
fi

GO_TEST_EXIT_CODE=${PIPESTATUS[0]}
exit $GO_TEST_EXIT_CODE
