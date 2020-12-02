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

set -e -o pipefail

KRITIS_DIR="$GOPATH/src/github.com/grafeas/kritis"

if [ -z "$VALIDATE_UPSTREAM" ]; then
	VALIDATE_REPO='https://github.com/grafeas/kritis.git'
	VALIDATE_BRANCH='master'

	VALIDATE_HEAD="$(git rev-parse --verify HEAD)"

	git fetch -q "$VALIDATE_REPO" "refs/heads/$VALIDATE_BRANCH"
	VALIDATE_UPSTREAM="$(git rev-parse --verify FETCH_HEAD)"

	VALIDATE_COMMIT_DIFF="$VALIDATE_UPSTREAM...$VALIDATE_HEAD"

	validate_diff() {
		if [ "$VALIDATE_UPSTREAM" != "$VALIDATE_HEAD" ]; then
			git diff "$VALIDATE_COMMIT_DIFF" "$@"
		fi
	}
fi
# See if there have been upstream changes
IFS=$'\n'
files=( $(validate_diff --name-only -- 'go.mod' 'go.sum' 'vendor/' || true) )
unset IFS

if [ ${#files[@]} -gt 0 ]; then
	cd $KRITIS_DIR
	go mod vendor
	diffs="$(git status --porcelain -- vendor go.mod go.sum 2>/dev/null)"
	if [ "$diffs" ]; then
		{
			echo 'Vendor not reproducible, please commit these changes to fix:'
			echo
			echo "$diffs"
		} >&2
		false
	fi
else
    echo 'No vendor changes from upstream. Skipping go mod vendor, go mod tidy'
fi
