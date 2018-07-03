/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cron

import (
	"context"
	"time"
)

// For testing
var (
	podChecker    = CheckPods
	checkInterval = 1 * time.Minute
)

// Start starts the background processing of image security policies.
func Start(ctx context.Context) {
	c := time.NewTicker(checkInterval)
	done := ctx.Done()

	for {
		select {
		case <-c.C:
			podChecker()
		case <-done:
			return
		}
	}
}

// CheckPods checks all running pods against defined policies.
func CheckPods() {
	// TODO:
	// Fetch ISP crds
	// Validate against all running pods
}
