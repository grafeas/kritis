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
	"testing"
	"time"
)

func TestStartCancels(t *testing.T) {

	// Speed up the checks for testing.
	checkInterval = 2 * time.Millisecond

	checked := false

	// Mock the check function and reset after the test.
	originalChecker := podChecker
	podChecker = func() {
		checked = true
	}
	defer func() {
		podChecker = originalChecker
	}()

	// Set a deadline of longer than the check interval
	ctx := context.Background()
	c, cancel := context.WithDeadline(ctx, time.Now().Add(10*checkInterval))
	defer cancel()

	// Make sure the checker is called and Start cancels correctly when the deadline expires.
	Start(c)

	if !checked {
		t.Fatalf("check function not called")
	}
}
