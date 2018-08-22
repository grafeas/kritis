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

package buildpolicy

import (
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
)

func Test_ValidateBuildPolicy(t *testing.T) {
	var tests = []struct {
		name         string
		requirements string
		builtFrom    string
		expectedErr  bool
	}{
		{
			name:         "simple string match",
			requirements: "some_source",
			builtFrom:    "some_source",
		},
		{
			name:         "regexp string match",
			requirements: ".*_source",
			builtFrom:    "some_source",
		},
		{
			name:         "no match fails",
			requirements: ".*_source",
			builtFrom:    "no_match",
			expectedErr:  true,
		},
		{
			name:         "invald regexp fails",
			requirements: "*",
			builtFrom:    "test",
			expectedErr:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bp := v1beta1.BuildPolicy{
				Spec: v1beta1.BuildPolicySpec{
					BuildRequirements: v1beta1.BuildRequirements{
						BuiltFrom: tc.requirements,
					},
				},
			}
			err := ValidateBuildPolicy(bp, tc.builtFrom)
			if tc.expectedErr != (err != nil) {
				t.Errorf("expected ValidateAndSign to return error %t, actual error %s", tc.expectedErr, err)
			}
		})
	}
}
