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

package gcbsigner

import (
	"reflect"
	"testing"

	"cloud.google.com/go/pubsub"
)

func TestExtractBuildProvenanceFromEvent(t *testing.T) {
	tests := []struct {
		name               string
		message            string
		shdErr             bool
		expectedProvenance []BuildProvenance
	}{
		{
			name: "ignores ':latest' entry in pubsub message",
			message: `{
    "id":"1",
    "status":"SUCCESS",
    "source": {
        "repoSource":{
                "projectId":"test1",
                "repoName":"repo",
                "tagName":"tag1"
        }
    },
    "results":{
        "images": [
            {
                "name":"image1",
                "digest":"sha256:1234"
            },
            {
                "name":"image1:latest",
                "digest":"sha256:1234"
            }
        ]
    }}`,
			expectedProvenance: []BuildProvenance{
				{
					BuildID:   "1",
					ImageRef:  "image1@sha256:1234",
					BuiltFrom: "https://source.developers.google.com/p/test1/r/repo:tag1",
				},
			},
		},
		{
			name: "ignores non-success messages",
			message: `{
    "id":"1",
    "status":"WORKING",
    "source": {
        "repoSource":{
                "projectId":"test1",
                "repoName":"repo",
                "tagName":"tag1"
        }
    },
    "results":{
        "images": [
            {
                "name":"image1",
                "digest":"sha256:1234"
            }
        ]
    }}`,
		},
		{
			name: "extracts multiple images",
			message: `{
    "id":"1",
    "status":"SUCCESS",
    "source": {
        "repoSource":{
                "projectId":"test1",
                "repoName":"repo",
                "tagName":"tag1"
        }
    },
    "results":{
        "images": [
            {
                "name":"image1",
                "digest":"sha256:1234"
            },
            {
                "name":"image2",
                "digest":"sha256:1234"
            }
        ]
    }}`,
			expectedProvenance: []BuildProvenance{
				{
					BuildID:   "1",
					ImageRef:  "image1@sha256:1234",
					BuiltFrom: "https://source.developers.google.com/p/test1/r/repo:tag1",
				},
				{
					BuildID:   "1",
					ImageRef:  "image2@sha256:1234",
					BuiltFrom: "https://source.developers.google.com/p/test1/r/repo:tag1",
				},
			},
		},
		{
			name: "extracts branch based builds",
			message: `{
    "id":"1",
    "status":"SUCCESS",
    "source": {
        "repoSource":{
                "projectId":"test1",
                "repoName":"repo",
                "branchName":"branch_1"
        }
    },
    "results":{
        "images": [
            {
                "name":"image1",
                "digest":"sha256:1234"
            }
        ]
    }}`,
			expectedProvenance: []BuildProvenance{
				{
					BuildID:   "1",
					ImageRef:  "image1@sha256:1234",
					BuiltFrom: "https://source.developers.google.com/p/test1/r/repo:branch_1",
				},
			},
		},
		{
			name: "extracts sha based builds",
			message: `{
    "id":"1",
    "status":"SUCCESS",
    "source": {
        "repoSource":{
                "projectId":"test1",
                "repoName":"repo",
                "commitSha":"1234"
        }
    },
    "results":{
        "images": [
            {
                "name":"image1",
                "digest":"sha256:1234"
            }
        ]
    }}`,
			expectedProvenance: []BuildProvenance{
				{
					BuildID:   "1",
					ImageRef:  "image1@sha256:1234",
					BuiltFrom: "https://source.developers.google.com/p/test1/r/repo@1234",
				},
			},
		},
		{
			name:    "reports error for invalid text",
			message: "XX",
			shdErr:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := pubsub.Message{Data: []byte(tc.message)}
			provenance, err := ExtractBuildProvenanceFromEvent(&msg)
			if (err != nil) != tc.shdErr {
				t.Errorf("ExtractBuildProvenanceFromEvent returned error %s, want %t", err, tc.shdErr)
			}
			if !reflect.DeepEqual(provenance, tc.expectedProvenance) {
				t.Errorf(" Got provenance: %v\nExpected: %v", tc.expectedProvenance, provenance)
			}
		})
	}
}
