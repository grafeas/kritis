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
	"encoding/json"
	"fmt"
	"strings"

	"cloud.google.com/go/pubsub"
	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/constants"
)

// ExtractBuildProvenanceFromEvent extracts the build provenance from a Cloud
// Builder event.
// Return the list of images built and their build provenance.  If the event
// does contain relevant buikld info (e.g., the build is not yet complete, or
// no images were produced) then 'nil' will be returned.
//
// TODO this should validate the provenance in the pubsub message against the
// information in Container Analysis that is created by Cloud Builder.
func ExtractBuildProvenanceFromEvent(msg *pubsub.Message) ([]BuildProvenance, error) {
	var event buildEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		return nil, err
	}
	glog.Infof("build %q, status: %q", event.ID, event.Status)
	glog.Infof("messages: %q", msg.Data)
	if event.Status != "SUCCESS" {
		return nil, nil
	}
	glog.Infof("complete build %q", event.ID)
	provenance := make([]BuildProvenance, 0, len(event.Results.Images))
	for _, image := range event.Results.Images {
		if strings.Contains(image.Name, ":latest") {
			// GCB creates two entries per built image, one with
			// tag, one without (i.e., image name only).  Ignore the
			// entry with tag.
			continue
		}
		imageRef := fmt.Sprintf("%s@%s", image.Name, image.Digest)
		glog.Infof("process image %s", imageRef)
		sourceSuffix := fmt.Sprintf("@%s", event.Source.RepoSource.CommitSHA)
		if len(sourceSuffix) == 1 {
			sourceSuffix = fmt.Sprintf(":%s", event.Source.RepoSource.TagName)
		}
		if len(sourceSuffix) == 1 {
			sourceSuffix = fmt.Sprintf(":%s", event.Source.RepoSource.BranchName)
		}

		source := fmt.Sprintf(constants.CloudSourceRepoPattern, event.Source.RepoSource.ProjectID, event.Source.RepoSource.RepoName, sourceSuffix)
		provenance = append(provenance, BuildProvenance{
			BuildID:   event.ID,
			ImageRef:  imageRef,
			BuiltFrom: source,
		})
	}
	return provenance, nil
}

type buildSource struct {
	RepoSource struct {
		RepoName   string
		ProjectID  string
		BranchName string
		TagName    string
		CommitSHA  string
	}
}

type buildResults struct {
	Images []struct {
		Name   string
		Digest string
	}
}

type buildEvent struct {
	ID      string
	Status  string
	Source  buildSource
	Results buildResults
}
