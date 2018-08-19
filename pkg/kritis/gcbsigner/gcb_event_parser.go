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

	"github.com/golang/glog"

	"cloud.google.com/go/pubsub"
)

func ExtractImageBuildInfoFromEvent(msg *pubsub.Message) ([]ImageBuildInfo, error) {
	// TODO this should validate the Informatian against the information in
	// Container Analysis that is created by Cloud Builder
	var event BuildEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		return nil, err
	}
	glog.Infof("build %q, status: %q", event.ID, event.Status)
	glog.Infof("messages: %q", msg.Data)
	if event.Status == "SUCCESS" {
		glog.Infof("complete build %q", event.ID)
		buildInfo := make([]ImageBuildInfo, 0, len(event.Results.Images))
		for _, image := range event.Results.Images {
			if strings.Contains(image.Name, ":latest") {
				continue
			}
			imageRef := fmt.Sprintf("%s@%s", image.Name, image.Digest)
			glog.Infof("process image %s", imageRef)
			sourceSuffix := fmt.Sprintf("@%s", event.Source.RepoSource.CommitSha)
			if len(sourceSuffix) == 1 {
				sourceSuffix = fmt.Sprintf(":%s", event.Source.RepoSource.TagName)
			}
			if len(sourceSuffix) == 1 {
				sourceSuffix = fmt.Sprintf(":%s", event.Source.RepoSource.BranchName)
			}

			source := fmt.Sprintf("https://source.developers.google.com/p/%s/r/%s%s", event.Source.RepoSource.ProjectID, event.Source.RepoSource.RepoName, sourceSuffix)
			buildInfo = append(buildInfo, ImageBuildInfo{
				BuildID:   event.ID,
				ImageRef:  imageRef,
				BuiltFrom: source,
			})
		}
		return buildInfo, nil
	}
	return nil, nil
}

type BuildSource struct {
	RepoSource struct {
		RepoName   string
		ProjectID  string
		BranchName string
		TagName    string
		CommitSha  string
	}
}

type BuildResults struct {
	Images []struct {
		Name   string
		Digest string
	}
}

type BuildEvent struct {
	ID      string
	Status  string
	Source  BuildSource
	Results BuildResults
}
