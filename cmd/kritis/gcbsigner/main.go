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
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/crd/buildpolicy"
	"github.com/grafeas/kritis/pkg/kritis/gcbsigner"
	"github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"golang.org/x/net/context"

	"cloud.google.com/go/pubsub"
)

func main() {
	gcbProject := flag.String("gcb_project", "", "Id of the project running GCB")
	gcbSubscription := flag.String("gcb_subscription", "build-signer", "Name of the GCB subscription")
	resourceNamespace := flag.String("resource_namespace", os.Getenv("SIGNER_NAMESPACE"), "Namespace the signer CRDs and secrets are stored in")
	flag.Parse()

	err := run(*gcbProject, *gcbSubscription, *resourceNamespace)
	if err != nil {
		glog.Fatalf("Error running signer: %v", err)
	}
}

func run(gcbProject string, gcbSubscription string, ns string) error {
	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, gcbProject)
	if err != nil {
		return fmt.Errorf("Could not create pubsub Client: %v", err)
	}

	sub := client.Subscription(gcbSubscription)
	for err == nil {
		glog.Infof("Listening")
		err = sub.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
			if err := process(ns, msg); err != nil {
				glog.Errorf("Error signing: %v", err)
				msg.Nack()
			} else {
				msg.Ack()
			}
		})
	}
	return fmt.Errorf("Error receiving message: %v", err)
}

func process(ns string, msg *pubsub.Message) error {
	buildInfos, err := gcbsigner.ExtractImageBuildInfoFromEvent(msg)
	if err != nil {
		return err
	}
	if buildInfos == nil {
		// No relevant builds in this event
		return nil
	}
	bps, err := buildpolicy.BuildPolicies(ns)
	if err != nil {
		return err
	}
	client, err := containeranalysis.NewContainerAnalysisClient()
	if err != nil {
		return err
	}

	r := gcbsigner.New(client, &gcbsigner.Config{
		Secret:   secrets.Fetch,
		Validate: buildpolicy.ValidateBuildPolicy,
	})
	for _, buildInfo := range buildInfos {
		if err := r.ValidateAndSign(buildInfo, bps); err != nil {
			return err
		}
	}
	return nil
}
