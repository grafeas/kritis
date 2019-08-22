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
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"time"

	_ "net/http/pprof"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/cmd/kritis/version"
	"github.com/grafeas/kritis/pkg/kritis/admission"
	"github.com/grafeas/kritis/pkg/kritis/admission/constants"
	"github.com/grafeas/kritis/pkg/kritis/crd/kritisconfig"
	"github.com/grafeas/kritis/pkg/kritis/cron"
	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	"github.com/grafeas/kritis/pkg/kritis/metadata/grafeas"
	"github.com/pkg/errors"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

const (
	// Default values for the configuration
	DefaultMetadataBackend = constants.ContainerAnalysisMetadata
	DefaultCronInterval    = "1h"
	DefaultServerAddr      = ":443"
)

var (
	tlsCertFile string
	tlsKeyFile  string
	showVersion bool
	runCron     bool
)

func main() {
	flag.StringVar(&tlsCertFile, "tls-cert-file", "/var/tls/tls.crt", "TLS certificate file.")
	flag.StringVar(&tlsKeyFile, "tls-key-file", "/var/tls/tls.key", "TLS key file.")
	flag.BoolVar(&showVersion, "version", false, "kritis-server version")
	flag.BoolVar(&runCron, "run-cron", false, "Run cron job in foreground.")
	flag.Parse()
	if err := flag.Set("logtostderr", "true"); err != nil {
		glog.Fatal(errors.Wrap(err, "unable to set logtostderr"))
	}

	if showVersion {
		fmt.Println(version.Commit)
		return
	}

	// Set the defaults that will be used if no KritisConfig is defined
	metadataBackend := DefaultMetadataBackend
	cronInterval := DefaultCronInterval
	serverAddr := DefaultServerAddr

	config := &admission.Config{
		Metadata: metadataBackend,
	}

	kritisConfig, err := kritisconfig.KritisConfig()
	if err != nil {
		glog.Fatalf("failed to get kritis config: %v", err)
	}

	if kritisConfig == nil {
		glog.Info("no KritisConfigs found in any namespace, will assume the defaults")

	} else {
		// TODO(https://github.com/grafeas/kritis/issues/304): Use CRD validation instead
		if kritisConfig.Spec.MetadataBackend != "" {
			config.Metadata = kritisConfig.Spec.MetadataBackend
		}
		if kritisConfig.Spec.CronInterval != "" {
			cronInterval = kritisConfig.Spec.CronInterval
		}
		if kritisConfig.Spec.ServerAddr != "" {
			serverAddr = kritisConfig.Spec.ServerAddr
		}
		if config.Metadata == constants.GrafeasMetadata {
			config.Grafeas = kritisConfig.Spec.Grafeas
			if err := grafeas.ValidateConfig(config.Grafeas); err != nil {
				glog.Fatal(err)
			}
		}
	}

	// TODO: (tejaldesai) This is getting complicated. Use CLI Library.
	if runCron {
		cronConfig, err := getCronConfig(config)
		if err != nil {
			glog.Fatalf("could not run cron job in foreground: %v", err)
		}
		if err := cron.RunInForeground(*cronConfig); err != nil {
			glog.Fatalf("error checking pods: %v", err)
		}
		return
	}
	// Kick off back ground cron job.
	if err := StartCronJob(config, cronInterval); err != nil {
		glog.Fatalf("failed to start background job: %v", err)
	}

	// Start the Kritis Server.
	glog.Infof("running the server: %s", serverAddr)
	http.HandleFunc("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admission.ReviewHandler(w, r, config)
	}))
	httpsServer := NewServer(serverAddr)
	glog.Fatal(httpsServer.ListenAndServeTLS(tlsCertFile, tlsKeyFile))
}

func NewServer(addr string) *http.Server {
	return &http.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			// TODO: Change this to tls.RequireAndVerifyClientCert
			ClientAuth: tls.NoClientCert,
		},
	}
}

// StartCron starts the cron.StartCronJob in background.
func StartCronJob(config *admission.Config, cronInterval string) error {
	d, err := time.ParseDuration(cronInterval)
	if err != nil {
		return err
	}
	cronConfig, err := getCronConfig(config)
	if err != nil {
		return err
	}
	go cron.Start(context.Background(), *cronConfig, d)
	return nil
}

func getCronConfig(config *admission.Config) (*cron.Config, error) {
	ki, err := kubernetesutil.GetClientset()
	if err != nil {
		return nil, err
	}
	kcs := ki.(*kubernetes.Clientset)
	client, err := admission.MetadataClient(config)
	if err != nil {
		return nil, err
	}
	return cron.NewCronConfig(kcs, client), nil
}
