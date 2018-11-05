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

	"github.com/golang/glog"
	"github.com/grafeas/kritis/cmd/kritis/version"
	"github.com/grafeas/kritis/pkg/kritis/admission"
	"github.com/grafeas/kritis/pkg/kritis/crd/kritisconfig"
	"github.com/grafeas/kritis/pkg/kritis/cron"
	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	"github.com/pkg/errors"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
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

	kritisConfigs, err := kritisconfig.KritisConfigs("default")
	if err != nil {
		errMsg := fmt.Sprintf("error getting kritis config: %v", err)
		glog.Errorf(errMsg)
		return
	}
	if len(kritisConfigs) == 0 {
		glog.Errorf("No KritisConfigs found in any namespace")
		return
	} else if len(kritisConfigs) > 1 {
		glog.Errorf("More than 1 KritisConfig found, will use the 0th object")
	}

	kritisConf := kritisConfigs[0]
	// TODO(https://github.com/grafeas/kritis/issues/304): Use CRD validation instead
	if kritisConf.Spec.MetadataBackend == "" {
		glog.Errorf("No KritisConfigs MetadataBackend is defined in the spec")
		return
	}
	if kritisConf.Spec.CronInterval == "" {
		glog.Errorf("No KritisConfigs CronInterval is defined in the spec")
		return
	}
	if kritisConf.Spec.ServerAddr == "" {
		glog.Errorf("No KritisConfigs ServerAddr is defined in the spec")
		return
	}

	config := &admission.Config{
		Metadata: kritisConf.Spec.MetadataBackend,
	}
	// TODO: (tejaldesai) This is getting complicated. Use CLI Library.
	if runCron {
		cronConfig, err := getCronConfig(config)
		if err != nil {
			glog.Fatalf("Could not run cron job in foreground: %s", err)
		}
		if err := cron.RunInForeground(*cronConfig); err != nil {
			glog.Fatalf("Error Checking pods: %s", err)
		}
		return
	}
	// Kick off back ground cron job.
	if err := StartCronJob(config, kritisConf.Spec.CronInterval); err != nil {
		glog.Fatal(errors.Wrap(err, "starting background job"))
	}

	// Start the Kritis Server.
	glog.Info("Running the server")
	http.HandleFunc("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admission.ReviewHandler(w, r, config)
	}))
	httpsServer := NewServer(kritisConf.Spec.ServerAddr)
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
