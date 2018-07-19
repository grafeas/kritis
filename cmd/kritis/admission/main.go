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
	"log"
	"net/http"
	"time"

	"github.com/grafeas/kritis/pkg/kritis/admission"
	"github.com/grafeas/kritis/pkg/kritis/cron"
	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	"github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
	"github.com/pkg/errors"
	"k8s.io/client-go/kubernetes"
)

var (
	tlsCertFile  string
	tlsKeyFile   string
	cronInterval string
)

const (
	Addr = ":443"
)

func main() {
	flag.StringVar(&tlsCertFile, "tls-cert-file", "/var/tls/tls.crt", "TLS certificate file.")
	flag.StringVar(&tlsKeyFile, "tls-key-file", "/var/tls/tls.key", "TLS key file.")
	flag.Set("logtostderr", "true")
	flag.StringVar(&cronInterval, "cron-interval", "1h", "Cron Job time interval as Duration e.g. 1h, 2s")
	flag.Parse()

	log.Println("Running the background job in background")
	// Kick off back ground cron job.
	e := make(chan error, 1)
	go StartCronJob(e)
	if err := <-e; err != nil {
		log.Fatal(errors.Wrap(err, "Could not start Cron Job due to "))
	}

	// Start the Kritis Server.
	log.Println("Running the server")
	http.HandleFunc("/", admission.AdmissionReviewHandler)
	httpsServer := NewServer(Addr)
	log.Fatal(httpsServer.ListenAndServeTLS(tlsCertFile, tlsKeyFile))

	log.Println("End Running the server")
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

func StartCronJob(e chan error) {
	checkInterval, err := time.ParseDuration(cronInterval)
	if err != nil {
		e <- err
	}
	ctx := context.Background()
	ki, err := kubernetesutil.GetClientset()
	if err != nil {
		e <- err
	}
	kcs := ki.(*kubernetes.Clientset)
	metadataClient, err := containeranalysis.NewContainerAnalysisClient()
	if err != nil {
		e <- err
	}
	close(e)
	cron.Start(ctx, *cron.NewCronConfig(kcs, *metadataClient), checkInterval)
}
