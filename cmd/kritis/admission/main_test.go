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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/grafeas/kritis1/pkg/kritis/admission"
)

const (
	RandomPortAddress = ":0"
	CertFile          = "./certs/cert.pem"
	KeyFile           = "./certs/key.pem"
)

var tcIntTest = []struct {
	name             string
	certFile         string
	keyFile          string
	expectedHttpResp int
	err              error
}{
	{"secure connection", CertFile, KeyFile, http.StatusOK, nil},
	{"insecure connection", "", "", http.StatusContinue, fmt.Errorf("Get https://[::]:41071/: dial tcp [::]:41071: connect: connection refused")},
}

func TestHTTPSServer(t *testing.T) {
	http.HandleFunc("/", admission.AdmissionReviewHandler)
	for _, tc := range tcIntTest {
		t.Run(tc.name, func(t *testing.T) {
			// Get a fre port and start a server in background
			port := getFreePort(t)
			srv := NewServer(port)
			go srv.ListenAndServeTLS(tc.certFile, tc.keyFile)
			defer srv.Close()

			time.Sleep(100 * time.Millisecond)

			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			// Create a clint and make a request
			client := &http.Client{Transport: tr}
			res, err := client.Get(buildSecureUrl(srv.Addr, "/"))
			if err != tc.err {
				t.Fatalf("Exptect %v\nGot %v", tc.err, err)
			}
			if res.StatusCode != tc.expectedHttpResp {
				t.Errorf("Response code was %v; want %v", res.StatusCode, tc.expectedHttpResp)
			}
		})
	}
}

func buildSecureUrl(addr string, path string) string {
	return "https://" + addr + path
}

func getFreePort(t *testing.T) string {
	addr, err := net.ResolveTCPAddr("tcp", ":0")
	if err != nil {

	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}
