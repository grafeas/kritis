/*
Copyright 2020 Google LLC

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
	"encoding/json"
	"fmt"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/discovery"
	grafeaspb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
)

type EvaluationStatus string

const (
	Ok        EvaluationStatus = "ok"
	Signed    EvaluationStatus = "signed"
	NotSigned EvaluationStatus = "not-signed"
	Failed    EvaluationStatus = "failed"
)

type SignRequest struct {
	Image string
}

type SignResponse struct {
	Image      string           `json:"image,omitempty"`
	Status     EvaluationStatus `json:"status,omitempty"`
	Message    string           `json:"message,omitempty"`
	Violations []string         `json:"violations,omitempty"`
}

// write the sign `response` to `w` with status `code`
func WriteResponse(w http.ResponseWriter, response SignResponse, code int) {
	body, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	glog.Infof("%s\t%s", response.Image, response.Message)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	w.Write(body)
}

// Google Pub/Sub message
type PubSubMessage struct {
	Message struct {
		Data []byte `json:"data,omitempty"`
		ID   string `json:"id"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// Google Container Analysis occurrence notification
type ContainerAnalysisOccurrenceEvent struct {
	Name             string    `json:"name"`
	Kind             string    `json:"kind"`
	NotificationTime time.Time `json:"notificationTime"`
}

// retrieve the container analysis occurrence associated with this notification
func GetOccurrence(event ContainerAnalysisOccurrenceEvent) (*grafeaspb.Occurrence, error) {
	request := grafeaspb.GetOccurrenceRequest{Name: event.Name}
	response, err := grafeas.GetOccurrence(context.Background(), &request)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve discovery occurrence %s", event.Name)
	}
	return response, nil
}

// implements `/event` handles a container analysis occurrence notification
func containerAnalysisEvent(w http.ResponseWriter, r *http.Request) {
	var m PubSubMessage
	var event ContainerAnalysisOccurrenceEvent
	err := json.NewDecoder(r.Body).Decode(&m)
	if err != nil {
		response := SignResponse{Status: Failed,
			Message: fmt.Sprintf("could not unmarshal the pubsub message, %s", err.Error())}
		WriteResponse(w, response, http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(m.Message.Data, &event)
	if err != nil {
		response := SignResponse{Status: Failed,
			Message: fmt.Sprintf("could not unmarshal container analysis occurrence, %s", err.Error())}
		WriteResponse(w, response, http.StatusBadRequest)
		return
	}

	if event.Kind != "DISCOVERY" {
		response := SignResponse{Message: "ignoring non-DISCOVERY occurrence"}
		WriteResponse(w, response, http.StatusOK)
		return
	}

	occurrence, err := GetOccurrence(event)
	if err != nil {
		glog.Errorf("Failed to retrieve reported occurrence %s, %s", event.Name, err.Error())
		response := SignResponse{Status: Failed, Message: err.Error()}
		WriteResponse(w, response, http.StatusInternalServerError)
		return
	}

	status := occurrence.GetDiscovered().GetDiscovered().GetAnalysisStatus()
	if status != discovery.Discovered_FINISHED_SUCCESS {
		response := SignResponse{Message: fmt.Sprintf("ignoring DISCOVERY occurrence in status %s", string(status))}
		WriteResponse(w, response, http.StatusOK)
		return
	}
	image := occurrence.Resource.Uri
	if strings.HasPrefix(image, "https://") {
		image = image[8:]
	}
	doCheckAndSign(w, SignRequest{Image: image}, http.StatusOK)
}

// implements `/check-only`
func check(w http.ResponseWriter, r *http.Request) {
	var request SignRequest
	var response SignResponse

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		response.Status = Failed
		response.Message = fmt.Sprintf("failed to decode body, %s", err)
		WriteResponse(w, response, http.StatusBadRequest)
		return
	}
	response.Image = request.Image

	violations, err := DoCheck(request.Image)
	if err != nil {
		response.Status = Failed
		response.Message = err.Error()
		WriteResponse(w, response, http.StatusBadRequest)
		return
	}
	if violations != nil {
		response.Status = Failed
		response.Violations = violations
		WriteResponse(w, response, http.StatusUnprocessableEntity)
	} else {
		response.Status = Ok
		WriteResponse(w, response, http.StatusOK)
	}
}

// implements `/check-and-sign`
func checkAndSign(w http.ResponseWriter, r *http.Request) {

	var request SignRequest
	var response SignResponse

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		response.Status = Failed
		response.Message = fmt.Sprintf("failed to decode body, %s", err)
		WriteResponse(w, response, http.StatusBadRequest)
		return
	}
	doCheckAndSign(w, request, http.StatusUnprocessableEntity)
}

// check and sign is called either directly via /check-and-sign or indirect via
// the /event notification.
func doCheckAndSign(w http.ResponseWriter, request SignRequest, violationStatus int) {
	response := SignResponse{Image: request.Image}

	violations, err := DoCheck(request.Image)
	if err != nil {
		response.Status = Failed
		response.Message = err.Error()
		WriteResponse(w, response, http.StatusInternalServerError)
		return
	}

	if violations != nil {
		response.Status = NotSigned
		response.Message = fmt.Sprintf("image violates policy")
		response.Violations = violations
		WriteResponse(w, response, violationStatus)
		return
	}

	err = DoSign(request.Image)
	if err != nil {
		response.Status = Failed
		response.Message = err.Error()
		WriteResponse(w, response, http.StatusInternalServerError)
		return
	}

	response.Status = Signed
	response.Message = "image passed vulnerability policy"
	WriteResponse(w, response, http.StatusOK)
}

func Serve() {
	var err error

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.HandleFunc("/check-only", check)
	http.HandleFunc("/check-and-sign", checkAndSign)
	http.HandleFunc("/event", containerAnalysisEvent)

	glog.Infof("listening on port %s", port)
	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		glog.Fatalf("server stopped with error, %s", err)
	}
}
