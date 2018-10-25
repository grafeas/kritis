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

// Package constants defines all constants needed for AdmissionController.
package constants

// A Status a string type used for metav1.Status.Status responses.
// See https://github.com/kubernetes/community/blob/master/contributors/devel/api-conventions.md#response-status-kind
type Status string

const (
	// SuccessStatus is the status type returned when admitting a pod.
	SuccessStatus Status = "Success"
	// FailureStatus is the status type returned when denying a pod.
	FailureStatus Status = "Failure"
)

const (
	// SuccessMessage is the status message returned when admitting a pod.
	SuccessMessage = "Successfully admitted."
)

const (
	// RSABits is the number of bits in new RSA keys created for attestation purposes.
	RSABits = 4096
)

// A list of all Kubernetes objects kritis can validate
const (
	Pod        = "Pod"
	ReplicaSet = "ReplicaSet"
	Deployment = "Deployment"
)

var (
	// SupportedTypes is a list of Kubernetes types that kritis can validate
	SupportedTypes = []string{Pod, ReplicaSet, Deployment}
)

// Types of supported metadata fetchers
const (
	GrafeasMetadata           = "grafeas"
	ContainerAnalysisMetadata = "containerAnalysis"
)
