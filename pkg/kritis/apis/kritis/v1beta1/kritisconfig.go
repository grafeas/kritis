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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type KritisConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec KritisConfigSpec `json:"spec"`
}

// KritisConfigSpec is the spec for a KritisConfig resource
type KritisConfigSpec struct {
	// The backend to use for storing security metadata
	MetadataBackend string `json:"metadataBackend"`
	// Cron job time interval, as Duration e.g. "1h", "2s"
	CronInterval string `json:"cronInterval"`
	// Server address, with the preceding colon
	ServerAddr string `json:"serverAddr"`
	// Grafeas configuration used for communicating with Grafeas backend
	Grafeas GrafeasConfigSpec `json:"grafeas"`
}

// GrafeasConfigSpec holds the configuration required for connecting to grafeas instance
type GrafeasConfigSpec struct {
	Addr string `json:"addr"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KritisConfigList is a list of KritisConfig resources
type KritisConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []KritisConfig `json:"items"`
}
