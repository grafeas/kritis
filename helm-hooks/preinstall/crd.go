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

const (
	attestationAuthorityCRD = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: attestationauthorities.kritis.grafeas.io
  labels:
    %s: ""
spec:
  group: kritis.grafeas.io
  versions:
    - name: v1beta1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                attestationAuthorityNames:
                  type: array
                  items:
                    type: string
  scope: Namespaced
  names:
    kind: GenericAttestationPolicy
    plural: genericattestationpolicies`

	genericAttestationPolicyCRD = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: genericattestationpolicies.kritis.grafeas.io
  labels:
    %s: ""
spec:
  group: kritis.grafeas.io
  versions:
    - name: v1beta1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                attestationAuthorityNames:
                  type: array
                  items:
                    type: string
  scope: Namespaced
  names:
    kind: GenericAttestationPolicy
    plural: genericattestationpolicies`

	imageSecurityPolicyCRD = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: imagesecuritypolicies.kritis.grafeas.io
  labels:
    %s: ""
spec:
  group: kritis.grafeas.io
  versions:
    - name: v1beta1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                imageAllowList:
                  type: array
                  items:
                    type: string
                packageVulnerabilityRequirements:
                  type: object
                  properties:
                    maximumSeverity:
                      type: string
                    maximumFixUnavailableSeverity:
                      type: string
                    allowlistCVEs:
                      type: array
                      items:
                        type: string
                attestationAuthorityNames:
                  type: array
                  items:
                    type: string
  scope: Namespaced
  names:
    kind: ImageSecurityPolicy
    plural: imagesecuritypolicies`

	kritisConfigCRD = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: kritisconfigs.kritis.grafeas.io
  labels:
    %s: ""
spec:
  group: kritis.grafeas.io
  versions:
    - name: v1beta1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                metadataBackend:
                  type: string
                cronInterval:
                  type: string
                serverAddr:
                  type: string
                grafeas:
                  type: object
                  properties:
                    addr:
                      type: string
  scope: Cluster
  names:
    kind: KritisConfig
    plural: kritisconfigs
    singular: kritisconfig`
)
