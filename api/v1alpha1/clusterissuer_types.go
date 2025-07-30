/*
Copyright 2025.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterIssuerSpec defines the desired state of ClusterIssuer
// It reuses the same fields as IssuerSpec
type ClusterIssuerSpec struct {
	IssuerSpec `json:",inline"`
}

// ClusterIssuerStatus defines the observed state of ClusterIssuer
type ClusterIssuerStatus struct {
	// Conditions represent the latest available observations of an issuer's current state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:scope=Cluster

// ClusterIssuer is the Schema for the cluster-wide issuers API
type ClusterIssuer struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of ClusterIssuer
	// +required
	Spec ClusterIssuerSpec `json:"spec"`

	// status defines the observed state of ClusterIssuer
	// +optional
	Status ClusterIssuerStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// ClusterIssuerList contains a list of ClusterIssuer
type ClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterIssuer{}, &ClusterIssuerList{})
}
