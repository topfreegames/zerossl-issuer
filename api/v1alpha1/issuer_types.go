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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IssuerSpec defines the desired state of Issuer
type IssuerSpec struct {
	// APIKeySecretRef is a reference to a secret containing the ZeroSSL API key
	// +required
	APIKeySecretRef corev1.SecretKeySelector `json:"apiKeySecretRef"`

	// ValidityDays is the number of days the certificate should be valid for
	// +optional
	// +kubebuilder:default=90
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=365
	ValidityDays int `json:"validityDays,omitempty"`

	// StrictDomains enables strict domain validation
	// +optional
	// +kubebuilder:default=true
	StrictDomains bool `json:"strictDomains,omitempty"`
}

// IssuerStatus defines the observed state of Issuer.
type IssuerStatus struct {
	// Conditions represent the latest available observations of an issuer's current state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Issuer is the Schema for the issuers API
type Issuer struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of Issuer
	// +required
	Spec IssuerSpec `json:"spec"`

	// status defines the observed state of Issuer
	// +optional
	Status IssuerStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// IssuerList contains a list of Issuer
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Issuer{}, &IssuerList{})
}
