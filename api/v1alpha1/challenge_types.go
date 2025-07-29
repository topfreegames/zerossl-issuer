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

// ChallengeSpec defines the desired state of Challenge
type ChallengeSpec struct {
	// CertificateRequestRef is a reference to the CertificateRequest that this challenge is for
	// +required
	CertificateRequestRef string `json:"certificateRequestRef"`

	// CertificateID is the ZeroSSL certificate ID
	// +required
	CertificateID string `json:"certificateID"`

	// ValidationMethod is the validation method used for this challenge
	// +kubebuilder:validation:Enum=DNS
	// +required
	ValidationMethod string `json:"validationMethod"`

	// ValidationRecords contains the validation records for this challenge
	// +optional
	ValidationRecords []ValidationRecord `json:"validationRecords,omitempty"`
}

// ValidationRecord contains the validation data for a single domain
type ValidationRecord struct {
	// Domain is the domain being validated
	// +required
	Domain string `json:"domain"`

	// CNAMEName is the name of the CNAME record
	// +required
	CNAMEName string `json:"cnameName"`

	// CNAMEValue is the value of the CNAME record
	// +required
	CNAMEValue string `json:"cnameValue"`
}

// ChallengeStatus defines the observed state of Challenge
type ChallengeStatus struct {
	// Conditions represent the latest available observations of the challenge state
	// +optional
	Conditions []ChallengeCondition `json:"conditions,omitempty"`
}

// ChallengeCondition contains condition information for a Challenge
type ChallengeCondition struct {
	// Type of the condition
	// +required
	Type string `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown')
	// +kubebuilder:validation:Enum=True;False;Unknown
	// +required
	Status metav1.ConditionStatus `json:"status"`

	// Reason is a brief machine readable explanation for the condition's last transition
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last transition
	// +optional
	Message string `json:"message,omitempty"`

	// LastTransitionTime is the timestamp corresponding to the last status change of this condition
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status",description="Status of the challenge"
// +kubebuilder:printcolumn:name="Method",type="string",JSONPath=".spec.validationMethod",description="Validation method"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Challenge is the Schema for the challenges API
type Challenge struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ChallengeSpec   `json:"spec,omitempty"`
	Status ChallengeStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ChallengeList contains a list of Challenge
type ChallengeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Challenge `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Challenge{}, &ChallengeList{})
}
