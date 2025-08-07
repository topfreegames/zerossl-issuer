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

package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
	"github.com/topfreegames/zerossl-issuer/internal/zerossl"
)

// Using shared MockZeroSSLClient from mock_client_test.go

func generateTestCSR(t *testing.T, dnsNames []string) []byte {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Use the first DNS name as common name, or default
	commonName := "test.example.com"
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	}

	// Create a CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: dnsNames,
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	require.NoError(t, err)

	// Encode CSR in PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM
}

func TestCertificateRequestReconciler(t *testing.T) {
	// Create a test CSR
	csrPEM := generateTestCSR(t, []string{"test.example.com", "test2.example.com"})

	// Create test objects
	issuer := &zerosslv1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: "default",
		},
		Spec: zerosslv1alpha1.IssuerSpec{
			APIKeySecretRef: corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "test-secret",
				},
				Key: "api-key",
			},
			ValidityDays: 90,
		},
		Status: zerosslv1alpha1.IssuerStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Ready",
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"api-key": []byte("test-api-key"),
		},
	}

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cr",
			Namespace: "default",
		},
		Spec: cmapi.CertificateRequestSpec{
			Request: csrPEM,
			IssuerRef: cmmeta.ObjectReference{
				Name:  "test-issuer",
				Kind:  "Issuer",
				Group: zerosslv1alpha1.GroupVersion.Group,
			},
		},
	}

	// Create a fake client
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, cmapi.AddToScheme(scheme))
	require.NoError(t, zerosslv1alpha1.AddToScheme(scheme))
	require.NoError(t, cmmeta.AddToScheme(scheme))

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(issuer, secret, cr).
		WithStatusSubresource(&cmapi.CertificateRequest{}).
		Build()

	// Create a fake event recorder
	eventRecorder := record.NewFakeRecorder(100)

	// Create the reconciler with a mock client that returns successful responses
	reconciler := &CertificateRequestReconciler{
		Client:                  client,
		Scheme:                  scheme,
		recorder:                eventRecorder,
		maxConcurrentReconciles: 1,
		clientFactory: func(apiKey string) ZeroSSLClient {
			return &MockZeroSSLClient{
				CreateCertificateResp: &zerossl.CertificateResponse{
					ID:     "test-cert-id",
					Status: "issued",
				},
				DownloadCertificateResp: &zerossl.DownloadCertificateResponse{
					Certificate:   "test-certificate",
					CACertificate: "test-ca-certificate",
				},
				GetCertificateResp: &zerossl.CertificateResponse{
					ID:     "test-cert-id",
					Status: "issued",
				},
			}
		},
	}

	// First reconciliation - this will create the certificate and add the annotation
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-cr",
			Namespace: "default",
		},
	})
	require.NoError(t, err)

	// Check that the CertificateRequest was updated with the annotation
	updatedCR := &cmapi.CertificateRequest{}
	err = client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cr",
		Namespace: "default",
	}, updatedCR)
	require.NoError(t, err)

	// Check that the certificate ID annotation was set
	assert.Contains(t, updatedCR.Annotations, CertificateRequestIDAnnotation)
	assert.Equal(t, "test-cert-id", updatedCR.Annotations[CertificateRequestIDAnnotation])

	// Second reconciliation - this will process the existing certificate and download it
	_, err = reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-cr",
			Namespace: "default",
		},
	})
	require.NoError(t, err)

	// Get the updated CertificateRequest
	updatedCR = &cmapi.CertificateRequest{}
	err = client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cr",
		Namespace: "default",
	}, updatedCR)
	require.NoError(t, err)

	// Check that the Ready condition was set
	var readyCondition *cmapi.CertificateRequestCondition
	for _, cond := range updatedCR.Status.Conditions {
		if cond.Type == ConditionReady {
			readyCondition = &cond
		}
	}
	require.NotNil(t, readyCondition, "Ready condition not found, available conditions: %v", updatedCR.Status.Conditions)
	assert.Equal(t, cmmeta.ConditionTrue, readyCondition.Status)
	assert.Equal(t, "Issued", readyCondition.Reason)

	// Check that the certificate contains both the leaf and intermediate certificate
	expectedCertificateChain := "test-certificate\ntest-ca-certificate"
	assert.Equal(t, []byte(expectedCertificateChain), updatedCR.Status.Certificate)
	// The CA field is not set anymore as it's included in the certificate chain
}

func TestCertificateRequestProcessingStatus(t *testing.T) {
	// Create a test CSR
	csrPEM := generateTestCSR(t, []string{"test.example.com"})

	// Create test objects
	issuer := &zerosslv1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: "default",
		},
		Spec: zerosslv1alpha1.IssuerSpec{
			APIKeySecretRef: corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "test-secret",
				},
				Key: "api-key",
			},
			ValidityDays: 90,
		},
		Status: zerosslv1alpha1.IssuerStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Ready",
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	certificateRequest := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cr",
			Namespace: "default",
		},
		Spec: cmapi.CertificateRequestSpec{
			Request: csrPEM,
			IssuerRef: cmmeta.ObjectReference{
				Group: "zerossl.cert-manager.io",
				Kind:  "Issuer",
				Name:  "test-issuer",
			},
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"api-key": []byte("test-api-key"),
		},
	}

	// Create a fake client with the objects
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, cmapi.AddToScheme(scheme))
	require.NoError(t, zerosslv1alpha1.AddToScheme(scheme))
	require.NoError(t, cmmeta.AddToScheme(scheme))

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(issuer, certificateRequest, secret).
		WithStatusSubresource(&cmapi.CertificateRequest{}).
		Build()

	// Create a reconciler with a mock client that returns "pending" status
	reconciler := &CertificateRequestReconciler{
		Client:                  client,
		Scheme:                  scheme,
		recorder:                record.NewFakeRecorder(10),
		maxConcurrentReconciles: 1,
		clientFactory: func(apiKey string) ZeroSSLClient {
			return &MockZeroSSLClient{
				CreateCertificateResp: &zerossl.CertificateResponse{
					ID:     "test-cert-id",
					Status: "pending", // Certificate is still processing
				},
				GetCertificateResp: &zerossl.CertificateResponse{
					ID:     "test-cert-id",
					Status: "pending", // Still processing
				},
			}
		},
	}

	// First reconciliation - this will create the certificate and set processing status
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-cr",
			Namespace: "default",
		},
	})
	require.NoError(t, err)

	// Check that the CertificateRequest was updated with the annotation
	updatedCR := &cmapi.CertificateRequest{}
	err = client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cr",
		Namespace: "default",
	}, updatedCR)
	require.NoError(t, err)

	// Check that the certificate ID annotation was set
	assert.Contains(t, updatedCR.Annotations, CertificateRequestIDAnnotation)
	assert.Equal(t, "test-cert-id", updatedCR.Annotations[CertificateRequestIDAnnotation])

	// Second reconciliation - certificate is still processing, now we should see the processing status
	_, err = reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-cr",
			Namespace: "default",
		},
	})
	require.NoError(t, err)

	// Get the updated CertificateRequest again
	updatedCR = &cmapi.CertificateRequest{}
	err = client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cr",
		Namespace: "default",
	}, updatedCR)
	require.NoError(t, err)

	// Verify the processing status is set
	var readyCondition *cmapi.CertificateRequestCondition
	for _, cond := range updatedCR.Status.Conditions {
		if cond.Type == ConditionReady {
			readyCondition = &cond
		}
	}
	require.NotNil(t, readyCondition, "Ready condition not found, available conditions: %v", updatedCR.Status.Conditions)
	assert.Equal(t, cmmeta.ConditionFalse, readyCondition.Status)
	assert.Equal(t, "CertificateProcessing", readyCondition.Reason)
	assert.Contains(t, readyCondition.Message, "is still being processed")

	// Update mock to return issued status
	reconciler.clientFactory = func(apiKey string) ZeroSSLClient {
		return &MockZeroSSLClient{
			GetCertificateResp: &zerossl.CertificateResponse{
				ID:     "test-cert-id",
				Status: "issued", // Now issued
			},
			DownloadCertificateResp: &zerossl.DownloadCertificateResponse{
				Certificate:   "test-certificate",
				CACertificate: "test-ca-certificate",
			},
		}
	}

	// Third reconciliation - certificate is now issued
	_, err = reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-cr",
			Namespace: "default",
		},
	})
	require.NoError(t, err)

	// Get the final updated CertificateRequest
	updatedCR = &cmapi.CertificateRequest{}
	err = client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cr",
		Namespace: "default",
	}, updatedCR)
	require.NoError(t, err)

	// Verify the Ready condition is now True
	for _, cond := range updatedCR.Status.Conditions {
		if cond.Type == ConditionReady {
			readyCondition = &cond
		}
	}
	require.NotNil(t, readyCondition)
	assert.Equal(t, cmmeta.ConditionTrue, readyCondition.Status)
	assert.Equal(t, "Issued", readyCondition.Reason)
	assert.Equal(t, "Certificate has been issued successfully", readyCondition.Message)

	// Check that the certificate was set
	assert.NotEmpty(t, updatedCR.Status.Certificate)
}

func TestGetDNSNamesFromCSR(t *testing.T) {
	// Create a test CSR with DNS names
	csrPEM := generateTestCSR(t, []string{"test.example.com", "test2.example.com"})

	// Test getting DNS names from the CSR
	dnsNames, err := getDNSNamesFromCSR(csrPEM)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"test.example.com", "test2.example.com"}, dnsNames)

	// Test getting DNS names from a CSR with only CommonName
	csrPEM = generateTestCSR(t, nil)

	dnsNames, err = getDNSNamesFromCSR(csrPEM)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"test.example.com"}, dnsNames)

	// Test error handling for invalid CSR
	_, err = getDNSNamesFromCSR([]byte("invalid"))
	assert.Error(t, err)
}

func TestIsDenied(t *testing.T) {
	cr := &cmapi.CertificateRequest{
		Status: cmapi.CertificateRequestStatus{
			Conditions: []cmapi.CertificateRequestCondition{
				{
					Type:   "Denied",
					Status: cmmeta.ConditionTrue,
				},
			},
		},
	}
	assert.True(t, isDenied(cr))

	cr = &cmapi.CertificateRequest{
		Status: cmapi.CertificateRequestStatus{
			Conditions: []cmapi.CertificateRequestCondition{
				{
					Type:   "Denied",
					Status: cmmeta.ConditionFalse,
				},
			},
		},
	}
	assert.False(t, isDenied(cr))
}

func TestIsComplete(t *testing.T) {
	cr := &cmapi.CertificateRequest{
		Status: cmapi.CertificateRequestStatus{
			Conditions: []cmapi.CertificateRequestCondition{
				{
					Type:   "Ready",
					Status: cmmeta.ConditionTrue,
				},
			},
		},
	}
	assert.True(t, isComplete(cr))

	cr = &cmapi.CertificateRequest{
		Status: cmapi.CertificateRequestStatus{
			Conditions: []cmapi.CertificateRequestCondition{
				{
					Type:   "Ready",
					Status: cmmeta.ConditionFalse,
				},
			},
		},
	}
	assert.False(t, isComplete(cr))
}

func TestIsIssuerReady(t *testing.T) {
	issuer := &zerosslv1alpha1.Issuer{
		Status: zerosslv1alpha1.IssuerStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Ready",
					Status: metav1.ConditionTrue,
				},
			},
		},
	}
	assert.True(t, isIssuerReady(issuer))

	issuer = &zerosslv1alpha1.Issuer{
		Status: zerosslv1alpha1.IssuerStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Ready",
					Status: metav1.ConditionFalse,
				},
			},
		},
	}
	assert.False(t, isIssuerReady(issuer))
}

func TestFindSolverForDomain(t *testing.T) {
	issuer := &zerosslv1alpha1.Issuer{
		Spec: zerosslv1alpha1.IssuerSpec{
			Solvers: []zerosslv1alpha1.ACMESolver{
				{
					Selector: &zerosslv1alpha1.ACMESolverSelector{
						DNSNames: []string{"specific.example.com"},
					},
					DNS01: &zerosslv1alpha1.ACMEChallengeSolverDNS01{
						Route53: &zerosslv1alpha1.ACMEChallengeSolverDNS01Route53{
							Region:       "us-east-1",
							HostedZoneID: "ZONE1",
						},
					},
				},
				{
					Selector: &zerosslv1alpha1.ACMESolverSelector{
						DNSZones: []string{"example.com"},
					},
					DNS01: &zerosslv1alpha1.ACMEChallengeSolverDNS01{
						Route53: &zerosslv1alpha1.ACMEChallengeSolverDNS01Route53{
							Region:       "us-east-1",
							HostedZoneID: "ZONE2",
						},
					},
				},
				{
					DNS01: &zerosslv1alpha1.ACMEChallengeSolverDNS01{
						Route53: &zerosslv1alpha1.ACMEChallengeSolverDNS01Route53{
							Region:       "us-east-1",
							HostedZoneID: "ZONE3",
						},
					},
				},
			},
		},
	}

	// Test exact domain match
	solver := findSolverForDomain(issuer, "specific.example.com")
	require.NotNil(t, solver)
	assert.Equal(t, "ZONE1", solver.DNS01.Route53.HostedZoneID)

	// Test domain in zone match
	solver = findSolverForDomain(issuer, "sub.example.com")
	require.NotNil(t, solver)
	assert.Equal(t, "ZONE2", solver.DNS01.Route53.HostedZoneID)

	// Test catch-all solver
	solver = findSolverForDomain(issuer, "other-domain.com")
	require.NotNil(t, solver)
	assert.Equal(t, "ZONE3", solver.DNS01.Route53.HostedZoneID)

	// Test no solvers
	issuer.Spec.Solvers = []zerosslv1alpha1.ACMESolver{}
	solver = findSolverForDomain(issuer, "example.com")
	assert.Nil(t, solver)
}

func TestContainsDomain(t *testing.T) {
	domains := []string{"example.com", "example.org"}

	assert.True(t, containsDomain(domains, "example.com"))
	assert.True(t, containsDomain(domains, "example.org"))
	assert.False(t, containsDomain(domains, "example.net"))
	assert.False(t, containsDomain(domains, "sub.example.com"))
}

func TestMatchesDomainInZones(t *testing.T) {
	zones := []string{"example.com", "example.org"}

	assert.True(t, matchesDomainInZones(zones, "example.com"))
	assert.True(t, matchesDomainInZones(zones, "example.org"))
	assert.True(t, matchesDomainInZones(zones, "sub.example.com"))
	assert.True(t, matchesDomainInZones(zones, "sub.sub.example.com"))
	assert.False(t, matchesDomainInZones(zones, "example.net"))
	assert.False(t, matchesDomainInZones(zones, "sub.example.net"))
}

func TestHasDNSValidator(t *testing.T) {
	issuer := &zerosslv1alpha1.Issuer{
		Spec: zerosslv1alpha1.IssuerSpec{
			Solvers: []zerosslv1alpha1.ACMESolver{
				{
					Selector: &zerosslv1alpha1.ACMESolverSelector{
						DNSZones: []string{"example.com"},
					},
					DNS01: &zerosslv1alpha1.ACMEChallengeSolverDNS01{
						Route53: &zerosslv1alpha1.ACMEChallengeSolverDNS01Route53{
							Region:       "us-east-1",
							HostedZoneID: "ZONE1",
						},
					},
				},
			},
		},
	}

	// Test with DNS validator
	domains := []string{"test.example.com", "test.example.org"}
	assert.True(t, hasDNSValidator(issuer, domains))

	// Test without DNS validator
	domains = []string{"test.example.org", "test.example.net"}
	assert.False(t, hasDNSValidator(issuer, domains))
}

// TestEmptyValidationMap tests handling of empty validation maps
func TestEmptyValidationMap(t *testing.T) {
	// Create a certificate info with empty validation map
	certInfo := &zerossl.CertificateResponse{
		ID:     "test-cert-id",
		Status: "pending_validation",
		Validation: zerossl.ValidationInfo{
			EmailValidation: make(map[string][]string),
			OtherMethods:    make(map[string]zerossl.ValidationOtherMethodDetails),
		},
	}

	// Test the getDomains function
	domains := getDomains(certInfo)
	assert.Equal(t, 0, len(domains), "Empty validation map should return zero domains")

	// Create an issuer for testing
	issuer := &zerosslv1alpha1.Issuer{
		Spec: zerosslv1alpha1.IssuerSpec{
			Solvers: []zerosslv1alpha1.ACMESolver{
				{
					Selector: &zerosslv1alpha1.ACMESolverSelector{
						DNSZones: []string{"example.com"},
					},
					DNS01: &zerosslv1alpha1.ACMEChallengeSolverDNS01{
						Route53: &zerosslv1alpha1.ACMEChallengeSolverDNS01Route53{
							Region:       "us-east-1",
							HostedZoneID: "ZONE1",
						},
					},
				},
			},
		},
	}

	// Test the validation record extraction
	validationRecords := []zerosslv1alpha1.ValidationRecord{}
	for _, domain := range getDomains(certInfo) {
		if solver := findSolverForDomain(issuer, domain); solver != nil && solver.DNS01 != nil {
			// No domains to process, so this loop should not execute
			t.Errorf("Expected no domains, but found domain: %s", domain)
		}
	}

	// Verification
	assert.Equal(t, 0, len(validationRecords), "Should have zero validation records from empty validation map")
}
