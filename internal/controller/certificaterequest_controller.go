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
	"crypto/x509"
	"encoding/pem"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
	"github.com/topfreegames/zerossl-issuer/internal/zerossl"
)

const (
	// CertificateRequestIDAnnotation is the annotation key for storing the ZeroSSL certificate ID
	CertificateRequestIDAnnotation = "zerossl.cert-manager.io/certificate-id"
	// ConditionReady is the type for the Ready condition
	ConditionReady = "Ready"
)

// ZeroSSLClient is an interface for the ZeroSSL client
type ZeroSSLClient interface {
	CreateCertificate(req *zerossl.CertificateRequest) (*zerossl.CertificateResponse, error)
	DownloadCertificate(id string) (*zerossl.CertificateResponse, error)
}

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// clientFactory is a function that creates a new ZeroSSL client
	clientFactory func(string) ZeroSSLClient
}

// NewCertificateRequestReconciler creates a new CertificateRequestReconciler
func NewCertificateRequestReconciler(k8sClient client.Client, scheme *runtime.Scheme) *CertificateRequestReconciler {
	return &CertificateRequestReconciler{
		Client: k8sClient,
		Scheme: scheme,
		clientFactory: func(apiKey string) ZeroSSLClient {
			return zerossl.NewClient(apiKey)
		},
	}
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/finalizers,verbs=update
// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=issuers,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling CertificateRequest", "namespace", req.Namespace, "name", req.Name)

	// Get the CertificateRequest
	cr := &cmapi.CertificateRequest{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get CertificateRequest: %v", err)
	}

	// Check if the CertificateRequest has been denied
	if isDenied(cr) {
		logger.Info("CertificateRequest has been denied, not processing")
		return ctrl.Result{}, nil
	}

	// Check if the CertificateRequest has already been completed
	if isComplete(cr) {
		logger.Info("CertificateRequest is complete, not processing")
		return ctrl.Result{}, nil
	}

	// Check if the CertificateRequest references a ZeroSSL issuer
	issuerGvk := zerosslv1alpha1.GroupVersion.WithKind("Issuer")
	issuerGroup := issuerGvk.Group

	if cr.Spec.IssuerRef.Group != issuerGroup {
		logger.Info("CertificateRequest does not reference a ZeroSSL issuer", "group", cr.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// Get the referenced issuer
	issuer := &zerosslv1alpha1.Issuer{}
	issuerName := types.NamespacedName{
		Name:      cr.Spec.IssuerRef.Name,
		Namespace: req.Namespace,
	}

	if err := r.Get(ctx, issuerName, issuer); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get issuer: %v", err)
	}

	// Check if the issuer is ready
	if !isIssuerReady(issuer) {
		setFailureCondition(cr, "IssuerNotReady", "Issuer is not ready")
		if err := r.Status().Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
		}
		return ctrl.Result{}, nil
	}

	// Get the API key from the secret
	secret := &corev1.Secret{}
	secretName := types.NamespacedName{
		Name:      issuer.Spec.APIKeySecretRef.Name,
		Namespace: issuer.Namespace,
	}

	if err := r.Get(ctx, secretName, secret); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get API key secret: %v", err)
	}

	apiKey, ok := secret.Data[issuer.Spec.APIKeySecretRef.Key]
	if !ok {
		return ctrl.Result{}, fmt.Errorf("API key not found in secret")
	}

	// Create ZeroSSL client
	zerosslClient := r.clientFactory(string(apiKey))

	// Extract domains from the CSR
	domains, err := getDNSNamesFromCSR(cr.Spec.Request)
	if err != nil {
		setFailureCondition(cr, "InvalidCSR", fmt.Sprintf("Failed to get DNS names from CSR: %v", err))
		if err := r.Status().Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
		}
		return ctrl.Result{}, nil
	}

	// Create certificate request
	certReq := &zerossl.CertificateRequest{
		Domains:       domains,
		ValidityDays:  issuer.Spec.ValidityDays,
		CSR:           string(cr.Spec.Request),
		StrictDomains: true,
	}

	certResp, err := zerosslClient.CreateCertificate(certReq)
	if err != nil {
		setFailureCondition(cr, "CertificateIssuanceFailed", fmt.Sprintf("Failed to create certificate: %v", err))
		if err := r.Status().Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
		}
		return ctrl.Result{}, nil
	}

	// Store the certificate ID in annotations
	if cr.Annotations == nil {
		cr.Annotations = make(map[string]string)
	}
	cr.Annotations[CertificateRequestIDAnnotation] = certResp.ID

	// Update the CertificateRequest with the annotation
	if err := r.Update(ctx, cr); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update CertificateRequest annotations: %v", err)
	}

	// Download the certificate
	certResp, err = zerosslClient.DownloadCertificate(certResp.ID)
	if err != nil {
		setFailureCondition(cr, "CertificateDownloadFailed", fmt.Sprintf("Failed to download certificate: %v", err))
		if err := r.Status().Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
		}
		return ctrl.Result{}, nil
	}

	// Update the CertificateRequest status with the certificate and CA bundle
	cr.Status.Certificate = []byte(certResp.Certificate)
	cr.Status.CA = []byte(certResp.CACertificate)

	// Set the Ready condition
	setReadyCondition(cr, "CertificateIssued", "Certificate has been issued successfully")
	if err := r.Status().Update(ctx, cr); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Named("certificaterequest").
		Complete(r)
}

// Helper functions

func isDenied(cr *cmapi.CertificateRequest) bool {
	for _, c := range cr.Status.Conditions {
		if c.Type == "Denied" && c.Status == cmmeta.ConditionTrue {
			return true
		}
	}
	return false
}

func isComplete(cr *cmapi.CertificateRequest) bool {
	for _, c := range cr.Status.Conditions {
		if c.Type == ConditionReady && c.Status == cmmeta.ConditionTrue {
			return true
		}
	}
	return false
}

func isIssuerReady(issuer *zerosslv1alpha1.Issuer) bool {
	for _, c := range issuer.Status.Conditions {
		if c.Type == ConditionReady && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

func setFailureCondition(cr *cmapi.CertificateRequest, reason, message string) {
	now := metav1.Now()
	cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{
		Type:               ConditionReady,
		Status:             cmmeta.ConditionFalse,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: &now,
	})
}

func setReadyCondition(cr *cmapi.CertificateRequest, reason, message string) {
	now := metav1.Now()
	cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{
		Type:               ConditionReady,
		Status:             cmmeta.ConditionTrue,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: &now,
	})
}

func getDNSNamesFromCSR(csrBytes []byte) ([]string, error) {
	block, _ := pem.Decode(csrBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM block")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %v", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("failed to verify CSR signature: %v", err)
	}

	// Get DNS names from the CSR
	dnsNames := csr.DNSNames
	if len(dnsNames) == 0 {
		// If no DNS names are found, use the Common Name as a DNS name
		if csr.Subject.CommonName != "" {
			dnsNames = []string{csr.Subject.CommonName}
		} else {
			return nil, fmt.Errorf("no DNS names found in CSR")
		}
	}

	return dnsNames, nil
}
