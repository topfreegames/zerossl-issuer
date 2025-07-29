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
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
	"github.com/topfreegames/zerossl-issuer/internal/zerossl"
)

const (
	// RetryAfterValidation is the time to wait between validation checks
	RetryAfterValidation = 30 * time.Second
)

// ZeroSSLClient is an interface for the ZeroSSL client
type ZeroSSLClient interface {
	CreateCertificate(req *zerossl.CertificateRequest) (*zerossl.CertificateResponse, error)
	DownloadCertificate(id string) (*zerossl.DownloadCertificateResponse, error)
	InitiateValidation(id string, method zerossl.ValidationMethod) (*zerossl.CertificateResponse, error)
	VerifyDNSValidation(id string) error
	GetCertificate(id string) (*zerossl.CertificateResponse, error)
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

	// Check if the CertificateRequest has been denied or completed
	if isDenied(cr) {
		logger.Info("CertificateRequest has been denied, not processing")
		return ctrl.Result{}, nil
	}
	if isComplete(cr) {
		logger.Info("CertificateRequest is complete, not processing")
		return ctrl.Result{}, nil
	}

	// Check if the CertificateRequest references a ZeroSSL issuer
	if !r.isZeroSSLIssuer(cr) {
		logger.Info("CertificateRequest does not reference a ZeroSSL issuer", "group", cr.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// Process the certificate request
	return r.processCertificateRequest(ctx, req, cr)
}

// isZeroSSLIssuer checks if the certificate request references a ZeroSSL issuer
func (r *CertificateRequestReconciler) isZeroSSLIssuer(cr *cmapi.CertificateRequest) bool {
	issuerGvk := zerosslv1alpha1.GroupVersion.WithKind("Issuer")
	issuerGroup := issuerGvk.Group
	return cr.Spec.IssuerRef.Group == issuerGroup
}

// processCertificateRequest handles the main certificate request processing logic
func (r *CertificateRequestReconciler) processCertificateRequest(ctx context.Context, req ctrl.Request, cr *cmapi.CertificateRequest) (ctrl.Result, error) {
	// Get the referenced issuer
	issuer, err := r.getIssuer(ctx, req.Namespace, cr.Spec.IssuerRef.Name)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Check if the issuer is ready
	if !isIssuerReady(issuer) {
		setFailureCondition(cr, "IssuerNotReady", "Issuer is not ready")
		if err := r.Status().Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
		}
		return ctrl.Result{}, nil
	}

	// Get ZeroSSL client
	zerosslClient, err := r.getZeroSSLClient(ctx, issuer)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Extract domains from the CSR
	domains, err := getDNSNamesFromCSR(cr.Spec.Request)
	if err != nil {
		setFailureCondition(cr, "InvalidCSR", fmt.Sprintf("Failed to get DNS names from CSR: %v", err))
		if err := r.Status().Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
		}
		return ctrl.Result{}, nil
	}

	// Check if there is a certificate ID already stored in annotations
	var certID string
	if cr.Annotations != nil {
		certID = cr.Annotations[CertificateRequestIDAnnotation]
	}

	// If no certificate ID is stored, create a new certificate
	if certID == "" {
		return r.createNewCertificate(ctx, cr, issuer, zerosslClient, domains)
	}

	// For existing certificates or when completing DNS validation
	return r.handleExistingCertificate(ctx, cr, issuer, zerosslClient, domains, certID)
}

// getIssuer retrieves the issuer referenced by the certificate request
func (r *CertificateRequestReconciler) getIssuer(ctx context.Context, namespace, name string) (*zerosslv1alpha1.Issuer, error) {
	issuer := &zerosslv1alpha1.Issuer{}
	issuerName := types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}

	if err := r.Get(ctx, issuerName, issuer); err != nil {
		return nil, fmt.Errorf("failed to get issuer: %v", err)
	}

	return issuer, nil
}

// getZeroSSLClient creates a ZeroSSL client from the issuer configuration
func (r *CertificateRequestReconciler) getZeroSSLClient(ctx context.Context, issuer *zerosslv1alpha1.Issuer) (ZeroSSLClient, error) {
	// Get the API key from the secret
	secret := &corev1.Secret{}
	secretName := types.NamespacedName{
		Name:      issuer.Spec.APIKeySecretRef.Name,
		Namespace: issuer.Namespace,
	}

	if err := r.Get(ctx, secretName, secret); err != nil {
		return nil, fmt.Errorf("failed to get API key secret: %v", err)
	}

	apiKey, ok := secret.Data[issuer.Spec.APIKeySecretRef.Key]
	if !ok {
		return nil, fmt.Errorf("API key not found in secret")
	}

	// Create ZeroSSL client
	return r.clientFactory(string(apiKey)), nil
}

// createNewCertificate handles the creation of a new certificate
func (r *CertificateRequestReconciler) createNewCertificate(
	ctx context.Context,
	cr *cmapi.CertificateRequest,
	issuer *zerosslv1alpha1.Issuer,
	zerosslClient ZeroSSLClient,
	domains []string,
) (ctrl.Result, error) {
	// Determine if we need to use DNS validation
	useDNS := false
	for _, domain := range domains {
		if solver := findSolverForDomain(issuer, domain); solver != nil && solver.DNS01 != nil {
			useDNS = true
			break
		}
	}

	// Create certificate request
	certReq := &zerossl.CertificateRequest{
		Domains:       domains,
		ValidityDays:  issuer.Spec.ValidityDays,
		CSR:           string(cr.Spec.Request),
		StrictDomains: issuer.Spec.StrictDomains,
	}

	// Set validation method if using DNS
	if useDNS {
		certReq.ValidationMethod = zerossl.ValidationMethodDNS
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
	certID := certResp.ID

	// Update the CertificateRequest with the annotation
	if err := r.Update(ctx, cr); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update CertificateRequest annotations: %v", err)
	}

	// If using DNS validation, get validation data and return to wait for DNS records to be created
	if useDNS {
		return r.handleDNSValidation(ctx, cr, zerosslClient, certID)
	}

	return ctrl.Result{}, nil
}

// handleDNSValidation processes DNS validation for a certificate
func (r *CertificateRequestReconciler) handleDNSValidation(
	ctx context.Context,
	cr *cmapi.CertificateRequest,
	zerosslClient ZeroSSLClient,
	certID string,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Get certificate information to extract validation requirements
	certInfo, err := zerosslClient.GetCertificate(certID)
	if err != nil {
		setFailureCondition(cr, "ValidationDataFailed", fmt.Sprintf("Failed to get certificate info: %v", err))
		if err := r.Status().Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
		}
		return ctrl.Result{}, nil
	}

	// Log validation records for DNS solver to create
	logger.Info("DNS validation required", "certificate", certID)
	if certInfo.Validation.OtherMethods != nil {
		for domain, validationDetails := range certInfo.Validation.OtherMethods {
			cnameSource := validationDetails.CNAMEValidationP1
			cnameTarget := validationDetails.CNAMEValidationP2

			if cnameSource != "" && cnameTarget != "" {
				logger.Info("CNAME validation record",
					"domain", domain,
					"cnameSource", cnameSource,
					"cnameTarget", cnameTarget)
			}
		}
	}

	// DNS records need to be created externally, so we'll requeue for later
	return ctrl.Result{Requeue: true, RequeueAfter: 60 * time.Second}, nil
}

// handleExistingCertificate processes a certificate that has already been created
func (r *CertificateRequestReconciler) handleExistingCertificate(
	ctx context.Context,
	cr *cmapi.CertificateRequest,
	issuer *zerosslv1alpha1.Issuer,
	zerosslClient ZeroSSLClient,
	domains []string,
	certID string,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Get certificate status first
	certInfo, err := zerosslClient.GetCertificate(certID)
	if err != nil {
		logger.Error(err, "Failed to get certificate status", "certificate", certID)
		setFailureCondition(cr, "CertificateStatusCheckFailed", fmt.Sprintf("Failed to check certificate status: %v", err))
		if err := r.Status().Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
		}
		return ctrl.Result{}, nil
	}

	logger.Info("Certificate status check", "certificate", certID, "status", certInfo.Status)

	// For DNS validation certificates, handle challenge resource
	useDNS := hasDNSValidator(issuer, domains)
	if useDNS && certInfo.Status != StatusIssued {
		return r.handleChallengeResource(ctx, cr, issuer, zerosslClient, certID)
	}

	// If certificate is issued or using HTTP validation, download it
	if certInfo.Status == StatusIssued {
		return r.downloadAndFinalizeCertificate(ctx, cr, zerosslClient, certID)
	}

	// If not issued and not using DNS validation, just wait
	return ctrl.Result{Requeue: true, RequeueAfter: 30 * time.Second}, nil
}

// handleChallengeResource manages the Challenge resource for DNS validation
func (r *CertificateRequestReconciler) handleChallengeResource(
	ctx context.Context,
	cr *cmapi.CertificateRequest,
	issuer *zerosslv1alpha1.Issuer,
	zerosslClient ZeroSSLClient,
	certID string,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Check if a Challenge already exists for this certificate
	challengeName := fmt.Sprintf("%s-challenge", cr.Name)
	challenge := &zerosslv1alpha1.Challenge{}
	err := r.Get(ctx, client.ObjectKey{Namespace: cr.Namespace, Name: challengeName}, challenge)

	// If challenge doesn't exist, create it
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Creating new challenge resource", "name", challengeName)

			// Get certificate information first to extract the CNAME validation data
			certInfo, err := zerosslClient.GetCertificate(certID)
			if err != nil {
				setFailureCondition(cr, "ValidationDataFailed", fmt.Sprintf("Failed to get certificate info: %v", err))
				if err := r.Status().Update(ctx, cr); err != nil {
					return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
				}
				return ctrl.Result{}, nil
			}

			// Get domain to solver mapping for Route53 configuration
			domainToSolver := make(map[string]*zerosslv1alpha1.ACMESolver)
			for _, domain := range getDomains(certInfo) {
				if solver := findSolverForDomain(issuer, domain); solver != nil && solver.DNS01 != nil {
					domainToSolver[domain] = solver
				}
			}

			// Create validation records from CNAME data
			validationRecords := []zerosslv1alpha1.ValidationRecord{}

			// Extract CNAME validation data from certificate info
			for domain, validationDetails := range certInfo.Validation.OtherMethods {
				// Skip domains that don't have Route53 solver configured
				if _, ok := domainToSolver[domain]; !ok {
					continue
				}

				cnameSource := validationDetails.CNAMEValidationP1
				cnameTarget := validationDetails.CNAMEValidationP2

				if cnameSource != "" && cnameTarget != "" {
					record := zerosslv1alpha1.ValidationRecord{
						Domain:     domain,
						CNAMEName:  cnameSource,
						CNAMEValue: cnameTarget,
					}
					validationRecords = append(validationRecords, record)

					logger.Info("Found CNAME validation record",
						"domain", domain,
						"cnameSource", cnameSource,
						"cnameTarget", cnameTarget)
				}
			}

			if len(validationRecords) == 0 {
				logger.Error(nil, "No validation records found in certificate info")
				setFailureCondition(cr, "ValidationDataMissing", "No validation records found in certificate response")
				if err := r.Status().Update(ctx, cr); err != nil {
					return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
				}
				return ctrl.Result{}, nil
			}

			// Create the Challenge resource
			newChallenge := &zerosslv1alpha1.Challenge{
				ObjectMeta: metav1.ObjectMeta{
					Name:      challengeName,
					Namespace: cr.Namespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: cmapi.SchemeGroupVersion.String(),
							Kind:       "CertificateRequest",
							Name:       cr.Name,
							UID:        cr.UID,
							Controller: ptr.To(true),
						},
					},
				},
				Spec: zerosslv1alpha1.ChallengeSpec{
					CertificateRequestRef: cr.Name,
					CertificateID:         certID,
					ValidationMethod:      "DNS",
					ValidationRecords:     validationRecords,
				},
			}

			// Create the Challenge in the cluster
			if err := r.Create(ctx, newChallenge); err != nil {
				setFailureCondition(cr, "ChallengeCreationFailed", fmt.Sprintf("Failed to create Challenge: %v", err))
				if err := r.Status().Update(ctx, cr); err != nil {
					return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
				}
				return ctrl.Result{}, nil
			}

			// Wait for Challenge to be processed
			return ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second}, nil
		}

		// Handle other errors
		setFailureCondition(cr, "ChallengeCheckFailed", fmt.Sprintf("Failed to check Challenge: %v", err))
		if err := r.Status().Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
		}
		return ctrl.Result{}, nil
	}

	// Challenge exists, check its status
	isReady := false
	for _, condition := range challenge.Status.Conditions {
		if condition.Type == "Ready" {
			if condition.Status == metav1.ConditionTrue {
				isReady = true
				break
			}
		}
	}

	if isReady {
		// Challenge is ready, check certificate status
		certInfo, err := zerosslClient.GetCertificate(certID)
		if err != nil {
			setFailureCondition(cr, "CertificateStatusCheckFailed", fmt.Sprintf("Failed to check certificate status: %v", err))
			if err := r.Status().Update(ctx, cr); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
			}
			return ctrl.Result{}, nil
		}

		if certInfo.Status == StatusIssued {
			return r.downloadAndFinalizeCertificate(ctx, cr, zerosslClient, certID)
		}

		// Certificate still not issued, wait
		logger.Info("Certificate validation successful but not issued yet", "certificate", certID, "status", certInfo.Status)
		return ctrl.Result{Requeue: true, RequeueAfter: 30 * time.Second}, nil
	}

	// Challenge is still processing, wait
	logger.Info("Challenge is still processing", "challenge", challengeName)
	return ctrl.Result{Requeue: true, RequeueAfter: 30 * time.Second}, nil
}

// downloadAndFinalizeCertificate downloads a certificate and updates the CertificateRequest status
func (r *CertificateRequestReconciler) downloadAndFinalizeCertificate(
	ctx context.Context,
	cr *cmapi.CertificateRequest,
	zerosslClient ZeroSSLClient,
	certID string,
) (ctrl.Result, error) {
	// Download the certificate
	downloadResp, err := zerosslClient.DownloadCertificate(certID)
	if err != nil {
		setFailureCondition(cr, "CertificateDownloadFailed", fmt.Sprintf("Failed to download certificate: %v", err))
		if err := r.Status().Update(ctx, cr); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %v", err)
		}
		return ctrl.Result{}, nil
	}

	// Update the CertificateRequest status with the certificate and CA bundle
	// Format certificate chain as leaf + intermediate
	certificateChain := downloadResp.Certificate
	if downloadResp.CACertificate != "" {
		certificateChain = certificateChain + "\n" + downloadResp.CACertificate
	}
	cr.Status.Certificate = []byte(certificateChain)

	// Set the Ready condition
	setReadyCondition(cr, "Issued", "Certificate has been issued successfully")
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

	// Check if there's already a Ready condition and update it
	for i, condition := range cr.Status.Conditions {
		if condition.Type == ConditionReady {
			cr.Status.Conditions[i] = cmapi.CertificateRequestCondition{
				Type:               ConditionReady,
				Status:             cmmeta.ConditionFalse,
				Reason:             reason,
				Message:            message,
				LastTransitionTime: &now,
			}
			return
		}
	}

	// If no Ready condition exists, append a new one
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

	// Check if there's already a Ready condition and update it
	for i, condition := range cr.Status.Conditions {
		if condition.Type == ConditionReady {
			cr.Status.Conditions[i] = cmapi.CertificateRequestCondition{
				Type:               ConditionReady,
				Status:             cmmeta.ConditionTrue,
				Reason:             reason,
				Message:            message,
				LastTransitionTime: &now,
			}
			return
		}
	}

	// If no Ready condition exists, append a new one
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

// Helper functions to support DNS validation

// findSolverForDomain finds the appropriate solver for a given domain
func findSolverForDomain(issuer *zerosslv1alpha1.Issuer, domain string) *zerosslv1alpha1.ACMESolver {
	if len(issuer.Spec.Solvers) == 0 {
		return nil
	}

	var matchingSolver *zerosslv1alpha1.ACMESolver

	// First pass: look for exact DNS name matches
	for i := range issuer.Spec.Solvers {
		solver := &issuer.Spec.Solvers[i]
		if solver.Selector == nil {
			// This solver has no selectors, so it's a catch-all
			// We'll use this one if no others match
			if matchingSolver == nil {
				matchingSolver = solver
			}
			continue
		}

		if containsDomain(solver.Selector.DNSNames, domain) {
			return solver
		}
	}

	// Second pass: look for DNS zone matches
	for i := range issuer.Spec.Solvers {
		solver := &issuer.Spec.Solvers[i]
		if solver.Selector == nil {
			continue
		}

		if matchesDomainInZones(solver.Selector.DNSZones, domain) {
			return solver
		}
	}

	// Return the catch-all solver if we found one
	return matchingSolver
}

// containsDomain checks if the domain list contains the specified domain
func containsDomain(domains []string, domain string) bool {
	for _, d := range domains {
		if d == domain {
			return true
		}
	}
	return false
}

// matchesDomainInZones checks if the domain is in any of the DNS zones
func matchesDomainInZones(zones []string, domain string) bool {
	for _, zone := range zones {
		if strings.HasSuffix(domain, "."+zone) || domain == zone {
			return true
		}
	}
	return false
}

// hasDNSValidator checks if any of the domains requires DNS validation
func hasDNSValidator(issuer *zerosslv1alpha1.Issuer, domains []string) bool {
	for _, domain := range domains {
		solver := findSolverForDomain(issuer, domain)
		if solver != nil && solver.DNS01 != nil {
			return true
		}
	}
	return false
}

// getDomains extracts domain names from certificate validation info
func getDomains(certInfo *zerossl.CertificateResponse) []string {
	domains := []string{}

	// Check email validation domains
	if certInfo.Validation.EmailValidation != nil {
		for domain := range certInfo.Validation.EmailValidation {
			domains = append(domains, domain)
		}
	}

	// Check other methods domains
	if certInfo.Validation.OtherMethods != nil {
		for domain := range certInfo.Validation.OtherMethods {
			domains = append(domains, domain)
		}
	}

	return domains
}
