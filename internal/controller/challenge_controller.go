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
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
	"github.com/topfreegames/zerossl-issuer/internal/aws"
	"github.com/topfreegames/zerossl-issuer/internal/zerossl"
)

const (
	// StatusIssued represents the "issued" certificate status from ZeroSSL
	StatusIssued = "issued"
	// ChallengeFinalizer is the name of the finalizer used to clean up Route53 DNS records
	ChallengeFinalizer = "zerossl.cert-manager.io/dns-cleanup"
)

// ChallengeReconciler reconciles a Challenge object
type ChallengeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// clientFactory is a function that creates a new ZeroSSL client
	clientFactory func(string) ZeroSSLClient
}

// NewChallengeReconciler creates a new ChallengeReconciler
func NewChallengeReconciler(k8sClient client.Client, scheme *runtime.Scheme) *ChallengeReconciler {
	return &ChallengeReconciler{
		Client: k8sClient,
		Scheme: scheme,
		clientFactory: func(apiKey string) ZeroSSLClient {
			return zerossl.NewClient(apiKey)
		},
	}
}

// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=challenges,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=challenges/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=challenges/finalizers,verbs=update
// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=issuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

func (r *ChallengeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling Challenge", "namespace", req.Namespace, "name", req.Name)

	// Get the Challenge
	challenge := &zerosslv1alpha1.Challenge{}
	if err := r.Get(ctx, req.NamespacedName, challenge); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get Challenge: %v", err)
	}

	// Handle finalizer
	if challenge.DeletionTimestamp.IsZero() {
		// The object is not being deleted, so if it does not have our finalizer,
		// then add the finalizer and update the object.
		if !containsString(challenge.GetFinalizers(), ChallengeFinalizer) && challenge.Spec.ValidationMethod == "DNS" {
			challenge.SetFinalizers(append(challenge.GetFinalizers(), ChallengeFinalizer))
			if err := r.Update(ctx, challenge); err != nil {
				return ctrl.Result{}, err
			}
			// Return immediately so that the updated object is processed in the next reconcile
			return ctrl.Result{}, nil
		}
	} else {
		// The object is being deleted
		if containsString(challenge.GetFinalizers(), ChallengeFinalizer) {
			// Handle the cleanup of DNS records before allowing the challenge to be deleted
			if err := r.cleanupDNSRecords(ctx, challenge); err != nil {
				logger.Error(err, "Failed to clean up DNS records")
				return ctrl.Result{}, err
			}

			// Remove our finalizer from the list and update it
			challenge.SetFinalizers(removeString(challenge.GetFinalizers(), ChallengeFinalizer))
			if err := r.Update(ctx, challenge); err != nil {
				return ctrl.Result{}, err
			}
		}
		// Stop reconciliation as the item is being deleted
		return ctrl.Result{}, nil
	}

	// Check if challenge is already completed
	if isChallengeReady(challenge) {
		logger.Info("Challenge is already ready", "namespace", req.Namespace, "name", req.Name)
		return ctrl.Result{}, nil
	}

	// Get the issuer for this certificate
	issuer, err := r.getIssuerForChallenge(ctx, challenge)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Get ZeroSSL client
	zerosslClient, err := r.getZeroSSLClient(ctx, issuer)
	if err != nil {
		return r.markChallengeFailed(ctx, challenge, "ClientError", fmt.Sprintf("Failed to get ZeroSSL client: %v", err))
	}

	// Verify DNS validation
	if challenge.Spec.ValidationMethod == "DNS" {
		return r.handleDNSChallenge(ctx, challenge, zerosslClient)
	}

	return ctrl.Result{}, fmt.Errorf("unsupported validation method: %s", challenge.Spec.ValidationMethod)
}

// handleDNSChallenge handles DNS validation challenges
func (r *ChallengeReconciler) handleDNSChallenge(ctx context.Context, challenge *zerosslv1alpha1.Challenge, zerosslClient ZeroSSLClient) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Processing DNS validation", "certificateID", challenge.Spec.CertificateID)

	// First, get the issuer to access Route53 configuration
	issuer, err := r.getIssuerForChallenge(ctx, challenge)
	if err != nil {
		return r.markChallengeFailed(ctx, challenge, "IssuerRetrievalFailed", fmt.Sprintf("Failed to get issuer: %v", err))
	}

	// Check for Route53 configuration
	// For each validation record, find appropriate solver
	for _, record := range challenge.Spec.ValidationRecords {
		domain := record.Domain
		solver := findSolverForDomain(issuer, domain)

		if solver == nil || solver.DNS01 == nil || solver.DNS01.Route53 == nil {
			logger.Info("No Route53 solver found for domain", "domain", domain)
			continue
		}

		route53Config := solver.DNS01.Route53

		// Apply CNAME record
		err := r.applyRoute53CNAMERecord(ctx, route53Config, record.CNAMEName, record.CNAMEValue, challenge.Namespace)
		if err != nil {
			logger.Error(err, "Failed to apply Route53 CNAME record",
				"domain", domain,
				"source", record.CNAMEName,
				"target", record.CNAMEValue)
			return r.markChallengeFailed(ctx, challenge, "Route53Failed", fmt.Sprintf("Failed to apply Route53 CNAME record: %v", err))
		}

		logger.Info("Successfully applied Route53 CNAME record",
			"domain", domain,
			"source", record.CNAMEName,
			"target", record.CNAMEValue)
	}

	// Give DNS time to propagate
	logger.Info("DNS records created, waiting for propagation")

	// After creating records, verify DNS validation
	err = zerosslClient.VerifyDNSValidation(challenge.Spec.CertificateID)
	if err != nil {
		logger.Info("DNS validation error", "error", err.Error())
		return r.markChallengeFailed(ctx, challenge, "DNSValidationFailed", fmt.Sprintf("Failed to verify DNS validation: %v", err))
	}

	// Check certificate status
	certInfo, err := zerosslClient.GetCertificate(challenge.Spec.CertificateID)
	if err != nil {
		return r.markChallengeFailed(ctx, challenge, "CertificateCheckFailed", fmt.Sprintf("Failed to check certificate status: %v", err))
	}

	if certInfo.Status == StatusIssued {
		return r.markChallengeSucceeded(ctx, challenge, "Validated", "DNS validation successful, certificate issued")
	}

	// Requeue for status check
	logger.Info("Certificate not issued yet, requeuing", "status", certInfo.Status)
	return r.markChallengeProcessing(ctx, challenge, "Waiting", "Certificate validation successful, waiting for issuance")
}

// applyRoute53CNAMERecord applies a CNAME record to Route53
func (r *ChallengeReconciler) applyRoute53CNAMERecord(ctx context.Context, route53Config *zerosslv1alpha1.ACMEChallengeSolverDNS01Route53, source, target string, namespace string) error {
	logger := log.FromContext(ctx)

	// Create Route53 client
	r53Client, err := aws.NewRoute53Client(ctx, r.Client, route53Config, namespace)
	if err != nil {
		logger.Error(err, "Failed to create Route53 client",
			"region", route53Config.Region,
			"accessKeyID", route53Config.AccessKeyID)
		return err
	}

	// Update CNAME record
	err = r53Client.UpsertCNAMERecord(ctx, route53Config.HostedZoneID, source, target)
	if err != nil {
		logger.Error(err, "Failed to create Route53 CNAME record",
			"hostedZone", route53Config.HostedZoneID,
			"source", source,
			"target", target)
		return err
	}

	logger.Info("Successfully created Route53 CNAME record",
		"hostedZone", route53Config.HostedZoneID,
		"source", source,
		"target", target)

	return nil
}

// getIssuerForChallenge retrieves the issuer for a challenge
func (r *ChallengeReconciler) getIssuerForChallenge(ctx context.Context, challenge *zerosslv1alpha1.Challenge) (*zerosslv1alpha1.Issuer, error) {
	// Get the CertificateRequest first to find out which issuer was used
	// For simplicity, we assume the CertificateRequest name is in the CertificateRequestRef field
	crName := challenge.Spec.CertificateRequestRef

	// This is a simple lookup that assumes the CertificateRequest is in the same namespace
	// In a real implementation, you might want to store the full reference including namespace
	cr := &cmapi.CertificateRequest{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: challenge.Namespace, Name: crName}, cr); err != nil {
		return nil, fmt.Errorf("failed to get CertificateRequest: %v", err)
	}

	// Get the issuer reference kind (default to "Issuer" if not specified)
	kind := cr.Spec.IssuerRef.Kind
	if kind == "" {
		kind = "Issuer"
	}

	// Check if the reference is to a ClusterIssuer
	if strings.EqualFold(kind, "ClusterIssuer") {
		clusterIssuer := &zerosslv1alpha1.ClusterIssuer{}
		clusterIssuerName := types.NamespacedName{
			Name: cr.Spec.IssuerRef.Name,
			// ClusterIssuers are not namespaced
		}

		if err := r.Get(ctx, clusterIssuerName, clusterIssuer); err != nil {
			return nil, fmt.Errorf("failed to get ClusterIssuer: %v", err)
		}

		// Convert ClusterIssuer spec to Issuer for compatibility
		issuer := &zerosslv1alpha1.Issuer{
			ObjectMeta: metav1.ObjectMeta{
				Name: clusterIssuer.Name,
				// Intentionally leave namespace empty to indicate this is from a ClusterIssuer
			},
			Spec: zerosslv1alpha1.IssuerSpec{
				APIKeySecretRef: clusterIssuer.Spec.APIKeySecretRef,
				ValidityDays:    clusterIssuer.Spec.ValidityDays,
				StrictDomains:   clusterIssuer.Spec.StrictDomains,
				Solvers:         clusterIssuer.Spec.Solvers,
			},
			Status: zerosslv1alpha1.IssuerStatus{
				Conditions: clusterIssuer.Status.Conditions,
			},
		}

		return issuer, nil
	}

	// Now get the issuer
	issuer := &zerosslv1alpha1.Issuer{}
	issuerName := types.NamespacedName{
		Name:      cr.Spec.IssuerRef.Name,
		Namespace: challenge.Namespace,
	}

	if err := r.Get(ctx, issuerName, issuer); err != nil {
		return nil, fmt.Errorf("failed to get issuer: %v", err)
	}

	return issuer, nil
}

// getZeroSSLClient creates a ZeroSSL client from the issuer configuration
func (r *ChallengeReconciler) getZeroSSLClient(ctx context.Context, issuer *zerosslv1alpha1.Issuer) (ZeroSSLClient, error) {
	// Determine if this was originally a ClusterIssuer by checking if the issuer doesn't have a namespace
	// ClusterIssuers have secrets in the cert-manager namespace
	secretNamespace := issuer.Namespace
	if secretNamespace == "" {
		// This is from a ClusterIssuer, use cert-manager namespace
		secretNamespace = "cert-manager"
	}

	// Get the API key from the secret
	secret := &corev1.Secret{}
	secretName := types.NamespacedName{
		Name:      issuer.Spec.APIKeySecretRef.Name,
		Namespace: secretNamespace,
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

// markChallengeProcessing updates the Challenge to indicate that it's still processing
func (r *ChallengeReconciler) markChallengeProcessing(ctx context.Context, challenge *zerosslv1alpha1.Challenge, reason, message string) (ctrl.Result, error) {
	setChallengeCondition(challenge, ConditionReady, metav1.ConditionFalse, reason, message)
	if err := r.Status().Update(ctx, challenge); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update Challenge status: %v", err)
	}
	return ctrl.Result{Requeue: true, RequeueAfter: 30 * time.Second}, nil
}

// markChallengeFailed updates the Challenge to indicate that it has failed
func (r *ChallengeReconciler) markChallengeFailed(ctx context.Context, challenge *zerosslv1alpha1.Challenge, reason, message string) (ctrl.Result, error) {
	setChallengeCondition(challenge, ConditionReady, metav1.ConditionFalse, reason, message)
	if err := r.Status().Update(ctx, challenge); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update Challenge status: %v", err)
	}
	return ctrl.Result{}, nil
}

// markChallengeSucceeded updates the Challenge to indicate that it has succeeded
func (r *ChallengeReconciler) markChallengeSucceeded(ctx context.Context, challenge *zerosslv1alpha1.Challenge, reason, message string) (ctrl.Result, error) {
	setChallengeCondition(challenge, ConditionReady, metav1.ConditionTrue, reason, message)
	if err := r.Status().Update(ctx, challenge); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update Challenge status: %v", err)
	}
	return ctrl.Result{}, nil
}

// setChallengeCondition sets a condition on the Challenge
func setChallengeCondition(challenge *zerosslv1alpha1.Challenge, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()

	// Check if there's already a condition with this type and update it
	for i, condition := range challenge.Status.Conditions {
		if condition.Type == condType {
			challenge.Status.Conditions[i] = zerosslv1alpha1.ChallengeCondition{
				Type:               condType,
				Status:             status,
				Reason:             reason,
				Message:            message,
				LastTransitionTime: &now,
			}
			return
		}
	}

	// If no condition with this type exists, append a new one
	challenge.Status.Conditions = append(challenge.Status.Conditions, zerosslv1alpha1.ChallengeCondition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: &now,
	})
}

// isChallengeReady checks if the Challenge is ready
func isChallengeReady(challenge *zerosslv1alpha1.Challenge) bool {
	for _, condition := range challenge.Status.Conditions {
		if condition.Type == ConditionReady && condition.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// Helper functions for finalizers
// containsString checks if a string is in a slice
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// removeString removes a string from a slice
func removeString(slice []string, s string) []string {
	var result []string
	for _, item := range slice {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}

// cleanupDNSRecords removes all DNS records created for this challenge
func (r *ChallengeReconciler) cleanupDNSRecords(ctx context.Context, challenge *zerosslv1alpha1.Challenge) error {
	logger := log.FromContext(ctx)
	logger.Info("Cleaning up DNS records for challenge", "namespace", challenge.Namespace, "name", challenge.Name)

	// First, get the issuer to access Route53 configuration
	issuer, err := r.getIssuerForChallenge(ctx, challenge)
	if err != nil {
		return fmt.Errorf("failed to get issuer during cleanup: %v", err)
	}

	// Delete all validation records
	for _, record := range challenge.Spec.ValidationRecords {
		domain := record.Domain
		solver := findSolverForDomain(issuer, domain)

		if solver == nil || solver.DNS01 == nil || solver.DNS01.Route53 == nil {
			logger.Info("No Route53 solver found for domain during cleanup", "domain", domain)
			continue
		}

		route53Config := solver.DNS01.Route53

		// Delete CNAME record
		err := r.deleteRoute53CNAMERecord(ctx, route53Config, record.CNAMEName, record.CNAMEValue, challenge.Namespace)
		if err != nil {
			logger.Error(err, "Failed to delete Route53 CNAME record",
				"domain", domain,
				"source", record.CNAMEName,
				"target", record.CNAMEValue)
			// Continue with other records even if one fails
			continue
		}

		logger.Info("Successfully deleted Route53 CNAME record",
			"domain", domain,
			"source", record.CNAMEName,
			"target", record.CNAMEValue)
	}

	return nil
}

// deleteRoute53CNAMERecord deletes a CNAME record from Route53
func (r *ChallengeReconciler) deleteRoute53CNAMERecord(ctx context.Context, route53Config *zerosslv1alpha1.ACMEChallengeSolverDNS01Route53, source, target string, namespace string) error {
	logger := log.FromContext(ctx)

	// Create Route53 client
	r53Client, err := aws.NewRoute53Client(ctx, r.Client, route53Config, namespace)
	if err != nil {
		logger.Error(err, "Failed to create Route53 client during cleanup",
			"region", route53Config.Region,
			"accessKeyID", route53Config.AccessKeyID)
		return err
	}

	// Delete CNAME record
	err = r53Client.DeleteCNAMERecord(ctx, route53Config.HostedZoneID, source, target)
	if err != nil {
		logger.Error(err, "Failed to delete Route53 CNAME record",
			"hostedZone", route53Config.HostedZoneID,
			"source", source,
			"target", target)
		return err
	}

	logger.Info("Successfully deleted Route53 CNAME record",
		"hostedZone", route53Config.HostedZoneID,
		"source", source,
		"target", target)

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ChallengeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zerosslv1alpha1.Challenge{}).
		Named("challenge").
		Complete(r)
}
