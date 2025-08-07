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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"

	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
	"github.com/topfreegames/zerossl-issuer/internal/zerossl"
)

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// recorder is used to record events
	recorder record.EventRecorder
	// maxConcurrentReconciles is the maximum number of concurrent reconciles
	maxConcurrentReconciles int
}

// NewIssuerReconciler creates a new IssuerReconciler
func NewIssuerReconciler(k8sClient client.Client, scheme *runtime.Scheme, recorder record.EventRecorder, maxConcurrentReconciles int) *IssuerReconciler {
	return &IssuerReconciler{
		Client:                  k8sClient,
		Scheme:                  scheme,
		recorder:                recorder,
		maxConcurrentReconciles: maxConcurrentReconciles,
	}
}

// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=issuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=issuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=issuers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile handles the reconciliation loop for ZeroSSL issuers
func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling ZeroSSL issuer", "namespace", req.Namespace, "name", req.Name)

	// Get the Issuer resource
	issuer := &zerosslv1alpha1.Issuer{}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Issuer resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Issuer")
		return ctrl.Result{}, fmt.Errorf("failed to get issuer: %v", err)
	}

	// Initialize the status if it's nil
	if issuer.Status.Conditions == nil {
		logger.Info("Initializing issuer status conditions")
		issuer.Status.Conditions = []metav1.Condition{}
	}

	// Validate the issuer configuration
	if err := r.validateIssuer(ctx, issuer); err != nil {
		logger.Error(err, "Failed to validate issuer configuration")
		// Record a warning event
		r.recorder.Event(issuer, corev1.EventTypeWarning, "ValidationFailed", fmt.Sprintf("Failed to validate issuer configuration: %v", err))

		// Update the Ready condition
		meta.SetStatusCondition(&issuer.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "ValidationFailed",
			Message:            err.Error(),
			LastTransitionTime: metav1.Now(),
		})

		if err := r.Status().Update(ctx, issuer); err != nil {
			logger.Error(err, "Failed to update issuer status")
			return ctrl.Result{}, fmt.Errorf("failed to update issuer status: %v", err)
		}

		return ctrl.Result{}, err
	}

	// Update the Ready condition to true
	logger.Info("Issuer configuration validated successfully")
	// Record a success event
	r.recorder.Event(issuer, corev1.EventTypeNormal, "IssuerReady", "Issuer configuration validated and ready for use")

	meta.SetStatusCondition(&issuer.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Configured",
		Message:            "Issuer is configured correctly",
		LastTransitionTime: metav1.Now(),
	})

	if err := r.Status().Update(ctx, issuer); err != nil {
		logger.Error(err, "Failed to update issuer status")
		return ctrl.Result{}, fmt.Errorf("failed to update issuer status: %v", err)
	}

	logger.Info("Reconciliation completed successfully")
	return ctrl.Result{}, nil
}

// validateIssuer validates the issuer configuration
func (r *IssuerReconciler) validateIssuer(ctx context.Context, issuer *zerosslv1alpha1.Issuer) error {
	// Get the secret containing the API key
	secret := &corev1.Secret{}
	secretName := types.NamespacedName{
		Namespace: issuer.Namespace,
		Name:      issuer.Spec.APIKeySecretRef.Name,
	}

	if err := r.Get(ctx, secretName, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("secret %s/%s not found", secretName.Namespace, secretName.Name)
		}
		return fmt.Errorf("failed to get secret %s/%s: %v", secretName.Namespace, secretName.Name, err)
	}

	// Get the API key from the secret
	apiKey, ok := secret.Data[issuer.Spec.APIKeySecretRef.Key]
	if !ok {
		return fmt.Errorf("key %s not found in secret %s/%s", issuer.Spec.APIKeySecretRef.Key, secretName.Namespace, secretName.Name)
	}

	if len(apiKey) == 0 {
		return fmt.Errorf("apiKey in secret %s/%s is empty", secretName.Namespace, secretName.Name)
	}

	// Create ZeroSSL client and validate API key
	zerosslClient := zerossl.NewClient(string(apiKey))
	if err := zerosslClient.ValidateAPIKey(); err != nil {
		return fmt.Errorf("invalid API key: %v", err)
	}

	if issuer.Spec.ValidityDays < 1 || issuer.Spec.ValidityDays > 365 {
		return fmt.Errorf("validityDays must be between 1 and 365")
	}

	// Validate solvers if specified
	for i, solver := range issuer.Spec.Solvers {
		if err := r.validateSolver(ctx, issuer.Namespace, &solver); err != nil {
			return fmt.Errorf("invalid solver at index %d: %v", i, err)
		}
	}

	return nil
}

// validateSolver validates an individual ACME solver configuration
func (r *IssuerReconciler) validateSolver(ctx context.Context, namespace string, solver *zerosslv1alpha1.ACMESolver) error {
	// Validate the DNS01 solver if specified
	if solver.DNS01 != nil {
		if err := r.validateDNS01Solver(ctx, namespace, solver.DNS01); err != nil {
			return fmt.Errorf("invalid DNS01 solver: %v", err)
		}
	}

	// Validate that at least one solver method is configured
	if solver.DNS01 == nil {
		return fmt.Errorf("no solver method configured")
	}

	return nil
}

// validateDNS01Solver validates a DNS01 solver configuration
func (r *IssuerReconciler) validateDNS01Solver(ctx context.Context, namespace string, dns01 *zerosslv1alpha1.ACMEChallengeSolverDNS01) error {
	// Validate Route53 configuration if specified
	if dns01.Route53 != nil {
		route53 := dns01.Route53

		// Validate required fields
		if route53.HostedZoneID == "" {
			return fmt.Errorf("hostedZoneID must be specified")
		}

		if route53.Region == "" {
			return fmt.Errorf("region must be specified")
		}

		// Validate secret access key if specified
		if route53.SecretAccessKeySecretRef.Name != "" {
			secretName := types.NamespacedName{
				Namespace: namespace,
				Name:      route53.SecretAccessKeySecretRef.Name,
			}

			secret := &corev1.Secret{}
			if err := r.Get(ctx, secretName, secret); err != nil {
				if apierrors.IsNotFound(err) {
					return fmt.Errorf("secret %s/%s not found", secretName.Namespace, secretName.Name)
				}
				return fmt.Errorf("failed to get secret %s/%s: %v", secretName.Namespace, secretName.Name, err)
			}

			key := route53.SecretAccessKeySecretRef.Key
			if _, ok := secret.Data[key]; !ok {
				return fmt.Errorf("key %s not found in secret %s/%s", key, secretName.Namespace, secretName.Name)
			}
		}
	} else {
		return fmt.Errorf("no DNS01 provider configured")
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zerosslv1alpha1.Issuer{}).
		Named("issuer").
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.maxConcurrentReconciles,
		}).
		Complete(r)
}
