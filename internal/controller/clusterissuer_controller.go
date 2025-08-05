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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"

	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
	"github.com/topfreegames/zerossl-issuer/internal/zerossl"
)

// ClusterIssuerReconciler reconciles a ClusterIssuer object
type ClusterIssuerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// maxConcurrentReconciles is the maximum number of concurrent reconciles
	maxConcurrentReconciles int
}

// NewClusterIssuerReconciler creates a new ClusterIssuerReconciler
func NewClusterIssuerReconciler(k8sClient client.Client, scheme *runtime.Scheme, maxConcurrentReconciles int) *ClusterIssuerReconciler {
	return &ClusterIssuerReconciler{
		Client:                  k8sClient,
		Scheme:                  scheme,
		maxConcurrentReconciles: maxConcurrentReconciles,
	}
}

// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=clusterissuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=clusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zerossl.cert-manager.io,resources=clusterissuers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile handles the reconciliation loop for ZeroSSL cluster issuers
func (r *ClusterIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling ZeroSSL cluster issuer", "name", req.Name)

	// Get the ClusterIssuer resource
	clusterIssuer := &zerosslv1alpha1.ClusterIssuer{}
	if err := r.Get(ctx, req.NamespacedName, clusterIssuer); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("ClusterIssuer resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get ClusterIssuer")
		return ctrl.Result{}, fmt.Errorf("failed to get cluster issuer: %v", err)
	}

	// Initialize the status if it's nil
	if clusterIssuer.Status.Conditions == nil {
		logger.Info("Initializing cluster issuer status conditions")
		clusterIssuer.Status.Conditions = []metav1.Condition{}
	}

	// Validate the cluster issuer configuration
	if err := r.validateClusterIssuer(ctx, clusterIssuer); err != nil {
		logger.Error(err, "Failed to validate cluster issuer configuration")
		// Update the Ready condition
		meta.SetStatusCondition(&clusterIssuer.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "ValidationFailed",
			Message:            err.Error(),
			LastTransitionTime: metav1.Now(),
		})

		if err := r.Status().Update(ctx, clusterIssuer); err != nil {
			logger.Error(err, "Failed to update cluster issuer status")
			return ctrl.Result{}, fmt.Errorf("failed to update cluster issuer status: %v", err)
		}

		return ctrl.Result{}, err
	}

	// Update the Ready condition to true
	logger.Info("ClusterIssuer configuration validated successfully")
	meta.SetStatusCondition(&clusterIssuer.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Configured",
		Message:            "ClusterIssuer is configured correctly",
		LastTransitionTime: metav1.Now(),
	})

	if err := r.Status().Update(ctx, clusterIssuer); err != nil {
		logger.Error(err, "Failed to update cluster issuer status")
		return ctrl.Result{}, fmt.Errorf("failed to update cluster issuer status: %v", err)
	}

	logger.Info("Reconciliation completed successfully")
	return ctrl.Result{}, nil
}

// validateClusterIssuer validates the cluster issuer configuration
func (r *ClusterIssuerReconciler) validateClusterIssuer(ctx context.Context, clusterIssuer *zerosslv1alpha1.ClusterIssuer) error {
	// For ClusterIssuer, we use the "cert-manager" namespace for looking up secrets
	// This is the standard cert-manager approach for cluster-wide resources
	namespace := "cert-manager"

	// Get the secret containing the API key
	secret := &corev1.Secret{}
	secretName := types.NamespacedName{
		Namespace: namespace,
		Name:      clusterIssuer.Spec.APIKeySecretRef.Name,
	}

	if err := r.Get(ctx, secretName, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("secret %s/%s not found", secretName.Namespace, secretName.Name)
		}
		return fmt.Errorf("failed to get secret %s/%s: %v", secretName.Namespace, secretName.Name, err)
	}

	// Get the API key from the secret
	apiKey, ok := secret.Data[clusterIssuer.Spec.APIKeySecretRef.Key]
	if !ok {
		return fmt.Errorf("key %s not found in secret %s/%s", clusterIssuer.Spec.APIKeySecretRef.Key, secretName.Namespace, secretName.Name)
	}

	if len(apiKey) == 0 {
		return fmt.Errorf("apiKey in secret %s/%s is empty", secretName.Namespace, secretName.Name)
	}

	// Create ZeroSSL client and validate API key
	zerosslClient := zerossl.NewClient(string(apiKey))
	if err := zerosslClient.ValidateAPIKey(); err != nil {
		return fmt.Errorf("invalid API key: %v", err)
	}

	if clusterIssuer.Spec.ValidityDays < 1 || clusterIssuer.Spec.ValidityDays > 365 {
		return fmt.Errorf("validityDays must be between 1 and 365")
	}

	// Validate solvers if specified
	for i, solver := range clusterIssuer.Spec.Solvers {
		if err := r.validateClusterSolver(ctx, namespace, &solver); err != nil {
			return fmt.Errorf("invalid solver at index %d: %v", i, err)
		}
	}

	return nil
}

// validateClusterSolver validates an individual ACME solver configuration for ClusterIssuer
func (r *ClusterIssuerReconciler) validateClusterSolver(ctx context.Context, namespace string, solver *zerosslv1alpha1.ACMESolver) error {
	// Validate the DNS01 solver if specified
	if solver.DNS01 != nil {
		if err := r.validateClusterDNS01Solver(ctx, namespace, solver.DNS01); err != nil {
			return fmt.Errorf("invalid DNS01 solver: %v", err)
		}
	}

	// Validate that at least one solver method is configured
	if solver.DNS01 == nil {
		return fmt.Errorf("no solver method configured")
	}

	return nil
}

// validateClusterDNS01Solver validates a DNS01 solver configuration for ClusterIssuer
func (r *ClusterIssuerReconciler) validateClusterDNS01Solver(ctx context.Context, namespace string, dns01 *zerosslv1alpha1.ACMEChallengeSolverDNS01) error {
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
func (r *ClusterIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zerosslv1alpha1.ClusterIssuer{}).
		Named("clusterissuer").
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.maxConcurrentReconciles,
		}).
		Complete(r)
}
