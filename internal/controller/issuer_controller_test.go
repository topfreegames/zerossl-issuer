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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
	"github.com/topfreegames/zerossl-issuer/internal/zerossl"
)

var _ = Describe("Issuer Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"
		const secretName = "test-secret"
		const apiKeyValue = "test-api-key"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}

		secretNamespacedName := types.NamespacedName{
			Name:      secretName,
			Namespace: "default",
		}

		BeforeEach(func() {
			// Delete any existing test resources
			existing := &zerosslv1alpha1.Issuer{}
			err := k8sClient.Get(ctx, typeNamespacedName, existing)
			if err == nil {
				Expect(k8sClient.Delete(ctx, existing)).To(Succeed())
			}

			existingSecret := &corev1.Secret{}
			err = k8sClient.Get(ctx, secretNamespacedName, existingSecret)
			if err == nil {
				Expect(k8sClient.Delete(ctx, existingSecret)).To(Succeed())
			}
		})

		AfterEach(func() {
			// Cleanup issuer
			resource := &zerosslv1alpha1.Issuer{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}

			// Cleanup secret
			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, secretNamespacedName, secret)
			if err == nil {
				Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			}
		})

		It("should fail reconciliation when secret reference is missing", func() {
			By("Creating an issuer without a secret reference")
			issuer := &zerosslv1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: zerosslv1alpha1.IssuerSpec{
					ValidityDays: 90,
				},
			}
			Expect(k8sClient.Create(ctx, issuer)).To(Succeed())

			By("Reconciling the created resource")
			reconciler := &IssuerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("resource name may not be empty"))

			// Check that the status condition was updated
			updatedIssuer := &zerosslv1alpha1.Issuer{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedIssuer)).To(Succeed())
			condition := meta.FindStatusCondition(updatedIssuer.Status.Conditions, "Ready")
			Expect(condition).NotTo(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionFalse))
			Expect(condition.Reason).To(Equal("ValidationFailed"))
		})

		It("should fail reconciliation when secret key is missing", func() {
			By("Creating a secret without the required key")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: "default",
				},
				Data: map[string][]byte{
					"wrong-key": []byte(apiKeyValue),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating an issuer referencing the secret")
			issuer := &zerosslv1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: zerosslv1alpha1.IssuerSpec{
					APIKeySecretRef: corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "api-key",
					},
					ValidityDays: 90,
				},
			}
			Expect(k8sClient.Create(ctx, issuer)).To(Succeed())

			By("Reconciling the created resource")
			reconciler := &IssuerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("key api-key not found in secret"))
		})

		It("should fail reconciliation when validityDays is invalid", func() {
			By("Creating a secret with the API key")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: "default",
				},
				Data: map[string][]byte{
					"api-key": []byte(apiKeyValue),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating an issuer with invalid validityDays")
			issuer := &zerosslv1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: zerosslv1alpha1.IssuerSpec{
					APIKeySecretRef: corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "api-key",
					},
					ValidityDays: 400, // Invalid: more than 365
				},
			}
			err := k8sClient.Create(ctx, issuer)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.validityDays: Invalid value: 400: spec.validityDays in body should be less than or equal to 365"))
		})

		It("should successfully reconcile a valid issuer", func() {
			// Set up the mock client and restore factory afterwards
			mockClient := &MockZeroSSLClient{
				ValidateAPIKeyErr: nil, // Return success for API key validation
			}
			originalFactory := zerossl.SetClientFactory(func(apiKey string) zerossl.ZeroSSLClientInterface {
				return mockClient
			})
			defer zerossl.SetClientFactory(originalFactory)

			By("Creating a secret with the API key")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: "default",
				},
				Data: map[string][]byte{
					"api-key": []byte(apiKeyValue),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating a valid issuer")
			issuer := &zerosslv1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: zerosslv1alpha1.IssuerSpec{
					APIKeySecretRef: corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "api-key",
					},
					ValidityDays: 90,
				},
			}
			Expect(k8sClient.Create(ctx, issuer)).To(Succeed())

			By("Reconciling the created resource")
			reconciler := &IssuerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Check that the status condition was updated
			updatedIssuer := &zerosslv1alpha1.Issuer{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedIssuer)).To(Succeed())
			condition := meta.FindStatusCondition(updatedIssuer.Status.Conditions, "Ready")
			Expect(condition).NotTo(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionTrue))
			Expect(condition.Reason).To(Equal("Configured"))
		})
	})
})
