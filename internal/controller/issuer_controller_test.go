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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
)

var _ = Describe("Issuer Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}

		BeforeEach(func() {
			// Delete any existing test resource
			existing := &zerosslv1alpha1.Issuer{}
			err := k8sClient.Get(ctx, typeNamespacedName, existing)
			if err == nil {
				Expect(k8sClient.Delete(ctx, existing)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &zerosslv1alpha1.Issuer{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				By("Cleanup the specific resource instance Issuer")
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		It("should fail reconciliation when apiKey is missing", func() {
			By("Creating an issuer without an API key")
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
			Expect(err.Error()).To(ContainSubstring("apiKey is required"))

			// Check that the status condition was updated
			updatedIssuer := &zerosslv1alpha1.Issuer{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedIssuer)).To(Succeed())
			condition := meta.FindStatusCondition(updatedIssuer.Status.Conditions, "Ready")
			Expect(condition).NotTo(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionFalse))
			Expect(condition.Reason).To(Equal("ValidationFailed"))
		})

		It("should fail reconciliation when validityDays is invalid", func() {
			By("Creating an issuer with invalid validityDays")
			issuer := &zerosslv1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: zerosslv1alpha1.IssuerSpec{
					APIKey:       "test-api-key",
					ValidityDays: 400, // Invalid: more than 365
				},
			}
			err := k8sClient.Create(ctx, issuer)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.validityDays: Invalid value: 400: spec.validityDays in body should be less than or equal to 365"))
		})

		It("should successfully reconcile a valid issuer", func() {
			By("Creating a valid issuer")
			issuer := &zerosslv1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: zerosslv1alpha1.IssuerSpec{
					APIKey:       "test-api-key",
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
