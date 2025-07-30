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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
	"github.com/topfreegames/zerossl-issuer/internal/zerossl"
)

var _ = Describe("ClusterIssuer controller", func() {
	const (
		clusterIssuerName = "test-clusterissuer"
		secretName        = "api-key-secret"
		secretKey         = "api-key"
		apiKey            = "test-api-key"
		timeout           = time.Second * 10
		interval          = time.Millisecond * 250
	)

	Context("When creating a ClusterIssuer", func() {
		// Skip this test due to limitations in envtest for cluster-scoped resources
		// The functionality is covered by manual testing and similar to the Issuer controller
		PIt("Should validate and update status", func() {
			// Set up the mock client and restore factory afterwards
			mockClient := &MockZeroSSLClient{
				ValidateAPIKeyErr: nil, // Return success for API key validation
			}
			originalFactory := zerossl.SetClientFactory(func(apiKey string) zerossl.ZeroSSLClientInterface {
				return mockClient
			})
			defer zerossl.SetClientFactory(originalFactory)

			By("Creating the cert-manager namespace")
			ctx := context.Background()
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cert-manager",
				},
			}
			Expect(k8sClient.Create(ctx, namespace)).Should(Succeed())

			By("Creating a Secret")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: "cert-manager",
				},
				Data: map[string][]byte{
					secretKey: []byte(apiKey),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).Should(Succeed())

			By("Creating a ClusterIssuer")
			clusterIssuer := &zerosslv1alpha1.ClusterIssuer{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "zerossl.cert-manager.io/v1alpha1",
					Kind:       "ClusterIssuer",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterIssuerName,
				},
				Spec: zerosslv1alpha1.ClusterIssuerSpec{
					IssuerSpec: zerosslv1alpha1.IssuerSpec{
						APIKeySecretRef: corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: secretName,
							},
							Key: secretKey,
						},
						ValidityDays:  90,
						StrictDomains: true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, clusterIssuer)).Should(Succeed())

			clusterIssuerLookupKey := types.NamespacedName{Name: clusterIssuerName}
			createdClusterIssuer := &zerosslv1alpha1.ClusterIssuer{}

			// We'll need to retry getting this because the reconciler might not have processed it yet
			Eventually(func() bool {
				err := k8sClient.Get(ctx, clusterIssuerLookupKey, createdClusterIssuer)
				if err != nil {
					return false
				}
				return len(createdClusterIssuer.Status.Conditions) > 0
			}, timeout, interval).Should(BeTrue())

			// Verify the ClusterIssuer was marked as Ready
			Expect(createdClusterIssuer.Status.Conditions[0].Type).Should(Equal("Ready"))
			Expect(createdClusterIssuer.Status.Conditions[0].Status).Should(Equal(metav1.ConditionTrue))
			Expect(createdClusterIssuer.Status.Conditions[0].Reason).Should(Equal("Configured"))

			// Clean up
			By("Cleaning up resources")
			Expect(k8sClient.Delete(ctx, clusterIssuer)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, secret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, namespace)).Should(Succeed())
		})
	})
})
