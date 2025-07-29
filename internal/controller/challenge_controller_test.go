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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
	"github.com/topfreegames/zerossl-issuer/internal/zerossl"
)

// Using the mock client from mock_client_test.go

var _ = Describe("Challenge Controller", func() {
	const (
		ChallengeName      = "test-challenge"
		ChallengeNamespace = "default"
		CertificateID      = "test-cert-id"

		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When reconciling a Challenge", func() {
		It("Should properly set conditions", func() {
			By("Creating a Challenge with DNS validation")
			ctx := context.Background()

			challenge := &zerosslv1alpha1.Challenge{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ChallengeName,
					Namespace: ChallengeNamespace,
				},
				Spec: zerosslv1alpha1.ChallengeSpec{
					CertificateRequestRef: "test-request",
					CertificateID:         CertificateID,
					ValidationMethod:      "DNS",
					ValidationRecords: []zerosslv1alpha1.ValidationRecord{
						{
							Domain:     "example.com",
							CNAMEName:  "_zerossl.example.com",
							CNAMEValue: "abcdef.zerossl.com",
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, challenge)).Should(Succeed())

			challengeLookupKey := types.NamespacedName{Name: ChallengeName, Namespace: ChallengeNamespace}
			createdChallenge := &zerosslv1alpha1.Challenge{}

			// We'll need to retry getting this newly created Challenge, given that creation may not immediately happen.
			Eventually(func() bool {
				err := k8sClient.Get(ctx, challengeLookupKey, createdChallenge)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			// Verify that the created Challenge has the expected values
			Expect(createdChallenge.Spec.CertificateID).Should(Equal(CertificateID))
			Expect(createdChallenge.Spec.ValidationMethod).Should(Equal("DNS"))
			Expect(createdChallenge.Spec.ValidationRecords).Should(HaveLen(1))
			Expect(createdChallenge.Spec.ValidationRecords[0].Domain).Should(Equal("example.com"))
		})
	})

	Context("When using the shared mock client", func() {
		It("Should create a mock client correctly", func() {
			mockClient := &MockZeroSSLClient{
				VerifyDNSValidationErr: nil,
				GetCertificateResp: &zerossl.CertificateResponse{
					ID:     "test-cert-id",
					Status: "issued",
				},
			}

			// Test the mock client
			err := mockClient.VerifyDNSValidation("test-id")
			Expect(err).ToNot(HaveOccurred())

			resp, err := mockClient.GetCertificate("test-id")
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.Status).To(Equal("issued"))
		})
	})
})
