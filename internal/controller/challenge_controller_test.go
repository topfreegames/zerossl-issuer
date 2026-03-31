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
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	sigs_client "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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

// newChallengeTestScheme builds the runtime scheme needed by challenge controller tests.
func newChallengeTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, cmapi.AddToScheme(s))
	require.NoError(t, cmmeta.AddToScheme(s))
	require.NoError(t, zerosslv1alpha1.AddToScheme(s))
	return s
}

// newChallengeReconcilerWithObjects creates a ChallengeReconciler backed by a fake
// client pre-populated with the given objects.
func newChallengeReconcilerWithObjects(t *testing.T, objs ...sigs_client.Object) *ChallengeReconciler {
	t.Helper()
	s := newChallengeTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	return NewChallengeReconciler(fakeClient, s, record.NewFakeRecorder(10), 1)
}

// TestCleanupDNSRecords_SkipsWhenCertificateRequestNotFound verifies the fix for
// Challenges getting permanently stuck in Terminating when their parent
// CertificateRequest was already deleted before the finalizer ran.
func TestCleanupDNSRecords_SkipsWhenCertificateRequestNotFound(t *testing.T) {
	reconciler := newChallengeReconcilerWithObjects(t) // empty fake client — no CR exists

	challenge := &zerosslv1alpha1.Challenge{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-challenge",
			Namespace: "default",
		},
		Spec: zerosslv1alpha1.ChallengeSpec{
			CertificateRequestRef: "nonexistent-cr",
			CertificateID:         "test-cert-id",
			ValidationMethod:      "DNS",
			ValidationRecords: []zerosslv1alpha1.ValidationRecord{
				{
					Domain:     "example.com",
					CNAMEName:  "_zerossl.example.com",
					CNAMEValue: "abc.zerossl.com",
				},
			},
		},
	}

	err := reconciler.cleanupDNSRecords(context.Background(), challenge)
	assert.NoError(t, err, "cleanupDNSRecords must return nil when the CertificateRequest is gone so the finalizer can be removed")
}

// TestGetIssuerForChallenge_ErrorIsUnwrappableAsNotFound verifies that when the
// CertificateRequest referenced by a Challenge does not exist, the error from
// getIssuerForChallenge is wrapped with %%w so apierrors.IsNotFound identifies it
// through the chain — allowing cleanupDNSRecords to distinguish missing CRs from
// transient API failures.
func TestGetIssuerForChallenge_ErrorIsUnwrappableAsNotFound(t *testing.T) {
	reconciler := newChallengeReconcilerWithObjects(t) // empty fake client — no CR exists

	challenge := &zerosslv1alpha1.Challenge{
		ObjectMeta: metav1.ObjectMeta{Name: "test-challenge", Namespace: "default"},
		Spec:       zerosslv1alpha1.ChallengeSpec{CertificateRequestRef: "nonexistent-cr"},
	}

	_, err := reconciler.getIssuerForChallenge(context.Background(), challenge)
	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(err),
		"error must unwrap to a NotFound API error; got: %v", err)
}

// TestGetIssuerForChallenge_ClusterIssuerHasEmptyNamespace verifies that when the
// CertificateRequest references a ClusterIssuer, getIssuerForChallenge returns an
// Issuer with an empty namespace. cleanupDNSRecords uses that empty namespace as the
// signal to look up AWS secrets in cert-manager namespace rather than the challenge
// namespace.
func TestGetIssuerForChallenge_ClusterIssuerHasEmptyNamespace(t *testing.T) {
	clusterIssuer := &zerosslv1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-issuer"},
		Spec: zerosslv1alpha1.ClusterIssuerSpec{
			IssuerSpec: zerosslv1alpha1.IssuerSpec{
				APIKeySecretRef: corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "zerossl-api-key"},
					Key:                  "api-key",
				},
			},
		},
		Status: zerosslv1alpha1.ClusterIssuerStatus{
			Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}},
		},
	}

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cr", Namespace: "some-app"},
		Spec: cmapi.CertificateRequestSpec{
			IssuerRef: cmmeta.ObjectReference{
				Name:  "test-cluster-issuer",
				Kind:  "ClusterIssuer",
				Group: zerosslv1alpha1.GroupVersion.Group,
			},
		},
	}

	reconciler := newChallengeReconcilerWithObjects(t, clusterIssuer, cr)

	challenge := &zerosslv1alpha1.Challenge{
		ObjectMeta: metav1.ObjectMeta{Name: "test-challenge", Namespace: "some-app"},
		Spec:       zerosslv1alpha1.ChallengeSpec{CertificateRequestRef: "test-cr"},
	}

	issuer, err := reconciler.getIssuerForChallenge(context.Background(), challenge)
	require.NoError(t, err)
	assert.Empty(t, issuer.Namespace,
		"ClusterIssuer must produce an issuer with empty namespace so AWS secrets are resolved from cert-manager namespace, not the challenge namespace")
}
