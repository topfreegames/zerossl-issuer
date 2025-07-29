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

package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
)

func TestNewRoute53Client(t *testing.T) {
	// Create a fake client with the necessary objects
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aws-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"secret": []byte("test-secret-key"),
		},
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	// Create a test route53 configuration
	route53Config := &zerosslv1alpha1.ACMEChallengeSolverDNS01Route53{
		Region:       "us-east-1",
		AccessKeyID:  "test-access-key",
		HostedZoneID: "test-zone",
		SecretAccessKeySecretRef: corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: "aws-secret",
			},
			Key: "secret",
		},
	}

	// Test successful client creation
	t.Run("Success case", func(t *testing.T) {
		ctx := context.Background()
		client, err := NewRoute53Client(ctx, fakeClient, route53Config, "default")
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})

	// Test missing secret
	t.Run("Missing secret", func(t *testing.T) {
		ctx := context.Background()
		route53ConfigBad := &zerosslv1alpha1.ACMEChallengeSolverDNS01Route53{
			Region:       "us-east-1",
			AccessKeyID:  "test-access-key",
			HostedZoneID: "test-zone",
			SecretAccessKeySecretRef: corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "nonexistent-secret",
				},
				Key: "secret",
			},
		}
		client, err := NewRoute53Client(ctx, fakeClient, route53ConfigBad, "default")
		assert.Error(t, err)
		assert.Nil(t, client)
	})

	// Test missing key in secret
	t.Run("Missing key in secret", func(t *testing.T) {
		ctx := context.Background()
		route53ConfigBad := &zerosslv1alpha1.ACMEChallengeSolverDNS01Route53{
			Region:       "us-east-1",
			AccessKeyID:  "test-access-key",
			HostedZoneID: "test-zone",
			SecretAccessKeySecretRef: corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "aws-secret",
				},
				Key: "nonexistent-key",
			},
		}
		client, err := NewRoute53Client(ctx, fakeClient, route53ConfigBad, "default")
		assert.Error(t, err)
		assert.Nil(t, client)
	})
}
