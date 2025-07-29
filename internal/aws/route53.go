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
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	zerosslv1alpha1 "github.com/topfreegames/zerossl-issuer/api/v1alpha1"
)

const (
	// TTL for DNS records in seconds
	recordTTL = 60
)

// Route53Client handles interactions with AWS Route53
type Route53Client struct {
	client *route53.Client
}

// NewRoute53Client creates a new Route53Client from issuer configuration
func NewRoute53Client(ctx context.Context, k8sClient client.Client, route53Config *zerosslv1alpha1.ACMEChallengeSolverDNS01Route53, namespace string) (*Route53Client, error) {
	// Get AWS credentials
	accessKeyID := route53Config.AccessKeyID
	region := route53Config.Region

	var secretAccessKey string
	if route53Config.SecretAccessKeySecretRef.Name != "" {
		// Get secret access key from secret reference
		secret := &corev1.Secret{}
		namespacedName := client.ObjectKey{
			Name:      route53Config.SecretAccessKeySecretRef.Name,
			Namespace: namespace,
		}

		if err := k8sClient.Get(ctx, namespacedName, secret); err != nil {
			return nil, fmt.Errorf("failed to get Secret with AWS credentials: %v", err)
		}

		keyBytes, ok := secret.Data[route53Config.SecretAccessKeySecretRef.Key]
		if !ok {
			return nil, fmt.Errorf("AWS secret access key not found in secret %s with key %s",
				route53Config.SecretAccessKeySecretRef.Name,
				route53Config.SecretAccessKeySecretRef.Key)
		}

		secretAccessKey = string(keyBytes)
	} else {
		return nil, fmt.Errorf("secretAccessKey reference is required")
	}

	// Create AWS configuration with static credentials
	awsCfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			accessKeyID,
			secretAccessKey,
			"", // Session token is optional and typically not used for static credentials
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS config: %v", err)
	}

	// Create Route53 client
	r53Client := route53.NewFromConfig(awsCfg)

	return &Route53Client{
		client: r53Client,
	}, nil
}

// UpsertCNAMERecord creates or updates a CNAME record in Route53
func (r *Route53Client) UpsertCNAMERecord(ctx context.Context, hostedZoneID, recordName, recordValue string) error {
	// Ensure record name ends with a dot
	if recordName[len(recordName)-1] != '.' {
		recordName = recordName + "."
	}

	// Ensure record value ends with a dot (if it's a domain name)
	if recordValue[len(recordValue)-1] != '.' {
		recordValue = recordValue + "."
	}

	// Build the change request
	change := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneID),
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{
				{
					Action: types.ChangeActionUpsert,
					ResourceRecordSet: &types.ResourceRecordSet{
						Name: aws.String(recordName),
						Type: types.RRTypeCname,
						TTL:  aws.Int64(recordTTL),
						ResourceRecords: []types.ResourceRecord{
							{
								Value: aws.String(recordValue),
							},
						},
					},
				},
			},
		},
	}

	// Execute the change
	_, err := r.client.ChangeResourceRecordSets(ctx, change)
	if err != nil {
		return fmt.Errorf("failed to update Route53 record: %v", err)
	}

	return nil
}

// DeleteCNAMERecord deletes a CNAME record from Route53
func (r *Route53Client) DeleteCNAMERecord(ctx context.Context, hostedZoneID, recordName, recordValue string) error {
	// Ensure record name ends with a dot
	if recordName[len(recordName)-1] != '.' {
		recordName = recordName + "."
	}

	// Ensure record value ends with a dot (if it's a domain name)
	if recordValue[len(recordValue)-1] != '.' {
		recordValue = recordValue + "."
	}

	// Build the change request
	change := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneID),
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{
				{
					Action: types.ChangeActionDelete,
					ResourceRecordSet: &types.ResourceRecordSet{
						Name: aws.String(recordName),
						Type: types.RRTypeCname,
						TTL:  aws.Int64(recordTTL),
						ResourceRecords: []types.ResourceRecord{
							{
								Value: aws.String(recordValue),
							},
						},
					},
				},
			},
		},
	}

	// Execute the change
	_, err := r.client.ChangeResourceRecordSets(ctx, change)
	if err != nil {
		return fmt.Errorf("failed to delete Route53 record: %v", err)
	}

	return nil
}
