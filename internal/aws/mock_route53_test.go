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
)

// MockRoute53Client is a mock implementation of the Route53 client for testing
type MockRoute53Client struct {
	UpsertCNAMERecordFunc func(ctx context.Context, hostedZoneID, recordName, recordValue string) error
	DeleteCNAMERecordFunc func(ctx context.Context, hostedZoneID, recordName, recordValue string) error
}

// UpsertCNAMERecord is a mock implementation of UpsertCNAMERecord
func (m *MockRoute53Client) UpsertCNAMERecord(ctx context.Context, hostedZoneID, recordName, recordValue string) error {
	if m.UpsertCNAMERecordFunc != nil {
		return m.UpsertCNAMERecordFunc(ctx, hostedZoneID, recordName, recordValue)
	}
	return nil
}

// DeleteCNAMERecord is a mock implementation of DeleteCNAMERecord
func (m *MockRoute53Client) DeleteCNAMERecord(ctx context.Context, hostedZoneID, recordName, recordValue string) error {
	if m.DeleteCNAMERecordFunc != nil {
		return m.DeleteCNAMERecordFunc(ctx, hostedZoneID, recordName, recordValue)
	}
	return nil
}
