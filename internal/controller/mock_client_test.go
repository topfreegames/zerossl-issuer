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
	"github.com/topfreegames/zerossl-issuer/internal/zerossl"
)

// MockZeroSSLClient is a mock implementation of ZeroSSLClient for testing
type MockZeroSSLClient struct {
	CreateCertificateResp *zerossl.CertificateResponse
	CreateCertificateErr  error

	DownloadCertificateResp *zerossl.DownloadCertificateResponse
	DownloadCertificateErr  error

	GetValidationDataResp *zerossl.ValidationResponse
	GetValidationDataErr  error

	VerifyDNSValidationErr error

	GetCertificateResp *zerossl.CertificateResponse
	GetCertificateErr  error
}

// CreateCertificate mocks the CreateCertificate method
func (m *MockZeroSSLClient) CreateCertificate(req *zerossl.CertificateRequest) (*zerossl.CertificateResponse, error) {
	if m.CreateCertificateErr != nil {
		return nil, m.CreateCertificateErr
	}

	// Use provided response or create a default one
	if m.CreateCertificateResp != nil {
		return m.CreateCertificateResp, nil
	}

	// Default response with CNAME validation
	validation := make(zerossl.ValidationInfo)
	for _, domain := range req.Domains {
		details := zerossl.ValidationDetails{}
		details.OtherMethods.CNAMEValidationP1 = "_zerossl." + domain
		details.OtherMethods.CNAMEValidationP2 = "verify.zerossl.com"
		validation[domain] = details
	}

	return &zerossl.CertificateResponse{
		ID:         "test-cert-id",
		Status:     "pending_validation",
		Validation: validation,
	}, nil
}

// DownloadCertificate mocks the DownloadCertificate method
func (m *MockZeroSSLClient) DownloadCertificate(id string) (*zerossl.DownloadCertificateResponse, error) {
	if m.DownloadCertificateErr != nil {
		return nil, m.DownloadCertificateErr
	}

	// Use provided response or create a default one
	if m.DownloadCertificateResp != nil {
		return m.DownloadCertificateResp, nil
	}

	return &zerossl.DownloadCertificateResponse{
		Certificate:   "-----BEGIN CERTIFICATE-----\nTEST CERTIFICATE\n-----END CERTIFICATE-----",
		CACertificate: "-----BEGIN CERTIFICATE-----\nTEST CA CERTIFICATE\n-----END CERTIFICATE-----",
	}, nil
}

// GetValidationData mocks the GetValidationData method
func (m *MockZeroSSLClient) GetValidationData(id string, method zerossl.ValidationMethod) (*zerossl.ValidationResponse, error) {
	if m.GetValidationDataErr != nil {
		return nil, m.GetValidationDataErr
	}

	// Use provided response or create a default one
	if m.GetValidationDataResp != nil {
		return m.GetValidationDataResp, nil
	}

	return &zerossl.ValidationResponse{
		Success: true,
		Records: []zerossl.ValidationRecord{
			{
				Domain:         "test.example.com",
				ValidationType: "TXT",
				TXTName:        "_acme-challenge.test.example.com",
				TXTValue:       "test-validation-token",
			},
		},
	}, nil
}

// VerifyDNSValidation mocks the VerifyDNSValidation method
func (m *MockZeroSSLClient) VerifyDNSValidation(id string) error {
	return m.VerifyDNSValidationErr
}

// GetCertificate mocks the GetCertificate method
func (m *MockZeroSSLClient) GetCertificate(id string) (*zerossl.CertificateResponse, error) {
	if m.GetCertificateErr != nil {
		return nil, m.GetCertificateErr
	}

	// Use provided response or create a default one
	if m.GetCertificateResp != nil {
		return m.GetCertificateResp, nil
	}

	// Default response with CNAME validation
	validation := make(zerossl.ValidationInfo)
	domain := "test.example.com"
	details := zerossl.ValidationDetails{}
	details.OtherMethods.CNAMEValidationP1 = "_zerossl." + domain
	details.OtherMethods.CNAMEValidationP2 = "verify.zerossl.com"
	validation[domain] = details

	return &zerossl.CertificateResponse{
		ID:         "test-cert-id",
		Status:     "issued",
		Validation: validation,
	}, nil
}
