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

	InitiateValidationResp *zerossl.CertificateResponse
	InitiateValidationErr  error

	VerifyDNSValidationErr error

	GetCertificateResp *zerossl.CertificateResponse
	GetCertificateErr  error

	ValidateAPIKeyErr error
}

// ValidateAPIKey mocks the ValidateAPIKey method
func (m *MockZeroSSLClient) ValidateAPIKey() error {
	return m.ValidateAPIKeyErr
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
	validation := zerossl.ValidationInfo{
		EmailValidation: make(map[string][]string),
		OtherMethods:    make(map[string]zerossl.ValidationOtherMethodDetails),
	}

	for _, domain := range req.Domains {
		validation.OtherMethods[domain] = zerossl.ValidationOtherMethodDetails{
			CNAMEValidationP1: "_zerossl." + domain,
			CNAMEValidationP2: "verify.zerossl.com",
		}
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

// InitiateValidation mocks the InitiateValidation method
func (m *MockZeroSSLClient) InitiateValidation(id string, method zerossl.ValidationMethod) (*zerossl.CertificateResponse, error) {
	if m.InitiateValidationErr != nil {
		return nil, m.InitiateValidationErr
	}

	// Use provided response or create a default one
	if m.InitiateValidationResp != nil {
		return m.InitiateValidationResp, nil
	}

	// Default response with CNAME validation
	domain := "test.example.com"
	validation := zerossl.ValidationInfo{
		EmailValidation: make(map[string][]string),
		OtherMethods:    make(map[string]zerossl.ValidationOtherMethodDetails),
	}

	validation.OtherMethods[domain] = zerossl.ValidationOtherMethodDetails{
		CNAMEValidationP1: "_zerossl." + domain,
		CNAMEValidationP2: "verify.zerossl.com",
	}

	return &zerossl.CertificateResponse{
		ID:         id,
		Status:     "pending_validation",
		Validation: validation,
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
	domain := "test.example.com"
	validation := zerossl.ValidationInfo{
		EmailValidation: make(map[string][]string),
		OtherMethods:    make(map[string]zerossl.ValidationOtherMethodDetails),
	}

	validation.OtherMethods[domain] = zerossl.ValidationOtherMethodDetails{
		CNAMEValidationP1: "_zerossl." + domain,
		CNAMEValidationP2: "verify.zerossl.com",
	}

	return &zerossl.CertificateResponse{
		ID:         "test-cert-id",
		Status:     "issued",
		Validation: validation,
	}, nil
}
