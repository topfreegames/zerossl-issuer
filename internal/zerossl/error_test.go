package zerossl

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestErrorParsing(t *testing.T) {
	// Test case for a standard ZeroSSL error response
	errorResponse := ZeroSSLErrorResponse{
		Success: false,
		Error: Error{
			Code: 2823,
			Type: "failed_validating_certificate",
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(errorResponse)
	if err != nil {
		t.Fatalf("Failed to marshal error response: %v", err)
	}

	// Create a mock HTTP response
	resp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Body:       io.NopCloser(bytes.NewReader(jsonData)),
	}

	// Test handleResponse
	err = handleResponse(resp)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// Check if the error is of the correct type
	zeroCertErr, ok := AsError(err)
	if !ok {
		t.Fatalf("Expected ZeroSSL error, got %T", err)
	}

	// Check error code and type
	if zeroCertErr.Code != 2823 {
		t.Errorf("Expected error code 2823, got %d", zeroCertErr.Code)
	}
	if zeroCertErr.Type != "failed_validating_certificate" {
		t.Errorf("Expected error type 'failed_validating_certificate', got %s", zeroCertErr.Type)
	}

	// Test IsValidationError helper
	if !zeroCertErr.IsValidationError() {
		t.Error("Expected IsValidationError to return true")
	}
}

func TestErrorHelpers(t *testing.T) {
	testCases := []struct {
		name           string
		errorCode      int
		errorType      string
		isAuth         bool
		isNotFound     bool
		isNotIssued    bool
		isNotDownload  bool
		isLimitReached bool
		isValidation   bool
	}{
		{
			name:      "Auth error - invalid access key",
			errorCode: ErrorInvalidAccessKey,
			errorType: "invalid_access_key",
			isAuth:    true,
		},
		{
			name:       "Certificate not found error",
			errorCode:  ErrorCertificateNotFound,
			errorType:  "certificate_not_found",
			isNotFound: true,
		},
		{
			name:        "Certificate not issued error",
			errorCode:   ErrorCertificateNotIssued,
			errorType:   "certificate_not_issued",
			isNotIssued: true,
		},
		{
			name:          "Certificate not downloadable error",
			errorCode:     ErrorCertificateNotDownloadable,
			errorType:     "certificate_not_downloadable",
			isNotDownload: true,
		},
		{
			name:           "Certificate limit reached error",
			errorCode:      ErrorCertificateLimitReached,
			errorType:      "certificate_limit_reached",
			isLimitReached: true,
		},
		{
			name:         "Validation error",
			errorCode:    ErrorFailedValidatingCertificate,
			errorType:    "failed_validating_certificate",
			isValidation: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := &Error{
				Code: tc.errorCode,
				Type: tc.errorType,
			}

			if tc.isAuth != err.IsAuthError() {
				t.Errorf("IsAuthError() = %v, want %v", err.IsAuthError(), tc.isAuth)
			}
			if tc.isNotFound != err.IsCertificateNotFoundError() {
				t.Errorf("IsCertificateNotFoundError() = %v, want %v", err.IsCertificateNotFoundError(), tc.isNotFound)
			}
			if tc.isNotIssued != err.IsCertificateNotIssuedError() {
				t.Errorf("IsCertificateNotIssuedError() = %v, want %v", err.IsCertificateNotIssuedError(), tc.isNotIssued)
			}
			if tc.isNotDownload != err.IsCertificateNotDownloadableError() {
				t.Errorf("IsCertificateNotDownloadableError() = %v, want %v", err.IsCertificateNotDownloadableError(), tc.isNotDownload)
			}
			if tc.isLimitReached != err.IsCertificateLimitReachedError() {
				t.Errorf("IsCertificateLimitReachedError() = %v, want %v", err.IsCertificateLimitReachedError(), tc.isLimitReached)
			}
			if tc.isValidation != err.IsValidationError() {
				t.Errorf("IsValidationError() = %v, want %v", err.IsValidationError(), tc.isValidation)
			}
		})
	}
}
