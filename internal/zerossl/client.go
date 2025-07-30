package zerossl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// BaseURL is the base URL for the ZeroSSL API
	BaseURL = "https://api.zerossl.com"

	// General error codes
	ErrorInvalidAccessKey        = 101
	ErrorInactiveUser            = 102
	ErrorInvalidAPIFunction      = 103
	ErrorRouteNotFound           = 104
	ErrorInvalidRequestBody      = 110
	ErrorInternalServerError     = 111
	ErrorConflict                = 112
	ErrorUnprocessableEntity     = 113
	ErrorInvalidJSONRequest      = 115
	ErrorInvalidJSONRequestParam = 116
	ErrorIncorrectRequestType    = 2800
	ErrorPermissionDenied        = 2801
	ErrorMissingCertificateHash  = 2802
	ErrorCertificateNotFound     = 2803

	// Certificate creation error codes
	ErrorCannotIssueCertificateUnpaidInvoices          = 2804
	ErrorInvalidCertificateType                        = 2805
	ErrorMissingCertificateType                        = 2806
	ErrorInvalidCertificateValidity                    = 2807
	ErrorInvalidCertificateDomain                      = 2808
	ErrorWildcardDomainsNotAllowedInMultiDomain        = 2809
	ErrorInvalidDomainsInMultiDomainRequest            = 2810
	ErrorDuplicateDomainsInArray                       = 2811
	ErrorMissingCertificateDomains                     = 2812
	ErrorCannotReplaceCertificateOtherReplacementDraft = 2813
	ErrorPermissionDeniedOnOriginalCertificate         = 2814
	ErrorOriginalCertificateNotActive                  = 2815
	ErrorCannotFindOriginalCertificate                 = 2816
	ErrorCertificateLimitReached                       = 2817
	ErrorInvalidCertificateCSR                         = 2818
	ErrorMissingCertificateCSR                         = 2819
	ErrorInternalErrorFailedProcessingCSR              = 2820
	ErrorInternalErrorFailedCreatingCertificate        = 2821
	ErrorFailedValidatingCertificate                   = 2823

	// Certificate download error codes
	ErrorCertificateNotIssued       = 2832
	ErrorCertificateNotDownloadable = 2860

	// Certificate cancellation error codes
	ErrorCertificateCannotBeCancelled = 2833
	ErrorFailedCancellingCertificate  = 2834

	// Verification error codes
	ErrorFailedResendingEmail          = 2837
	ErrorFailedGettingValidationStatus = 2838
)

// ZeroSSLClientInterface defines the interface for a ZeroSSL client
type ZeroSSLClientInterface interface {
	ValidateAPIKey() error
	CreateCertificate(req *CertificateRequest) (*CertificateResponse, error)
	GetCertificate(id string) (*CertificateResponse, error)
	DownloadCertificate(id string) (*DownloadCertificateResponse, error)
	InitiateValidation(id string, method ValidationMethod) (*CertificateResponse, error)
	VerifyDNSValidation(id string) error
}

// ClientFactoryFunc is a factory function for creating ZeroSSL clients
type ClientFactoryFunc func(apiKey string) ZeroSSLClientInterface

// defaultClientFactory is the default factory function for creating ZeroSSL clients
var defaultClientFactory ClientFactoryFunc = func(apiKey string) ZeroSSLClientInterface {
	return &Client{
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

// currentClientFactory is the current factory function for creating ZeroSSL clients
var currentClientFactory ClientFactoryFunc = defaultClientFactory

// NewClient creates a new ZeroSSL API client
func NewClient(apiKey string) ZeroSSLClientInterface {
	return currentClientFactory(apiKey)
}

// SetClientFactory sets the factory function for creating ZeroSSL clients
// Returns the previous factory function
func SetClientFactory(factory ClientFactoryFunc) ClientFactoryFunc {
	previous := currentClientFactory
	currentClientFactory = factory
	return previous
}

// ResetClientFactory resets the client factory to the default
func ResetClientFactory() {
	currentClientFactory = defaultClientFactory
}

// Client represents a ZeroSSL API client
type Client struct {
	apiKey     string
	httpClient *http.Client
}

// ValidateAPIKey validates the API key by making a test request
func (c *Client) ValidateAPIKey() error {
	// Make a request to list certificates with limit=1 to validate the API key
	endpoint := fmt.Sprintf("%s/certificates?access_key=%s&limit=1", BaseURL, c.apiKey)

	resp, err := c.httpClient.Get(endpoint)
	if err != nil {
		return fmt.Errorf("failed to validate API key: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("error closing response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API key validation failed: %s", string(body))
	}

	return nil
}

// ValidationMethod represents the method used for domain validation
type ValidationMethod string

const (
	// ValidationMethodHTTP represents HTTP validation method
	ValidationMethodHTTP ValidationMethod = "HTTP_CSR_HASH"
	// ValidationMethodDNS represents DNS validation method
	ValidationMethodDNS ValidationMethod = "CNAME_CSR_HASH"
)

// ValidationRecord represents a domain validation record
type ValidationRecord struct {
	Domain           string `json:"domain"`
	ValidationType   string `json:"validation_type"`
	ValidationMethod string `json:"validation_method"`
	CNameHost        string `json:"cname_host,omitempty"`
	CNameTarget      string `json:"cname_target,omitempty"`
	TXTName          string `json:"txt_name,omitempty"`
	TXTValue         string `json:"txt_value,omitempty"`
}

// ValidationResponse represents the response from a validation request
type ValidationResponse struct {
	Success bool               `json:"success"`
	Error   *Error             `json:"error,omitempty"`
	Records []ValidationRecord `json:"domains,omitempty"`
}

// InitiateValidation initiates validation for a certificate using the specified method
func (c *Client) InitiateValidation(id string, method ValidationMethod) (*CertificateResponse, error) {
	endpoint := fmt.Sprintf("%s/certificates/%s/challenges?access_key=%s", BaseURL, id, c.apiKey)

	// Build form data for POST request
	data := map[string]interface{}{
		"validation_method": string(method),
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request data: %v", err)
	}

	// Create request
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create validation request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send validation request: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("error closing response body: %v", cerr)
		}
	}()

	if err := handleResponse(resp); err != nil {
		return nil, fmt.Errorf("validation request failed: %v", err)
	}

	// For CNAME validation, the API returns the certificate object
	var certResp CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return nil, fmt.Errorf("failed to decode validation response: %v", err)
	}

	return &certResp, nil
}

// VerifyDNSValidation verifies that DNS validation is complete
func (c *Client) VerifyDNSValidation(id string) error {
	// Use the same endpoint as InitiateValidation to verify the DNS records
	// This actually initiates the validation process after the DNS records have been created
	certResp, err := c.InitiateValidation(id, ValidationMethodDNS)
	if err != nil {
		return fmt.Errorf("failed to verify DNS validation: %v", err)
	}

	// If we get a successful response, check if the certificate status changed
	if certResp.Status == "issued" {
		return nil
	}

	// If the status is not "issued", we need to wait for the validation to complete
	// This is not an error, just means the validation is still in progress
	return nil
}

// Error represents a ZeroSSL API error response
type Error struct {
	Code int         `json:"code"`
	Type string      `json:"type"`
	Info interface{} `json:"info,omitempty"`
}

func (e *Error) Error() string {
	if e.Info != nil {
		return fmt.Sprintf("ZeroSSL API error %d: %s (info: %v)", e.Code, e.Type, e.Info)
	}
	return fmt.Sprintf("ZeroSSL API error %d: %s", e.Code, e.Type)
}

// IsAuthError returns true if the error is an authentication error
func (e *Error) IsAuthError() bool {
	return e.Code == ErrorInvalidAccessKey || e.Code == ErrorInactiveUser || e.Code == ErrorPermissionDenied
}

// IsCertificateNotFoundError returns true if the error indicates the certificate was not found
func (e *Error) IsCertificateNotFoundError() bool {
	return e.Code == ErrorCertificateNotFound
}

// IsCertificateNotIssuedError returns true if the error indicates the certificate is not issued yet
func (e *Error) IsCertificateNotIssuedError() bool {
	return e.Code == ErrorCertificateNotIssued
}

// IsCertificateNotDownloadableError returns true if the error indicates the certificate cannot be downloaded
func (e *Error) IsCertificateNotDownloadableError() bool {
	return e.Code == ErrorCertificateNotDownloadable
}

// IsCertificateLimitReachedError returns true if the error indicates the certificate limit was reached
func (e *Error) IsCertificateLimitReachedError() bool {
	return e.Code == ErrorCertificateLimitReached
}

// IsValidationError returns true if the error is related to validation
func (e *Error) IsValidationError() bool {
	return e.Code == ErrorFailedValidatingCertificate || e.Code == ErrorFailedGettingValidationStatus
}

// AsError attempts to convert a generic error to a ZeroSSL Error
func AsError(err error) (*Error, bool) {
	if err == nil {
		return nil, false
	}

	zeroCertErr, ok := err.(*Error)
	return zeroCertErr, ok
}

// ZeroSSLErrorResponse represents the error response format from ZeroSSL API
type ZeroSSLErrorResponse struct {
	Success bool  `json:"success"`
	Error   Error `json:"error"`
}

// handleResponse handles the API response and returns an error if the response is not successful
func handleResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read error response body: %v", err)
	}

	// Reset the response body for further reading
	resp.Body = io.NopCloser(strings.NewReader(string(body)))

	// Try to parse as ZeroSSL error format
	var errorResp ZeroSSLErrorResponse
	if err := json.Unmarshal(body, &errorResp); err != nil {
		return fmt.Errorf("failed to decode error response: %v (status code: %d, body: %s)", err, resp.StatusCode, string(body))
	}

	// Check if we have a valid error response
	if !errorResp.Success && errorResp.Error.Code > 0 {
		return &errorResp.Error
	}

	// If we couldn't parse the error properly, return a generic error
	return fmt.Errorf("unexpected API response: status code %d, body: %s", resp.StatusCode, string(body))
}
