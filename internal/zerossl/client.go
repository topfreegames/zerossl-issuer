package zerossl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// BaseURL is the base URL for the ZeroSSL API
	BaseURL = "https://api.zerossl.com"
)

// Client represents a ZeroSSL API client
type Client struct {
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new ZeroSSL API client
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
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
	formData := url.Values{}
	formData.Add("validation_method", string(method))

	// Create request
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create validation request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("ZeroSSL API error %d: %s", e.Code, e.Message)
}

// handleResponse handles the API response and returns an error if the response is not successful
func handleResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	var apiError Error
	if err := json.NewDecoder(resp.Body).Decode(&apiError); err != nil {
		return fmt.Errorf("failed to decode error response: %v", err)
	}

	return &apiError
}
