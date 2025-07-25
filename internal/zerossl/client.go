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
	ValidationMethodDNS ValidationMethod = "DNS_CSR_HASH"
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

// GetValidationData gets the validation data for a certificate
func (c *Client) GetValidationData(id string, method ValidationMethod) (*ValidationResponse, error) {
	endpoint := fmt.Sprintf("%s/certificates/%s/challenges?access_key=%s&validation_method=%s",
		BaseURL, id, c.apiKey, method)

	resp, err := c.httpClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get validation data: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("error closing response body: %v", cerr)
		}
	}()

	var validationResp ValidationResponse
	if err := json.NewDecoder(resp.Body).Decode(&validationResp); err != nil {
		return nil, fmt.Errorf("failed to decode validation response: %v", err)
	}

	if !validationResp.Success {
		if validationResp.Error != nil {
			return nil, validationResp.Error
		}
		return nil, fmt.Errorf("validation request failed without specific error")
	}

	return &validationResp, nil
}

// VerifyDNSValidation verifies that DNS validation is complete
func (c *Client) VerifyDNSValidation(id string) error {
	endpoint := fmt.Sprintf("%s/certificates/%s/challenges/verify?access_key=%s", BaseURL, id, c.apiKey)

	data := url.Values{}
	data.Set("validation_method", string(ValidationMethodDNS))

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create verification request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send verification request: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("error closing response body: %v", cerr)
		}
	}()

	var verifyResp struct {
		Success bool   `json:"success"`
		Error   *Error `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&verifyResp); err != nil {
		return fmt.Errorf("failed to decode verification response: %v", err)
	}

	if !verifyResp.Success {
		if verifyResp.Error != nil {
			return verifyResp.Error
		}
		return fmt.Errorf("verification failed without specific error")
	}

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
