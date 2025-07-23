package zerossl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API key validation failed: %s", string(body))
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
