package zerossl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// CertificateRequest represents a request to create a new certificate
type CertificateRequest struct {
	Domains          []string         `json:"certificate_domains"`
	ValidityDays     int              `json:"certificate_validity_days"`
	CSR              string           `json:"certificate_csr"`
	StrictDomains    bool             `json:"strict_domains"`
	ValidationMethod ValidationMethod `json:"validation_method,omitempty"`
}

// ValidationDetails contains validation method details
type ValidationDetails struct {
	OtherMethods struct {
		CNAMEValidationP1      string `json:"cname_validation_p1"`
		CNAMEValidationP2      string `json:"cname_validation_p2"`
		FileValidationURLHttp  string `json:"file_validation_url_http"`
		FileValidationURLHttps string `json:"file_validation_url_https"`
	} `json:"other_methods"`
}

// ValidationInfo contains validation information per domain
type ValidationInfo map[string]ValidationDetails

// CertificateResponse represents the response from creating a certificate
type CertificateResponse struct {
	ID               string         `json:"id"`
	Status           string         `json:"status"`
	ValidationEmails string         `json:"validation_emails,omitempty"`
	ValidationMethod string         `json:"validation_method,omitempty"`
	Validation       ValidationInfo `json:"validation,omitempty"`
	CreatedAt        string         `json:"created_at"`
	Certificate      string         `json:"certificate,omitempty"`
	CACertificate    string         `json:"ca_bundle,omitempty"`
}

// DownloadCertificateResponse represents the response from downloading a certificate
// which has a different structure than the CertificateResponse
type DownloadCertificateResponse struct {
	Certificate   string `json:"certificate.crt"`
	CACertificate string `json:"ca_bundle.crt"`
}

// CreateCertificate creates a new SSL certificate
func (c *Client) CreateCertificate(req *CertificateRequest) (*CertificateResponse, error) {
	endpoint := fmt.Sprintf("%s/certificates?access_key=%s", BaseURL, c.apiKey)

	// Convert domains array to comma-separated string
	domains := strings.Join(req.Domains, ",")

	// Prepare request body
	data := map[string]interface{}{
		"certificate_domains":       domains,
		"certificate_validity_days": req.ValidityDays,
		"certificate_csr":           req.CSR,
		"strict_domains":            req.StrictDomains,
	}

	// Add validation method if specified
	if req.ValidationMethod != "" {
		data["validation_method"] = string(req.ValidationMethod)
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request data: %v", err)
	}

	// Create request
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("error closing response body: %v", cerr)
		}
	}()

	if err := handleResponse(resp); err != nil {
		return nil, err
	}

	// Parse response
	var certResp CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &certResp, nil
}

// GetCertificate retrieves a certificate by its ID
func (c *Client) GetCertificate(id string) (*CertificateResponse, error) {
	endpoint := fmt.Sprintf("%s/certificates/%s?access_key=%s", BaseURL, id, c.apiKey)

	resp, err := c.httpClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("error closing response body: %v", cerr)
		}
	}()

	if err := handleResponse(resp); err != nil {
		return nil, err
	}

	var certResp CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &certResp, nil
}

// DownloadCertificate downloads the certificate and CA bundle for a given certificate ID
func (c *Client) DownloadCertificate(id string) (*DownloadCertificateResponse, error) {
	endpoint := fmt.Sprintf("%s/certificates/%s/download/return?access_key=%s", BaseURL, id, c.apiKey)

	resp, err := c.httpClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to download certificate: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("error closing response body: %v", cerr)
		}
	}()

	if err := handleResponse(resp); err != nil {
		return nil, err
	}

	var downloadResp DownloadCertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&downloadResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &downloadResp, nil
}
