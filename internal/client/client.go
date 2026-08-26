/*
Copyright 2026.

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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	api "github.com/dns3l/dns3l-core/api/v1"
)

// Client represents a DNS3L API client
type Client struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
	authToken  string
}

type DNS3LClient interface {
	GetInfo(ctx context.Context) (*api.ServerInfo, error)
	GetCA(ctx context.Context, caID string) (*api.CAInfo, error)
	ListCAs(ctx context.Context) ([]*api.CAInfo, error)
	GetCertificate(ctx context.Context, caID, name string) (*api.CertInfo, error)
	ListCertificates(ctx context.Context, caID string, opts ...QueryOption) ([]api.CertInfo, error)
	ClaimCertificate(ctx context.Context, caID string, req *api.CertClaimInfo) error
	GetCertificatePEM(ctx context.Context, caID, name string) (*api.CertResources, error)
	GetCertificatePEMChain(ctx context.Context, caID, name string) (string, error)
	GetCertificatePEMKey(ctx context.Context, caID, name string) (string, error)
	DeleteCertificate(ctx context.Context, caID, name string) error
}

// NewClient creates a new DNS3L API client
func NewClient(baseURL string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("baseURL cannot be empty")
	}

	// Ensure baseURL ends with /api/v1
	baseURL = strings.TrimSuffix(baseURL, "/")
	if !strings.HasSuffix(baseURL, "/api/v1") {
		baseURL = baseURL + "/api/v1"
	}

	c := &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Option is a functional option for configuring the client
type Option func(*Client)

// WithAPIKey sets the API key for authentication
func WithAPIKey(key string) Option {
	return func(c *Client) {
		c.apiKey = key
	}
}

// WithAuthToken sets the OIDC auth token for authentication
func WithAuthToken(token string) Option {
	return func(c *Client) {
		c.authToken = token
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		c.httpClient = client
	}
}

type ErrorMessage struct {
	api.ErrorMsg
}

func (e ErrorMessage) Error() string {
	return fmt.Sprintf("HTTP: %d - %s ", e.Code, e.Message)
}

// do performs an HTTP request and handles responses
func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	targetURL := c.baseURL + path
	var bodyReader io.Reader

	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if c.apiKey != "" {
		req.Header.Set("X-DNS3L-API-Key", c.apiKey)
	} else if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	//nolint:errcheck // nothing we can do
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorMessage
		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		return nil, errResp
	}

	return respBody, nil
}

// GetInfo retrieves API and daemon version information
func (c *Client) GetInfo(ctx context.Context) (*api.ServerInfo, error) {
	respBody, err := c.do(ctx, http.MethodGet, "/info", nil)
	if err != nil {
		return nil, err
	}

	var info api.ServerInfo
	if err := json.Unmarshal(respBody, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal info response: %w", err)
	}

	return &info, nil
}

// GetCA retrieves information about a specific CA
func (c *Client) GetCA(ctx context.Context, caID string) (*api.CAInfo, error) {
	if caID == "" {
		return nil, fmt.Errorf("caID cannot be empty")
	}

	path := fmt.Sprintf("/ca/%s", url.PathEscape(caID))
	respBody, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var ca api.CAInfo
	if err := json.Unmarshal(respBody, &ca); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CA response: %w", err)
	}

	return &ca, nil
}

// ListCAs retrieves all available CAs
func (c *Client) ListCAs(ctx context.Context) ([]*api.CAInfo, error) {
	respBody, err := c.do(ctx, http.MethodGet, "/ca", nil)
	if err != nil {
		return nil, err
	}

	var cas []*api.CAInfo
	if err := json.Unmarshal(respBody, &cas); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CAs response: %w", err)
	}

	return cas, nil
}

// GetCertificate retrieves information about a specific certificate from a CA
func (c *Client) GetCertificate(ctx context.Context, caID, name string) (*api.CertInfo, error) {
	if caID == "" {
		return nil, fmt.Errorf("caID cannot be empty")
	}
	if name == "" {
		return nil, fmt.Errorf("certificate name cannot be empty")
	}

	path := fmt.Sprintf("/ca/%s/crt/%s", url.PathEscape(caID), url.PathEscape(name))
	respBody, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var cert api.CertInfo
	if err := json.Unmarshal(respBody, &cert); err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate response: %w", err)
	}

	return &cert, nil
}

// ListCertificates retrieves all certificates from a CA
func (c *Client) ListCertificates(ctx context.Context, caID string, opts ...QueryOption) ([]*api.CertInfo, error) {
	if caID == "" {
		return nil, fmt.Errorf("caID cannot be empty")
	}

	q := &queryParams{}
	for _, opt := range opts {
		opt(q)
	}

	path := fmt.Sprintf("/ca/%s/crt", url.PathEscape(caID))
	if len(q.queryString) > 0 {
		path += "?" + q.queryString
	}

	respBody, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var certs []*api.CertInfo
	if err := json.Unmarshal(respBody, &certs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificates response: %w", err)
	}

	return certs, nil
}

// ClaimCertificate claims a certificate from an ACME CA
func (c *Client) ClaimCertificate(ctx context.Context, caID string, req *api.CertClaimInfo) error {
	if caID == "" {
		return fmt.Errorf("caID cannot be empty")
	}
	if req == nil {
		return fmt.Errorf("claim request cannot be nil")
	}
	if req.Name == "" {
		return fmt.Errorf("certificate name cannot be empty")
	}

	path := fmt.Sprintf("/ca/%s/crt", url.PathEscape(caID))
	_, err := c.do(ctx, http.MethodPost, path, req)
	return err
}

// GetCertificatePEM retrieves the certificate and chain in PEM format
func (c *Client) GetCertificatePEM(ctx context.Context, caID, name string) (*api.CertResources, error) {
	if caID == "" {
		return nil, fmt.Errorf("caID cannot be empty")
	}
	if name == "" {
		return nil, fmt.Errorf("certificate name cannot be empty")
	}

	path := fmt.Sprintf("/ca/%s/crt/%s/pem", url.PathEscape(caID), url.PathEscape(name))
	respBody, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var res api.CertResources
	if err := json.Unmarshal(respBody, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PEM response: %w", err)
	}

	return &res, nil
}

// GetCertificatePEMChain retrieves the full certificate chain in PEM format
func (c *Client) GetCertificatePEMChain(ctx context.Context, caID, name string) (string, error) {
	if caID == "" {
		return "", fmt.Errorf("caID cannot be empty")
	}
	if name == "" {
		return "", fmt.Errorf("certificate name cannot be empty")
	}

	path := fmt.Sprintf("/ca/%s/crt/%s/pem/fullchain", url.PathEscape(caID), url.PathEscape(name))
	respBody, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}

	return string(respBody), nil
}

// GetCertificatePEMKey retrieves the certificate private key in PEM format
func (c *Client) GetCertificatePEMKey(ctx context.Context, caID, name string) (string, error) {
	if caID == "" {
		return "", fmt.Errorf("caID cannot be empty")
	}
	if name == "" {
		return "", fmt.Errorf("certificate name cannot be empty")
	}

	path := fmt.Sprintf("/ca/%s/crt/%s/pem/key", url.PathEscape(caID), url.PathEscape(name))
	respBody, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}

	return string(respBody), nil
}

// DeleteCertificate deletes a certificate from a CA
func (c *Client) DeleteCertificate(ctx context.Context, caID, name string) error {
	if caID == "" {
		return fmt.Errorf("caID cannot be empty")
	}
	if name == "" {
		return fmt.Errorf("certificate name cannot be empty")
	}

	path := fmt.Sprintf("/ca/%s/crt/%s", url.PathEscape(caID), url.PathEscape(name))
	_, err := c.do(ctx, http.MethodDelete, path, nil)
	return err
}

// queryParams holds query parameters for API calls
type queryParams struct {
	queryString string
}

// QueryOption is a functional option for query parameters
type QueryOption func(*queryParams)

// WithSearch adds a search filter
func WithSearch(search string) QueryOption {
	return func(q *queryParams) {
		q.addParam("search", search)
	}
}

// WithSuffix adds a suffix filter
func WithSuffix(suffix string) QueryOption {
	return func(q *queryParams) {
		q.addParam("suffix", suffix)
	}
}

// WithLimit sets the page limit
func WithLimit(limit int) QueryOption {
	return func(q *queryParams) {
		q.addParam("limit", fmt.Sprintf("%d", limit))
	}
}

// WithOffset sets the page offset
func WithOffset(offset int) QueryOption {
	return func(q *queryParams) {
		q.addParam("offset", fmt.Sprintf("%d", offset))
	}
}

func (q *queryParams) addParam(key, value string) {
	if q.queryString == "" {
		q.queryString = url.QueryEscape(key) + "=" + url.QueryEscape(value)
	} else {
		q.queryString += "&" + url.QueryEscape(key) + "=" + url.QueryEscape(value)
	}
}
