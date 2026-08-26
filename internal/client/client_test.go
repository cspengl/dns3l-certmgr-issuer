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

//nolint:goconst // allow tests to be atomic
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	api "github.com/dns3l/dns3l-core/api/v1"
	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name       string
		baseURL    string
		opts       []Option
		wantErr    bool
		wantURL    string
		wantAPIKey string
		wantToken  string
	}{
		{
			name:    "empty baseURL should error",
			baseURL: "",
			wantErr: true,
		},
		{
			name:    "baseURL without /api/v1 should be normalized",
			baseURL: "http://localhost:8080",
			wantURL: "http://localhost:8080/api/v1",
		},
		{
			name:    "baseURL with /api/v1 should not be duplicated",
			baseURL: "http://localhost:8080/api/v1",
			wantURL: "http://localhost:8080/api/v1",
		},
		{
			name:    "baseURL with trailing slash should be handled",
			baseURL: "http://localhost:8080/api/v1/",
			wantURL: "http://localhost:8080/api/v1",
		},
		{
			name:       "WithAPIKey option should set apiKey",
			baseURL:    "http://localhost:8080",
			opts:       []Option{WithAPIKey("test-key")},
			wantURL:    "http://localhost:8080/api/v1",
			wantAPIKey: "test-key",
		},
		{
			name:      "WithAuthToken option should set authToken",
			baseURL:   "http://localhost:8080",
			opts:      []Option{WithAuthToken("test-token")},
			wantURL:   "http://localhost:8080/api/v1",
			wantToken: "test-token",
		},
		{
			name:    "WithHTTPClient option should set custom client",
			baseURL: "http://localhost:8080",
			opts:    []Option{WithHTTPClient(&http.Client{Timeout: 5 * time.Second})},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.baseURL, tt.opts...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			if tt.wantURL != "" {
				assert.Equal(t, tt.wantURL, client.baseURL)
			}
			if tt.wantAPIKey != "" {
				assert.Equal(t, tt.wantAPIKey, client.apiKey)
			}
			if tt.wantToken != "" {
				assert.Equal(t, tt.wantToken, client.authToken)
			}
		})
	}
}

func TestGetInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/info", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // ignore error for test
		json.NewEncoder(w).Encode(api.ServerInfo{
			Version: &api.ServerInfoVersion{
				Daemon: "1.0.0",
				API:    "1.0.0",
			},
		})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	info, err := client.GetInfo(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "1.0.0", info.Version.Daemon)
}

func TestGetInfo_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		//nolint:errcheck // ignore error for test
		json.NewEncoder(w).Encode(api.ErrorMsg{
			Code:    500,
			Message: "Internal server error",
		})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	_, err := client.GetInfo(context.Background())
	assert.Error(t, err)
}

func TestGetCA(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/ca/"))
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // ignore error for test
		json.NewEncoder(w).Encode(api.CAInfo{
			ID:      "ca-1",
			Name:    "Test CA",
			Type:    "ACME",
			IsAcme:  true,
			Enabled: true,
		})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	ca, err := client.GetCA(context.Background(), "ca-1")
	assert.NoError(t, err)
	assert.NotNil(t, ca)
	assert.Equal(t, "ca-1", ca.ID)
	assert.Equal(t, "Test CA", ca.Name)
}

func TestGetCA_EmptyCAID(t *testing.T) {
	client, _ := NewClient("http://localhost:8080")
	_, err := client.GetCA(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "caID cannot be empty")
}

func TestListCAs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/ca", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		cas := []*api.CAInfo{
			{
				ID:      "ca-1",
				Name:    "Test CA 1",
				Type:    "ACME",
				IsAcme:  true,
				Enabled: true,
			},
			{
				ID:      "ca-2",
				Name:    "Test CA 2",
				Type:    "ACME",
				IsAcme:  true,
				Enabled: true,
			},
		}
		//nolint:errcheck // ignore error for test
		json.NewEncoder(w).Encode(cas)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	cas, err := client.ListCAs(context.Background())
	assert.NoError(t, err)
	assert.Len(t, cas, 2)
	assert.Equal(t, "ca-1", cas[0].ID)
}

func TestGetCertificate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/ca/"))
		assert.True(t, strings.Contains(r.URL.Path, "/crt/"))
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // ignore error for test
		json.NewEncoder(w).Encode(api.CertInfo{
			Name:      "test.example.com",
			Valid:     true,
			ValidTo:   time.Now().Add(30 * 24 * time.Hour).String(),
			Wildcard:  false,
			SubjectCN: "test.example.com",
			IssuerCN:  "Test CA",
		})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	cert, err := client.GetCertificate(context.Background(), "ca-1", "test.example.com")
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "test.example.com", cert.Name)
	assert.True(t, cert.Valid)
}

func TestGetCertificate_EmptyParams(t *testing.T) {
	client, _ := NewClient("http://localhost:8080")

	tests := []struct {
		name     string
		caID     string
		certName string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "empty caID",
			caID:     "",
			certName: "test.example.com",
			wantErr:  true,
			errMsg:   "caID cannot be empty",
		},
		{
			name:     "empty certificate name",
			caID:     "ca-1",
			certName: "",
			wantErr:  true,
			errMsg:   "certificate name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.GetCertificate(context.Background(), tt.caID, tt.certName)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestListCertificates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/ca/"))
		assert.True(t, strings.HasSuffix(r.URL.Path, "/crt"))

		w.Header().Set("Content-Type", "application/json")
		certs := []api.CertInfo{
			{
				Name:      "test1.example.com",
				Valid:     true,
				ValidTo:   time.Now().Add(30 * 24 * time.Hour).String(),
				SubjectCN: "test1.example.com",
			},
			{
				Name:      "test2.example.com",
				Valid:     true,
				ValidTo:   time.Now().Add(30 * 24 * time.Hour).String(),
				SubjectCN: "test2.example.com",
			},
		}
		//nolint:errcheck // ignore error for test
		json.NewEncoder(w).Encode(certs)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	certs, err := client.ListCertificates(context.Background(), "ca-1")
	assert.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestListCertificates_WithQueryOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		assert.Contains(t, query, "search")
		assert.Contains(t, query, "limit")
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // ignore error for test
		json.NewEncoder(w).Encode([]*api.CertInfo{})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	_, err := client.ListCertificates(
		context.Background(),
		"ca-1",
		WithSearch("test"),
		WithLimit(10),
	)
	assert.NoError(t, err)
}

func TestClaimCertificate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/ca/"))
		assert.True(t, strings.HasSuffix(r.URL.Path, "/crt"))

		var req api.CertClaimInfo
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)
		assert.Equal(t, "test.example.com", req.Name)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	err := client.ClaimCertificate(
		context.Background(),
		"ca-1",
		&api.CertClaimInfo{
			Name:            "test.example.com",
			Wildcard:        false,
			SubjectAltNames: []string{"test.example.com"},
		},
	)
	assert.NoError(t, err)
}

func TestClaimCertificate_InvalidParams(t *testing.T) {
	client, _ := NewClient("http://localhost:8080")

	tests := []struct {
		name    string
		caID    string
		req     *api.CertClaimInfo
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty caID",
			caID:    "",
			req:     &api.CertClaimInfo{Name: "test.example.com"},
			wantErr: true,
			errMsg:  "caID cannot be empty",
		},
		{
			name:    "nil request",
			caID:    "ca-1",
			req:     nil,
			wantErr: true,
			errMsg:  "claim request cannot be nil",
		},
		{
			name:    "empty certificate name",
			caID:    "ca-1",
			req:     &api.CertClaimInfo{Name: ""},
			wantErr: true,
			errMsg:  "certificate name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.ClaimCertificate(context.Background(), tt.caID, tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetCertificatePEM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/ca/"))
		assert.True(t, strings.HasSuffix(r.URL.Path, "/pem"))
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // ignore error for test
		json.NewEncoder(w).Encode(api.CertResources{
			Certificate: "-----BEGIN CERTIFICATE-----\nMIICrt...",
			Key:         "-----BEGIN PRIVATE KEY-----\nMIIEvQ...",
			Chain:       "-----BEGIN CERTIFICATE-----\nMIICrt...",
			Root:        "-----BEGIN CERTIFICATE-----\nMIICSj...",
		})
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	pem, err := client.GetCertificatePEM(context.Background(), "ca-1", "test.example.com")
	assert.NoError(t, err)
	assert.NotNil(t, pem)
	assert.NotEmpty(t, pem.Certificate)
	assert.NotEmpty(t, pem.Key)
}

func TestGetCertificatePEMChain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasSuffix(r.URL.Path, "/pem/fullchain"))
		//nolint:errcheck // ignore error for test
		fmt.Fprint(w, "-----BEGIN CERTIFICATE-----\nMIICrt...\n-----END CERTIFICATE-----")
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	chain, err := client.GetCertificatePEMChain(context.Background(), "ca-1", "test.example.com")
	assert.NoError(t, err)
	assert.Contains(t, chain, "BEGIN CERTIFICATE")
}

func TestGetCertificatePEMKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasSuffix(r.URL.Path, "/pem/key"))
		//nolint:errcheck // ignore error for test
		fmt.Fprint(w, "-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----")
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	key, err := client.GetCertificatePEMKey(context.Background(), "ca-1", "test.example.com")
	assert.NoError(t, err)
	assert.Contains(t, key, "BEGIN PRIVATE KEY")
}

func TestDeleteCertificate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/ca/"))
		assert.True(t, strings.Contains(r.URL.Path, "/crt/"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	err := client.DeleteCertificate(context.Background(), "ca-1", "test.example.com")
	assert.NoError(t, err)
}

func TestDeleteCertificate_EmptyParams(t *testing.T) {
	client, _ := NewClient("http://localhost:8080")

	tests := []struct {
		name     string
		caID     string
		certName string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "empty caID",
			caID:     "",
			certName: "test.example.com",
			wantErr:  true,
			errMsg:   "caID cannot be empty",
		},
		{
			name:     "empty certificate name",
			caID:     "ca-1",
			certName: "",
			wantErr:  true,
			errMsg:   "certificate name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.DeleteCertificate(context.Background(), tt.caID, tt.certName)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWithSearch(t *testing.T) {
	q := &queryParams{}
	WithSearch("example.com")(q)
	assert.Contains(t, q.queryString, "search")
	assert.Contains(t, q.queryString, "example.com")
}

func TestWithSuffix(t *testing.T) {
	q := &queryParams{}
	WithSuffix(".com")(q)
	assert.Contains(t, q.queryString, "suffix")
	assert.Contains(t, q.queryString, ".com")
}

func TestWithLimit(t *testing.T) {
	q := &queryParams{}
	WithLimit(50)(q)
	assert.Contains(t, q.queryString, "limit")
	assert.Contains(t, q.queryString, "50")
}

func TestWithOffset(t *testing.T) {
	q := &queryParams{}
	WithOffset(100)(q)
	assert.Contains(t, q.queryString, "offset")
	assert.Contains(t, q.queryString, "100")
}

func TestAuthenticationHeaders(t *testing.T) {
	tests := []struct {
		name          string
		apiKey        string
		authToken     string
		wantAPIKey    bool
		wantAuthToken bool
	}{
		{
			name:       "APIKey authentication",
			apiKey:     "test-key",
			wantAPIKey: true,
		},
		{
			name:          "AuthToken authentication",
			authToken:     "test-token",
			wantAuthToken: true,
		},
		{
			name:       "APIKey takes precedence over AuthToken",
			apiKey:     "test-key",
			authToken:  "test-token",
			wantAPIKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.wantAPIKey {
					assert.Equal(t, tt.apiKey, r.Header.Get("X-DNS3L-API-Key"))
				}
				if tt.wantAuthToken {
					authHeader := r.Header.Get("Authorization")
					assert.Contains(t, authHeader, "Bearer "+tt.authToken)
				}
				w.Header().Set("Content-Type", "application/json")
				//nolint:errcheck // ignore error for test
				json.NewEncoder(w).Encode(api.ServerInfo{})
			}))
			defer server.Close()

			var opts []Option
			if tt.apiKey != "" {
				opts = append(opts, WithAPIKey(tt.apiKey))
			}
			if tt.authToken != "" {
				opts = append(opts, WithAuthToken(tt.authToken))
			}

			client, _ := NewClient(server.URL, opts...)
			_, err := client.GetInfo(context.Background())
			assert.NoError(t, err)
		})
	}
}

func TestErrorResponse(t *testing.T) {
	err := ErrorMessage{
		ErrorMsg: api.ErrorMsg{
			Code:    400,
			Message: "Bad Request",
		},
	}
	errStr := err.Error()
	assert.Contains(t, errStr, "400")
	assert.Contains(t, errStr, "Bad Request")
}
