package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"ephor-scanner/internal/models"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIngestScan_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/scans/ingest" {
			t.Errorf("expected /api/v1/scans/ingest, got %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("User-Agent") != "ephor-scanner/v1.0.0" {
			t.Errorf("expected User-Agent ephor-scanner/v1.0.0, got %s", r.Header.Get("User-Agent"))
		}

		var req models.ScanIngestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if req.Namespace != "prod" {
			t.Errorf("expected namespace prod, got %s", req.Namespace)
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.ScanIngestResponse{
			ScanId:          42,
			Vulnerabilities: 5,
			Workloads:       2,
			CriticalVulns:   1,
		})
	}))
	defer server.Close()

	client := &Client{
		BaseUrl:    server.URL,
		Version:    "v1.0.0",
		HTTPClient: server.Client(),
	}

	resp, err := client.IngestScan(context.Background(), &models.ScanIngestRequest{
		Namespace: "prod",
		ScanLabel: "test-scan",
		Status:    models.ScanStatusCompleted,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ScanId != 42 {
		t.Errorf("ScanId = %d, want 42", resp.ScanId)
	}
	if resp.Vulnerabilities != 5 {
		t.Errorf("Vulnerabilities = %d, want 5", resp.Vulnerabilities)
	}
	if resp.CriticalVulns != 1 {
		t.Errorf("CriticalVulns = %d, want 1", resp.CriticalVulns)
	}
}

func TestIngestScan_ClientError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, `{"error":"validation failed"}`)
	}))
	defer server.Close()

	client := &Client{
		BaseUrl:    server.URL,
		Version:    "v1.0.0",
		HTTPClient: server.Client(),
	}

	_, err := client.IngestScan(context.Background(), &models.ScanIngestRequest{})
	if err == nil {
		t.Fatal("expected error for 422 response")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 422 {
		t.Errorf("StatusCode = %d, want 422", apiErr.StatusCode)
	}
	if apiErr.Body != `{"error":"validation failed"}` {
		t.Errorf("Body = %q, want %q", apiErr.Body, `{"error":"validation failed"}`)
	}
}

func TestIngestScan_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "internal server error")
	}))
	defer server.Close()

	client := &Client{
		BaseUrl:    server.URL,
		Version:    "v1.0.0",
		HTTPClient: server.Client(),
	}

	_, err := client.IngestScan(context.Background(), &models.ScanIngestRequest{})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", apiErr.StatusCode)
	}
}

func TestIngestScan_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &Client{
		BaseUrl: server.URL,
		Version: "v1.0.0",
		HTTPClient: &http.Client{
			Timeout: 50 * time.Millisecond,
		},
	}

	_, err := client.IngestScan(context.Background(), &models.ScanIngestRequest{})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestIngestSBOM_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sbom/ingest" {
			t.Errorf("expected /api/v1/sbom/ingest, got %s", r.URL.Path)
		}
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("expected Content-Encoding gzip, got %s", r.Header.Get("Content-Encoding"))
		}

		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Fatalf("failed to create gzip reader: %v", err)
		}
		defer func() { _ = gz.Close() }()

		var req models.SBOMIngestRequest
		if err := json.NewDecoder(gz).Decode(&req); err != nil {
			t.Fatalf("failed to decode gzipped request body: %v", err)
		}
		if req.ImageReference != "nginx:1.25" {
			t.Errorf("expected image_reference nginx:1.25, got %s", req.ImageReference)
		}
		if req.Format != "cyclonedx" {
			t.Errorf("expected format cyclonedx, got %s", req.Format)
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.SBOMIngestResponse{
			ImageReference: "nginx:1.25",
			Stored:         true,
		})
	}))
	defer server.Close()

	client := &Client{
		BaseUrl:    server.URL,
		Version:    "v1.0.0",
		HTTPClient: server.Client(),
	}

	resp, err := client.IngestSBOM(context.Background(), &models.SBOMIngestRequest{
		ImageReference: "nginx:1.25",
		ScanGroupId:    "test-group",
		Format:         "cyclonedx",
		SBOM:           json.RawMessage(`{"bomFormat":"CycloneDX"}`),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Stored {
		t.Error("expected Stored = true")
	}
}

func TestIngestScan_AuthHeader(t *testing.T) {
	var gotAuthHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("X-Auth-Token")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.ScanIngestResponse{})
	}))
	defer server.Close()

	// With auth configured
	client := &Client{
		BaseUrl:    server.URL,
		Version:    "v1.0.0",
		AuthHeader: "X-Auth-Token",
		AuthValue:  "secret-token",
		HTTPClient: server.Client(),
	}

	_, err := client.IngestScan(context.Background(), &models.ScanIngestRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuthHeader != "secret-token" {
		t.Errorf("auth header = %q, want %q", gotAuthHeader, "secret-token")
	}

	// Without auth configured
	gotAuthHeader = ""
	client = &Client{
		BaseUrl:    server.URL,
		Version:    "v1.0.0",
		HTTPClient: server.Client(),
	}

	_, err = client.IngestScan(context.Background(), &models.ScanIngestRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuthHeader != "" {
		t.Errorf("expected no auth header, got %q", gotAuthHeader)
	}
}
