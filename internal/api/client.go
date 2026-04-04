package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"ephor-scanner/config"
	"ephor-scanner/internal/models"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseUrl    string
	AuthHeader string
	AuthValue  string
	Version    string
	HTTPClient *http.Client
}

func NewClient(cfg *config.Config, version string) *Client {
	return &Client{
		BaseUrl:    cfg.EphorAPIUrl,
		AuthHeader: cfg.EphorAuthHeader,
		AuthValue:  cfg.EphorAuthValue,
		Version:    version,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) IngestScan(ctx context.Context, request *models.ScanIngestRequest) (*models.ScanIngestResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	var result models.ScanIngestResponse
	if err := c.doPost(ctx, PathScanIngest, body, false, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) IngestSBOM(ctx context.Context, request *models.SBOMIngestRequest) (*models.SBOMIngestResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	var result models.SBOMIngestResponse
	if err := c.doPost(ctx, PathSBOMIngest, body, true, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) doPost(ctx context.Context, path string, body []byte, compress bool, result any) error {
	url := c.BaseUrl + path

	var reader io.Reader
	if compress {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(body); err != nil {
			return fmt.Errorf("gzip compression failed: %w", err)
		}
		if err := gz.Close(); err != nil {
			return fmt.Errorf("gzip close failed: %w", err)
		}
		reader = &buf
	} else {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reader)
	if err != nil {
		return err
	}

	req.Header.Set(HeaderContentType, ContentTypeJSON)
	req.Header.Set(HeaderUserAgent, UserAgentPrefix+c.Version)
	if compress {
		req.Header.Set(HeaderContentEncoding, EncodingGzip)
	}
	if c.AuthHeader != "" && c.AuthValue != "" {
		req.Header.Set(c.AuthHeader, c.AuthValue)
	}

	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = rsp.Body.Close() }()

	if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(rsp.Body)
		return &APIError{
			StatusCode: rsp.StatusCode,
			Body:       string(respBody),
		}
	}

	return json.NewDecoder(rsp.Body).Decode(result)
}

type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api error: status %d, body: %s", e.StatusCode, e.Body)
}
