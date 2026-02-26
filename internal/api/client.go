package api

import (
	"bytes"
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
	url := c.BaseUrl + "/api/v1/scans/ingest"
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ephor-scanner/"+c.Version)
	if c.AuthHeader != "" && c.AuthValue != "" {
		req.Header.Set(c.AuthHeader, c.AuthValue)
	}

	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(rsp.Body)
		return nil, &APIError{
			StatusCode: rsp.StatusCode,
			Body:       string(respBody),
		}
	}

	var result models.ScanIngestResponse
	if err := json.NewDecoder(rsp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api error: status %d, body: %s", e.StatusCode, e.Body)
}
