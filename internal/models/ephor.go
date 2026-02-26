package models

import (
	"strings"
	"time"
)

// SplitImageRef splits a container image reference into name and tag.
// Handles registry ports (registry.io:5000/repo:tag), digest references
// (image@sha256:abc), and defaults to "latest" when no tag is present.
func SplitImageRef(ref string) (name, tag string) {
	if i := strings.Index(ref, "@"); i != -1 {
		return ref[:i], ref[i+1:]
	}

	i := strings.LastIndex(ref, ":")
	if i == -1 {
		return ref, "latest"
	}

	// If the part after the last colon contains a slash, it's a port not a tag
	if strings.Contains(ref[i+1:], "/") {
		return ref, "latest"
	}

	return ref[:i], ref[i+1:]
}

type ScanIngestRequest struct {
	Namespace    string         `json:"namespace"`
	ScanLabel    string         `json:"scan_label"`
	ScanGroupId  string         `json:"scan_group_id"`
	Status       ScanStatus     `json:"status"`
	StartedAt    *time.Time     `json:"started_at,omitempty"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
	TrivyVersion string         `json:"trivy_version,omitempty"`
	ScanConfig   map[string]any `json:"scan_config"`
	Workloads    []WorkloadData `json:"workloads"`
}

type WorkloadData struct {
	Namespace  string          `json:"namespace"`
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	Containers []ContainerData `json:"containers"`
}

type ContainerData struct {
	Name             string              `json:"name"`
	ImageName        string              `json:"image_name"`
	ImageTag         string              `json:"image_tag"`
	ImageCreated     *time.Time          `json:"image_created,omitempty"`
	BaseImageCreated *time.Time          `json:"base_image_created,omitempty"`
	Vulnerabilities  []VulnerabilityData `json:"vulnerabilities"`
}

type VulnerabilityData struct {
	CveId          string     `json:"cve_id"`
	PackageName    string     `json:"package_name"`
	PackageVersion string     `json:"package_version"`
	Severity       string     `json:"severity"`
	Title          string     `json:"title,omitempty"`
	Description    string     `json:"description,omitempty"`
	PrimaryURL     string     `json:"primary_url,omitempty"`
	PublishedDate  *time.Time `json:"published_date,omitempty"`
	FixedVersion   string     `json:"fixed_version,omitempty"`
	ScannerType    string     `json:"scanner_type"`
	FirstDetected  *time.Time `json:"first_detected,omitempty"`
	LastSeen       *time.Time `json:"last_seen,omitempty"`
}

type ScanIngestResponse struct {
	ScanId          int64 `json:"scan_id"`
	Vulnerabilities int   `json:"vulnerabilities"`
	Workloads       int   `json:"workloads"`
	CriticalVulns   int   `json:"critical_vulns"`
	AutoResolved    int   `json:"auto_resolved"`
	Reopened        int   `json:"reopened"`
}

type ScanStatus string

const (
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
)
