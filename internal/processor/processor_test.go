package processor

import (
	"ephor-scanner/internal/discovery"
	"ephor-scanner/internal/models"
	"ephor-scanner/internal/scanner"
	"fmt"
	"testing"
	"time"
)

var testMeta = ScanMeta{
	ScanGroupID:  "test-group-123",
	ScanLabel:    "test-scan",
	TrivyVersion: "0.58.0",
	StartedAt:    time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC),
}

func TestBuildNamespacePayload_AllSuccess(t *testing.T) {
	workloads := []discovery.Workload{
		{
			Namespace: "prod",
			Name:      "web",
			Kind:      "Deployment",
			Containers: []discovery.Container{
				{Name: "nginx", Image: "nginx:1.25"},
				{Name: "sidecar", Image: "envoy:v1.30"},
			},
		},
	}

	scanResults := map[string]*ScanResult{
		"nginx:1.25": {
			Report: &scanner.TrivyReport{
				Results: []scanner.TrivyResult{
					{
						Type: "os",
						Vulnerabilities: []scanner.TrivyVulnerability{
							{
								VulnerabilityID:  "CVE-2024-0001",
								PkgName:          "openssl",
								InstalledVersion: "3.0.1",
								FixedVersion:     "3.0.2",
								Severity:         "CRITICAL",
								Title:            "Buffer overflow in openssl",
								PublishedDate:    "2024-01-15T00:00:00Z",
							},
						},
					},
				},
			},
		},
		"envoy:v1.30": {
			Report: &scanner.TrivyReport{
				Results: []scanner.TrivyResult{},
			},
		},
	}

	payload := BuildNamespacePayload("prod", workloads, scanResults, testMeta)

	if payload.Status != models.ScanStatusCompleted {
		t.Errorf("Status = %q, want %q", payload.Status, models.ScanStatusCompleted)
	}
	if payload.Namespace != "prod" {
		t.Errorf("Namespace = %q, want %q", payload.Namespace, "prod")
	}
	if payload.ScanGroupId != "test-group-123" {
		t.Errorf("ScanGroupId = %q, want %q", payload.ScanGroupId, "test-group-123")
	}
	if payload.TrivyVersion != "0.58.0" {
		t.Errorf("TrivyVersion = %q, want %q", payload.TrivyVersion, "0.58.0")
	}
	if len(payload.Workloads) != 1 {
		t.Fatalf("expected 1 workload, got %d", len(payload.Workloads))
	}

	containers := payload.Workloads[0].Containers
	if len(containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(containers))
	}

	// nginx container should have 1 vulnerability
	nginx := containers[0]
	if nginx.ImageName != "nginx" || nginx.ImageTag != "1.25" {
		t.Errorf("nginx: ImageName=%q ImageTag=%q, want nginx:1.25", nginx.ImageName, nginx.ImageTag)
	}
	if len(nginx.Vulnerabilities) != 1 {
		t.Fatalf("nginx: expected 1 vulnerability, got %d", len(nginx.Vulnerabilities))
	}
	vuln := nginx.Vulnerabilities[0]
	if vuln.CveId != "CVE-2024-0001" {
		t.Errorf("CveId = %q, want CVE-2024-0001", vuln.CveId)
	}
	if vuln.ScannerType != "os" {
		t.Errorf("ScannerType = %q, want os", vuln.ScannerType)
	}
	if vuln.PublishedDate == nil {
		t.Error("PublishedDate is nil, expected parsed time")
	}

	// envoy container should have 0 vulnerabilities
	envoy := containers[1]
	if envoy.ImageName != "envoy" || envoy.ImageTag != "v1.30" {
		t.Errorf("envoy: ImageName=%q ImageTag=%q, want envoy:v1.30", envoy.ImageName, envoy.ImageTag)
	}
	if len(envoy.Vulnerabilities) != 0 {
		t.Errorf("envoy: expected 0 vulnerabilities, got %d", len(envoy.Vulnerabilities))
	}
}

func TestBuildNamespacePayload_PartialFailure(t *testing.T) {
	workloads := []discovery.Workload{
		{
			Namespace: "prod",
			Name:      "app",
			Kind:      "Deployment",
			Containers: []discovery.Container{
				{Name: "api", Image: "myapp:v1"},
				{Name: "worker", Image: "private.io:5000/worker:latest"},
			},
		},
	}

	scanResults := map[string]*ScanResult{
		"myapp:v1": {
			Report: &scanner.TrivyReport{
				Results: []scanner.TrivyResult{
					{
						Type: "gomod",
						Vulnerabilities: []scanner.TrivyVulnerability{
							{
								VulnerabilityID:  "CVE-2024-0002",
								PkgName:          "golang.org/x/net",
								InstalledVersion: "0.17.0",
								Severity:         "HIGH",
							},
						},
					},
				},
			},
		},
		"private.io:5000/worker:latest": {
			Err: fmt.Errorf("failed to pull image: unauthorized"),
		},
	}

	payload := BuildNamespacePayload("prod", workloads, scanResults, testMeta)

	// One succeeded, one failed → still completed
	if payload.Status != models.ScanStatusCompleted {
		t.Errorf("Status = %q, want %q", payload.Status, models.ScanStatusCompleted)
	}

	containers := payload.Workloads[0].Containers

	// api container has vulnerabilities
	if len(containers[0].Vulnerabilities) != 1 {
		t.Errorf("api: expected 1 vulnerability, got %d", len(containers[0].Vulnerabilities))
	}

	// worker container has empty vulnerabilities (scan failed)
	if len(containers[1].Vulnerabilities) != 0 {
		t.Errorf("worker: expected 0 vulnerabilities, got %d", len(containers[1].Vulnerabilities))
	}
	if containers[1].ImageName != "private.io:5000/worker" || containers[1].ImageTag != "latest" {
		t.Errorf("worker: ImageName=%q ImageTag=%q, want private.io:5000/worker:latest",
			containers[1].ImageName, containers[1].ImageTag)
	}
}

func TestBuildNamespacePayload_AllFailure(t *testing.T) {
	workloads := []discovery.Workload{
		{
			Namespace: "prod",
			Name:      "broken",
			Kind:      "StatefulSet",
			Containers: []discovery.Container{
				{Name: "db", Image: "postgres:16"},
			},
		},
	}

	scanResults := map[string]*ScanResult{
		"postgres:16": {
			Err: fmt.Errorf("trivy: timeout scanning image"),
		},
	}

	payload := BuildNamespacePayload("prod", workloads, scanResults, testMeta)

	if payload.Status != models.ScanStatusFailed {
		t.Errorf("Status = %q, want %q", payload.Status, models.ScanStatusFailed)
	}

	if len(payload.Workloads[0].Containers[0].Vulnerabilities) != 0 {
		t.Errorf("expected 0 vulnerabilities for failed scan, got %d",
			len(payload.Workloads[0].Containers[0].Vulnerabilities))
	}
}
