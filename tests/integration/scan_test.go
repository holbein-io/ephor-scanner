//go:build integration

package integration

import (
	"context"
	"ephor-scanner/config"
	"ephor-scanner/internal/discovery"
	"ephor-scanner/internal/models"
	"ephor-scanner/internal/processor"
	"ephor-scanner/internal/scanner"
	"testing"
	"time"
)

func newTestScanner() *scanner.Scanner {
	return scanner.NewScanner(&config.Config{
		TrivyBinary:          "trivy",
		TrivyCacheDir:        "/tmp/trivy-cache-test",
		TrivyScanTimeout:     5 * time.Minute,
		TrivyDBUpdateTimeout: 2 * time.Minute,
		TrivySkipDBUpdate:    false,
	})
}

func TestScanImage_Real(t *testing.T) {
	s := newTestScanner()
	ctx := context.Background()

	report, err := s.ScanImage(ctx, "alpine:3.21")
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}

	if report.ArtifactName == "" {
		t.Error("ArtifactName is empty")
	}
	if report.SchemaVersion == 0 {
		t.Error("SchemaVersion is 0")
	}
	if len(report.Results) == 0 {
		t.Error("Results is empty, expected at least one result target")
	}

	for i, r := range report.Results {
		if r.Target == "" {
			t.Errorf("Results[%d].Target is empty", i)
		}
		if r.Class == "" {
			t.Errorf("Results[%d].Class is empty", i)
		}
	}
}

func TestScanAndTransform_EndToEnd(t *testing.T) {
	s := newTestScanner()
	ctx := context.Background()

	report, err := s.ScanImage(ctx, "alpine:3.21")
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}

	workloads := []discovery.Workload{
		{
			Namespace: "default",
			Name:      "test-deploy",
			Kind:      "Deployment",
			Containers: []discovery.Container{
				{Name: "app", Image: "alpine:3.21"},
			},
		},
	}

	scanResults := map[string]*processor.ScanResult{
		"alpine:3.21": {Report: report},
	}

	meta := processor.ScanMeta{
		ScanGroupID:  "integration-test-id",
		ScanLabel:    "integration-test",
		TrivyVersion: "0.69.1",
		StartedAt:    time.Now(),
	}

	payload := processor.BuildNamespacePayload("default", workloads, scanResults, meta)

	if payload.Namespace != "default" {
		t.Errorf("Namespace = %q, want default", payload.Namespace)
	}
	if payload.Status != models.ScanStatusCompleted {
		t.Errorf("Status = %q, want %q", payload.Status, models.ScanStatusCompleted)
	}
	if len(payload.Workloads) != 1 {
		t.Fatalf("expected 1 workload, got %d", len(payload.Workloads))
	}

	c := payload.Workloads[0].Containers[0]
	if c.Name != "app" {
		t.Errorf("Container.Name = %q, want app", c.Name)
	}
	if c.ImageName != "alpine" {
		t.Errorf("ImageName = %q, want alpine", c.ImageName)
	}
	if c.ImageTag != "3.21" {
		t.Errorf("ImageTag = %q, want 3.21", c.ImageTag)
	}

	for i, v := range c.Vulnerabilities {
		if v.CveId == "" {
			t.Errorf("Vulnerability[%d].CveId is empty", i)
		}
		if v.Severity == "" {
			t.Errorf("Vulnerability[%d].Severity is empty", i)
		}
		if v.PackageName == "" {
			t.Errorf("Vulnerability[%d].PackageName is empty", i)
		}
	}
}
