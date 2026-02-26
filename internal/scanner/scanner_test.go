package scanner

import (
	"encoding/json"
	"os"
	"testing"
)

func TestParseScanReport(t *testing.T) {
	data, err := os.ReadFile("testdata/scan_report.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var report TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse fixture: %v", err)
	}

	if report.SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d, want 2", report.SchemaVersion)
	}
	if report.ArtifactName != "nginx:1.25" {
		t.Errorf("ArtifactName = %q, want %q", report.ArtifactName, "nginx:1.25")
	}
	if len(report.Results) != 2 {
		t.Fatalf("Results length = %d, want 2", len(report.Results))
	}

	// First result: os-pkgs with 2 vulns
	osResult := report.Results[0]
	if osResult.Target != "nginx:1.25 (debian 12.4)" {
		t.Errorf("Results[0].Target = %q, want %q", osResult.Target, "nginx:1.25 (debian 12.4)")
	}
	if osResult.Class != "os-pkgs" {
		t.Errorf("Results[0].Class = %q, want %q", osResult.Class, "os-pkgs")
	}
	if len(osResult.Vulnerabilities) != 2 {
		t.Fatalf("Results[0].Vulnerabilities length = %d, want 2", len(osResult.Vulnerabilities))
	}

	// Check a vuln with FixedVersion
	critical := osResult.Vulnerabilities[0]
	if critical.VulnerabilityID != "CVE-2024-1234" {
		t.Errorf("VulnerabilityID = %q, want %q", critical.VulnerabilityID, "CVE-2024-1234")
	}
	if critical.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want %q", critical.Severity, "CRITICAL")
	}
	if critical.FixedVersion != "3.0.13" {
		t.Errorf("FixedVersion = %q, want %q", critical.FixedVersion, "3.0.13")
	}

	// Check a vuln without FixedVersion
	low := osResult.Vulnerabilities[1]
	if low.FixedVersion != "" {
		t.Errorf("FixedVersion = %q, want empty", low.FixedVersion)
	}
	if low.Status != "affected" {
		t.Errorf("Status = %q, want %q", low.Status, "affected")
	}

	// Second result: lang-pkgs
	langResult := report.Results[1]
	if langResult.Class != "lang-pkgs" {
		t.Errorf("Results[1].Class = %q, want %q", langResult.Class, "lang-pkgs")
	}
	if langResult.Type != "gomod" {
		t.Errorf("Results[1].Type = %q, want %q", langResult.Type, "gomod")
	}
}

func TestParseVersion(t *testing.T) {
	data, err := os.ReadFile("testdata/version.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var version TrivyVersion
	if err := json.Unmarshal(data, &version); err != nil {
		t.Fatalf("failed to parse fixture: %v", err)
	}

	if version.Version != "0.67.2" {
		t.Errorf("Version = %q, want %q", version.Version, "0.67.2")
	}
	if version.VulnerabilityDB.Version != 2 {
		t.Errorf("VulnerabilityDB.Version = %d, want 2", version.VulnerabilityDB.Version)
	}
	if version.JavaDB.Version != 1 {
		t.Errorf("JavaDB.Version = %d, want 1", version.JavaDB.Version)
	}
	if version.CheckBundle.Digest == "" {
		t.Error("CheckBundle.Digest should not be empty")
	}
}

func TestParseScanReport_IgnoresUnknownFields(t *testing.T) {
	// Trivy may add new fields in future versions - our parser should not break
	data := []byte(`{
		"SchemaVersion": 2,
		"ArtifactName": "test:latest",
		"ArtifactType": "container_image",
		"SomeNewField": "should be ignored",
		"Metadata": {"OS": {"Family": "debian"}},
		"Results": [{
			"Target": "test:latest",
			"Class": "os-pkgs",
			"Type": "debian",
			"Packages": [{"Name": "apt", "Version": "2.6.1"}],
			"Vulnerabilities": []
		}]
	}`)

	var report TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("should not fail on unknown fields: %v", err)
	}
	if report.ArtifactName != "test:latest" {
		t.Errorf("ArtifactName = %q, want %q", report.ArtifactName, "test:latest")
	}
	if len(report.Results) != 1 {
		t.Fatalf("Results length = %d, want 1", len(report.Results))
	}
}
