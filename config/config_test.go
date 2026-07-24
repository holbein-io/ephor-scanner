package config

import (
	"os"
	"testing"
	"time"
)

func clearEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"EPHOR_API_URL", "EPHOR_AUTH_HEADER", "EPHOR_AUTH_VALUE",
		"SCAN_NAMESPACES", "SCAN_CONCURRENCY", "SCAN_SEVERITY", "SCAN_WORKLOAD_TYPES",
		"TRIVY_BINARY", "TRIVY_CACHE_DIR", "TRIVY_CACHE_MODE", "TRIVY_CACHE_BACKEND",
		"TRIVY_TIMEOUT", "TRIVY_DB_REPO", "TRIVY_JAVA_DB_REPO", "TRIVY_SKIP_DB_UPDATE",
		"SBOM_ENABLED", "SBOM_FORMAT",
		"LOG_LEVEL", "LOG_FORMAT",
	}
	for _, k := range keys {
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("failed to unset %s: %v", k, err)
		}
	}
}

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("EPHOR_API_URL", "https://api.example.com")
	t.Setenv("SCAN_NAMESPACES", "prod,staging")
}

func TestLoad_MissingRequiredVars(t *testing.T) {
	clearEnv(t)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when required vars are missing")
	}

	t.Setenv("EPHOR_API_URL", "https://api.example.com")
	_, err = Load()
	if err == nil {
		t.Fatal("expected error when SCAN_NAMESPACES is missing")
	}
}

func TestLoad_Defaults(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ScanConcurrency != 3 {
		t.Errorf("ScanConcurrency = %d, want 3", cfg.ScanConcurrency)
	}
	if cfg.TrivyBinary != "trivy" {
		t.Errorf("TrivyBinary = %q, want %q", cfg.TrivyBinary, "trivy")
	}
	if cfg.TrivyCacheDir != "/tmp/trivy-cache" {
		t.Errorf("TrivyCacheDir = %q, want %q", cfg.TrivyCacheDir, "/tmp/trivy-cache")
	}
	if cfg.TrivyScanTimeout != 5*time.Minute {
		t.Errorf("TrivyScanTimeout = %v, want %v", cfg.TrivyScanTimeout, 5*time.Minute)
	}
	if cfg.TrivySkipDBUpdate != false {
		t.Errorf("TrivySkipDBUpdate = %v, want false", cfg.TrivySkipDBUpdate)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, "json")
	}
	if len(cfg.ScanSeverity) != 4 {
		t.Errorf("ScanSeverity length = %d, want 4", len(cfg.ScanSeverity))
	}
	if len(cfg.ScanWorkloadTypes) != 4 {
		t.Errorf("ScanWorkloadTypes length = %d, want 4", len(cfg.ScanWorkloadTypes))
	}
	if cfg.SBOMEnabled != false {
		t.Errorf("SBOMEnabled = %v, want false", cfg.SBOMEnabled)
	}
	if cfg.SBOMFormat != "cyclonedx" {
		t.Errorf("SBOMFormat = %q, want %q", cfg.SBOMFormat, "cyclonedx")
	}
}

func TestLoad_CommaParsing(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("SCAN_SEVERITY", "CRITICAL , HIGH")
	t.Setenv("SCAN_WORKLOAD_TYPES", "Deployment,CronJob")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.ScanNamespaces) != 2 || cfg.ScanNamespaces[0] != "prod" || cfg.ScanNamespaces[1] != "staging" {
		t.Errorf("ScanNamespaces = %v, want [prod staging]", cfg.ScanNamespaces)
	}
	if len(cfg.ScanSeverity) != 2 || cfg.ScanSeverity[0] != CRITICAL || cfg.ScanSeverity[1] != HIGH {
		t.Errorf("ScanSeverity = %v, want [CRITICAL HIGH]", cfg.ScanSeverity)
	}
	if len(cfg.ScanWorkloadTypes) != 2 || cfg.ScanWorkloadTypes[0] != Deployment || cfg.ScanWorkloadTypes[1] != CronJob {
		t.Errorf("ScanWorkloadTypes = %v, want [Deployment CronJob]", cfg.ScanWorkloadTypes)
	}
}

func TestLoad_CustomOverrides(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("SCAN_CONCURRENCY", "10")
	t.Setenv("TRIVY_BINARY", "/usr/bin/trivy")
	t.Setenv("TRIVY_TIMEOUT", "10m")
	t.Setenv("TRIVY_SKIP_DB_UPDATE", "true")
	t.Setenv("LOG_LEVEL", "debug")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ScanConcurrency != 10 {
		t.Errorf("ScanConcurrency = %d, want 10", cfg.ScanConcurrency)
	}
	if cfg.TrivyBinary != "/usr/bin/trivy" {
		t.Errorf("TrivyBinary = %q, want %q", cfg.TrivyBinary, "/usr/bin/trivy")
	}
	if cfg.TrivyScanTimeout != 10*time.Minute {
		t.Errorf("TrivyScanTimeout = %v, want %v", cfg.TrivyScanTimeout, 10*time.Minute)
	}
	if cfg.TrivySkipDBUpdate != true {
		t.Errorf("TrivySkipDBUpdate = %v, want true", cfg.TrivySkipDBUpdate)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
}

func TestLoad_SBOMCustomValues(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("SBOM_ENABLED", "true")
	t.Setenv("SBOM_FORMAT", "spdx-json")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.SBOMEnabled != true {
		t.Errorf("SBOMEnabled = %v, want true", cfg.SBOMEnabled)
	}
	if cfg.SBOMFormat != "spdx-json" {
		t.Errorf("SBOMFormat = %q, want %q", cfg.SBOMFormat, "spdx-json")
	}
}

func TestLoad_SBOMInvalidFormatFallsBack(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("SBOM_FORMAT", "invalid-format")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.SBOMFormat != "cyclonedx" {
		t.Errorf("SBOMFormat = %q, want %q (fallback)", cfg.SBOMFormat, "cyclonedx")
	}
}

func TestLoad_CacheModeDefault(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TrivyCacheMode != CacheModeEphemeral {
		t.Errorf("TrivyCacheMode = %q, want %q", cfg.TrivyCacheMode, CacheModeEphemeral)
	}
}

func TestLoad_CacheModeSharedForcesSerial(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("TRIVY_CACHE_MODE", "shared")
	t.Setenv("SCAN_CONCURRENCY", "5")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ScanConcurrency != 1 {
		t.Errorf("ScanConcurrency = %d, want 1 (shared cache forces serial)", cfg.ScanConcurrency)
	}
}

func TestLoad_CacheModeRedisRequiresBackend(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("TRIVY_CACHE_MODE", "redis")

	if _, err := Load(); err == nil {
		t.Fatal("expected error when TRIVY_CACHE_MODE=redis without TRIVY_CACHE_BACKEND")
	}

	t.Setenv("TRIVY_CACHE_BACKEND", "redis://localhost:6379")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error with backend set: %v", err)
	}
	if cfg.TrivyCacheMode != CacheModeRedis {
		t.Errorf("TrivyCacheMode = %q, want %q", cfg.TrivyCacheMode, CacheModeRedis)
	}
}

func TestLoad_CacheModeInvalidFallsBack(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("TRIVY_CACHE_MODE", "bogus")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TrivyCacheMode != CacheModeEphemeral {
		t.Errorf("TrivyCacheMode = %q, want %q (fallback)", cfg.TrivyCacheMode, CacheModeEphemeral)
	}
}
