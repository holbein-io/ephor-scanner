package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// shared reuses one on-disk cache but its exclusive BoltDB lock forces serial
// scans; redis shares a lock-free backend so scans stay concurrent.
const (
	CacheModeEphemeral = "ephemeral"
	CacheModeShared    = "shared"
	CacheModeRedis     = "redis"
)

type Config struct {
	EphorAPIUrl     string
	EphorAuthHeader string
	EphorAuthValue  string

	ScanNamespaces    []string
	ScanConcurrency   int
	ScanSeverity      []Severity
	ScanWorkloadTypes []WorkloadTypes

	TrivyBinary          string
	TrivyCacheDir        string
	TrivyCacheMode       string
	TrivyCacheBackend    string
	TrivyScanTimeout     time.Duration
	TrivyDBUpdateTimeout time.Duration

	TrivyDBRepo       string
	TrivyJavaDBRepo   string
	TrivySkipDBUpdate bool

	SBOMEnabled bool
	SBOMFormat  string

	LogLevel  string
	LogFormat string
}

type Severity int
type WorkloadTypes int

const (
	CRITICAL Severity = iota
	HIGH
	MEDIUM
	LOW
)

const (
	Deployment WorkloadTypes = iota
	StatefulSet
	DaemonSet
	CronJob
)

var severityMap = map[string]Severity{
	"CRITICAL": CRITICAL,
	"HIGH":     HIGH,
	"MEDIUM":   MEDIUM,
	"LOW":      LOW,
}

var workloadTypeMap = map[string]WorkloadTypes{
	"Deployment":  Deployment,
	"StatefulSet": StatefulSet,
	"DaemonSet":   DaemonSet,
	"CronJob":     CronJob,
}

func (s Severity) String() string {
	switch s {
	case CRITICAL:
		return "CRITICAL"
	case HIGH:
		return "HIGH"
	case MEDIUM:
		return "MEDIUM"
	case LOW:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func (w WorkloadTypes) String() string {
	switch w {
	case Deployment:
		return "Deployment"
	case StatefulSet:
		return "StatefulSet"
	case DaemonSet:
		return "DaemonSet"
	case CronJob:
		return "CronJob"
	default:
		return "Unknown"
	}
}

func parseSeverities(raw string) []Severity {
	if raw == "" {
		return []Severity{CRITICAL, HIGH, MEDIUM, LOW}
	}
	var result []Severity
	for _, s := range strings.Split(raw, ",") {
		if sev, ok := severityMap[strings.TrimSpace(s)]; ok {
			result = append(result, sev)
		}
	}
	if len(result) == 0 {
		return []Severity{CRITICAL, HIGH, MEDIUM, LOW}
	}
	return result
}

func parseWorkloadTypes(raw string) []WorkloadTypes {
	if raw == "" {
		return []WorkloadTypes{Deployment, StatefulSet, DaemonSet, CronJob}
	}
	var result []WorkloadTypes
	for _, s := range strings.Split(raw, ",") {
		if wt, ok := workloadTypeMap[strings.TrimSpace(s)]; ok {
			result = append(result, wt)
		}
	}
	if len(result) == 0 {
		return []WorkloadTypes{Deployment, StatefulSet, DaemonSet, CronJob}
	}
	return result
}

func Load() (*Config, error) {
	var missing []string
	if os.Getenv("EPHOR_API_URL") == "" {
		missing = append(missing, "EPHOR_API_URL")
	}
	if os.Getenv("SCAN_NAMESPACES") == "" {
		missing = append(missing, "SCAN_NAMESPACES")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	cfg := &Config{
		EphorAPIUrl:     os.Getenv("EPHOR_API_URL"),
		EphorAuthHeader: os.Getenv("EPHOR_AUTH_HEADER"),
		EphorAuthValue:  os.Getenv("EPHOR_AUTH_VALUE"),

		ScanNamespaces:    strings.Split(os.Getenv("SCAN_NAMESPACES"), ","),
		ScanConcurrency:   getIntEnv("SCAN_CONCURRENCY", 3),
		ScanSeverity:      parseSeverities(os.Getenv("SCAN_SEVERITY")),
		ScanWorkloadTypes: parseWorkloadTypes(os.Getenv("SCAN_WORKLOAD_TYPES")),

		TrivyBinary:          GetEnvOrDefault("TRIVY_BINARY", "trivy"),
		TrivyCacheDir:        GetEnvOrDefault("TRIVY_CACHE_DIR", "/tmp/trivy-cache"),
		TrivyCacheMode:       parseCacheMode(GetEnvOrDefault("TRIVY_CACHE_MODE", CacheModeEphemeral)),
		TrivyCacheBackend:    GetEnvOrDefault("TRIVY_CACHE_BACKEND", ""),
		TrivyScanTimeout:     getDurationEnv("TRIVY_TIMEOUT", 5*time.Minute),
		TrivyDBUpdateTimeout: getDurationEnv("TRIVY_DB_UPDATE_TIMEOUT", 1*time.Minute),

		TrivyDBRepo:       GetEnvOrDefault("TRIVY_DB_REPO", ""),
		TrivyJavaDBRepo:   GetEnvOrDefault("TRIVY_JAVA_DB_REPO", ""),
		TrivySkipDBUpdate: getBoolEnvOrDefault("TRIVY_SKIP_DB_UPDATE", false),

		SBOMEnabled: getBoolEnvOrDefault("SBOM_ENABLED", false),
		SBOMFormat:  parseSBOMFormat(GetEnvOrDefault("SBOM_FORMAT", "cyclonedx")),

		LogLevel:  GetEnvOrDefault("LOG_LEVEL", "info"),
		LogFormat: GetEnvOrDefault("LOG_FORMAT", "json"),
	}

	if cfg.TrivyCacheMode == CacheModeRedis && cfg.TrivyCacheBackend == "" {
		return nil, fmt.Errorf("TRIVY_CACHE_BACKEND is required when TRIVY_CACHE_MODE=redis")
	}
	if cfg.TrivyCacheMode == CacheModeShared && cfg.ScanConcurrency > 1 {
		slog.Warn("TRIVY_CACHE_MODE=shared uses a single locked cache; forcing concurrency to 1",
			"requested_concurrency", cfg.ScanConcurrency)
		cfg.ScanConcurrency = 1
	}

	return cfg, nil
}

func parseCacheMode(raw string) string {
	switch strings.ToLower(raw) {
	case CacheModeShared:
		return CacheModeShared
	case CacheModeRedis:
		return CacheModeRedis
	default:
		return CacheModeEphemeral
	}
}

func parseSBOMFormat(raw string) string {
	switch strings.ToLower(raw) {
	case "cyclonedx":
		return "cyclonedx"
	case "spdx-json":
		return "spdx-json"
	default:
		return "cyclonedx"
	}
}

func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnvOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if seconds, err := strconv.Atoi(value); err == nil {
			return time.Duration(seconds) * time.Second
		}
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
