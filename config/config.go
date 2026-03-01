package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
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
	TrivyScanTimeout     time.Duration
	TrivyDBUpdateTimeout time.Duration

	TrivyDBRepo       string
	TrivySkipDBUpdate bool

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
		TrivyScanTimeout:     getDurationEnv("TRIVY_TIMEOUT", 5*time.Minute),
		TrivyDBUpdateTimeout: getDurationEnv("TRIVY_DB_UPDATE_TIMEOUT", 1*time.Minute),

		TrivyDBRepo:       GetEnvOrDefault("TRIVY_DB_REPO", ""),
		TrivySkipDBUpdate: getBoolEnvOrDefault("TRIVY_SKIP_DB_UPDATE", false),

		LogLevel:  GetEnvOrDefault("LOG_LEVEL", "info"),
		LogFormat: GetEnvOrDefault("LOG_FORMAT", "json"),
	}

	return cfg, nil
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
