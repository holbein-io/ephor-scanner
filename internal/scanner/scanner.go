package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"ephor-scanner/config"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"time"
)

type Scanner struct {
	BinaryDir       string
	CacheDir        string
	ScanTimeout     time.Duration
	DBUpdateTimeout time.Duration
	DBRepo          string
	SkipDBUpdate    bool
	dbReady         bool

	Namespaces    []string
	Concurrency   int
	Severity      []config.Severity
	WorkloadTypes []config.WorkloadTypes
}

func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{BinaryDir: cfg.TrivyBinary,
		CacheDir:        cfg.TrivyCacheDir,
		ScanTimeout:     cfg.TrivyScanTimeout,
		DBUpdateTimeout: cfg.TrivyDBUpdateTimeout,
		DBRepo:          cfg.TrivyDBRepo,
		SkipDBUpdate:    cfg.TrivySkipDBUpdate,
		Namespaces:      cfg.ScanNamespaces,
		Concurrency:     cfg.ScanConcurrency,
		Severity:        cfg.ScanSeverity,
		WorkloadTypes:   cfg.ScanWorkloadTypes,
	}
}

func (s *Scanner) UpdateDB(ctx context.Context) error {
	if s.SkipDBUpdate {
		slog.Warn("DB Update is disabled, skipping...")
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.DBUpdateTimeout)
	defer cancel()

	args := []string{"image", "--download-db-only", "--cache-dir", s.CacheDir,
		"--timeout", strconv.Itoa(int(s.DBUpdateTimeout.Seconds())) + "s"}
	if s.DBRepo != "" {
		args = append(args, "--db-repository", s.DBRepo)
	}

	cmd := exec.CommandContext(ctx, s.BinaryDir, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("trivy db update failed: %w\nstderr: %s", err, stderr.String())
	}

	s.dbReady = true
	return nil
}

func (s *Scanner) ScanImage(ctx context.Context, imageRef string) (*TrivyReport, error) {
	args := []string{"image", imageRef, "--format", "json", "--scanners", "vuln", "--cache-dir", s.CacheDir,
		"--timeout", strconv.Itoa(int(s.ScanTimeout.Seconds())) + "s"}
	if s.dbReady || s.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}
	if s.DBRepo != "" {
		args = append(args, "--db-repository", s.DBRepo)
	}
	ctx, cancel := context.WithTimeout(ctx, s.ScanTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.BinaryDir, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("trivy image scan failed: %w\nstderr: %s", err, stderr.String())
	}
	var report TrivyReport
	err = json.Unmarshal(stdout.Bytes(), &report)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	return &report, nil
}

func (s *Scanner) GetVersion(ctx context.Context) (*TrivyVersion, error) {
	args := []string{"version", "--format", "json"}

	cmd := exec.CommandContext(ctx, s.BinaryDir, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("trivy get version failed: %w\nstderr: %s", err, stderr.String())
	}
	var version TrivyVersion
	err = json.Unmarshal(stdout.Bytes(), &version)

	return &version, err
}
