package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"ephor-scanner/config"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Scanner struct {
	BinaryDir       string
	CacheDir        string
	ScanTimeout     time.Duration
	DBUpdateTimeout time.Duration
	DBRepo          string
	JavaDBRepo      string
	CacheMode       string
	CacheBackend    string
	SkipDBUpdate    bool
	dbReady         bool
	javaDBReady     bool

	Severity []config.Severity
}

func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{BinaryDir: cfg.TrivyBinary,
		CacheDir:        cfg.TrivyCacheDir,
		ScanTimeout:     cfg.TrivyScanTimeout,
		DBUpdateTimeout: cfg.TrivyDBUpdateTimeout,
		DBRepo:          cfg.TrivyDBRepo,
		JavaDBRepo:      cfg.TrivyJavaDBRepo,
		CacheMode:       cfg.TrivyCacheMode,
		CacheBackend:    cfg.TrivyCacheBackend,
		SkipDBUpdate:    cfg.TrivySkipDBUpdate,
		Severity:        cfg.ScanSeverity,
	}
}

var trivyOwnedEnv = []string{
	"TRIVY_TIMEOUT",
	"TRIVY_CACHE_DIR",
	"TRIVY_CACHE_BACKEND",
	"TRIVY_SKIP_DB_UPDATE",
}

func trivyEnv() []string {
	env := os.Environ()
	result := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains(trivyOwnedEnv, name) {
			continue
		}
		result = append(result, kv)
	}
	return result
}

func (s *Scanner) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, s.BinaryDir, args...)
	cmd.Env = trivyEnv()
	return cmd
}

func (s *Scanner) UpdateDB(ctx context.Context) error {
	if s.SkipDBUpdate {
		slog.Warn("DB Update is disabled, skipping...")
		return nil
	}
	if err := s.downloadDB(ctx, "--download-db-only", "--db-repository", s.DBRepo); err != nil {
		return fmt.Errorf("trivy db update failed: %w", err)
	}
	s.dbReady = true

	if err := s.downloadDB(ctx, "--download-java-db-only", "--java-db-repository", s.JavaDBRepo); err != nil {
		return fmt.Errorf("trivy java-db update failed: %w", err)
	}
	s.javaDBReady = true
	return nil
}

func (s *Scanner) downloadDB(ctx context.Context, downloadFlag, repoFlag, repo string) error {
	ctx, cancel := context.WithTimeout(ctx, s.DBUpdateTimeout)
	defer cancel()

	args := []string{"image", downloadFlag, "--cache-dir", s.CacheDir,
		"--timeout", strconv.Itoa(int(s.DBUpdateTimeout.Seconds())) + "s"}
	if repo != "" {
		args = append(args, repoFlag, repo)
	}

	cmd := s.command(ctx, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w\nstderr: %s", err, stderr.String())
	}
	return nil
}

func (s *Scanner) ScanImage(ctx context.Context, imageRef string) (*TrivyReport, error) {
	stdout, err := s.runImageScan(ctx, imageRef, "json", s.severityArgs()...)
	if err != nil {
		return nil, fmt.Errorf("trivy image scan failed: %w", err)
	}

	var report TrivyReport
	if err := json.Unmarshal(stdout, &report); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	return &report, nil
}

func (s *Scanner) GenerateSBOM(ctx context.Context, imageRef string, format string) ([]byte, error) {
	stdout, err := s.runImageScan(ctx, imageRef, format)
	if err != nil {
		return nil, fmt.Errorf("trivy sbom generation failed: %w", err)
	}

	return stdout, nil
}

func (s *Scanner) severityArgs() []string {
	if len(s.Severity) == 0 {
		return nil
	}
	levels := make([]string, 0, len(s.Severity))
	for _, sev := range s.Severity {
		levels = append(levels, sev.String())
	}
	return []string{"--severity", strings.Join(levels, ",")}
}

func (s *Scanner) runImageScan(ctx context.Context, imageRef string, format string, extraArgs ...string) ([]byte, error) {
	cacheDir, cleanup, err := s.resolveScanCache()
	if err != nil {
		return nil, fmt.Errorf("failed to prepare scan cache: %w", err)
	}
	defer cleanup()

	args := []string{"image", imageRef, "--format", format, "--scanners", "vuln", "--cache-dir", cacheDir,
		"--timeout", strconv.Itoa(int(s.ScanTimeout.Seconds())) + "s"}
	if s.CacheMode == config.CacheModeRedis {
		args = append(args, "--cache-backend", s.CacheBackend)
	}
	if s.dbReady || s.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}
	if s.javaDBReady || s.SkipDBUpdate {
		args = append(args, "--skip-java-db-update")
	}
	if s.DBRepo != "" {
		args = append(args, "--db-repository", s.DBRepo)
	}
	if s.JavaDBRepo != "" {
		args = append(args, "--java-db-repository", s.JavaDBRepo)
	}
	args = append(args, extraArgs...)

	ctx, cancel := context.WithTimeout(ctx, s.ScanTimeout)
	defer cancel()

	cmd := s.command(ctx, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w\nstderr: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// resolveScanCache returns the cache dir for a scan and a cleanup to run after it.
func (s *Scanner) resolveScanCache() (string, func(), error) {
	if s.CacheMode == config.CacheModeEphemeral {
		dir, err := s.createScanCacheDir()
		if err != nil {
			return "", func() {}, err
		}
		return dir, func() { _ = os.RemoveAll(dir) }, nil
	}
	return s.CacheDir, func() {}, nil
}

func (s *Scanner) createScanCacheDir() (string, error) {
	tmpDir, err := os.MkdirTemp("", "trivy-scan-*")
	if err != nil {
		return "", err
	}
	for _, sub := range []string{"db", "java-db"} {
		src := filepath.Join(s.CacheDir, sub)
		if _, err := os.Stat(src); err == nil {
			if err := os.Symlink(src, filepath.Join(tmpDir, sub)); err != nil {
				_ = os.RemoveAll(tmpDir)
				return "", err
			}
		}
	}
	return tmpDir, nil
}

func (s *Scanner) GetVersion(ctx context.Context) (*TrivyVersion, error) {
	args := []string{"version", "--format", "json"}

	cmd := s.command(ctx, args...)
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
