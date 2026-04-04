package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ephor-scanner/config"
	"ephor-scanner/internal/api"
	"ephor-scanner/internal/discovery"
	"ephor-scanner/internal/models"
	"ephor-scanner/internal/processor"
	"ephor-scanner/internal/scanner"

	"github.com/google/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var version = "dev"

func main() {
	initLogger()
	startedAt := time.Now()
	scanGroupID := uuid.New().String()
	slog.SetDefault(slog.Default().With("scan_group_id", scanGroupID))

	slog.Info("ephor-scanner starting", "version", version)

	// 1. Load config
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	slog.Info("configuration loaded", "namespaces", cfg.ScanNamespaces, "concurrency", cfg.ScanConcurrency, "sbom_enabled", cfg.SBOMEnabled)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// 2. Discover workloads
	k8sClient, err := buildK8sClient()
	if err != nil {
		slog.Error("failed to create kubernetes client", "error", err)
		os.Exit(1)
	}

	disc := discovery.NewDiscoverer(cfg, k8sClient)
	workloads, err := disc.Discover(ctx, cfg.ScanNamespaces)
	if err != nil {
		slog.Error("failed to discover workloads", "error", err)
		os.Exit(1)
	}
	slog.Info("discovery completed", "workloads", len(workloads))

	if len(workloads) == 0 {
		slog.Warn("no workloads found, nothing to scan")
		return
	}

	// 3. Deduplicate images
	uniqueImages := processor.DeduplicateImages(workloads)
	slog.Info("image deduplication completed", "unique_images", len(uniqueImages))

	// 4. Update Trivy DB and scan images
	sc := scanner.NewScanner(cfg)

	if err := sc.UpdateDB(ctx); err != nil {
		slog.Error("failed to update trivy db, continuing with existing db", "error", err)
	}

	trivyVersion := ""
	if v, err := sc.GetVersion(ctx); err == nil {
		trivyVersion = v.Version
	}

	scanResults := processor.ScanImages(ctx, sc, uniqueImages, cfg.ScanConcurrency)
	slog.Info("scanning completed", "total", len(uniqueImages), "results", len(scanResults))

	// 5. Generate SBOMs (if enabled)
	var sbomResults map[string]*processor.SBOMResult
	if cfg.SBOMEnabled {
		slog.Info("sbom generation enabled", "format", cfg.SBOMFormat)
		sbomResults = processor.GenerateSBOMs(ctx, sc, uniqueImages, cfg.ScanConcurrency, cfg.SBOMFormat)
		slog.Info("sbom generation completed", "total", len(uniqueImages), "results", len(sbomResults))
	}

	// 6. Build and deliver per-namespace payloads
	client := api.NewClient(cfg, version)
	meta := processor.ScanMeta{
		ScanGroupID:  scanGroupID,
		ScanLabel:    "ephor-scanner/" + version,
		TrivyVersion: trivyVersion,
		StartedAt:    startedAt,
	}

	var deliveryFailures int
	namespaceWorkloads := groupByNamespace(workloads)

	for ns, nsWorkloads := range namespaceWorkloads {
		payload := processor.BuildNamespacePayload(ns, nsWorkloads, scanResults, meta)

		resp, err := client.IngestScan(ctx, payload)
		if err != nil {
			slog.Error("failed to deliver scan results",
				"namespace", ns,
				"error", err,
			)
			deliveryFailures++
			continue
		}
		slog.Info("scan results delivered",
			"namespace", ns,
			"scan_id", resp.ScanId,
			"vulnerabilities", resp.Vulnerabilities,
			"workloads", resp.Workloads,
			"critical", resp.CriticalVulns,
		)
	}

	// 7. Deliver SBOMs (if enabled)
	var sbomDeliveryFailures int
	if cfg.SBOMEnabled && sbomResults != nil {
		for imageRef, result := range sbomResults {
			if result.Err != nil {
				continue
			}

			digest := ""
			if scanResult, ok := scanResults[imageRef]; ok && scanResult.Report != nil {
				if len(scanResult.Report.Metadata.RepoDigests) > 0 {
					digest = scanResult.Report.Metadata.RepoDigests[0]
				}
			}

			sbomReq := &models.SBOMIngestRequest{
				ImageReference: imageRef,
				ImageDigest:    digest,
				ScanGroupId:    scanGroupID,
				Format:         cfg.SBOMFormat,
				SBOM:           json.RawMessage(result.Data),
			}

			resp, err := client.IngestSBOM(ctx, sbomReq)
			if err != nil {
				slog.Warn("failed to deliver sbom",
					"image", imageRef,
					"error", err,
				)
				sbomDeliveryFailures++
				continue
			}
			slog.Info("sbom delivered",
				"image", imageRef,
				"stored", resp.Stored,
			)
		}
	}

	// 8. Summary
	duration := time.Since(startedAt)
	slog.Info("ephor-scanner completed",
		"duration", duration.Round(time.Second).String(),
		"namespaces", len(namespaceWorkloads),
		"unique_images", len(uniqueImages),
		"delivery_failures", deliveryFailures,
		"sbom_delivery_failures", sbomDeliveryFailures,
	)

	if deliveryFailures > 0 {
		os.Exit(1)
	}
}

func buildK8sClient() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		slog.Debug("not running in-cluster, trying kubeconfig", "error", err)
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
		cfg, err = kubeConfig.ClientConfig()
		if err != nil {
			return nil, err
		}
	}
	return kubernetes.NewForConfig(cfg)
}

func groupByNamespace(workloads []discovery.Workload) map[string][]discovery.Workload {
	result := make(map[string][]discovery.Workload)
	for _, w := range workloads {
		result[w.Namespace] = append(result[w.Namespace], w)
	}
	return result
}

func initLogger() {
	levelStr := config.GetEnvOrDefault("LOG_LEVEL", "INFO")
	var level slog.Level
	switch strings.ToUpper(levelStr) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var handler slog.Handler
	if config.GetEnvOrDefault("LOG_FORMAT", "json") == "text" {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
}
