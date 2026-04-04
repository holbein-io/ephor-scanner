package processor

import (
	"context"
	"log/slog"
	"sync"
)

func GenerateSBOMs(ctx context.Context, s ImageScanner, images []string, concurrency int, format string) map[string]*SBOMResult {
	results := make(map[string]*SBOMResult, len(images))
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, concurrency)

	for _, image := range images {
		if ctx.Err() != nil {
			slog.Warn("sbom generation cancelled, skipping remaining images")
			break
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(img string) {
			defer wg.Done()
			defer func() { <-sem }()

			slog.Info("generating sbom", "image", img, "format", format)
			data, err := s.GenerateSBOM(ctx, img, format)

			mu.Lock()
			results[img] = &SBOMResult{Data: data, Err: err}
			mu.Unlock()

			if err != nil {
				slog.Error("sbom generation failed", "image", img, "error", err)
			} else {
				slog.Info("sbom generated", "image", img, "bytes", len(data))
			}
		}(image)
	}

	wg.Wait()
	return results
}

func ScanImages(ctx context.Context, s ImageScanner, images []string, concurrency int) map[string]*ScanResult {
	results := make(map[string]*ScanResult, len(images))
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, concurrency)

	for _, image := range images {
		if ctx.Err() != nil {
			slog.Warn("scan cancelled, skipping remaining images")
			break
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(img string) {
			defer wg.Done()
			defer func() { <-sem }()

			slog.Info("scanning image", "image", img)
			report, err := s.ScanImage(ctx, img)

			mu.Lock()
			results[img] = &ScanResult{Report: report, Err: err}
			mu.Unlock()

			if err != nil {
				slog.Error("scan failed", "image", img, "error", err)
			} else {
				slog.Info("scan completed", "image", img)
			}
		}(image)
	}

	wg.Wait()
	return results
}
