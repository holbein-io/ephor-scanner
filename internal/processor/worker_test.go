package processor

import (
	"context"
	"ephor-scanner/internal/scanner"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

type mockScanner struct {
	scanFunc func(ctx context.Context, imageRef string) (*scanner.TrivyReport, error)
	sbomFunc func(ctx context.Context, imageRef string, format string) ([]byte, error)
}

func (m *mockScanner) ScanImage(ctx context.Context, imageRef string) (*scanner.TrivyReport, error) {
	return m.scanFunc(ctx, imageRef)
}

func (m *mockScanner) GenerateSBOM(ctx context.Context, imageRef string, format string) ([]byte, error) {
	if m.sbomFunc != nil {
		return m.sbomFunc(ctx, imageRef, format)
	}
	return nil, fmt.Errorf("sbom not implemented")
}

func TestScanImages_AllSuccess(t *testing.T) {
	s := &mockScanner{
		scanFunc: func(ctx context.Context, imageRef string) (*scanner.TrivyReport, error) {
			return &scanner.TrivyReport{ArtifactName: imageRef}, nil
		},
	}

	images := []string{"nginx:1.25", "postgres:16", "redis:7"}
	results := ScanImages(context.Background(), s, images, 2)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for _, img := range images {
		r, ok := results[img]
		if !ok {
			t.Errorf("missing result for %s", img)
			continue
		}
		if r.Err != nil {
			t.Errorf("%s: unexpected error: %v", img, r.Err)
		}
		if r.Report.ArtifactName != img {
			t.Errorf("%s: ArtifactName = %q", img, r.Report.ArtifactName)
		}
	}
}

func TestScanImages_PartialFailure(t *testing.T) {
	s := &mockScanner{
		scanFunc: func(ctx context.Context, imageRef string) (*scanner.TrivyReport, error) {
			if imageRef == "broken:latest" {
				return nil, fmt.Errorf("pull failed")
			}
			return &scanner.TrivyReport{ArtifactName: imageRef}, nil
		},
	}

	images := []string{"nginx:1.25", "broken:latest", "redis:7"}
	results := ScanImages(context.Background(), s, images, 3)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	if results["nginx:1.25"].Err != nil {
		t.Errorf("nginx: unexpected error: %v", results["nginx:1.25"].Err)
	}
	if results["redis:7"].Err != nil {
		t.Errorf("redis: unexpected error: %v", results["redis:7"].Err)
	}
	if results["broken:latest"].Err == nil {
		t.Error("broken: expected error, got nil")
	}
	if results["broken:latest"].Report != nil {
		t.Error("broken: expected nil report")
	}
}

func TestGenerateSBOMs_PassesFormat(t *testing.T) {
	var gotFormat string
	s := &mockScanner{
		sbomFunc: func(ctx context.Context, imageRef string, format string) ([]byte, error) {
			gotFormat = format
			return []byte(`{}`), nil
		},
	}

	GenerateSBOMs(context.Background(), s, []string{"nginx:1.25"}, 1, "spdx-json")
	if gotFormat != "spdx-json" {
		t.Errorf("format = %q, want %q", gotFormat, "spdx-json")
	}
}

func TestScanImages_ConcurrencyBound(t *testing.T) {
	var active atomic.Int32
	var maxActive atomic.Int32

	s := &mockScanner{
		scanFunc: func(ctx context.Context, imageRef string) (*scanner.TrivyReport, error) {
			cur := active.Add(1)
			for {
				old := maxActive.Load()
				if cur <= old || maxActive.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
			active.Add(-1)
			return &scanner.TrivyReport{}, nil
		},
	}

	images := []string{"a:1", "b:1", "c:1", "d:1", "e:1", "f:1"}
	results := ScanImages(context.Background(), s, images, 2)

	if len(results) != 6 {
		t.Fatalf("expected 6 results, got %d", len(results))
	}
	if maxActive.Load() > 2 {
		t.Errorf("max concurrent scans = %d, want <= 2", maxActive.Load())
	}
}
