package processor

import (
	"context"
	"ephor-scanner/internal/scanner"
	"time"
)

type ImageScanner interface {
	ScanImage(ctx context.Context, imageRef string) (*scanner.TrivyReport, error)
}

type ScanResult struct {
	Report *scanner.TrivyReport
	Err    error
}

type ScanMeta struct {
	ScanGroupID  string
	ScanLabel    string
	TrivyVersion string
	StartedAt    time.Time
	CompletedAt  time.Time
}
