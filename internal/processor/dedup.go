package processor

import (
	"ephor-scanner/internal/discovery"
)

func DeduplicateImages(workloads []discovery.Workload) []string {
	seen := make(map[string]struct{})
	for _, w := range workloads {
		for _, c := range w.Containers {
			seen[c.Image] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for image := range seen {
		result = append(result, image)
	}
	return result
}
